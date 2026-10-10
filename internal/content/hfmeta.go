package content

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/cards"
	"github.com/fr0g-66723067-io/sc4n/internal/jinja"
	"github.com/fr0g-66723067-io/sc4n/internal/tokenizer"
)

// hfMeta runs the Hugging Face metadata rules for one config-family document.
// base is the file's final path element (config.json, adapter_config.json, …).
//
// The document is decoded once, with UseNumber so a numeric field is never
// rounded, and cards.ScanJSONFile runs the card/injection/unicode detectors over
// every key and value (that call also drives the shared indicator engine, which
// is why this package does not stringscan the raw bytes a second time).
func hfMeta(ctx *artifact.Ctx, name, base string, data []byte, truncated bool) {
	if truncated {
		// A document larger than MaxStringBlob was not read in full, so decoding
		// it would either fail or describe a prefix as if it were the whole file.
		// The truncation is already reported by the caller; scan the prefix as
		// raw text so an indicator in the part we did read is still found.
		stringscanBytes(ctx, data)
		return
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		// A malformed metadata document is not this package's structural call;
		// cards reports the parse and falls back to raw-text scanning.
		cards.ScanJSONFile(ctx.Sink, 0, name, data)
		return
	}
	cards.ScanJSONFile(ctx.Sink, 0, name, data)

	switch base {
	case "adapter_config.json":
		adapterExternalBase(ctx, name, data, doc)
	case "modules.json":
		modulesRemote(ctx, name, data, doc)
	}
	autoMapRule(ctx, name, data, doc)
	architectureRule(ctx, name, data, doc)
	trustRemoteCodeRule(ctx, name, data, doc)
	chatTemplateRule(ctx, name, data)
}

// autoMapRule reports every auto_map it finds, wherever in the document it sits
// (a config may nest it under a sub-config). Each referenced module is named, and
// sc4n states whether the matching .py file exists next to the artifact, because
// a local module is code the loader will import.
func autoMapRule(ctx *artifact.Ctx, name string, data []byte, doc any) {
	walkMaps(doc, func(m map[string]any) {
		v, ok := m["auto_map"]
		if !ok {
			return
		}
		for _, ref := range moduleRefs(v) {
			ev := "auto_map references " + ref
			if mod := moduleOfRef(ref); mod != "" {
				if p, present := moduleExists(name, mod); present {
					ev += "; the module file " + p + " exists in the scanned tree"
				} else {
					ev += "; the module file " + mod + ".py is not present in the scanned tree"
				}
			}
			ctx.Sink.EmitExtra(ruleAutoMap, offsetOf(data, ref), ev,
				map[string]string{"module": ref, "file": baseName(name)})
		}
	})
}

// moduleRefs flattens an auto_map value: it is a string, an array of strings, or
// an object whose values are either. Every string is a `module.ClassName`
// reference.
func moduleRefs(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		if x != "" {
			out = append(out, x)
		}
	case []any:
		for _, it := range x {
			out = append(out, moduleRefs(it)...)
		}
	case map[string]any:
		keys := sortedKeys(x)
		for _, k := range keys {
			out = append(out, moduleRefs(x[k])...)
		}
	}
	return out
}

// moduleOfRef turns `pkg.mod.ClassName` into `pkg/mod`. It returns "" when the
// reference has no dotted class part or carries an attribute suffix, both of
// which mean the module file cannot be derived by string manipulation alone.
func moduleOfRef(ref string) string {
	if i := strings.IndexByte(ref, '['); i >= 0 {
		ref = ref[:i]
	}
	i := strings.LastIndexByte(ref, '.')
	if i <= 0 || i == len(ref)-1 {
		return ""
	}
	mod := ref[:i]
	for _, part := range strings.Split(mod, ".") {
		if !isIdent(part) {
			return ""
		}
	}
	return strings.ReplaceAll(mod, ".", "/")
}

// moduleExists reports whether module (a slash path without .py) resolves to a
// file next to the artifact. It is a non-following existence check used only for
// evidence: the file's own contents are scanned separately by the Python layer
// when the whole tree is scanned. Absolute paths and `..` segments are refused
// before any filesystem call, and the member chain of a nested artifact has no
// directory on disk, so it yields no answer rather than guessing.
func moduleExists(name, module string) (string, bool) {
	dir := realDir(name)
	if dir == "" || module == "" {
		return "", false
	}
	rel := module + ".py"
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", false
	}
	p := filepath.Join(dir, filepath.FromSlash(rel))
	fi, err := os.Lstat(p)
	if err != nil || fi.IsDir() {
		return "", false
	}
	return p, true
}

// architectureRule is informational and only fires for a name outside the set
// Transformers ships, so an ordinary checkpoint never trips it.
func architectureRule(ctx *artifact.Ctx, name string, data []byte, doc any) {
	walkMaps(doc, func(m map[string]any) {
		v, ok := m["architectures"]
		if !ok {
			return
		}
		for _, a := range stringsOf(v) {
			if a == "" || knownArchitectures[a] {
				continue
			}
			ctx.Sink.EmitExtra(ruleUnknownArchitecture, offsetOf(data, a),
				"architecture "+clip(a, 120)+" is not one Transformers ships",
				map[string]string{"architecture": a, "file": baseName(name)})
		}
	})
}

// trustRemoteCodeRule fires only for a truthful flag: a config that says
// `"trust_remote_code": false` is telling the reader the opposite.
func trustRemoteCodeRule(ctx *artifact.Ctx, name string, data []byte, doc any) {
	walkMaps(doc, func(m map[string]any) {
		v, ok := m["trust_remote_code"]
		if !ok || !truthy(v) {
			return
		}
		ctx.Sink.EmitExtra(ruleTrustRemoteCode, offsetOf(data, "trust_remote_code"),
			"config sets trust_remote_code, which instructs the loader to import and execute repository code",
			map[string]string{"file": baseName(name)})
	})
}

// chatTemplateRule extracts every chat template from the document and hands each
// one to the Jinja2 analyser, so a list-shaped template is fully walked. It emits
// one informational finding per entry naming where the template came from.
func chatTemplateRule(ctx *artifact.Ctx, name string, data []byte) {
	templates := tokenizer.ChatTemplates(data)
	for i, tmpl := range templates {
		base := offsetOf(data, tmpl)
		ctx.Sink.EmitExtra(ruleConfigChatTemplate, base,
			"chat_template["+itoa(i)+"] was analysed by the Jinja2 rules: "+clip(tmpl, 80),
			map[string]string{"file": baseName(name), "index": itoa(i)})
		jinja.Analyze(ctx.Sink, base, name, tmpl)
	}
}

// adapterExternalBase reports a PEFT adapter whose base model does not resolve
// to a directory in the scanned tree.
func adapterExternalBase(ctx *artifact.Ctx, name string, data []byte, doc any) {
	m, ok := doc.(map[string]any)
	if !ok {
		return
	}
	v, ok := m["base_model_name_or_path"]
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return
	}
	if localDirExists(name, s) {
		return
	}
	ctx.Sink.EmitExtra(ruleAdapterExternalBase, offsetOf(data, s),
		"adapter base_model_name_or_path "+clip(s, 120)+" does not resolve inside the scanned tree, so the base model is a separate artifact",
		map[string]string{"base_model_name_or_path": s, "file": baseName(name)})
}

// modulesRemote reports a sentence-transformers module entry whose path is empty
// or points outside the scanned tree.
func modulesRemote(ctx *artifact.Ctx, name string, data []byte, doc any) {
	arr, ok := doc.([]any)
	if !ok {
		return
	}
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		path, _ := m["path"].(string)
		if path != "" && !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") &&
			!filepath.IsAbs(path) && !strings.Contains(path, "..") && localDirExists(name, path) {
			continue
		}
		if path != "" && !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") &&
			!filepath.IsAbs(path) && !strings.Contains(path, "..") && !strings.Contains(path, "/") {
			// A bare subdirectory name with no separator is a local module
			// (e.g. "1_Pooling"); an absent directory only means the tree is a
			// partial checkout, which is not this rule's subject.
			continue
		}
		ctx.Sink.EmitExtra(ruleModulesRemoteModule, offsetOf(data, pathOrType(path, typ)),
			"modules.json entry "+clip(typ, 80)+" resolves to a remote module (path "+clip(path, 80)+")",
			map[string]string{"type": typ, "path": path, "file": baseName(name)})
	}
}

func pathOrType(path, typ string) string {
	if path != "" {
		return path
	}
	return typ
}

// gitAttributes reports LFS and non-LFS filter/diff drivers. It parses the file
// line by line because .gitattributes is a whitespace-separated pattern/attribute
// list, not YAML or JSON, and the plan links no parser for it.
func gitAttributes(ctx *artifact.Ctx, name string, data []byte) {
	for _, ln := range lineSpans(data) {
		fields := strings.Fields(string(data[ln.start:ln.end]))
		if len(fields) < 2 {
			continue
		}
		for _, attr := range fields[1:] {
			if attr == "filter=lfs" || attr == "diff=lfs" || attr == "merge=lfs" {
				ctx.Sink.Emit(ruleGitattributesLFS, int64(ln.start),
					".gitattributes routes "+clip(fields[0], 60)+" through Git LFS ("+attr+")")
				continue
			}
			key, val, ok := strings.Cut(attr, "=")
			if !ok {
				continue
			}
			switch key {
			case "filter":
				ctx.Sink.Emit(ruleGitattributesFilter, int64(ln.start),
					".gitattributes assigns filter driver "+clip(val, 60)+" to "+clip(fields[0], 60)+
						"; the driver's command lives in the local Git configuration")
			case "diff":
				if !builtinDiffDrivers[val] {
					ctx.Sink.Emit(ruleGitattributesFilter, int64(ln.start),
						".gitattributes assigns non-builtin diff driver "+clip(val, 60)+" to "+clip(fields[0], 60)+
							"; a diff driver may name a textconv command Git executes")
				}
			}
		}
	}
}

type span struct{ start, end int }

// lineSpans returns each line's byte range, exclusive of the trailing newline.
func lineSpans(b []byte) []span {
	var out []span
	start := 0
	for i := range b {
		if b[i] == '\n' {
			end := i
			if end > start && b[end-1] == '\r' {
				end--
			}
			out = append(out, span{start, end})
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, span{start, len(b)})
	}
	return out
}

// localDirExists reports whether a path-shaped value resolves to a directory
// next to the artifact. It is used to decide whether a reference is local or
// remote; it is a non-following stat and never reads the target.
func localDirExists(name, value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "..") {
		return false
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return false
	}
	dir := realDir(name)
	if dir == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(value)))
	return err == nil && fi.IsDir()
}

// realDir returns the directory of a real on-disk artifact path, or "" for an
// archive member (whose display name carries a `:` chain) or a stdin artifact.
func realDir(name string) string {
	if strings.Contains(name, ":") {
		return ""
	}
	dir := filepath.Dir(name)
	if dir == "." {
		return ""
	}
	return dir
}

// walkMaps calls fn for every JSON object in v, in a deterministic order.
func walkMaps(v any, fn func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		fn(x)
		for _, k := range sortedKeys(x) {
			walkMaps(x[k], fn)
		}
	case []any:
		for _, it := range x {
			walkMaps(it, fn)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stringsOf flattens a JSON string or array-of-strings value.
func stringsOf(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, it := range x {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// truthy accepts the boolean true and the string spellings YAML-ish configs use.
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || strings.EqualFold(x, "yes")
	}
	return false
}

// offsetOf resolves a decoded value to a file offset when it appears verbatim,
// falling back to the start of the document. It is evidence localisation only.
func offsetOf(data []byte, s string) int64 {
	if s == "" {
		return 0
	}
	if i := bytes.Index(data, []byte(s)); i >= 0 {
		return int64(i)
	}
	return 0
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// knownArchitectures is the set of model classes Transformers ships. The list is
// deliberately broad (the rule is informational, and a false "unknown" is noise),
// covering the encoder/decoder/vision/audio/multimodal families.
var knownArchitectures = map[string]bool{
	"AlbertForMaskedLM": true, "AlbertForPreTraining": true, "AlbertForQuestionAnswering": true,
	"AlbertForSequenceClassification": true, "AlbertForTokenClassification": true, "AlbertModel": true,
	"AutoModel": true, "AutoModelForCausalLM": true,
	"BartForCausalLM": true, "BartForConditionalGeneration": true, "BartForQuestionAnswering": true,
	"BartForSequenceClassification": true, "BartModel": true,
	"BertForMaskedLM": true, "BertForMultipleChoice": true, "BertForPreTraining": true,
	"BertForQuestionAnswering": true, "BertForSequenceClassification": true,
	"BertForTokenClassification": true, "BertModel": true,
	"BigBirdForSequenceClassification": true, "BigBirdModel": true,
	"BloomForCausalLM": true, "BloomForSequenceClassification": true, "BloomModel": true,
	"CLIPModel": true, "CLIPTextModel": true, "CLIPVisionModel": true, "CLIPVisionModelWithProjection": true,
	"CohereForCausalLM": true, "CohereModel": true,
	"ConvBertForMaskedLM": true, "ConvBertModel": true,
	"DebertaForSequenceClassification": true, "DebertaModel": true,
	"DebertaV2ForSequenceClassification": true, "DebertaV2Model": true,
	"DeiTForImageClassification": true, "DeiTModel": true,
	"DistilBertForMaskedLM": true, "DistilBertForQuestionAnswering": true,
	"DistilBertForSequenceClassification": true, "DistilBertForTokenClassification": true,
	"DistilBertModel": true,
	"ElectraForMaskedLM": true, "ElectraForQuestionAnswering": true,
	"ElectraForSequenceClassification": true, "ElectraForTokenClassification": true, "ElectraModel": true,
	"EncoderDecoderModel": true,
	"FalconForCausalLM": true, "FalconForSequenceClassification": true, "FalconModel": true,
	"FlaubertModel": true, "FNetModel": true,
	"GPT2ForSequenceClassification": true, "GPT2forCausalLM": true,
	"GPT2LMHeadModel": true, "GPT2Model": true,
	"GPTBigCodeForCausalLM": true, "GPTBigCodeModel": true,
	"GPTJForCausalLM": true, "GPTJForSequenceClassification": true, "GPTJModel": true,
	"GPTNeoForCausalLM": true, "GPTNeoModel": true,
	"GPTNeoXForCausalLM": true, "GPTNeoXForSequenceClassification": true, "GPTNeoXModel": true,
	"GemmaForCausalLM": true, "GemmaForSequenceClassification": true, "GemmaModel": true,
	"Gemma2ForCausalLM": true, "Gemma2Model": true,
	"HubertModel": true, "LayoutLMModel": true,
	"LlamaForCausalLM": true, "LlamaForQuestionAnswering": true,
	"LlamaForSequenceClassification": true, "LlamaModel": true,
	"LongformerForMaskedLM": true, "LongformerForSequenceClassification": true, "LongformerModel": true,
	"MarianMTModel": true, "MBartForConditionalGeneration": true,
	"MistralForCausalLM": true, "MistralForSequenceClassification": true, "MistralModel": true,
	"MixtralForCausalLM": true, "MixtralModel": true,
	"MPNetForMaskedLM": true, "MPNetForSequenceClassification": true, "MPNetModel": true,
	"NllbTokenizer": true, "NllbMoeForConditionalGeneration": true,
	"OPTForCausalLM": true, "OPTForSequenceClassification": true, "OPTModel": true,
	"PegasusForConditionalGeneration": true, "PegasusModel": true,
	"PhiForCausalLM": true, "PhiForSequenceClassification": true, "PhiModel": true,
	"Phi3ForCausalLM": true, "Phi3Model": true,
	"PreTrainedModel": true,
	"Qwen2ForCausalLM": true, "Qwen2ForSequenceClassification": true, "Qwen2Model": true,
	"Qwen2MoeForCausalLM": true,
	"RobertaForMaskedLM": true, "RobertaForMultipleChoice": true,
	"RobertaForQuestionAnswering": true, "RobertaForSequenceClassification": true,
	"RobertaForTokenClassification": true, "RobertaModel": true,
	"RoFormerForMaskedLM": true, "RoFormerModel": true,
	"SiglipModel": true, "SqueezeBertForMaskedLM": true, "SqueezeBertModel": true,
	"T5EncoderModel": true, "T5ForConditionalGeneration": true, "T5Model": true,
	"TapasForQuestionAnswering": true, "TapasModel": true,
	"ViTForImageClassification": true, "ViTModel": true,
	"Wav2Vec2ForAudioFrameClassification": true, "Wav2Vec2ForCTC": true,
	"Wav2Vec2ForSequenceClassification": true, "Wav2Vec2Model": true,
	"WhisperForAudioClassification": true, "WhisperForConditionalGeneration": true, "WhisperModel": true,
	"XLMRobertaForMaskedLM": true, "XLMRobertaForQuestionAnswering": true,
	"XLMRobertaForSequenceClassification": true, "XLMRobertaForTokenClassification": true,
	"XLMRobertaModel": true, "XLNetForSequenceClassification": true, "XLNetModel": true,
	"XLMForSequenceClassification": true, "XLMModel": true,
	"XLMWithLMHeadModel": true,
	"SentenceTransformer": true,
}

// builtinDiffDrivers are the diff drivers Git ships; naming one is a
// syntax-highlighting convention, not a request to run a command.
var builtinDiffDrivers = map[string]bool{
	"ada": true, "asciidoc": true, "bibtex": true, "cpp": true, "csharp": true, "css": true,
	"dts": true, "elixir": true, "fortran": true, "fountain": true, "golang": true, "html": true,
	"java": true, "kotlin": true, "markdown": true, "matlab": true, "objc": true, "pascal": true,
	"perl": true, "php": true, "python": true, "ruby": true, "rust": true, "scheme": true,
	"tex": true, "lfs": true,
}
