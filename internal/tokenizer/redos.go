package tokenizer

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// knownTokenizerClasses is the set of tokenizer_class values Transformers ships
// itself. The list is deliberately broad — a fast/slow pair for each family —
// because the rule is informational and a false "unknown" is noise.
var knownTokenizerClasses = map[string]bool{
	"PreTrainedTokenizer": true, "PreTrainedTokenizerFast": true,
	"BertTokenizer": true, "BertTokenizerFast": true,
	"GPT2Tokenizer": true, "GPT2TokenizerFast": true,
	"LlamaTokenizer": true, "LlamaTokenizerFast": true,
	"CodeLlamaTokenizer": true, "CodeLlamaTokenizerFast": true,
	"MistralTokenizer": true,
	"T5Tokenizer":      true, "T5TokenizerFast": true,
	"RobertaTokenizer": true, "RobertaTokenizerFast": true,
	"XLMRobertaTokenizer": true, "XLMRobertaTokenizerFast": true,
	"ElectraTokenizer": true, "ElectraTokenizerFast": true,
	"DebertaTokenizer": true, "DebertaTokenizerFast": true,
	"DebertaV2Tokenizer": true, "DebertaV2TokenizerFast": true,
	"Qwen2Tokenizer": true, "Qwen2TokenizerFast": true,
	"GemmaTokenizer": true, "GemmaTokenizerFast": true,
	"Gemma2Tokenizer": true, "Gemma2TokenizerFast": true,
	"BloomTokenizerFast": true, "GPTNeoXTokenizerFast": true,
	"BartTokenizer": true, "BartTokenizerFast": true,
	"MBart50Tokenizer": true, "MBart50TokenizerFast": true,
	"M2M100Tokenizer": true, "MarianTokenizer": true,
	"WhisperTokenizer": true, "WhisperTokenizerFast": true,
	"Wav2Vec2CTCTokenizer": true, "Wav2Vec2Tokenizer": true,
	"CLIPTokenizer": true, "CLIPTokenizerFast": true,
	"AlbertTokenizer": true, "AlbertTokenizerFast": true,
	"DistilBertTokenizer": true, "DistilBertTokenizerFast": true,
	"FalconTokenizer": true, "CohereTokenizerFast": true,
	"SiglipTokenizer": true, "Speech2TextTokenizer": true,
	"BlipTokenizerFast": true, "DonutSwinTokenizer": true,
	"LlavaTokenizer": true, "PhimTokenizerFast": true,
	"SeamlessM4TTokenizer": true, "SeamlessM4TTokenizerFast": true,
	"ByT5Tokenizer": true, "PegasusTokenizer": true,
	"RealmTokenizer": true, "SplinterTokenizer": true,
	"CanineTokenizer": true, "LayoutLMTokenizer": true,
	"MarkupLMTokenizer": true, "DPRQuestionEncoderTokenizer": true,
	"TrOCRTokenizer": true, "NllbTokenizer": true, "NllbTokenizerFast": true,
	"CodeGenTokenizer": true, "CodeGenTokenizerFast": true,
	"PhoBertTokenizer": true, "VitsTokenizer": true,
	"Mask2FormerImageProcessor": true, // tolerated: appears in some configs
}

// specialTokenKeys are the tokenizer_config.json / special_tokens_map.json keys
// whose values are strings or {content: …} objects that reach a model.
var specialTokenKeys = []string{
	"bos_token", "eos_token", "unk_token", "sep_token", "pad_token",
	"cls_token", "mask_token", "additional_special_tokens", "extra_special_tokens",
}

// AnalyzeJSON scans a decoded tokenizer.json (or tokenizer_config.json) for
// catastrophic-backtracking and non-RE2 regex patterns and for injection text
// in special tokens. data is the raw JSON; base is the offset of the file.
func AnalyzeJSON(sink *report.Sink, base int64, path string, data []byte) {
	if len(data) == 0 {
		return
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		// A malformed document is not this package's finding to make; the
		// repo-level JSON walker reports it. Return without a finding so the
		// same file does not produce two parse errors from two packages.
		return
	}
	e := &emitter{sink: sink, base: base, path: path, data: data}
	e.walk(doc)
	if m, ok := doc.(map[string]any); ok {
		e.specialTokens(m)
		if s, ok := m["tokenizer_class"].(string); ok && !knownTokenizerClasses[s] {
			sink.EmitExtra(ruleUnknownClass, e.off(s),
				"tokenizer_class "+strconv.Quote(truncate(s, 120))+" is not a class Transformers ships",
				map[string]string{"tokenizer_class": s})
		}
	}
}

type emitter struct {
	sink *report.Sink
	base int64
	path string
	data []byte
}

// off resolves a decoded JSON string to a file offset when possible, falling
// back to the start of the document. It tries the plain form and the
// JSON-escaped form, because a regex is almost always escaped on the wire.
func (e *emitter) off(s string) int64 {
	if s == "" {
		return e.base
	}
	if i := bytes.Index(e.data, []byte(s)); i >= 0 {
		return e.base + int64(i)
	}
	if q, err := json.Marshal(s); err == nil && len(q) > 2 {
		if i := bytes.Index(e.data, q[1:len(q)-1]); i >= 0 {
			return e.base + int64(i)
		}
	}
	return e.base
}

// walk visits every value and reports every string that is the value of a
// "Regex" key, or of a "pattern" key whose sibling "type" is "Regex" (the older
// tokenizers JSON shape). Map keys are visited in sorted order so the emission
// order does not depend on map iteration.
func (e *emitter) walk(v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := x[k]
			if k == "Regex" {
				if s, ok := val.(string); ok {
					e.regex(s)
					continue
				}
			}
			if k == "pattern" {
				if s, ok := val.(string); ok {
					if t, _ := x["type"].(string); t == "Regex" {
						e.regex(s)
						continue
					}
				}
			}
			e.walk(val)
		}
	case []any:
		for _, it := range x {
			e.walk(it)
		}
	}
}

func (e *emitter) regex(re string) {
	for _, h := range findRedos(re) {
		e.sink.EmitExtra(ruleRedos, e.off(re)+int64(h.off),
			"regex uses a "+h.construct+" ("+h.detail+"): "+strconv.Quote(truncate(re, 120)),
			map[string]string{"construct": h.construct, "pattern": truncate(re, 256)})
	}
}

// specialTokens scans the values of the special-token keys and of
// added_tokens/added_tokens_decoder through the shared indicator engine, which
// already carries the injection phrasing, webhook and credential tables.
func (e *emitter) specialTokens(m map[string]any) {
	for _, k := range specialTokenKeys {
		if v, ok := m[k]; ok {
			e.scanTokenValue(v)
		}
	}
	if arr, ok := m["added_tokens"].([]any); ok {
		for _, it := range arr {
			if obj, ok := it.(map[string]any); ok {
				if s, ok := obj["content"].(string); ok {
					stringscan.EmitString(e.sink, e.off(s), s)
				}
			}
		}
	}
	if dec, ok := m["added_tokens_decoder"].(map[string]any); ok {
		keys := make([]string, 0, len(dec))
		for k := range dec {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if obj, ok := dec[k].(map[string]any); ok {
				if s, ok := obj["content"].(string); ok {
					stringscan.EmitString(e.sink, e.off(s), s)
				}
			}
		}
	}
}

func (e *emitter) scanTokenValue(v any) {
	switch x := v.(type) {
	case string:
		stringscan.EmitString(e.sink, e.off(x), x)
	case map[string]any:
		if s, ok := x["content"].(string); ok {
			stringscan.EmitString(e.sink, e.off(s), s)
		}
	case []any:
		for _, it := range x {
			e.scanTokenValue(it)
		}
	}
}

// ChatTemplates extracts every chat template string from a tokenizer_config.json
// or a tokenizer.json document. The chat_template field may be a string, a list
// of {name, template} objects, or an object keyed by name; every entry is
// returned, in document order for a list, so a scanner that stops at the first
// entry misses a malicious second one.
func ChatTemplates(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []string
	collectChatTemplates(doc, &out)
	return out
}

func collectChatTemplates(v any, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		if ct, ok := x["chat_template"]; ok {
			appendChatTemplate(ct, out)
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			if k == "chat_template" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectChatTemplates(x[k], out)
		}
	case []any:
		for _, it := range x {
			collectChatTemplates(it, out)
		}
	}
}

func appendChatTemplate(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, it := range x {
			switch e := it.(type) {
			case string:
				*out = append(*out, e)
			case map[string]any:
				if t, ok := e["template"].(string); ok {
					*out = append(*out, t)
				}
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if t, ok := x[k].(string); ok {
				*out = append(*out, t)
			}
		}
	}
}

// redosHit is one construct found in a regex, with its byte offset in the
// pattern so the finding points at the construct rather than the whole regex.
type redosHit struct {
	construct string
	detail    string
	off       int
}

// findRedos walks a regex source (not a compiled pattern) for the constructs
// RE2 rejects and a backtracking engine turns into super-linear work. It tracks
// character classes so a literal `[+*]` is not mistaken for a quantifier, and a
// group stack so `(a+)+` is reported while `(ab)+` is not.
func findRedos(re string) []redosHit {
	var hits []redosHit
	add := func(c, d string, off int) { hits = append(hits, redosHit{construct: c, detail: d, off: off}) }

	inClass := false
	type group struct{ hasQuant bool }
	var stack []group
	prevWasGroup := false
	prevGroupQuant := false

	for i := 0; i < len(re); i++ {
		c := re[i]
		if c == '\\' {
			if i+1 < len(re) {
				switch d := re[i+1]; {
				case d >= '1' && d <= '9':
					add("backreference", "\\"+string(d), i)
				case d == 'k' && i+2 < len(re) && re[i+2] == '<':
					add("named backreference", "\\k<", i)
				}
			}
			i++
			prevWasGroup, prevGroupQuant = false, false
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			continue
		}

		switch c {
		case '[':
			inClass = true
			prevWasGroup, prevGroupQuant = false, false

		case '(':
			if i+1 < len(re) && re[i+1] == '?' {
				rest := re[i+2:]
				switch {
				case strings.HasPrefix(rest, "<="):
					add("lookbehind", "(?<=", i)
				case strings.HasPrefix(rest, "<!"):
					add("negative lookbehind", "(?<!", i)
				case strings.HasPrefix(rest, "="):
					add("lookahead", "(?=", i)
				case strings.HasPrefix(rest, "!"):
					add("negative lookahead", "(?!)", i)
				case strings.HasPrefix(rest, ">"):
					add("atomic group", "(?>", i)
				case strings.HasPrefix(rest, "R)"):
					add("recursion", "(?R)", i)
				case strings.HasPrefix(rest, "0)"):
					add("recursion", "(?0)", i)
				case strings.HasPrefix(rest, "&"):
					add("subroutine call", "(?&", i)
				case strings.HasPrefix(rest, "P>"):
					add("subroutine call", "(?P>", i)
				case strings.HasPrefix(rest, "P="):
					add("named backreference", "(?P=", i)
				case strings.HasPrefix(rest, "("):
					add("conditional group", "(?(", i)
				}
			}
			stack = append(stack, group{})
			prevWasGroup, prevGroupQuant = false, false

		case ')':
			var g group
			if len(stack) > 0 {
				g = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			if len(stack) > 0 && g.hasQuant {
				stack[len(stack)-1].hasQuant = true
			}
			prevWasGroup, prevGroupQuant = true, g.hasQuant

		case '*', '+', '?':
			if i+1 < len(re) && re[i+1] == '+' {
				add("possessive quantifier", string(c)+"+", i)
				i++
			} else if i+1 < len(re) && re[i+1] == '?' {
				i++ // lazy, which RE2 also supports
			}
			if prevWasGroup && prevGroupQuant {
				add("nested quantifier", "a group containing a quantifier is itself quantified", i)
			}
			if len(stack) > 0 {
				stack[len(stack)-1].hasQuant = true
			}
			prevWasGroup, prevGroupQuant = false, false

		case '{':
			end := strings.IndexByte(re[i:], '}')
			if end < 0 || !isQuantifierBody(re[i+1:i+end]) {
				prevWasGroup, prevGroupQuant = false, false
				continue
			}
			if i+end+1 < len(re) && re[i+end+1] == '+' {
				add("possessive quantifier", re[i:i+end+2], i)
			}
			if prevWasGroup && prevGroupQuant {
				add("nested quantifier", "a group containing a quantifier is itself quantified", i)
			}
			if len(stack) > 0 {
				stack[len(stack)-1].hasQuant = true
			}
			i += end
			prevWasGroup, prevGroupQuant = false, false

		default:
			prevWasGroup, prevGroupQuant = false, false
		}
	}
	return hits
}

// isQuantifierBody reports whether a `{...}` body is a repetition count
// (`2`, `2,`, `2,5`) rather than a literal brace group such as `{x}`.
func isQuantifierBody(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != ',' && (s[i] < '0' || s[i] > '9') {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
