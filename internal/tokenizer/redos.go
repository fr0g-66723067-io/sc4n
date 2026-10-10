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
	e := &emitter{sink: sink, base: base, path: path, offsets: buildOffsets(data)}
	e.walk(doc)
	if m, ok := doc.(map[string]any); ok {
		e.specialTokens(m)
		if s, ok := m["tokenizer_class"].(string); ok && !knownTokenizerClasses[s] {
			sink.EmitExtra(ruleUnknownClass, e.off(s),
				"tokenizer_class "+strconv.Quote(report.TruncateEvidence(s, 120))+" is not a class Transformers ships",
				map[string]string{"tokenizer_class": s})
		}
	}
}

type emitter struct {
	sink *report.Sink
	base int64
	path string
	// offsets maps a decoded string value to the file offset this emitter
	// reports for it, built by buildOffsets in one pass over the document. The
	// offset used to be found by probing the whole document for every reported
	// value (bytes.Index plus a json.Marshal fallback on a miss), which is
	// quadratic in the document: 50 000 added_tokens took 66 s.
	offsets map[string]int64
}

// off resolves a decoded JSON string to a file offset. A value the index does
// not describe resolves to the start of the document, which is what the old
// whole-document probe returned when both of its searches missed.
func (e *emitter) off(s string) int64 {
	if s == "" {
		return e.base
	}
	if off, ok := e.offsets[s]; ok {
		return off
	}
	return e.base
}

// buildOffsets indexes every string key and value of the document against the
// offset the emitter reports for it: the position of the value's own bytes
// inside the token's raw text, or — when the token is escaped on the wire, as a
// regex with backslashes is — the position of the value's escaped encoding. The
// earliest such position in document order wins, so an identical earlier key or
// an equal earlier value is reported at its first occurrence, which is what the
// per-value whole-document probe returned.
//
// The one answer that differs from that probe: a value that also occurs as a
// substring of an *earlier, longer* value is reported at its own token rather
// than inside the longer one. The probe happened to find the substring; pointing
// at the value's own token is the more useful location, and reproducing the
// probe here would mean searching every earlier token for every value, which is
// the quadratic behaviour this index exists to remove.
//
// One pass, so the cost is linear in the document.
func buildOffsets(data []byte) map[string]int64 {
	raw := map[string]int64{}     // first occurrence of the decoded bytes
	escaped := map[string]int64{} // first occurrence of the escaped body
	dec := json.NewDecoder(bytes.NewReader(data))
	prev := int64(0)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		cur := dec.InputOffset()
		if s, ok := tok.(string); ok {
			if q, body, ok := rawStringToken(data, prev, cur); ok {
				if j := strings.Index(body, s); j >= 0 {
					recordFirst(raw, s, q+1+int64(j))
				} else if qb, err := json.Marshal(s); err == nil && len(qb) > 2 {
					if j := strings.Index(body, string(qb[1:len(qb)-1])); j >= 0 {
						recordFirst(escaped, s, q+1+int64(j))
					}
				}
			}
		}
		prev = cur
	}
	for s, off := range escaped {
		if _, ok := raw[s]; !ok {
			raw[s] = off
		}
	}
	return raw
}

// rawStringToken locates the raw text of a JSON string token whose decoded form
// the decoder returned between prev and cur (two json.Decoder.InputOffset
// readings). The span holds only punctuation and whitespace before the opening
// quote, and any quote inside the value is escaped, so the first '"' in the
// span opens the token and the byte before cur closes it.
func rawStringToken(data []byte, prev, cur int64) (int64, string, bool) {
	if prev < 0 || cur > int64(len(data)) || cur-prev < 2 {
		return 0, "", false
	}
	span := data[prev:cur]
	q := bytes.IndexByte(span, '"')
	if q < 0 || q+2 > len(span) || span[len(span)-1] != '"' {
		return 0, "", false
	}
	return prev + int64(q), string(span[q+1 : len(span)-1]), true
}

// recordFirst keeps the earliest offset recorded for a value, so the emission
// order of the walk cannot change which occurrence a finding points at.
func recordFirst(m map[string]int64, s string, off int64) {
	if cur, ok := m[s]; !ok || off < cur {
		m[s] = off
	}
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
			"regex uses a "+h.construct+" ("+h.detail+"): "+strconv.Quote(report.TruncateEvidence(re, 120)),
			map[string]string{"construct": h.construct, "pattern": report.TruncateEvidence(re, 256)})
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
			end := indexByteWithin(re, i, '}', 32)
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

// indexByteWithin reports the offset, relative to i, of the first occurrence of
// c within the first max bytes of s[i:], or -1. A regex repetition body is at
// most a handful of bytes ({n}, {n,}, {n,m}), and the value is attacker-
// controlled JSON: searching to the end of the value for a closing brace at
// every '{' of a value that is all '{' is quadratic (1 MB of '{' cost 23 s),
// while a 32-byte window is linear and cannot miss a real quantifier.
func indexByteWithin(s string, i int, c byte, max int) int {
	hi := i + max
	if hi > len(s) {
		hi = len(s)
	}
	for j := i; j < hi; j++ {
		if s[j] == c {
			return j - i
		}
	}
	return -1
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
