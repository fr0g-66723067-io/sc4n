// Package content is the routing layer for the text-ish files of a model
// repository, plus the Hugging Face metadata rules.
//
// internal/artifact decides that a file *is* JSON, Markdown, Jinja or plain text;
// this package decides which library reads it. The artifact's own name is the
// discriminator, because for text content there is nothing else to go on: a
// README.md is read by internal/cards, a tokenizer.json by internal/tokenizer, a
// .jinja template by internal/jinja, and the config.json family by this package's
// hfmeta.go. Everything that no specific rule claims is still passed through the
// shared indicator engine, so a credential path or a webhook URL is found in any
// text file.
//
// The sniffer registered here runs at priority 40, below every binary and
// structural sniffer and above the built-in last-resort text classifier:
//
//   - it cannot be swallowed by onnx-proto (60): ONNX/TF/CoreML are protobuf
//     binaries, and this sniffer refuses any buffer with a NUL byte. Even a
//     protobuf-shaped file that happened to be NUL-free would be claimed by
//     onnx-proto first, because 60 > 40.
//   - it cannot swallow onnx-proto: it never runs before it, and it only ever
//     returns a text format (JSON/JSONLines/Markdown/YAML/Jinja). A binary that
//     onnx-proto declines is still refused here by the NUL/UTF-8 check.
//
// The only formats it returns are ones internal/artifact already has a capability
// row and an extension mapping for, so a newly recognised text file cannot trip
// SC4N-FORMAT-EXTENSION-MISMATCH.
package content

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/cards"
	"github.com/fr0g-66723067-io/sc4n/internal/jinja"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
	"github.com/fr0g-66723067-io/sc4n/internal/tokenizer"
)

// contentSniffPriority sits above the built-in "text" fallback (-100) and below
// onnx-proto/archive-zip (60), so every binary discriminator gets its chance
// first. See the package comment for why this cannot swallow or be swallowed.
const contentSniffPriority = 40

// jinjaSniffPriority sits above python-src (66) and tfjs-model (64): a file whose
// name says it is a template is a template, whatever its first lines look like.
// It sits below notebook (68), which owns .ipynb, and below pte (70) and
// pte-magic (72).
const jinjaSniffPriority = 67

func init() {
	artifact.RegisterSniffer("content-text", contentSniffPriority, sniff)
	artifact.RegisterSniffer("jinja-template", jinjaSniffPriority, sniffTemplate)
	p := parser{}
	for _, f := range []artifact.Format{
		artifact.FormatJSON,
		artifact.FormatJSONLines,
		artifact.FormatMarkdown,
		artifact.FormatText,
		artifact.FormatYAML,
		artifact.FormatJinja,
	} {
		// The capability rows for all six already exist in internal/artifact's
		// package init, so only the parser binding is added here. The guard keeps
		// the registration from colliding if another layer ever claims one.
		if _, ok := artifact.ParserFor(f); !ok {
			artifact.RegisterParser(f, p)
		}
	}
}

// sniff classifies a text artifact further than the built-in fallback does. A
// binary buffer (NUL byte) is never claimed; a file whose extension says .md,
// .yaml, .jsonl or .jinja is named accordingly; content decides between JSON and
// Jinja when the name is uninformative.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	n := s.Size()
	if n <= 0 {
		return artifact.FormatUnknown, false
	}
	probe := min(n, 4096)
	head, err := s.Bytes(0, probe)
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	if !texty(head) {
		return artifact.FormatUnknown, false
	}
	base := baseName(s.Name())
	switch {
	case isMarkdown(base):
		return artifact.FormatMarkdown, true
	case isYAML(base):
		return artifact.FormatYAML, true
	case isJSONLines(base):
		return artifact.FormatJSONLines, true
	case isJSONName(base):
		return artifact.FormatJSON, true
	case isJinjaName(base):
		return artifact.FormatJinja, true
	}
	if looksLikeJinjaHead(head) {
		return artifact.FormatJinja, true
	}
	if looksLikeJSON(head) {
		return artifact.FormatJSON, true
	}
	if looksLikeJinja(head) {
		return artifact.FormatJinja, true
	}
	// Not specific: return false so the built-in classifier records FormatText.
	return artifact.FormatUnknown, false
}

// sniffTemplate claims a chat template by name. The name decides: .jinja, .j2,
// .tmpl and .jinja2 are templates even when their first lines look like Python,
// which is how 24 of the 71 templates in llama.cpp's models/templates were
// dispatched to the UBJSON and Python analysers and never scanned as templates.
//
// Content is deliberately not consulted here. This sniffer sits above every
// binary sniffer (onnx-proto, archive-zip, xgb-ubj, tf-savedmodel, msgpack, …),
// so a content rule that accepts any NUL-free UTF-8 head containing "{{" lets a
// model file whose first bytes happen to hold "{{" be analysed as a template and
// never reach its own parser — an ONNX model with "{{" in an early string loses
// every ONNX rule, including the external-data traversal check. Content-based
// jinja detection belongs to the content sniffer at the bottom of the ladder,
// which runs after every binary sniffer has had its chance; a text file bearing
// "{{" is still a template, and a .onnx/.ubj/.mlmodel file is still itself.
func sniffTemplate(s source.Source, l limits.Limits) (artifact.Format, bool) {
	n := s.Size()
	if n <= 0 {
		return artifact.FormatUnknown, false
	}
	probe := min(n, 4096)
	head, err := s.Bytes(0, probe)
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	if !texty(head) {
		// A binary file named .jinja is still not a template.
		return artifact.FormatUnknown, false
	}
	if isJinjaName(baseName(s.Name())) {
		return artifact.FormatJinja, true
	}
	return artifact.FormatUnknown, false
}

type parser struct{}

// Parse reads the artifact once (bounded by MaxStringBlob) and routes it to the
// library its name selects. Every path ends in at least the shared indicator
// engine, so no text artifact is read by nothing.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	name := ctx.Sink.Artifact()
	if name == "" {
		name = s.Name()
	}
	base := baseName(name)

	data, truncated := readText(ctx, s)
	if data == nil {
		return nil
	}
	if !texty(data) {
		// The fallback classifier called it text, but it is not valid UTF-8.
		// Analysing arbitrary binary as prose would manufacture findings from
		// random bytes — a NUL-free symbol table such as cscope.out yields dozens
		// of "injection" hits from its own symbol names — so the prose-shaped
		// rules are skipped, as are the text-only layers (cards, tokenizer,
		// jinja). What still runs is the byte-safe tier: the literal table, the
		// raw-IP URL hunt, the credential/secret assignments and the
		// Unicode-anomaly pass, which decode runes and skip an invalid byte rather
		// than standing down, so they are correct on any buffer. The skip itself
		// is reported rather than the artifact being dropped in silence.
		stringscan.EmitKind(ctx.Sink, 0, data, stringscan.KindSecrets)
		stringscan.EmitUnicodeAnomalies(ctx.Sink, 0, data)
		ctx.Sink.EmitExtra(ruleNotUTF8, 0,
			"the artifact is not valid UTF-8, so the text-only layers did not run",
			map[string]string{"invalidAt": strconv.Itoa(firstInvalidUTF8(data))})
		return nil
	}

	switch {
	case isMarkdown(base):
		cards.ScanText(ctx.Sink, 0, name, string(data))
	case isJinjaName(base) || ctx.Format == artifact.FormatJinja:
		jinja.Analyze(ctx.Sink, 0, name, string(data))
		// The template tier: the shared engine still looks for a reachable secret
		// or endpoint, but the instruction/pseudo-tag indicator belongs to the
		// template analyser, which knows it is reading a template.
		stringscan.EmitKind(ctx.Sink, 0, data, stringscan.KindTemplate)
	case base == "tokenizer.json":
		if !truncated {
			tokenizer.AnalyzeJSON(ctx.Sink, 0, name, data)
		}
		chatTemplateRule(ctx, name, data)
		stringscan.Emit(ctx.Sink, 0, data)
	case base == "tokenizer_config.json" || base == "special_tokens_map.json":
		if !truncated {
			tokenizer.AnalyzeJSON(ctx.Sink, 0, name, data)
		}
		chatTemplateRule(ctx, name, data)
		stringscan.Emit(ctx.Sink, 0, data)
	case isHFMetaName(base):
		hfMeta(ctx, name, base, data, truncated)
	case base == ".gitattributes":
		gitAttributes(ctx, name, data)
		stringscan.Emit(ctx.Sink, 0, data)
	default:
		stringscan.Emit(ctx.Sink, 0, data)
	}
	return nil
}

// stringscanBytes runs the shared indicator engine over a raw buffer. It exists
// so hfmeta.go can scan a truncated document's prefix without importing the
// engine's helpers in two spellings.
func stringscanBytes(ctx *artifact.Ctx, data []byte) { stringscan.Emit(ctx.Sink, 0, data) }

// readText reads the artifact's bytes up to MaxStringBlob. A larger artifact is
// not truncated silently: SC4N-LIMIT-STRING is emitted with the observed size,
// and the returned bool records that only a prefix was read so the caller can
// decline to decode a partial JSON document.
func readText(ctx *artifact.Ctx, s source.Source) ([]byte, bool) {
	n := s.Size()
	if n <= 0 {
		return nil, false
	}
	cap := ctx.Limits.MaxStringBlob
	if cap <= 0 {
		cap = limits.Default().MaxStringBlob
	}
	truncated := false
	if n > cap {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", n, cap, "text artifact truncated before analysis")
		n = cap
		truncated = true
	}
	data, err := s.Bytes(0, n)
	if err != nil && len(data) == 0 {
		return nil, false
	}
	return data, truncated
}

// texty reports whether b is plausibly text: no NUL byte and valid UTF-8. The
// trailing-bytes tolerance covers a multi-byte rune cut by a truncation boundary.
func texty(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	if utf8.Valid(b) {
		return true
	}
	if len(b) > utf8.UTFMax && utf8.Valid(b[:len(b)-utf8.UTFMax]) {
		return true
	}
	return false
}

// firstInvalidUTF8 returns the offset of the first byte that starts an invalid
// UTF-8 sequence, or len(b) when the buffer is valid. It walks rune by rune so
// the answer names the byte a reader can look at.
func firstInvalidUTF8(b []byte) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			return i
		}
		i += size
	}
	return len(b)
}

// looksLikeJSON reports whether the buffer holds exactly one complete JSON value.
// One token is not enough: a text file whose first byte is '[' (BERT's
// vocab.txt starts with "[PAD]") or a digit (a SHA256SUMS line) yields a token
// without being JSON, and claiming it produced a format/extension mismatch for a
// file that was never anything but text.
//
// A value that does not complete inside the buffer is not claimed: a .json-named
// file is claimed by name first (isJSONName above) and is unaffected, and a large
// unnamed JSON document still reaches the indicator engine through the text path.
func looksLikeJSON(b []byte) bool {
	return decodesOneJSONValue(json.NewDecoder(bytes.NewReader(b)))
}

// decodesOneJSONValue reports whether the decoder holds exactly one complete JSON
// value: the first Decode succeeds and the next one reaches EOF.
func decodesOneJSONValue(dec *json.Decoder) bool {
	var v, rest json.RawMessage
	if err := dec.Decode(&v); err != nil {
		return false
	}
	return dec.Decode(&rest) == io.EOF
}

// looksLikeJinjaHead reports whether the first non-space byte begins a Jinja
// delimiter ({{, {% or {#). It is the narrow test that must run before the JSON
// guess: looksLikeJSON accepts a leading '{', so a template that begins with "{{"
// was claimed as JSON, never reached internal/jinja, and — in a file whose name
// does not say .json — gained an SC4N-FORMAT-EXTENSION-MISMATCH that was an
// artefact of the misclassification.
//
// It looks only at the head, so a JSON document that merely *contains* "{{" inside
// a string keeps its JSON classification; that is what the substring test below is
// for, and it is why this one is checked first rather than instead.
func looksLikeJinjaHead(b []byte) bool {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	if i+1 >= len(b) || b[i] != '{' {
		return false
	}
	switch b[i+1] {
	case '{', '%', '#':
		return true
	}
	return false
}

// looksLikeJinja detects the three Jinja2 delimiters in the content. It is only
// consulted when the name did not already say .json, so a JSON string containing
// "{{" is not misclassified.
func looksLikeJinja(b []byte) bool {
	return bytes.Contains(b, []byte("{{")) ||
		bytes.Contains(b, []byte("{%")) ||
		bytes.Contains(b, []byte("{#"))
}

// baseName is the final path element of a display name, after any archive-member
// chain (`a.whl:b.pth` -> `b.pth`) and after any directory separators.
func baseName(path string) string {
	if i := strings.LastIndexByte(path, ':'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	return path
}

func extOf(base string) string {
	i := strings.LastIndexByte(base, '.')
	if i < 0 || i == len(base)-1 {
		return ""
	}
	return strings.ToLower(base[i+1:])
}

func isMarkdown(base string) bool {
	switch extOf(base) {
	case "md", "markdown":
		return true
	}
	return false
}

func isYAML(base string) bool {
	switch extOf(base) {
	case "yml", "yaml":
		return true
	}
	return false
}

func isJSONLines(base string) bool {
	switch extOf(base) {
	case "jsonl", "ndjson":
		return true
	}
	return false
}

func isJSONName(base string) bool {
	return extOf(base) == "json"
}

func isJinjaName(base string) bool {
	switch extOf(base) {
	case "jinja", "j2", "tmpl", "jinja2":
		return true
	}
	return false
}

// isHFMetaName is the config.json family this package's rules own. tokenizer.json
// and tokenizer_config.json are handled by a separate branch because they route
// to internal/tokenizer first; .gitattributes has its own branch.
func isHFMetaName(base string) bool {
	switch base {
	case "config.json", "adapter_config.json", "modules.json",
		"model_index.json", "dataset_info.json":
		return true
	}
	return false
}
