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
	// A Go text/template is not Jinja. Both tests below accept "{{", which a Go
	// template is made of, and the analyser then reads Go's action keywords as
	// Jinja: `{{- range .Tools }}` was reported as `range` used as the receiver of
	// attribute access (SC4N-JINJA-DANGEROUS-GLOBAL, high) on unsloth's
	// Qwen3-Coder template. The name test above still wins for a file called
	// *.tmpl/*.jinja, exactly as sniffTemplate documents.
	goTmpl := looksLikeGoTemplate(head)
	if !goTmpl && looksLikeJinjaHead(head) {
		return artifact.FormatJinja, true
	}
	if looksLikeJSON(head) {
		return artifact.FormatJSON, true
	}
	if !goTmpl && looksLikeJinja(head) {
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
	if !texty(data) && base != ".gitattributes" {
		// The fallback classifier called it text, but it is not valid UTF-8.
		// Analysing arbitrary binary as prose would manufacture findings from
		// random bytes — a NUL-free symbol table such as cscope.out yields dozens
		// of "injection" hits from its own symbol names — so the prose-shaped
		// rules are skipped, as are the text-only layers (cards, tokenizer,
		// jinja). What still runs is the byte-safe tier: the literal table, the
		// raw-IP URL hunt and the credential/secret assignments, which are correct
		// on any buffer.
		//
		// Two claims are made only on a text-shaped buffer, because on binary they
		// describe nothing a reader can act on. The Unicode-shape pass decodes
		// runes, so on random bytes it reports "mixed scripts" about float
		// mantissas; and "the text-only layers did not run" is vacuous when there
		// was no text to lose. Both used to fire for every NUL-free binary member
		// of a torch checkpoint: 2,875 SC4N-CONTENT-NOT-UTF8 (low) and the
		// "mixed scripts" half of 4,032 SC4N-UNICODE-ANOMALY findings, on buffers
		// measuring 0.35-0.71 printable. The skip itself is still reported for a
		// buffer that opens as text or is mostly text.
		stringscan.EmitKind(ctx.Sink, 0, data, stringscan.KindSecrets)
		textish := mostlyText(data)
		if textish {
			stringscan.EmitUnicodeAnomalies(ctx.Sink, 0, data)
		}
		if textish || opensAsText(data) {
			ctx.Sink.EmitExtra(ruleNotUTF8, 0,
				"the artifact is not valid UTF-8, so the text-only layers did not run",
				map[string]string{"invalidAt": strconv.Itoa(firstInvalidUTF8(data))})
		}
		return nil
	}

	switch {
	case isJinjaName(base) || ctx.Format == artifact.FormatJinja:
		// Templates come first: a .txt holding a chat template is a program, not a
		// document, and the sniffer has already decided it is one.
		jinja.Analyze(ctx.Sink, 0, name, string(data))
		// The template tier: the shared engine still looks for a reachable secret
		// or endpoint, but the instruction/pseudo-tag indicator belongs to the
		// template analyser, which knows it is reading a template.
		stringscan.EmitKind(ctx.Sink, 0, data, stringscan.KindTemplate)
	case isDocument(base):
		// A card and a plain text document are both things a *reader* consumes:
		// nothing loads a .txt as code. They get the card tier, which keeps the
		// injection table and the secret values and leaves out the rules about what
		// a callable would do with the text. burner22/numbat's training_log_tail.txt
		// produced seven high SC4N-METADATA-CODE findings for "eval(step 1830050)",
		// a metrics line.
		cards.ScanText(ctx.Sink, 0, name, string(data))
	case base == "tokenizer.json":
		if !truncated {
			tokenizer.AnalyzeJSON(ctx.Sink, 0, name, data)
		}
		chatTemplateRule(ctx, name, data)
		emitTokenizerDocument(ctx, data)
	case base == "tokenizer_config.json" || base == "special_tokens_map.json":
		if !truncated {
			tokenizer.AnalyzeJSON(ctx.Sink, 0, name, data)
		}
		chatTemplateRule(ctx, name, data)
		emitTokenizerDocument(ctx, data)
	case base == "chat_template.json" || base == "added_tokens.json":
		// chat_template.json is the processor-side document that carries the same
		// templates tokenizer_config.json does (MiniMax-H3's FL2VA/processor/
		// chat_template.json), and added_tokens.json declares the tokens the
		// tokenizer expects to see. Both used to fall to the default branch, which
		// scans the bytes but never hands a template to the Jinja2 analyser.
		if base == "chat_template.json" {
			chatTemplateRule(ctx, name, data)
		}
		stringscan.Emit(ctx.Sink, 0, data)
	case base == "vocab.json":
		// vocab.json is a flat {token: id} table with nothing else in it, so the
		// whole document is vocabulary data and only the reachable-secret tier
		// applies. Its tokens are ordinary words, including `subprocess`; reading
		// them as prose reported code execution on Qwen3-0.6B and Qwen3-14B.
		stringscan.EmitKind(ctx.Sink, 0, data, stringscan.KindSecrets)
	case base == "unigram.json":
		// A sentencepiece unigram vocabulary: a "type"/"unk_id" header and the
		// table itself, which VocabSpans locates.
		emitTokenizerDocument(ctx, data)
	case isHFMetaName(base):
		hfMeta(ctx, name, base, data, truncated)
	case base == ".gitattributes":
		gitAttributes(ctx, name, data)
		stringscan.Emit(ctx.Sink, 0, data)
	default:
		emitTokenizerDocument(ctx, data)
	}
	return nil
}

// stringscanBytes runs the shared indicator engine over a raw buffer. It exists
// so hfmeta.go can scan a truncated document's prefix without importing the
// engine's helpers in two spellings.
func stringscanBytes(ctx *artifact.Ctx, data []byte) { stringscan.Emit(ctx.Sink, 0, data) }

// emitTokenizerDocument runs the shared indicator engine over a tokenizer
// document with its vocabulary left out. A vocabulary is a table of every token
// the model can emit — byte-level BPE fills it with joiners, soft hyphens and
// bidi marks, and words such as `subprocess` are tokens like any other — so
// judging it as prose reports ordinary data as hostile. The configuration around
// it (pre_tokenizer patterns, normalizer rules, added-token names) is still
// scanned at exact offsets, because that part is what the loader acts on.
func emitTokenizerDocument(ctx *artifact.Ctx, data []byte) {
	stringscan.EmitExcept(ctx.Sink, 0, data, tokenizer.VocabSpans(data))
}

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

// mostlyText reports whether b is predominantly printable ASCII, the condition
// under which a text-shape anomaly is meaningful. Measured on the unsafe corpus:
// genuine non-UTF-8 text artifacts are 0.83-0.99 printable
// (keras_metadata.pb 0.99, TestMsgPackFile.msgpack 0.83) while the torch storage
// members that produced 4,032 SC4N-UNICODE-ANOMALY findings are 0.35-0.71.
func mostlyText(b []byte) bool {
	const maxSample = 64 << 10
	if len(b) > maxSample {
		b = b[:maxSample]
	}
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\t' || c == '\n' || c == '\r' {
			printable++
		}
	}
	return printable*5 >= len(b)*4 // ratio >= 0.8, integer arithmetic
}

// opensAsText reports whether b begins with a run of printable bytes long enough
// that "text with binary appended" is a reading of the artifact rather than a
// coincidence. It mirrors the artifact package's minTextPrefix test for the
// buffer rather than the sniffer's head: a UTF-16 document that fails the decoders
// or a Latin-1 card both open as text, a float array does not.
func opensAsText(b []byte) bool {
	const minPrefix = 64
	if len(b) > 4<<10 {
		b = b[:4<<10]
	}
	n := 0
	for _, c := range b {
		switch {
		case c >= 0x20 && c < 0x7f, c == '\t', c == '\n', c == '\r':
			n++
			if n >= minPrefix {
				return true
			}
		default:
			return false
		}
	}
	return n >= minPrefix
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

// goTemplateKeywords are the action keywords Go's text/template uses inside
// {{ }}.
var goTemplateKeywords = []string{
	"range", "if", "else", "end", "with", "template",
	"define", "block", "break", "continue", "nil",
}

// goOperandKeywords are the keywords that take an operand: `{{ range .Tools }}` is
// Go, `{{ range(3) }}` is a Jinja call to the range builtin.
var goOperandKeywords = []string{"range", "if", "with"}

// looksLikeGoTemplate reports whether head is a Go text/template document: it
// contains a {{ ... }} action whose body starts with a Go keyword or with a
// leading-dot/$ operand, and it contains no {% or {# delimiter (which only Jinja2
// uses).
//
// It exists because Jinja2 and Go's text/template share "{{ }}": a Go template
// reached internal/jinja and was analysed as Jinja, so `{{- range .Tools }}` — an
// action keyword followed by a field reference — was reported as the Jinja global
// `range` receiving an attribute walk. The name test still wins for a file called
// *.tmpl/*.jinja.
func looksLikeGoTemplate(head []byte) bool {
	if bytes.Contains(head, []byte("{%")) || bytes.Contains(head, []byte("{#")) {
		return false
	}
	for i := 0; i < len(head); {
		j := bytes.Index(head[i:], []byte("{{"))
		if j < 0 {
			return false
		}
		rest := head[i+j+2:]
		k := bytes.Index(rest, []byte("}}"))
		if k < 0 {
			return false
		}
		if goTemplateAction(bytes.TrimSpace(rest[:k])) {
			return true
		}
		i += j + 2 + k + 2
	}
	return false
}

// goTemplateAction reports whether one action body is Go rather than Jinja2.
func goTemplateAction(body []byte) bool {
	body = bytes.TrimSpace(bytes.Trim(bytes.TrimSpace(body), "-"))
	if len(body) == 0 {
		return false
	}
	if body[0] == '$' || (body[0] == '.' && len(body) > 1 && isIdentByte(body[1])) {
		return true
	}
	word, operand := body, []byte(nil)
	if k := bytes.IndexAny(body, " \t\n"); k >= 0 {
		word, operand = body[:k], bytes.TrimSpace(body[k+1:])
	}
	for _, kw := range goOperandKeywords {
		if string(word) == kw {
			return len(operand) > 0
		}
	}
	for _, kw := range goTemplateKeywords {
		if string(word) == kw {
			return true
		}
	}
	return false
}

// isIdentByte reports whether c can start a Go template field or variable name.
func isIdentByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

// baseName is the final path element of a display name, after any archive-member
// chain (`a.whl:b.pth` -> `b.pth`) and after any directory separators.
func baseName(path string) string {
	if i := strings.LastIndexByte(path, ':'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
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

// isDocument reports whether the artifact is prose a reader consumes rather than
// data a loader or a callable acts on. It extends isMarkdown with the plain-text
// documents a repository carries beside its weights: training logs, notes,
// captured output.
func isDocument(base string) bool {
	switch extOf(base) {
	case "md", "markdown", "txt", "text", "log":
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
