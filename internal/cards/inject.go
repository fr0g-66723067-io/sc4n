package cards

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// cardDirectives are the instruction shapes SC4N-CARD-INJECTION reports. The
// list is complementary to the shared indicator table: it holds sentence
// imperatives and tool/function-call directives rather than the chat pseudo-tags
// and override phrases stringscan already carries.
var cardDirectives = []string{
	// The chat-format markers only. The bare identifiers `tool_calls`,
	// `function_call`, `recipient_name` and `tool_use` are the field names of every
	// tool-calling API example, so a card that documents function calling carried
	// them: mistralai/Mistral-Large-4-1T-A52B's README produced three medium
	// SC4N-CARD-INJECTION findings for its `tool_calls = response...` snippet, and
	// a card that really instructs the model says so in words ("the assistant
	// must", "always respond"), which the table still carries.
	"<tool_call>", "<function_call>", "<tool_use>", "<tool_response>",
	// The bare second person ("you must ", "you must not", "under no
	// circumstances") is the phrasing of licence text: "You must not use this
	// model in a manner that infringes..." produced two SC4N-CARD-INJECTION
	// findings on Mistral-Large-4-1T-A52B's card. The directive forms below keep
	// the second person only where it names the model or its answer.
	"always respond", "never reveal", "never mention", "do not disclose",
	"do not reveal this", "do not output", "do not echo",
	"the assistant must", "the model must", "system prompt is", "hidden instruction",
	// The above-anaphora family. "Ignore the above" and its variants carry no
	// noun of their own, which is exactly why they are the phrasing a card that
	// has been asked to override the text before it uses; the shared table
	// carries the same literals so one card reports both the metadata and the
	// card verdict.
	"ignore the above", "ignore all previous", "disregard the above",
	"forget the above", "forget all previous",
}

// decodedDirectives are the strings looked for inside a base64 blob that
// decodes to text. They are the second-stage shapes: an injected instruction, a
// URL to fetch, or code to run.
var decodedDirectives = []string{
	"ignore previous", "do not tell the user", "system prompt",
	"http://", "https://", "curl ", "wget ", "/bin/sh", "bash -",
	"os.system", "__import__", "subprocess", "eval(", "exec(",
	"pickle.load", "socket", "base64.b64decode", "import os",
}

// ScanText runs the card and metadata detectors over arbitrary text: a README, a
// dataset card, or one metadata value. what labels the source in evidence.
func ScanText(sink *report.Sink, base int64, what, text string) {
	scanWithKind(sink, base, what, text, stringscan.KindCard, true)
}

// ScanMetadata runs the same detectors over a *metadata* value, with the full
// indicator tier. The difference is the document's role, not its bytes: a
// configuration value that says `subprocess` or `trust_remote_code` is what the
// loader will do, while the same words in a card are an example in a code block.
// YAML frontmatter parsing is skipped because metadata values are strings from
// structured documents (such as JSON), not Markdown files with frontmatter.
func ScanMetadata(sink *report.Sink, base int64, what, text string) {
	scanWithKind(sink, base, what, text, stringscan.KindText, false)
}

func scanWithKind(sink *report.Sink, base int64, what, text string, kind stringscan.Kind, checkFrontmatter bool) {
	if text == "" {
		return
	}
	if checkFrontmatter {
		if _, ok := parseFrontmatter(text); !ok {
			sink.Emit(ruleCardParse, base, "unparseable YAML frontmatter in "+what+"; the document is scanned as raw text")
		}
	}
	// The shared engine already owns the injection phrases, chat pseudo-tags,
	// webhooks, credential paths and unicode anomalies. Do not duplicate them.
	stringscan.EmitStringKind(sink, base, text, kind)
	hidden(sink, base, what, text)
	directives(sink, base, what, text)
	base64Payloads(sink, base, what, text)
}

// ScanJSONFile runs the document-level card detectors over a decoded HF metadata
// document (config.json, model_index.json, dataset_info.json, and any other
// metadata JSON). README frontmatter is handled inside ScanText.
//
// Every value in the stream is decoded, not just the first. A metadata file can
// hold more than one JSON document, and a second one — or any trailing bytes —
// was previously neither decoded nor scanned, so a webhook in it produced no
// finding where the same bytes in a plain .json produced one. Whatever the
// decoder did not consume is scanned as raw text, so nothing past the last
// complete value is dropped in silence either.
func ScanJSONFile(sink *report.Sink, base int64, path string, data []byte) {
	if len(data) == 0 {
		return
	}
	// The document is walked twice at most: once to index where each string
	// literal begins and once for the detector pass. Locating every value with a
	// whole-document search made a metadata file with 150000 keys quadratic, and
	// the measured cost was over 300 s before this index existed.
	idx := buildOffsetIndex(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	decoded := 0
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			return
		}
		if err != nil {
			off := dec.InputOffset()
			if decoded == 0 {
				// The first value never completed, so the whole document is the
				// undecoded remainder.
				off = 0
			}
			if off > int64(len(data)) {
				off = int64(len(data))
			}
			sink.Emit(ruleCardParse, base+off, "metadata document "+path+" is not valid JSON; the remainder is scanned as raw text")
			ScanText(sink, base+off, path, string(data[off:]))
			return
		}
		decoded++
		walkJSONStrings(doc, func(s string) {
			ScanMetadata(sink, base+idx.locate(data, s), path, s)
		})
		walkJSONSecretPairs(doc, func(key, value string) {
			stringscan.EmitJSONSecretValue(sink, base+idx.locate(data, value), key, value)
		})
	}
}

// walkJSONSecretPairs calls fn for every key/value pair whose value is a string,
// in the same deterministic order walkJSONStrings uses. The pair is passed
// together because the secret rule needs the property name and its value, and
// the decoded walk otherwise hands each string over on its own.
func walkJSONSecretPairs(v any, fn func(key, value string)) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := x[k].(string); ok {
				fn(k, s)
			}
			walkJSONSecretPairs(x[k], fn)
		}
	case []any:
		for _, it := range x {
			walkJSONSecretPairs(it, fn)
		}
	}
}

// walkJSONStrings calls fn for every string that is a key or a value of the
// document, in a deterministic order.
func walkJSONStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fn(k)
			walkJSONStrings(x[k], fn)
		}
	case []any:
		for _, it := range x {
			walkJSONStrings(it, fn)
		}
	}
}

// offsetIndex maps every string literal in a JSON document to the offset of the
// first byte after its opening quote, so a decoded key or value can be located
// in constant time.
type offsetIndex map[string]int64

// buildOffsetIndex scans data once and records the position of the first
// occurrence of every string literal. It is the whole-document search that
// locate used to run per string, hoisted into a single pass; the JSON decoder
// reaches a string literal only after the document has decoded, so the scanner
// can assume well-formed literals (a stray quote would have failed the decode).
func buildOffsetIndex(data []byte) offsetIndex {
	idx := make(offsetIndex, len(data)/16)
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(data) && data[j] != '"' {
			if data[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(data) {
			return idx
		}
		var s string
		if err := json.Unmarshal(data[i:j+1], &s); err == nil {
			if _, ok := idx[s]; !ok {
				idx[s] = int64(i + 1)
			}
		}
		i = j
	}
	return idx
}

// locate finds the byte offset of a decoded JSON string inside the raw
// document, falling back to 0 when it cannot be resolved. A string the decoder
// produced is always in the index; the searches below are a safety net for a
// value the raw scan could not see.
func (idx offsetIndex) locate(data []byte, s string) int64 {
	if s == "" {
		return 0
	}
	if off, ok := idx[s]; ok {
		return off
	}
	if i := bytes.Index(data, []byte(s)); i >= 0 {
		return int64(i)
	}
	if q, err := json.Marshal(s); err == nil && len(q) > 2 {
		if i := bytes.Index(data, q[1:len(q)-1]); i >= 0 {
			return int64(i)
		}
	}
	return 0
}

// hidden reports HTML comments and runs of invisible/order-control characters.
//
// The two channels are split by what the text actually is, not by the channel:
// an HTML comment is reported high only when its body carries instruction-shaped
// text (the hidden-directive shape), and informational when it does not, because
// a commented-out heading, a lint directive and an uploader's section markers are
// editorial practice — 419 of the 450 comments and invisible runs in the 273-model
// HF campaign. A run of invisible characters is reported high when it reorders
// what a reader sees (Trojan Source) and medium when it only hides text, which is
// what a copy-paste from a rendered page leaves behind.
func hidden(sink *report.Sink, base int64, what, text string) {
	for i := 0; ; {
		j := strings.Index(text[i:], "<!--")
		if j < 0 {
			break
		}
		start := i + j
		rest := text[start+4:]
		k := strings.Index(rest, "-->")
		body := rest
		if k >= 0 {
			body = rest[:k]
		}
		quoted := strconv.Quote(report.TruncateEvidence(body, 120))
		secret := stringscan.HasSecretHit(body)
		if hasInstruction(body) {
			ev := "HTML comment in " + what + ", hidden from every Markdown renderer, carries instruction-shaped text: " + quoted
			if secret {
				sink.EmitRedacted(ruleCardHidden, base+int64(start),
					"HTML comment in "+what+", hidden from every Markdown renderer, carries instruction-shaped text and a masked secret", nil)
			} else {
				sink.Emit(ruleCardHidden, base+int64(start), ev)
			}
			if len(stringscan.ScanStringKind(body, stringscan.KindCard)) > 0 {
				if secret {
					sink.EmitRedacted(ruleCardInjection, base+int64(start),
						"instruction-like content hidden in an HTML comment in "+what+" and a masked secret", nil)
				} else {
					sink.Emit(ruleCardInjection, base+int64(start),
						"instruction-like content hidden in an HTML comment in "+what+": "+quoted)
				}
			}
		} else {
			if secret {
				sink.EmitRedacted(ruleCardComment, base+int64(start),
					"HTML comment in "+what+", hidden from every Markdown renderer, carries a masked secret", nil)
			} else {
				sink.Emit(ruleCardComment, base+int64(start),
					"HTML comment in "+what+", hidden from every Markdown renderer, carries no instruction: "+quoted)
			}
		}
		if k < 0 {
			break
		}
		i = start + 4 + k + 3
	}

	var hiddenRuns, hiddenChars, invisibleRuns, invisibleChars int
	var hiddenAt, invisibleAt int64 = -1, -1
	startIdx := 0
	// Exempt a single leading UTF-8 BOM (U+FEFF) at the very start of the text.
	if strings.HasPrefix(text, "\ufeff") {
		startIdx = len("\ufeff")
	}
	for i := startIdx; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !invisible(r) {
			i += size
			continue
		}
		// Exempt a standalone ZWJ (U+200D) joining emoji code points (e.g. 👨‍💻).
		if r == 0x200D && isEmojiZWJ(text, i, size) {
			i += size
			continue
		}
		start := i
		n := 0
		reorders := false
		for i < len(text) {
			r2, s2 := utf8.DecodeRuneInString(text[i:])
			if !invisible(r2) {
				break
			}
			if orderAffecting(r2) {
				reorders = true
			}
			i += s2
			n++
		}
		if reorders {
			hiddenRuns++
			hiddenChars += n
			if hiddenAt < 0 {
				hiddenAt = int64(start)
			}
			continue
		}
		invisibleRuns++
		invisibleChars += n
		if invisibleAt < 0 {
			invisibleAt = int64(start)
		}
	}
	// One finding per document, not one per run: DavidAU's GGUF card pads its
	// prose with zero-width spaces and produced 27 medium SC4N-CARD-INVISIBLE
	// findings for one author's habit, which is one decision ("this card carries
	// invisible characters") and not 27.
	if hiddenRuns > 0 {
		sink.Emit(ruleCardHidden, base+hiddenAt,
			fmt.Sprintf("%d invisible or text-order control character(s) in %s across %d run(s); at least one reorders text (Trojan Source)",
				hiddenChars, what, hiddenRuns))
	}
	if invisibleRuns > 0 {
		sink.Emit(ruleCardInvisible, base+invisibleAt,
			fmt.Sprintf("%d invisible character(s) in %s across %d run(s), which hide text without reordering it",
				invisibleChars, what, invisibleRuns))
	}
}

// isEmojiZWJ reports whether the U+200D at text[i:i+size] is a standalone emoji
// grapheme joiner bridging two emoji/variation-selector code points.
func isEmojiZWJ(text string, i, size int) bool {
	if i <= 0 || i+size >= len(text) {
		return false
	}
	prevR, _ := utf8.DecodeLastRuneInString(text[:i])
	nextR, _ := utf8.DecodeRuneInString(text[i+size:])
	return isEmojiRune(prevR) && isEmojiRune(nextR)
}

func isEmojiRune(r rune) bool {
	switch {
	case r == 0x20E3, r == 0xFE0E, r == 0xFE0F:
		return true
	case r >= 0x2300 && r <= 0x23FF,
		r >= 0x2600 && r <= 0x27BF,
		r >= 0x2B00 && r <= 0x2BFF,
		r >= 0x1F000 && r <= 0x1FAFF:
		return true
	}
	return false
}

// hasInstruction reports whether a comment body is shaped like an instruction: a
// card-tier shared indicator (the phrase and secret/unicode tables, excluding
// documentation-only code/loader/decoder tokens) or one of the card-specific
// directives. Both tables already exist; this is the one place that asks either.
func hasInstruction(body string) bool {
	if len(stringscan.ScanStringKind(body, stringscan.KindCard)) > 0 {
		return true
	}
	low := strings.ToLower(body)
	for _, d := range cardDirectives {
		if strings.Contains(low, d) {
			return true
		}
	}
	return false
}

// orderAffecting reports the invisible characters that reorder what a reader sees
// (Trojan Source): the bidirectional overrides and the three directional marks.
func orderAffecting(r rune) bool {
	switch r {
	case 0x061C, 0x200E, 0x200F:
		return true
	}
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069
}

// directives reports imperative and tool-call directives that the shared
// indicator table does not carry.
//
// One finding per phrase, not one per occurrence: a document *about* prompt
// injection quotes the same directive several times, and
// models/templates/README.md in llama.cpp's tree produced eight medium findings
// that way. The count travels in the evidence instead.
func directives(sink *report.Sink, base int64, what, text string) {
	low := strings.ToLower(text)
	for _, d := range cardDirectives {
		first, count := -1, 0
		from := 0
		for {
			at := strings.Index(low[from:], d)
			if at < 0 {
				break
			}
			off := from + at
			if first < 0 {
				first = off
			}
			count++
			from = off + len(d)
		}
		if first < 0 {
			continue
		}
		ev := what + " contains the model-directed directive " + strconv.Quote(d)
		if count > 1 {
			ev += " (" + strconv.Itoa(count) + " occurrences)"
		}
		sink.Emit(ruleCardInjection, base+int64(first), ev)
	}
}

// base64Payloads reports a long base64 run whose decoded bytes contain an
// instruction, a URL or code. Requiring the decoded content to be directive
// text keeps a data-URI image in a README from being reported.
func base64Payloads(sink *report.Sink, base int64, what, text string) {
	for i := 0; i < len(text); {
		if !isBase64Byte(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && isBase64Byte(text[i]) {
			i++
		}
		run := text[start:i]
		if len(run) < 64 {
			continue
		}
		dec, ok := decodeBase64(run)
		if !ok {
			continue
		}
		if !containsDirective(dec) {
			continue
		}
		sink.EmitExtra(ruleCardInjection, base+int64(start),
			fmt.Sprintf("%s carries a %d-character base64 blob that decodes to directive text", what, len(run)),
			map[string]string{"encoding": "base64", "length": strconv.Itoa(len(run))})
	}
}

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

func decodeBase64(run string) (string, bool) {
	s := strings.TrimRight(run, "=")
	if len(s) < 16 {
		return "", false
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(b), true
	}
	return "", false
}

func containsDirective(s string) bool {
	low := strings.ToLower(s)
	for _, d := range decodedDirectives {
		if strings.Contains(low, d) {
			return true
		}
	}
	return false
}

// invisible reports the zero-width and bidirectional control set: characters a
// reader does not see and, for the bidi overrides, characters that reorder what
// they do see. The Unicode Tags block (U+E0000-U+E007F) is in the set for the
// same reason the zero-width class is: a card carrying it reads as ordinary
// prose to the person the card is written for, while a tokeniser sees the
// text-tag characters it spells.
func invisible(r rune) bool {
	switch r {
	case 0x00AD, // soft hyphen
		0x061C, // Arabic letter mark
		0x180E, // Mongolian vowel separator
		0x200B, // zero-width space
		0x200C, // zero-width non-joiner
		0x200D, // zero-width joiner
		0x200E, // left-to-right mark
		0x200F, // right-to-left mark
		0x2060, // word joiner
		0xFEFF: // zero-width no-break space / BOM
		return true
	}
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r >= 0xE0000 && r <= 0xE007F
}
