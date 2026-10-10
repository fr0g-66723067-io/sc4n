package cards

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"tool_calls", "function_call", "recipient_name", "tool_use",
	"<tool_call>", "<function_call>", "<tool_use>", "<tool_response>",
	"you must ", "you must not", "you should always", "always respond",
	"never reveal", "never mention", "do not disclose", "do not reveal this",
	"do not output", "do not echo", "under no circumstances",
	"the assistant must", "the model must", "system prompt is", "hidden instruction",
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
	if text == "" {
		return
	}
	if _, ok := parseFrontmatter(text); !ok {
		sink.Emit(ruleCardParse, base, "unparseable YAML frontmatter in "+what+"; the document is scanned as raw text")
	}
	// The shared engine already owns the injection phrases, chat pseudo-tags,
	// webhooks, credential paths and unicode anomalies. Do not duplicate them.
	stringscan.EmitString(sink, base, text)
	hidden(sink, base, what, text)
	directives(sink, base, what, text)
	base64Payloads(sink, base, what, text)
}

// ScanJSONFile runs the document-level card detectors over a decoded HF metadata
// document (config.json, model_index.json, dataset_info.json, and any other
// metadata JSON). README frontmatter is handled inside ScanText.
func ScanJSONFile(sink *report.Sink, base int64, path string, data []byte) {
	if len(data) == 0 {
		return
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		sink.Emit(ruleCardParse, base, "metadata document "+path+" is not valid JSON; scanned as raw text")
		ScanText(sink, base, path, string(data))
		return
	}
	walkJSONStrings(doc, func(s string) {
		ScanText(sink, base+locate(data, s), path, s)
	})
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

// locate finds the byte offset of a decoded JSON string inside the raw
// document, falling back to 0 when it cannot be resolved.
func locate(data []byte, s string) int64 {
	if s == "" {
		return 0
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
// An HTML comment whose body carries instruction indicators is additionally
// reported as an injection, because that is the hidden-directive shape.
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
		sink.Emit(ruleCardHidden, base+int64(start),
			"HTML comment in "+what+", hidden from every Markdown renderer: "+strconv.Quote(truncateEvidence(body, 120)))
		if hits := stringscan.ScanString(body); len(hits) > 0 {
			sink.Emit(ruleCardInjection, base+int64(start),
				"instruction-like content hidden in an HTML comment in "+what+": "+strconv.Quote(truncateEvidence(body, 120)))
		}
		if k < 0 {
			break
		}
		i = start + 4 + k + 3
	}

	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !invisible(r) {
			i += size
			continue
		}
		start := i
		n := 0
		for i < len(text) {
			r2, s2 := utf8.DecodeRuneInString(text[i:])
			if !invisible(r2) {
				break
			}
			i += s2
			n++
		}
		sink.Emit(ruleCardHidden, base+int64(start),
			fmt.Sprintf("%d invisible or text-order control character(s) in %s", n, what))
	}
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
// they do see.
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
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069
}

func truncateEvidence(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
