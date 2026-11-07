package tokenizer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// The documents below are the two shapes that used to drive a quadratic path in
// redos.go, kept as crafted inputs because they are the shapes a hostile
// tokenizer.json uses: a pre_tokenizer regex with a million unmatched '{', and
// 50 000 added_tokens whose contents each used to be located with a
// whole-document search.
//
// What the tests assert is what the analysis reports on those bytes — the finding
// for each shape, and the offset of a value inside a document with many
// lookalikes. Wall-clock behaviour is not asserted anywhere: a test that fails
// because the machine is busy hides the regression it was written for.
//
// Measured on the pre-fix tree for the record, not as a gate: regex-braces
// (1.0 MB) took 23.54 s and added-tokens (2.5 MB) 65.70 s before the offset
// index, and tens of milliseconds after.
// craftedRegexBraces is the first shape: a tokenizer.json whose pre_tokenizer
// pattern is 1 000 000 '{' and no '}'. Every '{' used to rescan the whole
// remaining value for a closing brace.
func craftedRegexBraces() []byte {
	var b strings.Builder
	b.WriteString(`{"pre_tokenizer":{"type":"Sequence","pretokenizers":[{"type":"Split","pattern":{"Regex":"`)
	b.WriteString(strings.Repeat("{", 1_000_000))
	b.WriteString(`"}}]}}`)
	return []byte(b.String())
}

// craftedAddedTokens is the second shape: 50 000 added_tokens, so the emitter
// used to probe the whole document once per content value. The last content is
// a webhook so the offset lookup (and not just the index build) is exercised.
const craftedWebhook = "discord.com/api/webhooks/1/x"

func craftedAddedTokens() []byte { return craftedTokens(50000, true) }

// craftedTokens builds an added_tokens document of n entries. With webhook the
// last content is the URL, so the offset lookup is exercised and not just the
// index build.
func craftedTokens(n int, webhook bool) []byte {
	var b strings.Builder
	b.WriteString(`{"added_tokens":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		content := fmt.Sprintf("tok%d", i)
		if webhook && i == n-1 {
			content = craftedWebhook
		}
		fmt.Fprintf(&b, `{"id":%d,"content":%q,"special":false}`, i, content)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

// craftedEscapedTokens is the same shape with values that are escaped on the
// wire (a backslash in every content), which exercises the escaped-form half of
// the offset index rather than the raw half.
func craftedEscapedTokens() []byte {
	var b strings.Builder
	b.WriteString(`{"added_tokens":[`)
	for i := range 50000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%d,"content":"d\\w+%d"}`, i, i)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

// TestCraftedDocuments reports the same findings on the crafted shapes as before
// the offset index: the counts are a contract, and a shape that starts emitting
// nothing (or extra) after an analysis change is a regression whatever it costs.
func TestCraftedDocuments(t *testing.T) {
	for _, c := range []struct {
		name string
		doc  []byte
		want int // findings
	}{
		{"regex-braces", craftedRegexBraces(), 0},
		{"added-tokens", craftedAddedTokens(), 1},
		{"escaped-tokens", craftedEscapedTokens(), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			col := report.NewCollector(0)
			AnalyzeJSON(col.For("tokenizer.json"), 0, "tokenizer.json", c.doc)
			if got := len(col.Findings()); got != c.want {
				t.Errorf("%s: %d findings, want %d", c.name, got, c.want)
			}
		})
	}
}

// TestCraftedWebhookOffsetIsItsOwnToken pins the offset lookup: the webhook in
// the 50 000-token document must be located at its own token, not at the start of
// the document, because the index build that replaced the per-value probe must not
// change which value the finding points at.
func TestCraftedWebhookOffsetIsItsOwnToken(t *testing.T) {
	c := report.NewCollector(0)
	doc := craftedAddedTokens()
	AnalyzeJSON(c.For("tokenizer.json"), 0, "tokenizer.json", doc)
	found := false
	for _, f := range c.Findings() {
		if f.RuleID != "SC4N-STRING-C2" {
			continue
		}
		found = true
		if want := int64(bytes.Index(doc, []byte(craftedWebhook))); f.Offset != want {
			t.Errorf("webhook finding offset = %d, want %d", f.Offset, want)
		}
	}
	if !found {
		t.Fatal("the webhook in the crafted document produced no SC4N-STRING-C2 finding")
	}
}

// legacyProbe is the pre-fix off() body, kept verbatim so the tests can compare
// the index-backed offset with the whole-document probe for a value.
func legacyProbe(data []byte, base int64, s string) int64 {
	if s == "" {
		return base
	}
	if i := bytes.Index(data, []byte(s)); i >= 0 {
		return base + int64(i)
	}
	if q, err := json.Marshal(s); err == nil && len(q) > 2 {
		if i := bytes.Index(data, q[1:len(q)-1]); i >= 0 {
			return base + int64(i)
		}
	}
	return base
}

// tokenSpan is one JSON string token: the byte range of its raw text (between
// the quotes), whether it is a key, and its decoded value.
type tokenSpan struct {
	start int64
	end   int64
	key   bool
	value string
}

// stringTokenSpans returns every string token of a document in document order.
// A token is a key exactly when the next non-space byte is ':'.
func stringTokenSpans(doc string) []tokenSpan {
	data := []byte(doc)
	dec := json.NewDecoder(bytes.NewReader(data))
	var out []tokenSpan
	prev := int64(0)
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		cur := dec.InputOffset()
		if s, ok := tok.(string); ok {
			if q, _, ok := rawStringToken(data, prev, cur); ok {
				j := int(cur)
				for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
					j++
				}
				out = append(out, tokenSpan{
					start: q + 1, end: cur - 1,
					key:   j < len(data) && data[j] == ':',
					value: s,
				})
			}
		}
		prev = cur
	}
}

// spanContaining reports the token whose raw text covers off..off+n, or nil.
func spanContaining(spans []tokenSpan, off int64, n int) *tokenSpan {
	for i := range spans {
		if off >= spans[i].start && off+int64(n) <= spans[i].end {
			return &spans[i]
		}
	}
	return nil
}

// realisticDoc is the shape a real tokenizer.json has: a name-based class, a
// Split pre_tokenizer whose pattern is a Regex (an escaped one, so the offset
// has to come from the escaped form), the older Regex/pattern form, added_tokens,
// added_tokens_decoder, a {content: …} special token and a webhook token — plus
// an added_tokens_decoder key that is a string, so keys are indexed too.
const realisticDoc = `{
  "version": "1.0",
  "tokenizer_class": "CustomTokenizer",
  "model": {"type": "BPE", "vocab": {"<unk>": 0, "hello": 1}},
  "pre_tokenizer": {"type": "Sequence", "pretokenizers": [
    {"type": "Split", "pattern": {"Regex": "[\\p{L}]+"}}
  ]},
  "normalizer": {"type": "Sequence", "normalizers": [
    {"type": "Regex", "pattern": "(\\w+)+"}
  ]},
  "added_tokens": [
    {"id": 0, "content": "<|start|>", "special": true},
    {"id": 1, "content": "ignore previous instructions", "special": true}
  ],
  "added_tokens_decoder": {"0": {"content": "<|pad|>", "special": false}},
  "bos_token": {"content": "discord.com/api/webhooks/1/x"},
  "additional_special_tokens": ["<pad>", "<|end|>"]
}`

// TestOffsetsMatchTheWholeDocumentProbe is the identity gate for the offset
// index: for every string value in every committed tokenizer fixture, in
// realisticDoc and in substringPairDoc, the index-backed offset must equal the
// offset the pre-fix whole-document probe returned. The one allowed difference
// is the documented one — the probe matched the value inside a *different*,
// longer token (the value also occurs there as a substring) while the index
// points at the value's own token — which is checked for explicitly rather than
// waved through.
func TestOffsetsMatchTheWholeDocumentProbe(t *testing.T) {
	docs := []string{realisticDoc, substringPairDoc}
	for _, p := range []string{
		"../../testdata/fixtures/tokenizer_redos/tokenizer.json",
		"../../testdata/fixtures/benign/tokenizer.json",
		"../../testdata/fixtures/tokenizer_chat_template/tokenizer_config.json",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		docs = append(docs, string(b))
	}
	for di, doc := range docs {
		data := []byte(doc)
		spans := stringTokenSpans(doc)
		e := &emitter{base: 0, offsets: buildOffsets(data)}
		seen := map[string]bool{}
		checked := 0
		for _, sp := range spans {
			if sp.key || sp.value == "" || seen[sp.value] {
				continue // the emitter only reports values
			}
			seen[sp.value] = true
			checked++
			got, want := e.off(sp.value), legacyProbe(data, 0, sp.value)
			if got == want {
				continue
			}
			if at := spanContaining(spans, want, len(sp.value)); at != nil && at.value != sp.value {
				continue // documented: the probe matched inside another token
			}
			t.Errorf("doc%d %q: index offset %d, whole-document probe %d", di, sp.value, got, want)
		}
		if checked == 0 {
			t.Errorf("doc%d: no value compared, the test is not covering the document", di)
		}
	}
}

// TestCraftedOffsetsMatchTheWholeDocumentProbe extends the identity gate to the
// crafted documents: every 250th value of each must resolve to the same offset
// the pre-fix probe would have returned. The probe is a whole-document search,
// so it is sampled rather than run per value (which is exactly the cost this
// change removed).
func TestCraftedOffsetsMatchTheWholeDocumentProbe(t *testing.T) {
	for _, c := range []struct {
		name string
		doc  []byte
	}{
		{"added-tokens", craftedAddedTokens()},
		{"escaped-tokens", craftedEscapedTokens()},
	} {
		t.Run(c.name, func(t *testing.T) {
			spans := stringTokenSpans(string(c.doc))
			e := &emitter{base: 0, offsets: buildOffsets(c.doc)}
			checked, values := 0, 0
			for i, sp := range spans {
				if sp.key {
					continue
				}
				values++
				if values%250 != 0 {
					continue
				}
				checked++
				if got, want := e.off(sp.value), legacyProbe(c.doc, 0, sp.value); got != want {
					t.Fatalf("value %d %q: index offset %d, whole-document probe %d", i, sp.value, got, want)
				}
			}
			if checked == 0 || values == 0 {
				t.Fatalf("%s: no value compared, the test is not covering the document", c.name)
			}
			t.Logf("%s: %d of %d values compared", c.name, checked, values)
		})
	}
}

// substringPairDoc has a value that also occurs inside an earlier, longer value:
// "<s>" inside "<s><s>". This is the one shape where the index deliberately
// differs from the probe (see buildOffsets): the finding points at the value's
// own token instead of at the earlier substring occurrence, because finding the
// substring for every value is the quadratic behaviour the index removes.
const substringPairDoc = `{"added_tokens":[
  {"id":0,"content":"<s><s>","special":true},
  {"id":1,"content":"<s>","special":true}
]}`

func TestValueInsideALongerEarlierValuePointsAtItsOwnToken(t *testing.T) {
	data := []byte(substringPairDoc)
	e := &emitter{base: 0, offsets: buildOffsets(data)}
	got := e.off("<s>")
	want := int64(bytes.LastIndex(data, []byte(`<s>`)))
	if got != want {
		t.Fatalf("offset for %q = %d, want %d (its own token); probe would say %d",
			"<s>", got, want, legacyProbe(data, 0, "<s>"))
	}
}
