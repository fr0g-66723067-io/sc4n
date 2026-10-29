package tokenizer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// The tests in this file cover the two quadratic paths that used to live in
// redos.go. The before numbers were measured on the pre-fix tree by calling
// AnalyzeJSON on the crafted documents below; the after numbers on the fixed one:
//
//	regex-braces    1.0 MB   23.54 s  ->  0.04 s
//	added-tokens    2.5 MB   65.70 s  ->  0.27 s
//	escaped-tokens  1.8 MB   (untimed, the same shape as added-tokens)  ->  0.29 s
//
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

func timeAnalyze(doc []byte) (int, time.Duration) {
	c := report.NewCollector(0)
	start := time.Now()
	AnalyzeJSON(c.For("tokenizer.json"), 0, "tokenizer.json", doc)
	return len(c.Findings()), time.Since(start)
}

// TestCraftedDocumentsAreLinear is the regression guard: the before numbers were
// 23.5 s and 65.7 s, the after numbers are tens of milliseconds.
//
// An absolute wall-clock bound is the wrong instrument for that, and it was
// measured flapping: 10 s passed on an idle host (1.95 s for the whole test) and
// failed under `make test`'s 33-way parallelism (12.5 s for added-tokens) with no
// change to this package. The shape of the regression is what matters, so the
// guard measures the same document at two sizes and compares the times — a
// doubling costs ~2x when the analysis is linear and ~4x when it is quadratic
// (the before numbers were 16 s at 25k added tokens and 65.7 s at 50k, 4.1x). The
// absolute bound stays as a backstop for a regression that is catastrophic at one
// size, set well above the loaded-host measurement rather than at it.
func TestCraftedDocumentsAreLinear(t *testing.T) {
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
			got, d := timeAnalyze(c.doc)
			t.Logf("%s: %d bytes, %d findings, %s", c.name, len(c.doc), got, d)
			if got != c.want {
				t.Errorf("findings = %d, want %d", got, c.want)
			}
			if d > 45*time.Second {
				t.Errorf("took %s for %d bytes; the analysis is meant to be linear", d, len(c.doc))
			}
		})
	}

	// The ratio half: one doubling, measured back to back under whatever load the
	// host is under, so a busy machine inflates both numbers and cancels.
	t.Run("doubling-is-not-quadratic", func(t *testing.T) {
		const small = 25000
		_, t1 := timeAnalyze(craftedTokens(small, false))
		_, t2 := timeAnalyze(craftedAddedTokens())
		if len(craftedTokens(small, false)) == 0 || len(craftedAddedTokens()) == 0 {
			t.Fatal("empty document")
		}
		if t1 < 40*time.Millisecond {
			// Too fast to time reliably; the absolute bound above already covers it.
			t.Skipf("small document took %s, below the measurable floor", t1)
		}
		ratio := float64(t2) / float64(t1)
		t.Logf("%d tokens %s, %d tokens %s, ratio %.2f", small, t1, 50000, t2, ratio)
		if ratio > 3.0 {
			t.Errorf("doubling the document multiplied the time by %.2f (%s -> %s); the analysis is meant to be linear", ratio, t1, t2)
		}
	})

	// The webhook in the added-tokens document must still be located at its own
	// token, not at the start of the document: the offset lookup has to survive
	// the index build that replaced the per-value probe.
	c := report.NewCollector(0)
	doc := craftedAddedTokens()
	AnalyzeJSON(c.For("tokenizer.json"), 0, "tokenizer.json", doc)
	for _, f := range c.Findings() {
		if f.RuleID != "SC4N-STRING-C2" {
			continue
		}
		if want := int64(bytes.Index(doc, []byte(craftedWebhook))); f.Offset != want {
			t.Errorf("webhook finding offset = %d, want %d", f.Offset, want)
		}
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
