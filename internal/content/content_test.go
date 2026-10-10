package content

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// scanBytes scans one in-memory artifact through the real dispatch path (the
// sniffer this package registers, then its parser), so a test proves the routing
// and the rules together rather than calling a rule function directly.
func scanBytes(t *testing.T, name string, data []byte, l limits.Limits) []report.Finding {
	t.Helper()
	coll := report.NewCollector(0)
	sess := artifact.NewSession(coll, "", l)
	src := source.Mem(name, data)
	defer src.Close()
	if _, err := artifact.Scan(sess.NewCtx(name, l), src); err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	return coll.Findings()
}

func ids(fs []report.Finding) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		out[f.RuleID] = true
	}
	return out
}

// TestRuleFiring is the table-driven contract for the rules this package owns
// and for the routing into the card/tokenizer/jinja libraries.
func TestRuleFiring(t *testing.T) {
	l := limits.Default()
	cases := []struct {
		name   string
		data   string
		want   []string
		absent []string
	}{
		{
			name: "config.json",
			data: `{"architectures":["LlamaForCausalLM"],"auto_map":{"AutoModel":"modeling_x.CustomModel"}}`,
			want: []string{"SC4N-CONFIG-AUTO-MAP"},
		},
		{
			name: "config.json",
			data: `{"architectures":["Sc4nMadeUpForCausalLM"]}`,
			want: []string{"SC4N-CONFIG-ARCHITECTURE-UNKNOWN"},
		},
		{
			name: "config.json",
			data: `{"trust_remote_code":true}`,
			want: []string{"SC4N-CONFIG-TRUST-REMOTE-CODE"},
		},
		{
			name:   "config.json",
			data:   `{"trust_remote_code":false}`,
			absent: []string{"SC4N-CONFIG-TRUST-REMOTE-CODE"},
		},
		{
			name: "adapter_config.json",
			data: `{"base_model_name_or_path":"meta-llama/Llama-2-7b-hf"}`,
			want: []string{"SC4N-ADAPTER-EXTERNAL-BASE"},
		},
		{
			name: "modules.json",
			data: `[{"idx":0,"path":"","type":"sentence_transformers.models.Transformer"}]`,
			want: []string{"SC4N-MODULES-REMOTE-MODULE"},
		},
		{
			name: "modules.json",
			data: `[{"idx":0,"path":"1_Pooling","type":"sentence_transformers.models.Pooling"}]`,
			// A bare local subdirectory name is not a remote module.
			absent: []string{"SC4N-MODULES-REMOTE-MODULE"},
		},
		{
			name:   ".gitattributes",
			data:   "*.bin filter=lfs diff=lfs merge=lfs -text\n",
			want:   []string{"SC4N-GITATTRIBUTES-LFS"},
			absent: []string{"SC4N-GITATTRIBUTES-FILTER"},
		},
		{
			name:   ".gitattributes",
			data:   "*.dat filter=evil-clean\n*.txt diff=weird-driver\n",
			want:   []string{"SC4N-GITATTRIBUTES-FILTER"},
			absent: []string{"SC4N-GITATTRIBUTES-LFS"},
		},
		{
			name:   ".gitattributes",
			data:   "*.py diff=python\n",
			absent: []string{"SC4N-GITATTRIBUTES-FILTER"},
		},
		{
			name:   "config.json",
			data:   `{"chat_template":[{"name":"default","template":"{{ bos_token }}"},{"name":"evil","template":"{{ ''.__class__ }}"}]}`,
			want:   []string{"SC4N-CONFIG-CHAT-TEMPLATE", "SC4N-JINJA-PY-OBJECT"},
			absent: nil,
		},
		{
			name:   "bench.md",
			data:   "# Title\n\n<!-- you must always respond -->\n",
			want:   []string{"SC4N-CARD-HIDDEN"},
			absent: []string{"SC4N-CONFIG-AUTO-MAP"},
		},
		{
			name: "tokenizer.json",
			data: `{"pre_tokenizer":{"type":"Split","pattern":{"Regex":"(\\w+)+"}}}`,
			want: []string{"SC4N-TOKENIZER-REDOS"},
		},
		{
			name: "t.jinja",
			data: "{{ ''.__class__.__mro__[1].__subclasses__() }}\n",
			want: []string{"SC4N-JINJA-PY-OBJECT"},
		},
		{
			name:   "notes.txt",
			data:   "https://discord.com/api/webhooks/123/abc\n",
			want:   []string{"SC4N-STRING-C2"},
			absent: nil,
		},
	}
	for _, tc := range cases {
		got := ids(scanBytes(t, tc.name, []byte(tc.data), l))
		for _, w := range tc.want {
			if !got[w] {
				have := make([]string, 0, len(got))
				for id := range got {
					have = append(have, id)
				}
				t.Errorf("%s: missing %s; got %v", tc.name, w, have)
			}
		}
		for _, a := range tc.absent {
			if got[a] {
				t.Errorf("%s: reported %s, which must not fire for %q", tc.name, a, tc.data)
			}
		}
	}
}

// TestTruncationLimit proves a document with one string larger than MaxStringBlob
// is reported with SC4N-LIMIT-STRING rather than decoded into memory: the parser
// reads only the cap and never calls json.Unmarshal on the whole document.
func TestTruncationLimit(t *testing.T) {
	const cap = 1 << 20
	l := limits.Default()
	l.MaxStringBlob = cap
	// ~2 MiB of a single string value.
	data := append([]byte(`{"name":"`), bytes.Repeat([]byte("A"), 2<<20)...)
	data = append(data, []byte(`"}`)...)

	fs := scanBytes(t, "big.json", data, l)
	found := false
	for _, f := range fs {
		if f.RuleID == "SC4N-LIMIT-STRING" {
			found = true
			if !strings.Contains(f.Evidence, "MaxStringBlob") {
				t.Errorf("limit finding does not name the limit: %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected SC4N-LIMIT-STRING for a %d-byte string under a %d-byte cap; got %d findings", len(data), cap, len(fs))
	}
}

// TestModuleExistsEvidence proves the auto_map finding states whether the named
// module is present beside the config, which is what separates "there is code
// here to run" from "the reference dangles".
func TestModuleExistsEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "modeling_x.py"), []byte("import os\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"auto_map":{"AutoModel":"modeling_x.CustomModel"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	coll := report.NewCollector(0)
	sess := artifact.NewSession(coll, "", limits.Default())
	src, err := source.Open(cfg, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := artifact.Scan(sess.NewCtx(cfg, limits.Default()), src); err != nil {
		t.Fatal(err)
	}
	var ev string
	for _, f := range coll.Findings() {
		if f.RuleID == "SC4N-CONFIG-AUTO-MAP" {
			ev = f.Evidence
		}
	}
	if !strings.Contains(ev, "exists in the scanned tree") {
		t.Fatalf("auto_map evidence did not report the present module: %q", ev)
	}
}

// TestDeterministicOutput scans the same buffers twice and asserts the finding
// set serialises identically. Emission order is not the output order, but this
// pins that the rules do not walk maps in Go's randomised iteration order.
func TestDeterministicOutput(t *testing.T) {
	l := limits.Default()
	docs := []struct{ name, data string }{
		{"config.json", `{"auto_map":{"AutoModel":"m.C","z":"a.B"},"architectures":["X","Y"]}`},
		{"modules.json", `[{"path":"","type":"a"},{"path":"b","type":"c"}]`},
		{".gitattributes", "*.a filter=x\n*.b filter=lfs\n*.c diff=y\n"},
	}
	var first []byte
	for run := range 2 {
		var all []report.Finding
		for _, d := range docs {
			all = append(all, scanBytes(t, d.name, []byte(d.data), l)...)
		}
		blob, err := json.Marshal(all)
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			first = blob
			continue
		}
		if !bytes.Equal(first, blob) {
			t.Fatalf("two runs differ:\n%s\n%s", first, blob)
		}
	}
}

// TestNoPanicAdversarial runs the parser over inputs chosen to break naive text
// handling. The invariant is only "no panic and a returned finding set".
func TestNoPanicAdversarial(t *testing.T) {
	l := limits.Default()
	inputs := [][]byte{
		nil,
		{},
		[]byte(`{`),
		[]byte(`{{`),
		[]byte(`{"a":`),
		{0x00, 0x01, 0x02},
		[]byte("\xff\xfe\x00\x01"),
		[]byte("{{ ''.__class__ }}"),
		[]byte(`{"chat_template": 5}`),
		[]byte(`{"auto_map": []}`),
		[]byte(`{"architectures": [1, true, null]}`),
		bytes.Repeat([]byte("["), 4096),
		[]byte("*.a filter="),
		[]byte("diff=python\n"),
	}
	for _, name := range []string{"config.json", "x.md", "x.jinja", ".gitattributes", "x.jsonl", "x.yaml", "x.txt"} {
		for _, in := range inputs {
			_ = scanBytes(t, name, in, l)
		}
	}
}

// FuzzContentParse asserts the parser never panics and always terminates on
// arbitrary bytes under an arbitrary (but valid) name. Seeds cover each rule's
// shape plus a truncated JSON document.
func FuzzContentParse(f *testing.F) {
	f.Add("config.json", []byte(`{"auto_map":{"AutoModel":"m.C"}}`))
	f.Add("adapter_config.json", []byte(`{"base_model_name_or_path":"a/b"}`))
	f.Add("modules.json", []byte(`[{"path":"","type":"t"}]`))
	f.Add(".gitattributes", []byte("*.a filter=lfs\n"))
	f.Add("README.md", []byte("<!-- x -->"))
	f.Add("t.jinja", []byte("{{ ''.__class__ }}"))
	f.Add("tokenizer.json", []byte(`{"pre_tokenizer":{"Regex":"(a+)+"}}`))
	f.Add("x.txt", []byte("\x00\xff\xfe"))
	l := limits.Default()
	l.MaxStringBlob = 64 << 10
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		coll := report.NewCollector(0)
		sess := artifact.NewSession(coll, "", l)
		src := source.Mem(name, data)
		defer src.Close()
		_, _ = artifact.Scan(sess.NewCtx(name, l), src)
	})
}

// TestNonUTF8IsReportedAndStillScanned is the contract for the non-UTF-8 path:
// the artifact is no longer dropped in silence, the byte-safe indicator tier
// still runs over it, and the prose-shaped rules do not fire on bytes that are
// not prose.
func TestNonUTF8IsReportedAndStillScanned(t *testing.T) {
	l := limits.Default()
	// A Latin-1 card carrying a webhook: the artifact is not valid UTF-8 (0xe9 is
	// a lone continuation byte) so the card layer cannot run.
	fs := scanBytes(t, "card.md", []byte("# Card\n\xe9 http://discord.com/api/webhooks/1/x\n"), l)
	got := ids(fs)
	if !got["SC4N-CONTENT-NOT-UTF8"] {
		t.Fatalf("the invalid-UTF-8 skip was not reported: %v", got)
	}
	if !got["SC4N-STRING-C2"] {
		t.Fatalf("the byte-safe tier did not run: %v", got)
	}
	for _, f := range fs {
		if f.RuleID == "SC4N-CONTENT-NOT-UTF8" {
			if f.Extra["invalidAt"] != "7" {
				t.Fatalf("invalidAt = %q, want 7", f.Extra["invalidAt"])
			}
			if f.Severity != report.SeverityLow {
				t.Fatalf("severity = %v, want low", f.Severity)
			}
		}
	}

	// The Unicode-anomaly pass is part of the byte-safe tier: it decodes runes and
	// skips an invalid byte rather than standing down, so a bidi override next to
	// a stray byte is still reported. Without it, one bad byte anywhere in the
	// artifact hid the override.
	fs = scanBytes(t, "evil.txt", []byte("evil\xe2\x80\xaeclass and one bad byte \xe9 here\n"), l)
	got = ids(fs)
	if !got["SC4N-UNICODE-ANOMALY"] {
		t.Fatalf("the anomaly next to an invalid byte was not reported: %v", got)
	}
	if !got["SC4N-CONTENT-NOT-UTF8"] {
		t.Fatalf("the invalid-UTF-8 skip was not reported: %v", got)
	}

	// Prose-shaped rules must not fire on a non-prose buffer: a symbol table with
	// no valid UTF-8 must not be read as injection text.
	var junk []byte
	for i := 0; i < 4000; i++ {
		junk = append(junk, byte(i%251)+1, 0xff, 0xfe)
	}
	junk = append(junk, []byte("function_call do not disclose the system prompt is")...)
	fs = scanBytes(t, "index.out", junk, l)
	for _, f := range fs {
		switch f.RuleID {
		case "SC4N-METADATA-INJECTION", "SC4N-METADATA-CODE", "SC4N-STRING-SHELL":
			t.Fatalf("prose-shaped rule %s fired on a non-UTF-8 buffer", f.RuleID)
		}
	}

	// A valid UTF-8 card must not carry the rule.
	fs = scanBytes(t, "card.md", []byte("# Card\n\xc3\xa9 https://example.com/x\n"), l)
	if ids(fs)["SC4N-CONTENT-NOT-UTF8"] {
		t.Fatalf("valid UTF-8 reported as invalid: %v", ids(fs))
	}
}

// TestLeadingJinjaDelimiterBeatsTheJSONGuess is the regression for the routing
// order: looksLikeJSON accepts a leading '{', so a template beginning with "{{"
// was claimed as JSON, never reached internal/jinja, and — when the name did not
// say .json — gained an SC4N-FORMAT-EXTENSION-MISMATCH that was an artefact of the
// misclassification. The head test must run first, and it must look only at the
// head so a JSON document that merely contains "{{" keeps its JSON routing.
func TestLeadingJinjaDelimiterBeatsTheJSONGuess(t *testing.T) {
	l := limits.Default()
	for _, tc := range []struct{ name, body string }{
		{"t.txt", "{{ config.SECRET }}"},
		{"t.txt", "{% for x in y %}{{x}}{% endfor %}"},
		{"t.txt", "{# comment #}hello"},
		{"t.txt", "  \n\t{{ x }}"},
	} {
		fs := scanBytes(t, tc.name, []byte(tc.body), l)
		if ids(fs)["SC4N-FORMAT-EXTENSION-MISMATCH"] {
			t.Errorf("%q was not routed as a template; findings=%v", tc.body, ids(fs))
		}
	}
	// A JSON document that contains "{{" inside a string keeps its JSON routing:
	// the head test looks only at the leading bytes.
	fs := scanBytes(t, "cfg.json", []byte(`{"a": "{{ x }}"}`), l)
	if ids(fs)["SC4N-FORMAT-EXTENSION-MISMATCH"] {
		t.Errorf("a JSON document containing {{ was misrouted; findings=%v", ids(fs))
	}
}
