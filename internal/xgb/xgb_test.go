package xgb

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func parse(t *testing.T, name string, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", limits.Default())
	ctx := sess.NewCtx(name, limits.Default())
	s := source.Mem(name, data)
	defer s.Close()
	if err := (parser{}).Parse(ctx, s); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return c.Findings()
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// ubjKey/ubjStr/ubjLen mirror XGBoost's writer: `L` + int64 big-endian length.
func ubjLen(n int) []byte {
	b := []byte{'L'}
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(n))
	return append(b, v[:]...)
}

func ubjKey(k string) []byte { return append(ubjLen(len(k)), k...) }
func ubjStr(s string) []byte { return append([]byte{'S'}, append(ubjLen(len(s)), s...)...) }

func TestTrailingPayloadReported(t *testing.T) {
	data := append([]byte{'{'}, ubjKey("model")...)
	data = append(data, ubjStr("x")...)
	data = append(data, '}')
	data = append(data, []byte("PLANTED-PAYLOAD")...)
	fs := parse(t, "a.ubj", data)
	if !hasRule(fs, RuleTrailing.ID) {
		t.Fatalf("expected %s, got %v", RuleTrailing.ID, ids(fs))
	}
}

func TestMalformedReported(t *testing.T) {
	cases := map[string][]byte{
		"unknown marker":      {'!'},
		"negative string len": append([]byte{'S', 'i', 0xff}, []byte("x")...),
		"truncated string":    {'S', 'i', 10, 'a'},
		"unterminated array":  {'[', 'i', 1},
	}
	for name, data := range cases {
		fs := parse(t, "m.ubj", data)
		if !hasRule(fs, RuleStruct.ID) {
			t.Errorf("%s: expected %s, got %v", name, RuleStruct.ID, ids(fs))
		}
	}
}

func TestStringIndicatorReported(t *testing.T) {
	payload := "https://discord.com/api/webhooks/123/abc"
	data := append([]byte{'{'}, ubjKey("url")...)
	data = append(data, ubjStr(payload)...)
	data = append(data, '}')
	fs := parse(t, "ind.ubj", data)
	if !hasRule(fs, "SC4N-STRING-C2") {
		t.Fatalf("expected SC4N-STRING-C2, got %v", ids(fs))
	}
}

func TestTypedArrayAndKeysParse(t *testing.T) {
	// {"learner":{"weights":[<$l#L 3 (1,2,3)]}} with no end marker on the counted
	// array, per the UBJSON optimisation rules.
	data := append([]byte{'{'}, ubjKey("learner")...)
	data = append(data, '{')
	data = append(data, ubjKey("weights")...)
	data = append(data, '[', '$', 'l', '#')
	data = append(data, ubjLen(3)...)
	for _, v := range []uint32{1, 2, 3} {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], v)
		data = append(data, raw[:]...)
	}
	data = append(data, '}', '}')
	fs := parse(t, "ok.ubj", data)
	if len(fs) != 0 {
		t.Fatalf("expected clean parse, got %v", ids(fs))
	}
}

func TestSniffDoesNotClaimJSON(t *testing.T) {
	jsonDoc := []byte(`{"a":1}`)
	if _, ok := sniff(source.Mem("x.json", jsonDoc), limits.Default()); ok {
		t.Fatal("ordinary JSON was claimed as UBJSON")
	}
	ubj := append([]byte{'{'}, ubjKey("a")...)
	ubj = append(ubj, ubjStr("b")...)
	ubj = append(ubj, '}')
	if _, ok := sniff(source.Mem("x.ubj", ubj), limits.Default()); !ok {
		t.Fatal("UBJSON object was not recognised")
	}
	// UBJSON has no file identifier: the three bytes "UBJ" that some writers put
	// in front of a document are not evidence on their own. A valid document
	// behind them is still claimed, because the walk says so ...
	prefixed := append([]byte("UBJ"), ubj...)
	if _, ok := sniff(source.Mem("x.ubj", prefixed), limits.Default()); !ok {
		t.Fatal("a valid UBJSON document behind the optional UBJ prefix was not recognised")
	}
	// ... while text that merely begins with them is not.
	if _, ok := sniff(source.Mem("x.ubj", []byte("UBJ hello world")), limits.Default()); ok {
		t.Fatal("a text file beginning with the bytes UBJ was claimed as UBJSON")
	}
	if _, ok := sniff(source.Mem("x.ubj", []byte("UBJ{}")), limits.Default()); ok {
		t.Fatal("an empty object behind the UBJ prefix was claimed from the prefix alone")
	}
}

// TestTypedContainerOfContainers covers the container-type optimisation: a
// container whose declared element type is a container ("[$[#i2 …"), whose
// elements are written with their own opening marker omitted. The first document
// is [[null],[null]] and the second gives each element its own count; both are
// accepted by the Draft 12 reference decoder (py-ubjson 0.16.1).
func TestTypedContainerOfContainers(t *testing.T) {
	docs := map[string][]byte{
		// [ $ [ # i 0x02 (element: Z) ] (element: Z) ] == [[null],[null]]
		"element arrays closed by ]": {'[', '$', '[', '#', 'i', 2, 'Z', ']', 'Z', ']'},
		// [ $ [ # i 0x02 (element: # i 0x01 Z) (element: # i 0x01 Z) ]
		"element arrays with their own count": {'[', '$', '[', '#', 'i', 2, '#', 'i', 1, 'Z', '#', 'i', 1, 'Z'},
	}
	for name, data := range docs {
		if _, ok := sniff(source.Mem("t.ubj", data), limits.Default()); !ok {
			t.Errorf("%s: typed container of containers was not recognised", name)
		}
		if fs := parse(t, "t.ubj", data); len(fs) != 0 {
			t.Errorf("%s: expected clean parse, got %v", name, ids(fs))
		}
	}
}

// TestTypedObjectOfContainers is the object-side of the same optimisation: the
// value type of {"k": []} may be declared a container, so the empty value
// carries no opening marker (just its closing one).
func TestTypedObjectOfContainers(t *testing.T) {
	data := append([]byte{'{', '$', mArray, '#', mInt8, 1}, ubjKey("k")...)
	data = append(data, mEndArr)
	if _, ok := sniff(source.Mem("o.ubj", data), limits.Default()); !ok {
		t.Fatal("typed object of containers was not recognised")
	}
	if fs := parse(t, "o.ubj", data); len(fs) != 0 {
		t.Fatalf("expected clean parse, got %v", ids(fs))
	}
}

// TestSniffAcceptsHeadOfLargeDocument guards the head walk. The sniffer reads at
// most ubjSniffHead bytes, so a document larger than that is only ever seen as a
// prefix: the walk runs out of bytes without finding a contradiction, and that
// must still be a claim. A document the walk saw in full but could not finish,
// and a contradiction at any offset, must not be.
func TestSniffAcceptsHeadOfLargeDocument(t *testing.T) {
	big := append([]byte{'{'}, ubjKey("blob")...)
	big = append(big, mString)
	big = append(big, ubjLen(200<<10)...)
	big = append(big, bytes.Repeat([]byte{'x'}, 200<<10)...)
	big = append(big, mEndObj)
	if _, ok := sniff(source.Mem("big.ubj", big), limits.Default()); !ok {
		t.Fatal("head of a large valid UBJSON document was not recognised")
	}
	// An object cut off after its first key is the opposite case: the whole
	// artifact is there and the walk still found no end, so the parser reports it
	// as structurally invalid and the sniffer must not claim it.
	cut := append([]byte{'{'}, ubjKey("model")...)
	if _, ok := sniff(source.Mem("cut.ubj", cut), limits.Default()); ok {
		t.Fatal("a truncated document the walk saw in full was claimed")
	}
	// A contradiction is never evidence for the format, however far into the
	// document it happens: an unknown value marker is invalid UBJSON, so the
	// document must not be claimed even though it is longer than the ambiguous
	// two-byte prefix the shape check looks at.
	contradiction := append([]byte{'{'}, ubjKey("aaaaaaaaaaaa")...)
	contradiction = append(contradiction, '!') // an unknown value marker
	if _, ok := sniff(source.Mem("bad.ubj", contradiction), limits.Default()); ok {
		t.Fatal("a structurally invalid document past 16 bytes was claimed")
	}
}

// TestTypedContainerNestingIsBounded checks the recursion the container-type
// cases add: a chain of container-typed containers deeper than maxUBJDepth is a
// finding, not a stack overflow.
func TestTypedContainerNestingIsBounded(t *testing.T) {
	var data []byte
	for range maxUBJDepth + 8 {
		data = append(data, mArray, mType, mArray, mCount, mInt8, 1)
	}
	data = append(data, mNull)
	fs := parse(t, "deep.ubj", data)
	if !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("expected %s for over-deep nesting, got %v", RuleStruct.ID, ids(fs))
	}
}

func TestDeterministic(t *testing.T) {
	data := append([]byte{'{'}, ubjKey("k")...)
	data = append(data, ubjStr("v")...)
	data = append(data, '}')
	a, b := parse(t, "d.ubj", data), parse(t, "d.ubj", data)
	if len(a) != len(b) {
		t.Fatalf("nondeterministic finding count")
	}
	for i := range a {
		if a[i].RuleID != b[i].RuleID || a[i].Offset != b[i].Offset {
			t.Fatalf("nondeterministic finding %d", i)
		}
	}
}

// TestCommittedFixturesUnchanged pins the two committed UBJSON fixtures: the
// trailing payload is still reported, the benign model still produces nothing,
// and the sniffer still recognises both.
func TestCommittedFixturesUnchanged(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"../../testdata/fixtures/xgb_model.ubj", RuleTrailing.ID},
		{"../../testdata/fixtures/benign/xgb_model.ubj", ""},
	}
	for _, c := range cases {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if _, ok := sniff(source.Mem(c.path, data), limits.Default()); !ok {
			t.Errorf("%s: no longer recognised as UBJSON", c.path)
		}
		fs := parse(t, c.path, data)
		if hasRule(fs, RuleStruct.ID) {
			t.Errorf("%s: unexpected %s: %v", c.path, RuleStruct.ID, ids(fs))
		}
		if c.want == "" {
			if len(fs) != 0 {
				t.Errorf("%s: expected no findings, got %v", c.path, ids(fs))
			}
			continue
		}
		if !hasRule(fs, c.want) {
			t.Errorf("%s: expected %s, got %v", c.path, c.want, ids(fs))
		}
	}
}

// The llama.cpp source corpus the round measured. It contains no UBJSON artifact
// and a great many files whose first two bytes alone would pass the cheap shape
// gate; this test keeps both facts true against real files on disk.
//
// The corpus is not vendored — it is a checkout of someone else's source tree —
// so its location comes from the environment. The test skips when the variable is
// unset, which keeps a personal absolute path out of the repository.
var corpusRoot = os.Getenv("SC4N_XGB_CORPUS")

const (
	corpusMaxSize = 8 << 20
	// corpusUBJFiles is how many artifacts in corpusRoot the round measured as
	// UBJSON: none. A non-zero value here means the sniffer started claiming a
	// source file, and the finding check below then says whether it also claims a
	// document its own parser reports as invalid.
	corpusUBJFiles = 0
)

func TestRealCorpusHasNoUBJSONFalsePositives(t *testing.T) {
	if corpusRoot == "" {
		t.Skip("SC4N_XGB_CORPUS is unset: real-corpus check skipped")
	}
	if _, err := os.Stat(corpusRoot); err != nil {
		t.Skipf("real corpus absent: %v", err)
	}
	var claimed int
	err := filepath.WalkDir(corpusRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() == 0 || fi.Size() > corpusMaxSize {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if _, ok := sniff(source.Mem(p, data), limits.Default()); !ok {
			return nil
		}
		claimed++
		if fs := parse(t, p, data); hasRule(fs, RuleStruct.ID) {
			t.Errorf("%s: claimed as UBJSON but reported %s: %v", p, RuleStruct.ID, ids(fs))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimed != corpusUBJFiles {
		t.Errorf("corpus: %d artifact(s) claimed as UBJSON, want %d", claimed, corpusUBJFiles)
	}
}

func ids(fs []report.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func FuzzUBJWalk(f *testing.F) {
	f.Add([]byte("UBJ"))
	f.Add([]byte{'{', 'L', 0, 0, 0, 0, 0, 0, 0, 1, 'a', 'i', 1, '}'})
	f.Add([]byte{'[', '#', 'L', 0, 0, 0, 0, 0, 0, 0, 2, 'Z', 'T'})
	f.Add([]byte{'[', '$', 'l', '#', 'L', 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1})
	f.Add([]byte{'S', 'i', 3, 'a', 'b'})
	f.Fuzz(func(t *testing.T, b []byte) {
		c := report.NewCollector(1000)
		sess := artifact.NewSession(c, "", limits.Default())
		ctx := sess.NewCtx("f.ubj", limits.Default())
		s := source.Mem("f.ubj", b)
		defer s.Close()
		_ = (parser{}).Parse(ctx, s)
	})
}
