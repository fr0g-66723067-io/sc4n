package xgb

import (
	"encoding/binary"
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
		"unknown marker":      []byte{'!'},
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
	if _, ok := sniff(source.Mem("x.ubj", []byte("UBJ{}")), limits.Default()); !ok {
		t.Fatal("UBJ magic prefix was not recognised")
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
