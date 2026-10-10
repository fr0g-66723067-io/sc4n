package msgpack

import (
	"bytes"
	"testing"

	// Registers the pickle sniffer/parser so a nested-pickle blob can be
	// dispatched the way it is in a real binary.
	_ "github.com/fr0g-66723067-io/sc4n/internal/pickle"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func mstr(s string) []byte { return append([]byte{0xa0 | byte(len(s))}, s...) }

func mbin(b []byte) []byte { return append([]byte{0xc4, byte(len(b))}, b...) }

// mmap builds a fixmap from alternating key/value byte slices.
func mmap(kv ...[]byte) []byte {
	out := []byte{0x80 | byte(len(kv)/2)}
	for _, p := range kv {
		out = append(out, p...)
	}
	return out
}

func parse(t *testing.T, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	lim := limits.Default()
	sess := artifact.NewSession(c, "", lim)
	ctx := &artifact.Ctx{Session: sess, Sink: c.For("m.msgpack"), Limits: lim, Format: artifact.FormatMsgpack}
	src := source.Mem("m.msgpack", data)
	defer src.Close()
	_ = (parser{}).Parse(ctx, src)
	return c.Findings()
}

func ids(fs []report.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestParseMsgpackValid(t *testing.T) {
	doc := mmap(
		mstr("model"), mstr("bert"),
		mstr("layers"), append(append([]byte{0x92}, mstr("a")...), mstr("b")...),
	)
	fs := parse(t, doc)
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %v", ids(fs))
	}
}

func TestParseMsgpackTruncated(t *testing.T) {
	doc := []byte{0x80 | 1, 0xda, 0x00, 0x64} // map{str16 len 100}
	fs := parse(t, doc)
	if !ids(fs)["SC4N-MSGPACK-STRUCT"] {
		t.Fatalf("expected SC4N-MSGPACK-STRUCT, got %v", ids(fs))
	}
}

func TestParseMsgpackTrailing(t *testing.T) {
	doc := append(mmap(mstr("k"), []byte{0x01}), 0x00)
	fs := parse(t, doc)
	if !ids(fs)["SC4N-MSGPACK-STRUCT"] {
		t.Fatalf("expected trailing SC4N-MSGPACK-STRUCT, got %v", ids(fs))
	}
}

func TestParseMsgpackBadType(t *testing.T) {
	fs := parse(t, []byte{0x80 | 1, 0xc1, 0x01})
	if !ids(fs)["SC4N-MSGPACK-STRUCT"] {
		t.Fatalf("expected SC4N-MSGPACK-STRUCT for 0xc1, got %v", ids(fs))
	}
}

func TestParseMsgpackNestedPickle(t *testing.T) {
	gadget := []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85,
		0x52,
		0x2e,
	}
	fs := parse(t, mmap(mstr("w"), mbin(gadget)))
	if !ids(fs)["SC4N-PICKLE-GLOBAL-CRITICAL"] || !ids(fs)["SC4N-PICKLE-REDUCE"] {
		t.Fatalf("expected the nested pickle to be walked, got %v", ids(fs))
	}
}

func TestParseMsgpackNaNRuns(t *testing.T) {
	blob := bytes.Repeat([]byte{0x7f, 0xf8}, 6)
	doc := mmap(mstr("w"), mbin(blob))
	fs := parse(t, doc)
	if !ids(fs)["SC4N-MSGPACK-NAN-PAYLOAD"] {
		t.Fatalf("expected SC4N-MSGPACK-NAN-PAYLOAD, got %v", ids(fs))
	}
	// The finding must name the payload's offset in the artifact, not the
	// container header: every other finding this walker emits is absolute.
	wantOff := int64(bytes.Index(doc, blob))
	for _, f := range fs {
		if f.RuleID == "SC4N-MSGPACK-NAN-PAYLOAD" && f.Offset != wantOff {
			t.Fatalf("NAN-PAYLOAD offset = %d, want %d (the blob starts there)", f.Offset, wantOff)
		}
	}
}

func TestSniffMsgpack(t *testing.T) {
	doc := mmap(mstr("model"), mstr("bert"))
	src := source.Mem("m.msgpack", doc)
	defer src.Close()
	if f, ok := sniff(src, limits.Default()); !ok || f != artifact.FormatMsgpack {
		t.Fatalf("sniff = %v,%v; want msgpack,true", f, ok)
	}
	text := source.Mem("t.txt", []byte("this is ordinary text, not msgpack"))
	defer text.Close()
	if _, ok := sniff(text, limits.Default()); ok {
		t.Fatal("sniff claimed plain text")
	}
}

func TestMsgpackNoPanic(t *testing.T) {
	cases := map[string][]byte{
		"empty":      {},
		"one byte":   {0x80},
		"huge map":   {0xdf, 0xff, 0xff, 0xff, 0xff},
		"bad fixext": {0xd4},
		"deep":       bytes.Repeat([]byte{0x91}, 600),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_ = parse(t, data)
		})
	}
}
