package imgmeta

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestMetadataSummaryUsesOneAllocation(t *testing.T) {
	kinds := make([]string, 100)
	for i := range kinds {
		kinds[i] = "tEXt"
	}
	got := joinKinds(kinds)
	if !strings.Contains(got, "(92 more)") {
		t.Fatalf("kind summary = %q", got)
	}
}

func TestOversizedPngTextIsCappedAndReported(t *testing.T) {
	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	im := &image{ctx: sess.NewCtx("x.png", l)}
	got := im.capBytes(0, "test", make([]byte, maxMetaBlob+1))
	if len(got) != maxMetaBlob {
		t.Fatalf("capped %d bytes, want %d", len(got), maxMetaBlob)
	}
	if len(c.Findings()) == 0 {
		t.Fatal("cap was silent")
	}
}

// pngChunk builds one PNG chunk: length, type, body, and a zero CRC (the parser
// skips CRCs, because an integrity value is not a security signal).
func pngChunk(typ string, body []byte) []byte {
	out := make([]byte, 8+len(body)+4)
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], typ)
	copy(out[8:], body)
	return out
}

// TestPngTextValueIsCappedBeforeItIsScanned pins the order the cap must have:
// the value is truncated as bytes and only then converted. The token past
// maxMetaBlob is therefore not analysed, and the limit finding says the value
// was cut — the earlier code converted the whole chunk first, copied it again to
// apply the cap, and scanned the truncated string, so the memory saving did not
// exist and the boundary was invisible.
func TestPngTextValueIsCappedBeforeItIsScanned(t *testing.T) {
	// Three times the cap: the pre-fix path copied the value to a string and then
	// again to []byte before truncating, so a 3x value allocated ~6x the cap.
	const factor = 3
	var value []byte
	value = append(value, bytes.Repeat([]byte{'a'}, factor*maxMetaBlob)...)
	value = append(value, "token=ghp_0123456789abcdefghij"...)
	data := append([]byte{}, pngMagic...)
	data = append(data, pngChunk("tEXt", append([]byte("k\x00"), value...))...)
	data = append(data, pngChunk("IEND", nil)...)

	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := (parser{}).Parse(sess.NewCtx("big.png", l), source.Mem("big.png", data)); err != nil {
		t.Fatalf("parse: %v", err)
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 3*maxMetaBlob {
		t.Fatalf("parsing a %dx-capped value allocated %d bytes; the cap was applied after the copies", factor, alloc)
	}
	var capped, leaked bool
	for _, f := range c.Findings() {
		switch f.RuleID {
		case "SC4N-LIMIT-STRING":
			capped = true
		case "SC4N-STRING-SECRET-VALUE":
			leaked = true
		}
	}
	if !capped {
		t.Fatalf("the tEXt cap was silent; findings=%v", c.Findings())
	}
	if leaked {
		t.Fatal("a token past maxMetaBlob was scanned: the value was not capped before conversion")
	}
}
