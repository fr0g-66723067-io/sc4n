package archive

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func testCtx(t *testing.T, name string, l limits.Limits) (*artifact.Ctx, *report.Collector) {
	t.Helper()
	col := report.NewCollector(0)
	sess := artifact.NewSession(col, "", l)
	return sess.NewCtx(name, l), col
}

func hdrWithExtra(name string, method uint16, comp, uncomp uint32, extra []byte) []byte {
	var h [30]byte
	binary.LittleEndian.PutUint32(h[0:], sigLocal)
	binary.LittleEndian.PutUint16(h[4:], 20)
	binary.LittleEndian.PutUint16(h[8:], method)
	binary.LittleEndian.PutUint32(h[18:], comp)
	binary.LittleEndian.PutUint32(h[22:], uncomp)
	binary.LittleEndian.PutUint16(h[26:], uint16(len(name)))
	binary.LittleEndian.PutUint16(h[28:], uint16(len(extra)))
	out := append(h[:], name...)
	return append(out, extra...)
}

func zip64Extra(comp, uncomp uint64) []byte {
	var b [20]byte
	binary.LittleEndian.PutUint16(b[0:], 1)
	binary.LittleEndian.PutUint16(b[2:], 16)
	binary.LittleEndian.PutUint64(b[4:], uncomp)
	binary.LittleEndian.PutUint64(b[12:], comp)
	return b[:]
}

func TestZlibSnifferRequiresDecodableStream(t *testing.T) {
	bogus := append([]byte{0x78, 0x01}, bytes.Repeat([]byte{0xff}, 64)...)
	if f, ok := sniffZlib(source.Mem("x", bogus), limits.Default()); ok || f != artifact.FormatUnknown {
		t.Fatalf("bogus zlib header sniffed as %v, %v", f, ok)
	}
	var framed bytes.Buffer
	zw := zlib.NewWriter(&framed)
	_, _ = zw.Write([]byte("hello, world"))
	_ = zw.Close()
	if f, ok := sniffZlib(source.Mem("x", framed.Bytes()), limits.Default()); !ok || f != artifact.FormatZlib {
		t.Fatalf("a real zlib stream sniffed as %v, %v", f, ok)
	}
}

func TestZipRatioCapUsesBytesPresentNotDeclaredSize(t *testing.T) {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	body := bytes.Repeat([]byte("A"), 4096)
	_, _ = fw.Write(body)
	_ = fw.Close()
	l := limits.Default()
	l.MaxRatio = 10
	l.MaxDecompressedBytes = 1 << 20
	m := Member{Name: "x", Method: 8, CompressedSize: 1 << 20, dataOff: 0}
	rc, err := openZipMember(source.Mem("x", buf.Bytes()), l, m)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	_, rerr := io.ReadAll(rc)
	var le *LimitError
	if !errors.As(rerr, &le) {
		t.Fatalf("read error = %v, want a ratio LimitError", rerr)
	}
	if le.Cap > int64(buf.Len())*l.MaxRatio {
		t.Fatalf("ratio cap %d exceeds the bytes present (%d)*%d", le.Cap, buf.Len(), l.MaxRatio)
	}
}

func TestRecoverLocalMembersCountsZeroLengthMembers(t *testing.T) {
	var b []byte
	for _, name := range []string{"a", "b", "c"} {
		b = append(b, hdrWithExtra(name, 0, 0, 0, nil)...)
	}
	ms, capped, skipped := recoverLocalMembers(source.Mem("x", b), limits.Default())
	if capped {
		t.Fatal("three members hit a cap larger than three")
	}
	if len(ms) != 0 || len(skipped) != 3 {
		t.Fatalf("members=%d skipped=%v, want three skipped zero-length members", len(ms), skipped)
	}
}

func TestRecoverLocalMembersZip64SizeMustEndAtFraming(t *testing.T) {
	b := hdrWithExtra("big", 8, 0xffffffff, 0, zip64Extra(1<<20, 1))
	b = append(b, []byte("short")...) // the declared size lands past the source
	ms, _, _ := recoverLocalMembers(source.Mem("x", b), limits.Default())
	if len(ms) != 1 {
		t.Fatalf("recovered %d members, want 1", len(ms))
	}
	if !ms[0].sizeInvalid {
		t.Fatal("a zip64 size that does not end on framing was accepted")
	}
}

func TestTruncatedZeroLengthFloodHitsEntryCap(t *testing.T) {
	var b []byte
	for range 5 {
		b = append(b, hdrWithExtra("z", 0, 0, 0, nil)...)
	}
	l := limits.Default()
	l.MaxEntries = 2
	ctx, col := testCtx(t, "x", l)
	ctx.Format = artifact.FormatZip
	if !recoverTruncatedZip(ctx, source.Mem("x", b)) {
		t.Fatal("a capped zero-length flood was not reported as recovered")
	}
	var got strings.Builder
	for _, f := range col.Findings() {
		got.WriteString(f.RuleID + " ")
	}
	if !strings.Contains(got.String(), "SC4N-LIMIT-ENTRIES") ||
		!strings.Contains(got.String(), "SC4N-ARCHIVE-MEMBER-SKIPPED") {
		t.Fatalf("findings = %s, want an entry cap and skipped-member report", got.String())
	}
}
