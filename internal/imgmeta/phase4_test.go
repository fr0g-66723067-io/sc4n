package imgmeta

import (
	"bytes"
	"compress/zlib"
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

func TestExifIFDType13AndXPTags(t *testing.T) {
	// Build a minimal little-endian TIFF block with:
	// - IFD0 at offset 8 with 3 entries:
	//   1) 0x9c9c (XPComment, UTF-16LE) -> webhook 1
	//   2) 0x9c9e (XPKeywords, UTF-16LE) -> webhook 2
	//   3) 0x8769 (Exif sub-IFD pointer, type=13 IFD!) -> sub-IFD with UserComment (0x9286) webhook 3
	utf16LE := func(s string) []byte {
		out := make([]byte, 0, len(s)*2+2)
		for i := range len(s) {
			out = append(out, s[i], 0)
		}
		return append(out, 0, 0)
	}
	xpComment := utf16LE("https://discord.com/api/webhooks/1/comment")
	xpKeywords := utf16LE("https://hooks.slack.com/services/T/B/X")
	userComm := append([]byte("ASCII\x00\x00\x00"), "https://api.telegram.org/bot123/send"...)

	// Layout:
	// 0..7: TIFF header ("II", 42, ifd0=8)
	// 8..49: IFD0 (count=3, 3*12=36 bytes, next=4) -> ends at 50; pad to 64
	// 64..85: Sub-IFD (count=1, 1*12=12 bytes, next=4) -> ends at 82; pad to 96
	// 96..: payloads
	offComment := uint32(96)
	offKeywords := offComment + uint32(len(xpComment))
	offUserComm := offKeywords + uint32(len(xpKeywords))
	tiff := make([]byte, offUserComm+uint32(len(userComm)))
	le := binary.LittleEndian
	copy(tiff[0:2], "II")
	le.PutUint16(tiff[2:], 42)
	le.PutUint32(tiff[4:], 8)

	putEntry := func(at int, tag, typ uint16, count, val uint32) {
		le.PutUint16(tiff[at:], tag)
		le.PutUint16(tiff[at+2:], typ)
		le.PutUint32(tiff[at+4:], count)
		le.PutUint32(tiff[at+8:], val)
	}
	le.PutUint16(tiff[8:], 3)
	putEntry(10, 0x9c9c, 1, uint32(len(xpComment)), offComment)
	putEntry(22, 0x9c9e, 1, uint32(len(xpKeywords)), offKeywords)
	putEntry(34, 0x8769, 13, 1, 64) // TIFF type 13 = IFD!

	le.PutUint16(tiff[64:], 1)
	putEntry(66, 0x9286, 7, uint32(len(userComm)), offUserComm)

	copy(tiff[offComment:], xpComment)
	copy(tiff[offKeywords:], xpKeywords)
	copy(tiff[offUserComm:], userComm)

	data := append([]byte{}, pngMagic...)
	data = append(data, pngChunk("eXIf", tiff)...)
	data = append(data, pngChunk("IEND", nil)...)

	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	if err := (parser{}).Parse(sess.NewCtx("exif.png", l), source.Mem("exif.png", data)); err != nil {
		t.Fatal(err)
	}
	c2Count := 0
	hasComment, hasKeywords := false, false
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-STRING-C2" {
			c2Count++
		}
		if f.RuleID == "SC4N-IMG-METADATA" {
			hasComment = strings.Contains(f.Evidence, "XPComment")
			hasKeywords = strings.Contains(f.Evidence, "XPKeywords")
		}
	}
	if c2Count != 3 {
		t.Fatalf("expected 3 C2 findings (XPComment, XPKeywords, sub-IFD type 13 UserComment), got %d: %v", c2Count, c.Findings())
	}
	if !hasComment || !hasKeywords {
		t.Fatalf("metadata summary missing XPComment/XPKeywords: %v", c.Findings())
	}
}

func TestPNGInflateEnforcesRatioDecompressedAndCapBytes(t *testing.T) {
	// Compress 100 KiB of zeros -> tiny zlib stream (~150 bytes, ratio > 600).
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write(bytes.Repeat([]byte{'A'}, 100<<10))
	_ = zw.Close()

	makeZTXtPNG := func() []byte {
		body := append([]byte("k\x00\x00"), zbuf.Bytes()...)
		d := append([]byte{}, pngMagic...)
		d = append(d, pngChunk("zTXt", body)...)
		return append(d, pngChunk("IEND", nil)...)
	}

	// 1. Default MaxRatio = 200 fires SC4N-LIMIT-RATIO.
	l1 := limits.Default()
	c1 := report.NewCollector(0)
	s1 := artifact.NewSession(c1, "", l1)
	_ = (parser{}).Parse(s1.NewCtx("ratio.png", l1), source.Mem("ratio.png", makeZTXtPNG()))
	gotRatio := false
	for _, f := range c1.Findings() {
		if f.RuleID == "SC4N-LIMIT-RATIO" {
			gotRatio = true
		}
	}
	if !gotRatio {
		t.Fatalf("high-ratio zTXt did not emit SC4N-LIMIT-RATIO; findings=%v", c1.Findings())
	}

	// 2. Tight MaxDecompressedBytes fires SC4N-LIMIT-DECOMPRESSED and charges Session.
	l2 := limits.Default()
	l2.MaxRatio = 10000
	l2.MaxDecompressedBytes = 1024
	c2 := report.NewCollector(0)
	s2 := artifact.NewSession(c2, "", l2)
	_ = (parser{}).Parse(s2.NewCtx("decomp.png", l2), source.Mem("decomp.png", makeZTXtPNG()))
	gotDecomp := false
	for _, f := range c2.Findings() {
		if f.RuleID == "SC4N-LIMIT-DECOMPRESSED" {
			gotDecomp = true
		}
	}
	if !gotDecomp {
		t.Fatalf("zTXt exceeding MaxDecompressedBytes did not emit SC4N-LIMIT-DECOMPRESSED; findings=%v", c2.Findings())
	}
	if s2.RemainingDecompressed() != 0 {
		t.Fatalf("Session decompressed budget was not charged; remaining=%d", s2.RemainingDecompressed())
	}

	// 3. capBytes respects ctx.Limits.MaxStringBlob.
	l3 := limits.Default()
	l3.MaxStringBlob = 32
	c3 := report.NewCollector(0)
	s3 := artifact.NewSession(c3, "", l3)
	im := &image{ctx: s3.NewCtx("cap.png", l3)}
	got := im.capBytes(0, "tEXt", make([]byte, 64))
	if len(got) != 32 {
		t.Fatalf("capBytes returned %d bytes, want 32", len(got))
	}
}
