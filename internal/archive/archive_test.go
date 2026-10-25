package archive_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	// Registers the pickle parser, so a member that is a pickle is walked.
	_ "github.com/fr0g-66723067-io/sc4n/internal/pickle"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func newCtx(t *testing.T, name string, l limits.Limits) (*artifact.Ctx, *report.Collector) {
	t.Helper()
	col := report.NewCollector(0)
	sess := artifact.NewSession(col, "", l)
	return sess.NewCtx(name, l), col
}

func ids(fs []report.Finding) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		out[f.RuleID] = true
	}
	return out
}

func want(t *testing.T, got map[string]bool, rule string) {
	t.Helper()
	if !got[rule] {
		t.Fatalf("expected %s; findings were %v", rule, keys(got))
	}
}

func forbid(t *testing.T, got map[string]bool, rule string) {
	t.Helper()
	if got[rule] {
		t.Fatalf("did not expect %s; findings were %v", rule, keys(got))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func scanZip(t *testing.T, name string, data []byte, l limits.Limits) map[string]bool {
	t.Helper()
	return scanAs(t, name, data, artifact.FormatZip, l)
}

func scanAs(t *testing.T, name string, data []byte, f artifact.Format, l limits.Limits) map[string]bool {
	t.Helper()
	ctx, col := newCtx(t, name, l)
	ctx.Format = f
	if err := archive.Scan(ctx, source.Mem(name, data)); err != nil {
		t.Fatalf("archive.Scan: %v", err)
	}
	return ids(col.Findings())
}

// --- zip fixtures ------------------------------------------------------------------

type zspec struct {
	name      string
	localName string
	data      []byte
	method    uint16
	mode      uint32
	crc       uint32
	crcFixed  bool
}

func buildZip(t testing.TB, specs []zspec, zip64 bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	type cd struct {
		name         string
		method       uint16
		crc          uint32
		comp, uncomp uint32
		mode         uint32
		off          uint32
	}
	recs := make([]cd, len(specs))
	for i, sp := range specs {
		payload := sp.data
		if sp.method == 8 {
			payload = deflate(t, sp.data)
		}
		crc := sp.crc
		if !sp.crcFixed {
			crc = crc32.ChecksumIEEE(sp.data)
		}
		ln := sp.localName
		if ln == "" {
			ln = sp.name
		}
		off := uint32(buf.Len())
		writeLocal(&buf, sp.method, crc, uint32(len(payload)), uint32(len(sp.data)), ln)
		buf.Write(payload)
		recs[i] = cd{name: sp.name, method: sp.method, crc: crc, comp: uint32(len(payload)), uncomp: uint32(len(sp.data)), mode: sp.mode, off: off}
	}
	cdOff := uint32(buf.Len())
	for _, r := range recs {
		writeCentral(&buf, r.name, r.method, r.crc, r.comp, r.uncomp, r.mode, r.off)
	}
	cdSize := uint32(buf.Len()) - cdOff

	if zip64 {
		z64 := uint32(buf.Len())
		var rec [56]byte
		binary.LittleEndian.PutUint32(rec[0:], 0x06064b50)
		binary.LittleEndian.PutUint64(rec[4:], 44)
		binary.LittleEndian.PutUint16(rec[12:], (3<<8)|45)
		binary.LittleEndian.PutUint16(rec[14:], 45)
		binary.LittleEndian.PutUint64(rec[32:], uint64(len(recs)))
		binary.LittleEndian.PutUint64(rec[40:], uint64(cdSize))
		binary.LittleEndian.PutUint64(rec[48:], uint64(cdOff))
		buf.Write(rec[:])
		var loc [20]byte
		binary.LittleEndian.PutUint32(loc[0:], 0x07064b50)
		binary.LittleEndian.PutUint64(loc[8:], uint64(z64))
		binary.LittleEndian.PutUint32(loc[16:], 1)
		buf.Write(loc[:])
	}
	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:], 0x06054b50)
	entries := uint16(len(recs))
	if zip64 {
		entries = 0xffff
	}
	binary.LittleEndian.PutUint16(eocd[8:], entries)
	binary.LittleEndian.PutUint16(eocd[10:], entries)
	binary.LittleEndian.PutUint32(eocd[12:], cdSize)
	binary.LittleEndian.PutUint32(eocd[16:], cdOff)
	buf.Write(eocd[:])
	return buf.Bytes()
}

func writeLocal(buf *bytes.Buffer, method uint16, crc, comp, uncomp uint32, name string) {
	var b [30]byte
	binary.LittleEndian.PutUint32(b[0:], 0x04034b50)
	binary.LittleEndian.PutUint16(b[4:], 20)
	binary.LittleEndian.PutUint16(b[8:], method)
	binary.LittleEndian.PutUint32(b[14:], crc)
	binary.LittleEndian.PutUint32(b[18:], comp)
	binary.LittleEndian.PutUint32(b[22:], uncomp)
	binary.LittleEndian.PutUint16(b[26:], uint16(len(name)))
	buf.Write(b[:])
	buf.WriteString(name)
}

func writeCentral(buf *bytes.Buffer, name string, method uint16, crc, comp, uncomp, mode, off uint32) {
	var b [46]byte
	binary.LittleEndian.PutUint32(b[0:], 0x02014b50)
	binary.LittleEndian.PutUint16(b[4:], (3<<8)|20)
	binary.LittleEndian.PutUint16(b[6:], 20)
	binary.LittleEndian.PutUint16(b[10:], method)
	binary.LittleEndian.PutUint32(b[16:], crc)
	binary.LittleEndian.PutUint32(b[20:], comp)
	binary.LittleEndian.PutUint32(b[24:], uncomp)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(name)))
	binary.LittleEndian.PutUint32(b[38:], mode<<16)
	binary.LittleEndian.PutUint32(b[42:], off)
	buf.Write(b[:])
	buf.WriteString(name)
}

func deflate(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gadgetPickle is PROTO 4, STACK_GLOBAL("os","system"), "id", TUPLE1, REDUCE, STOP.
func gadgetPickle() []byte {
	return []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85, 0x52, 0x2e,
	}
}

// TestZip64NegativeEntryCountIsRejected: a zip64 end-of-central-directory whose
// total-entries field has the high bit set is negative as an int64. It used to
// reach make([]zipEntry, 0, min64int(count, 4096)) as a negative capacity and
// panic; it must be a parse error instead.
func TestZip64NegativeEntryCountIsRejected(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "a.bin", data: []byte("a")},
		{name: "b.bin", data: []byte("b")},
	}, true)
	patched := patchZip64Entries(t, data, 1<<63)
	if _, err := archive.Collect(source.Mem("neg64.zip", patched), limits.Default()); err == nil {
		t.Fatal("Collect accepted a zip64 directory with a negative entry count")
	}
	if _, err := archive.ZipNames(source.Mem("neg64.zip", patched), limits.Default(), 0); err == nil {
		t.Fatal("ZipNames accepted a zip64 directory with a negative entry count")
	}
}

// TestImpossibleEntryCountIsRejected: a plain EOCD claiming 0xffff entries in a
// file that cannot hold them is a malformed directory, not 65 535 reads.
func TestImpossibleEntryCountIsRejected(t *testing.T) {
	data := buildZip(t, []zspec{{name: "a.bin", data: []byte("a")}}, false)
	patched := patchEOCDEntries(t, data, 0xffff)
	if _, err := archive.Collect(source.Mem("liar.zip", patched), limits.Default()); err == nil {
		t.Fatal("Collect accepted an EOCD claiming 65535 entries in a tiny file")
	}
}

// patchZip64Entries rewrites the zip64 EOCD's total-entries field.
func patchZip64Entries(t testing.TB, data []byte, entries uint64) []byte {
	t.Helper()
	off := bytes.Index(data, []byte{0x50, 0x4b, 0x06, 0x06})
	if off < 0 || off+40 > len(data) {
		t.Fatal("no zip64 end-of-central-directory in the fixture")
	}
	out := bytes.Clone(data)
	binary.LittleEndian.PutUint64(out[off+32:], entries)
	return out
}

// patchEOCDEntries rewrites the plain EOCD's entry count (both copies).
func patchEOCDEntries(t testing.TB, data []byte, entries uint16) []byte {
	t.Helper()
	off := bytes.LastIndex(data, []byte{0x50, 0x4b, 0x05, 0x06})
	if off < 0 || off+22 > len(data) {
		t.Fatal("no end-of-central-directory in the fixture")
	}
	out := bytes.Clone(data)
	binary.LittleEndian.PutUint16(out[off+8:], entries)
	binary.LittleEndian.PutUint16(out[off+10:], entries)
	return out
}

// TestMemberExactlyAtTheCapIsScanned is the F3 regression: a member whose length
// is exactly the decompression cap used to be reported as over-cap (the cap
// check ran before the read that would have returned io.EOF), so the member was
// never dispatched and its findings were lost.
func TestMemberExactlyAtTheCapIsScanned(t *testing.T) {
	body := gadgetPickle()
	data := buildZip(t, []zspec{{name: "archive/data.pkl", data: body}}, false)
	l := limits.Default()
	l.MaxRatio = 1 // the ratio cap is now exactly the member's length
	got := scanZip(t, "exact.zip", data, l)
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-LIMIT-RATIO")
}

// TestStoredLargeMemberCRCIsChecked is the F18b regression: the crcSource wrapper
// handed to ScanMember was never closed, so the only integrity check performed
// for a stored member too large to buffer never ran.
func TestStoredLargeMemberCRCIsChecked(t *testing.T) {
	body := append([]byte("#!/bin/sh\n"), make([]byte, 4096)...)
	data := buildZip(t, []zspec{{name: "run.sh", data: body, crc: 0xdeadbeef, crcFixed: true}}, false)
	l := limits.Default()
	l.MaxStringBlob = 1024 // force the Section path
	got := scanZip(t, "badcrc.zip", data, l)
	want(t, got, "SC4N-ARCHIVE-SHEBANG")
	want(t, got, "SC4N-ARCHIVE-CRC")
}

func TestZipBombRatio(t *testing.T) {
	data := buildZip(t, []zspec{{name: "bomb.bin", data: make([]byte, 4<<20), method: 8}}, false)
	got := scanZip(t, "bomb.zip", data, limits.Default())
	want(t, got, "SC4N-LIMIT-RATIO")
}

func TestZipSlipPathAndLink(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "../evil.txt", data: []byte("pwned\n")},
		{name: "link", data: []byte("/etc/passwd"), mode: 0o120777},
	}, false)
	got := scanZip(t, "slip.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-PATH")
	want(t, got, "SC4N-ARCHIVE-LINK")
}

func TestZipNameMismatch(t *testing.T) {
	data := buildZip(t, []zspec{{name: "good.txt", localName: "evil.txt", data: []byte("x\n")}}, false)
	got := scanZip(t, "mismatch.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-NAME-MISMATCH")
}

// TestZipDataDescriptorIsNotAMismatch pins the C1 fix. Go's archive/zip.Writer
// (and Java, and Python's force_zip64 output) set general-purpose bit 3 and leave
// the local header's CRC and both sizes zero, because the writer had not computed
// them when it wrote the header; the real values follow the member data and are
// mirrored in the central directory. Comparing those zeroes against the central
// directory reported every such archive as SC4N-ARCHIVE-NAME-MISMATCH — including
// the committed benign/model.npz fixture, which is produced by Python's zipfile.
func TestZipDataDescriptorIsNotAMismatch(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("a.txt")
	if err != nil {
		t.Fatalf("zip.Create: %v", err)
	}
	if _, err := f.Write([]byte("hello world\n")); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	if buf.Bytes()[6]&0x8 == 0 {
		t.Fatal("the test's zip does not set the data-descriptor bit; it no longer covers the case")
	}
	got := scanZip(t, "descriptor.zip", buf.Bytes(), limits.Default())
	forbid(t, got, "SC4N-ARCHIVE-NAME-MISMATCH")
}

// TestZipZip64LocalSizesAreNotAMismatch is the same for a per-entry zip64 record:
// the local 32-bit size fields hold 0xFFFFFFFF and the real values are in the
// local header's zip64 extra field, so the comparison must read that field rather
// than compare the sentinel.
func TestZipZip64LocalSizesAreNotAMismatch(t *testing.T) {
	data := []byte("hello world\n")
	crc := crc32.ChecksumIEEE(data)

	var buf bytes.Buffer
	// Local header with the zip64 sentinel in both size fields and a zip64 extra
	// field carrying the real values, in the spec's order (uncompressed first).
	var lh [30]byte
	binary.LittleEndian.PutUint32(lh[0:], 0x04034b50)
	binary.LittleEndian.PutUint16(lh[4:], 45)
	binary.LittleEndian.PutUint32(lh[14:], crc)
	binary.LittleEndian.PutUint32(lh[18:], 0xffffffff)
	binary.LittleEndian.PutUint32(lh[22:], 0xffffffff)
	binary.LittleEndian.PutUint16(lh[26:], uint16(len("a.txt")))
	binary.LittleEndian.PutUint16(lh[28:], 20)
	buf.Write(lh[:])
	buf.WriteString("a.txt")
	var ex [20]byte
	binary.LittleEndian.PutUint16(ex[0:], 0x0001)
	binary.LittleEndian.PutUint16(ex[2:], 16)
	binary.LittleEndian.PutUint64(ex[4:], uint64(len(data)))  // uncompressed
	binary.LittleEndian.PutUint64(ex[12:], uint64(len(data))) // compressed
	buf.Write(ex[:])
	buf.Write(data)
	cdOff := uint32(buf.Len())
	writeCentral(&buf, "a.txt", 0, crc, uint32(len(data)), uint32(len(data)), 0, 0)
	cdSize := uint32(buf.Len()) - cdOff
	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:], 1)
	binary.LittleEndian.PutUint16(eocd[10:], 1)
	binary.LittleEndian.PutUint32(eocd[12:], cdSize)
	binary.LittleEndian.PutUint32(eocd[16:], cdOff)
	buf.Write(eocd[:])

	got := scanZip(t, "zip64entry.zip", buf.Bytes(), limits.Default())
	forbid(t, got, "SC4N-ARCHIVE-NAME-MISMATCH")
}

// TestZipLocalSizeMismatchStillReported guards the other half: a local header
// that genuinely disagrees with the central directory, with the data-descriptor
// bit clear and no zip64 sentinel, must still be reported.
func TestZipLocalSizeMismatchStillReported(t *testing.T) {
	data := buildZip(t, []zspec{{name: "a.txt", data: []byte("hello world\n")}}, false)
	// Corrupt the local header's compressed-size field only.
	binary.LittleEndian.PutUint32(data[18:], 0xdeadbeef)
	got := scanZip(t, "badsize.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-NAME-MISMATCH")
}

func TestZipDuplicateName(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "same.txt", data: []byte("a\n")},
		{name: "same.txt", data: []byte("b\n")},
	}, false)
	got := scanZip(t, "dup.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-DUPLICATE-NAME")
}

// TestCorruptMemberBeforePickle is the modelscan issue #354 regression: a member
// that fails its CRC must not stop the walk, and the pickle after it must still be
// reached.
func TestCorruptMemberBeforePickle(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "broken.bin", data: []byte("not what the crc says\n"), crc: 0xdeadbeef, crcFixed: true},
		{name: "archive/data.pkl", data: gadgetPickle(), method: 8},
	}, false)
	got := scanZip(t, "corrupt.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-CRC")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

func TestScriptShebangMember(t *testing.T) {
	data := buildZip(t, []zspec{{name: "run.sh", data: []byte("#!/bin/sh\necho hi\n")}}, false)
	got := scanZip(t, "script.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-SHEBANG")
}

// TestStoredLargeMemberSection proves a stored member above MaxStringBlob is
// handed to the parser as a zero-copy Section rather than being buffered.
func TestStoredLargeMemberSection(t *testing.T) {
	body := append([]byte("#!/bin/sh\n"), make([]byte, 4096)...)
	data := buildZip(t, []zspec{{name: "run.sh", data: body}}, false)
	l := limits.Default()
	l.MaxStringBlob = 1024
	got := scanZip(t, "big.zip", data, l)
	want(t, got, "SC4N-ARCHIVE-SHEBANG")
}

// TestSpillTooLargeContinues proves a member whose deflate stream exceeds
// MaxSpillBytes emits SC4N-LIMIT-SPILL and the walk continues to the next member.
func TestSpillTooLargeContinues(t *testing.T) {
	big := make([]byte, 2<<20)
	data := buildZip(t, []zspec{
		{name: "big.bin", data: big, method: 8},
		{name: "archive/data.pkl", data: gadgetPickle(), method: 8},
	}, false)
	l := limits.Default()
	l.MaxStringBlob = 1 << 16
	l.MaxSpillBytes = 1 << 20
	l.MaxRatio = 0
	got := scanZip(t, "spill.zip", data, l)
	want(t, got, "SC4N-LIMIT-SPILL")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-ARCHIVE-MEMBER-ERROR")
}

func TestDoubleCompressedReachesPickle(t *testing.T) {
	inner := zlibBytes(t, gadgetPickle())
	outer := gzipBytes(t, inner)
	got := scanAs(t, "model.pkl.gz.zlib", outer, artifact.FormatGzip, limits.Default())
	want(t, got, "SC4N-ARCHIVE-NESTED-COMPRESSION")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

func TestGzipBzip2DoubleCompression(t *testing.T) {
	// bzip2 -9 of the canonical gadget pickle; the standard library has no bzip2
	// writer, so the compressed layer is a fixed literal.
	const h = "425a6839314159265359662104e000000853e015000001100006228c2042040800200022268d34643c90a1a698002815cc87e299053c28b57c5dc914e1424198841380"
	bz, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	outer := gzipBytes(t, bz)
	got := scanAs(t, "model.pkl.gz.bz2", outer, artifact.FormatGzip, limits.Default())
	want(t, got, "SC4N-ARCHIVE-NESTED-COMPRESSION")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

func TestUnsupportedZstd(t *testing.T) {
	zst := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 32)...)
	ctx, col := newCtx(t, "u.zst", limits.Default())
	ctx.Format = artifact.FormatZstd
	if err := archive.Scan(ctx, source.Mem("u.zst", zst)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := ids(col.Findings())
	want(t, got, "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION")
}

func TestZip64Directory(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "a.bin", data: []byte("a")},
		{name: "b.bin", data: []byte("b")},
		{name: "c.bin", data: []byte("c")},
	}, true)
	ms, err := archive.Collect(source.Mem("z64.zip", data), limits.Default())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ms.Members) != 3 {
		t.Fatalf("members = %d, want 3", len(ms.Members))
	}
	if ms.Truncated {
		t.Fatal("zip64 directory incorrectly marked truncated")
	}
	names, err := archive.ZipNames(source.Mem("z64.zip", data), limits.Default(), 0)
	if err != nil {
		t.Fatalf("ZipNames: %v", err)
	}
	if strings.Join(names, ",") != "a.bin,b.bin,c.bin" {
		t.Fatalf("names = %v", names)
	}
}

func TestEntryCapTruncates(t *testing.T) {
	var specs []zspec
	for i := range 5 {
		specs = append(specs, zspec{name: string(rune('a'+i)) + ".bin", data: []byte("x")})
	}
	data := buildZip(t, specs, false)
	l := limits.Default()
	l.MaxEntries = 2
	ms, err := archive.Collect(source.Mem("many.zip", data), l)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !ms.Truncated || len(ms.Members) != 2 {
		t.Fatalf("members=%d truncated=%v, want 2/true", len(ms.Members), ms.Truncated)
	}
}

func TestTarLinks(t *testing.T) {
	data := tarBytes(t)
	ctx, col := newCtx(t, "links.tar", limits.Default())
	ms, err := archive.Collect(source.Mem("links.tar", data), limits.Default())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	ms.Check(ctx)
	got := ids(col.Findings())
	want(t, got, "SC4N-ARCHIVE-PATH")
	want(t, got, "SC4N-ARCHIVE-LINK")
}

func TestCompressorDetection(t *testing.T) {
	cases := []struct {
		b    []byte
		want archive.Compressor
	}{
		{[]byte{0x1f, 0x8b, 0x08}, archive.CompressorGzip},
		{[]byte{0x78, 0x9c, 0x00}, archive.CompressorZlib},
		{[]byte("BZh9"), archive.CompressorBzip2},
		{[]byte("\xfd7zXZ\x00"), archive.CompressorXz},
		{[]byte{0x04, 0x22, 0x4d, 0x18}, archive.CompressorLz4},
		{[]byte{0x28, 0xb5, 0x2f, 0xfd}, archive.CompressorZstd},
		{[]byte("7z\xbc\xaf\x27\x1c"), archive.CompressorSevenZip},
		{[]byte("Rar!\x1a\x07\x00"), archive.CompressorRar},
		// A legacy joblib frame is a 21-byte header and a zlib stream, not the
		// two magic bytes: "ZF" alone is ordinary text.
		{append([]byte("ZF"+hexLen(3)), zlibBytes(t, []byte("abc"))...), archive.CompressorZlibJoblibLegacy},
	}
	for _, c := range cases {
		got, ok := archive.DetectCompressor(source.Mem("x", c.b), limits.Default())
		if !ok || got != c.want {
			t.Errorf("DetectCompressor(% x) = %v,%v want %v", c.b, got, ok, c.want)
		}
	}
	if archive.Supported(archive.CompressorZstd) || archive.Supported(archive.CompressorXz) {
		t.Fatal("zstd/xz must not be supported")
	}
	if got, ok := archive.DetectCompressor(source.Mem("x", []byte("ZF\x00")), limits.Default()); ok {
		t.Fatalf("DetectCompressor(ZF NUL) = %v, want no detection", got)
	}
	if !archive.Supported(archive.CompressorGzip) || !archive.Supported(archive.CompressorBzip2) {
		t.Fatal("gzip/bzip2 must be supported")
	}
}

// TestGzipRatioCapIsReported drives the production decompression path with a
// MaxRatio low enough that a 1 MiB bomb exceeds it, and checks the cap is named.
func TestGzipRatioCapIsReported(t *testing.T) {
	bomb := gzipBytes(t, make([]byte, 1<<20))
	l := limits.Default()
	l.MaxRatio = 2
	got := scanAs(t, "bomb.pkl.gz", bomb, artifact.FormatGzip, l)
	want(t, got, "SC4N-LIMIT-RATIO")
}

// TestZeroLimitsDecompressFully: a zero-valued Limits means "unset", not
// "unlimited". Reading a zero MaxDecompressedBytes as MaxInt64 makes the running
// total comparison report the budget as exhausted and silently truncates the
// payload — the one outcome the limits design forbids. This goes through the
// production reader, not a helper.
func TestZeroLimitsDecompressFully(t *testing.T) {
	l := limits.Default()
	l.MaxDecompressedBytes = 0
	got := scanAs(t, "model.pkl.gz", gzipBytes(t, gadgetPickle()), artifact.FormatGzip, l)
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-LIMIT-DECOMPRESSED")
}

func TestPrefixedZipRecognised(t *testing.T) {
	body := buildZip(t, []zspec{{name: "data.bin", data: []byte("hi")}}, false)
	prefixed := append([]byte("SELFEXTRACT-STUB\x00\x00"), body...)
	ms, err := archive.Collect(source.Mem("prefixed.pt", prefixed), limits.Default())
	if err != nil {
		t.Fatalf("Collect prefixed: %v", err)
	}
	if len(ms.Members) != 1 || ms.Members[0].Name != "data.bin" {
		t.Fatalf("members = %+v", ms.Members)
	}
}

func tarBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	add := func(hdr *tar.Header, body []byte) {
		hdr.Format = tar.FormatUSTAR
		hdr.ModTime = time.Unix(0, 0)
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			if _, err := w.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(&tar.Header{Name: "data.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg}, []byte("abc"))
	add(&tar.Header{Name: "link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, nil)
	add(&tar.Header{Name: "../evil.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg}, []byte("bad"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zlibBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestZipTrailingDataIsScannedAndReported: bytes appended after the
// end-of-central-directory record are the standard polyglot shape. The members
// the central directory describes must still be walked, and the appended region
// must be reported rather than making the whole container unreadable.
func TestZipTrailingDataIsScannedAndReported(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "../evil.txt", data: []byte("x")},
	}, false)
	data = append(data, []byte("EVIL")...)

	got := scanZip(t, "poly.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-PATH")
	want(t, got, "SC4N-ARCHIVE-TRAILING-DATA")
	forbid(t, got, "SC4N-PARSE-FAILED")

	// The clean zip must not carry the rule.
	clean := buildZip(t, []zspec{{name: "ok.txt", data: []byte("x")}}, false)
	forbid(t, scanZip(t, "ok.zip", clean, limits.Default()), "SC4N-ARCHIVE-TRAILING-DATA")

	// A prefix (the torch prefixed-archive shape) is not trailing data: the
	// directory offsets are rebased, not appended to.
	prefixed := append([]byte("STUB"), clean...)
	forbid(t, scanZip(t, "stub.zip", prefixed, limits.Default()), "SC4N-ARCHIVE-TRAILING-DATA")
}

// TestNestedParseFailureIsReported: every container caller discards
// artifact.ScanMember's error, so the failure must be reported by ScanMember
// itself. An outer archive whose member is a damaged container is the modelscan
// #354 shape: without the finding the member is invisible and the report says
// clean.
func TestNestedParseFailureIsReported(t *testing.T) {
	// A container that carries no complete local header either: recovery has
	// nothing to walk, so the member stays a parse failure. (A zip whose EOCD is
	// merely damaged is now recoverable — see
	// TestNestedTruncatedZipIsRecoveredNotReportedAsFailure.)
	inner := buildZip(t, []zspec{{name: "payload.pkl", data: []byte("x")}}, false)
	broken := inner[:6]
	outer := buildZip(t, []zspec{{name: "inner.zip", data: broken}}, false)

	ctx, col := newCtx(t, "outer.zip", limits.Default())
	ctx.Format = artifact.FormatZip
	if err := archive.Scan(ctx, source.Mem("outer.zip", outer)); err != nil {
		t.Fatalf("outer scan: %v", err)
	}
	found := false
	for _, f := range col.Findings() {
		if f.RuleID == artifact.RuleParseFailed.ID {
			found = true
			if f.Artifact != "outer.zip:inner.zip" {
				t.Errorf("finding names %q, want outer.zip:inner.zip", f.Artifact)
			}
		}
	}
	if !found {
		t.Fatalf("nested parse failure not reported: %v", ids(col.Findings()))
	}
}

// TestNestedTruncatedZipIsRecoveredNotReportedAsFailure pins the boundary the
// header-slice recovery moved: a nested zip whose end-of-central-directory record
// is damaged is *not* a parse failure any more, because the local file headers are
// present and its members are scanned. The partial-container rule names the
// nested artifact so the result is not read as a scan of the whole inner file.
func TestNestedTruncatedZipIsRecoveredNotReportedAsFailure(t *testing.T) {
	inner := buildZip(t, []zspec{{name: "archive/data.pkl", data: gadgetPickle()}}, false)
	broken := inner[:len(inner)-10] // damage the end-of-central-directory record
	outer := buildZip(t, []zspec{{name: "inner.zip", data: broken}}, false)

	ctx, col := newCtx(t, "outer.zip", limits.Default())
	ctx.Format = artifact.FormatZip
	if err := archive.Scan(ctx, source.Mem("outer.zip", outer)); err != nil {
		t.Fatalf("outer scan: %v", err)
	}
	var truncated, pickle bool
	for _, f := range col.Findings() {
		switch f.RuleID {
		case "SC4N-ARCHIVE-TRUNCATED":
			truncated = true
			if f.Artifact != "outer.zip:inner.zip" {
				t.Errorf("truncated finding names %q, want outer.zip:inner.zip", f.Artifact)
			}
		case "SC4N-PICKLE-GLOBAL-CRITICAL":
			pickle = true
		case artifact.RuleParseFailed.ID:
			t.Errorf("parse failure reported for a recoverable slice: %+v", f)
		}
	}
	if !truncated || !pickle {
		t.Fatalf("truncated=%v pickle=%v; findings were %v", truncated, pickle, ids(col.Findings()))
	}
}

// rawTarHeader builds one 512-byte USTAR regular-file header that declares size
// without any of the data that size implies. A hand-written header is the shape
// an attacker uses: Go's reader trusts the declaration, so without a bound the
// walk would try to materialise the whole declared size.
func rawTarHeader(name string, size int64) []byte {
	return rawTarHeaderType(name, size, '0')
}

func rawTarHeaderType(name string, size int64, typeflag byte) []byte {
	h := make([]byte, 512)
	copy(h[0:100], name)
	copy(h[100:108], "0000644\x00")
	copy(h[108:116], "0000000\x00")
	copy(h[116:124], "0000000\x00")
	copy(h[124:136], fmt.Sprintf("%011o\x00", size))
	copy(h[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		h[i] = ' '
	}
	h[156] = typeflag
	copy(h[257:263], "ustar\x00")
	copy(h[263:265], "00")
	var sum int
	for _, b := range h {
		sum += int(b)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return h
}

func padTarBlock(b []byte) []byte {
	out := append([]byte(nil), b...)
	if r := len(out) % 512; r != 0 {
		out = append(out, make([]byte, 512-r)...)
	}
	return out
}

// paxRecord encodes one PAX extended-header record: "<len> <key>=<value>\n",
// where len counts the whole record including its own digits. The space is part
// of the count, which is the detail hand-rolled records get wrong.
func paxRecord(key, value string) string {
	body := key + "=" + value + "\n"
	n := len(body)
	for {
		m := 1 + len(body) + len(strconv.Itoa(n))
		if m == n {
			break
		}
		n = m
	}
	return strconv.Itoa(n) + " " + body
}

// paxSparseTar builds a GNU/PAX sparse tar whose single member declares realsize
// logical bytes while the archive holds one byte of real data. Go's reader
// synthesises the holes, so reading the member yields realsize bytes — the shape
// that turns a few archive bytes into a large spill without a bound.
func paxSparseTar(realsize int64) []byte {
	pax := paxRecord("GNU.sparse.size", strconv.FormatInt(realsize, 10)) +
		paxRecord("GNU.sparse.numblocks", "1") +
		paxRecord("GNU.sparse.map", "0,1") +
		paxRecord("path", "sparse.bin")
	var out []byte
	out = append(out, rawTarHeaderType("./PaxHeaders/sparse.bin", int64(len(pax)), 'x')...)
	out = append(out, padTarBlock([]byte(pax))...)
	out = append(out, rawTarHeaderType("sparse.bin", 1, '0')...)
	out = append(out, padTarBlock([]byte("A"))...)
	out = append(out, make([]byte, 1024)...) // end-of-archive marker
	return out
}

// dirBytes sums the size of the regular files directly under dir. t.Setenv points
// TMPDIR here, so it measures how much the scan spilled to disk.
func dirBytes(t *testing.T, dir string) int64 {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			total += info.Size()
		}
	}
	return total
}

// TestUnjustifiedTarMemberSize: a tar member declaring far more than the archive
// holds is refused before any of it is materialised. The declared size cannot be
// backed by the file, so it is a limit finding and TMPDIR must stay well under
// MaxSpillBytes rather than growing to the declared size.
func TestUnjustifiedTarMemberSize(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	hdr := rawTarHeader("sparse.bin", 1<<32)
	l := limits.Default()
	l.MaxStringBlob = 1 << 10
	l.MaxSpillBytes = 1 << 20

	got := scanAs(t, "sparse.tar", hdr, artifact.FormatTar, l)
	want(t, got, "SC4N-LIMIT-DECOMPRESSED")

	n := dirBytes(t, dir)
	t.Logf("TMPDIR holds %d bytes after the scan (MaxSpillBytes=%d)", n, l.MaxSpillBytes)
	if n >= l.MaxSpillBytes {
		t.Fatalf("TMPDIR grew to %d bytes, want under MaxSpillBytes=%d", n, l.MaxSpillBytes)
	}
}

// TestJustifiedTarMemberSize: a valid tar must not trip the justification bound.
func TestJustifiedTarMemberSize(t *testing.T) {
	forbid(t, scanAs(t, "ok.tar", tarBytes(t), artifact.FormatTar, limits.Default()), "SC4N-LIMIT-DECOMPRESSED")
}

// TestUnjustifiedSparseTarMemberSize: a GNU/PAX sparse member declares 4 GiB while
// the archive holds one byte and Go's reader synthesises the rest. The declared
// size cannot be backed by the archive, so the member is refused before the spill
// runs: the report carries the justification finding, not SC4N-LIMIT-SPILL, and
// nothing large is written under TMPDIR.
func TestUnjustifiedSparseTarMemberSize(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	l := limits.Default()
	l.MaxStringBlob = 1 << 10
	l.MaxSpillBytes = 1 << 20
	got := scanAs(t, "sparse.tar", paxSparseTar(1<<32), artifact.FormatTar, l)
	want(t, got, "SC4N-LIMIT-DECOMPRESSED")
	forbid(t, got, "SC4N-LIMIT-SPILL")
	n := dirBytes(t, dir)
	t.Logf("TMPDIR holds %d bytes after the scan (MaxSpillBytes=%d)", n, l.MaxSpillBytes)
	if n >= l.MaxSpillBytes {
		t.Fatalf("TMPDIR grew to %d bytes, want under MaxSpillBytes=%d", n, l.MaxSpillBytes)
	}
}

// TestSpillRefusalChargesCap: when the spill refuses a member, the bytes charged
// to the cumulative decompressed budget are the spill cap plus one, not the probe
// length. Two refused members must exhaust a budget that is only 1.5x the spill
// cap; charging the probe would leave the run looking clean and the later member
// would still be scanned.
func TestSpillRefusalChargesCap(t *testing.T) {
	big := make([]byte, 2<<20)
	data := buildZip(t, []zspec{
		{name: "big1.bin", data: big, method: 8},
		{name: "big2.bin", data: big, method: 8},
		{name: "archive/data.pkl", data: gadgetPickle(), method: 8},
	}, false)
	l := limits.Default()
	l.MaxStringBlob = 1 << 16
	l.MaxSpillBytes = 1 << 20
	l.MaxDecompressedBytes = 3 << 19 // 1.5 MiB: two spill charges exceed it, two probes do not
	l.MaxRatio = 0
	got := scanZip(t, "charge.zip", data, l)
	want(t, got, "SC4N-LIMIT-SPILL")
	want(t, got, "SC4N-LIMIT-DECOMPRESSED")
	forbid(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

// TestSkippedTarMembersAreReported: the tar walk dispatched only regular
// members, so a GNU sparse or contiguous member and a member with an empty name
// were skipped with no finding — and only the universal head/tail windows ever
// saw the file, so a payload in the parts they do not cover was invisible. A
// sparse member makes the gap concrete: a 4 MiB logical member lives in a 2 KB
// archive.
func TestSkippedTarMembersAreReported(t *testing.T) {
	// A GNU-format sparse header: magic "ustar " + version " \x00", the old GNU
	// sparse map at 386 (four offset/numbytes pairs), realSize at 483, and a
	// single stored 512-byte chunk.
	hdr := make([]byte, 512)
	copy(hdr[0:100], "sparse.bin")
	copy(hdr[100:108], "0000644\x00")
	copy(hdr[108:116], "0000000\x00")
	copy(hdr[116:124], "0000000\x00")
	copy(hdr[124:136], "00000001000\x00") // stored bytes
	copy(hdr[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		hdr[i] = ' '
	}
	hdr[156] = 'S'
	copy(hdr[257:263], "ustar ")
	copy(hdr[263:265], " \x00")
	copy(hdr[386:398], "00000000000\x00")  // first chunk at offset 0
	copy(hdr[398:410], "00000001000\x00")  // 512 bytes long
	copy(hdr[483:495], "000004000000\x00") // 4 MiB logical
	var sum int
	for _, b := range hdr {
		sum += int(b)
	}
	copy(hdr[148:156], fmt.Sprintf("%06o\x00 ", sum))

	sparse := append([]byte(nil), hdr...)
	sparse = append(sparse, make([]byte, 512)...) // the one stored chunk
	sparse = append(sparse, make([]byte, 1024)...)
	got := scanAs(t, "sparse.tar", sparse, artifact.FormatTar, limits.Default())
	want(t, got, "SC4N-ARCHIVE-MEMBER-SKIPPED")

	// A member with an empty name: the same rule, because the walk cannot report
	// it against a path and its bytes are not dispatched.
	empty := rawTarHeaderType("", 4, '0')
	empty = append(empty, []byte("abcd")...)
	empty = append(empty, make([]byte, 1024)...)
	want(t, scanAs(t, "empty.tar", empty, artifact.FormatTar, limits.Default()), "SC4N-ARCHIVE-MEMBER-SKIPPED")

	// A tar of regular members must not carry the rule.
	plain := rawTarHeader("a.txt", 4)
	plain = append(plain, []byte("abcd")...)
	plain = append(plain, make([]byte, 1024)...)
	forbid(t, scanAs(t, "plain.tar", plain, artifact.FormatTar, limits.Default()), "SC4N-ARCHIVE-MEMBER-SKIPPED")
}

// TestZipLocalHeaderFieldsAreCompared: only the local header's *name* used to be
// compared, so a member whose local header said "deflate" while the central
// directory said "stored" was read as stored bytes with no finding, and a stored
// member whose central record declared two different sizes was accepted.
func TestZipLocalHeaderFieldsAreCompared(t *testing.T) {
	base := buildZip(t, []zspec{{name: "a.txt", data: []byte("hello world")}}, false)

	// Local method patched to deflate; the central directory still says stored.
	method := append([]byte(nil), base...)
	binary.LittleEndian.PutUint16(method[8:], 8)
	want(t, scanZip(t, "method.zip", method, limits.Default()), "SC4N-ARCHIVE-NAME-MISMATCH")

	// Central record's compressed size patched away from the uncompressed size.
	sizes := append([]byte(nil), base...)
	cd := bytes.Index(sizes, []byte("PK\x01\x02"))
	if cd < 0 {
		t.Fatal("no central directory record in the fixture")
	}
	binary.LittleEndian.PutUint32(sizes[cd+20:], 99)
	want(t, scanZip(t, "sizes.zip", sizes, limits.Default()), "SC4N-ARCHIVE-NAME-MISMATCH")

	// An unreadable local header must not be read as if it started at offset 0:
	// the artifact's own leading bytes are not the member.
	broken := append([]byte(nil), base...)
	copy(broken[0:4], "XXXX")
	got := scanZip(t, "nolocal.zip", broken, limits.Default())
	want(t, got, "SC4N-ARCHIVE-MEMBER-ERROR")
	forbid(t, got, "SC4N-ARCHIVE-CRC")

	// The unmodified zip must be clean of both.
	clean := scanZip(t, "clean.zip", base, limits.Default())
	forbid(t, clean, "SC4N-ARCHIVE-NAME-MISMATCH")
	forbid(t, clean, "SC4N-ARCHIVE-MEMBER-ERROR")
}

// TestJoblibLegacyShape: the "ZF" frame is 21 bytes of header — the magic, the
// uncompressed length as a padded hex string — and then a zlib stream. Two ASCII
// letters are not enough to call a file a joblib archive.
func TestJoblibLegacyShape(t *testing.T) {
	body := []byte("hello joblib legacy")
	zbody := zlibBytes(t, body)
	frame := func(l int) []byte {
		return append([]byte("ZF"+hexLen(l)), zbody...)
	}
	for _, tc := range []struct {
		name string
		in   []byte
		want bool
	}{
		{"real frame", frame(len(body)), true},
		{"python2 wide header", append([]byte("ZF"+"0x14"+strings.Repeat(" ", 16)), zbody...), true},
		{"text starting with ZF", []byte("ZFooter notes for the release\n"), false},
		{"magic only", []byte("ZF"), false},
		{"header without a stream", append([]byte("ZF"+hexLen(4)), 'x', 'y'), false},
		{"no hex length", append([]byte("ZF"+"not-hex-here"), zbody...), false},
		{"zlib body but no header", append([]byte("ZF"), body...), false},
	} {
		if got := archive.JoblibLegacyShape(tc.in); got != tc.want {
			t.Errorf("%s: JoblibLegacyShape = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// hexLen renders n the way joblib's write_zfile did: "0x…" padded with spaces to
// the 19 characters a 64-bit length needs.
func hexLen(n int) string {
	s := "0x" + strconv.FormatInt(int64(n), 16)
	for len(s) < 19 {
		s += " "
	}
	return s
}

// --- truncated container: members recovered from local file headers ---------------

// localHeader builds one zip local file header (no extra field, no data
// descriptor, no central directory — the shape of a header slice).
func localHeader(name string, method, flags uint16, comp, uncomp uint32) []byte {
	var b [30]byte
	binary.LittleEndian.PutUint32(b[0:], 0x04034b50)
	binary.LittleEndian.PutUint16(b[4:], 20)
	binary.LittleEndian.PutUint16(b[6:], flags)
	binary.LittleEndian.PutUint16(b[8:], method)
	binary.LittleEndian.PutUint32(b[18:], comp)
	binary.LittleEndian.PutUint32(b[22:], uncomp)
	binary.LittleEndian.PutUint16(b[26:], uint16(len(name)))
	return append(b[:], name...)
}

// A slice of a torch checkpoint: a local header for archive/data.pkl with the
// data-descriptor flags torch writes, the pickle the member holds, and nothing
// after it. The pickle's global rule must be reachable, and the artifact must not
// be reported as a parse failure.
func TestTruncatedZipRecoversMembers(t *testing.T) {
	pkl := gadgetPickle()
	data := append([]byte{}, localHeader("archive/data.pkl", 0, 0x8, 0, 0)...)
	data = append(data, pkl...)

	got := scanZip(t, "best.pt", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-TRUNCATED")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	want(t, got, "SC4N-PICKLE-REDUCE")
	forbid(t, got, "SC4N-PARSE-FAILED")
}

// The same container with a plain-text member: the partial-container rule fires
// (the container *is* truncated) and no pickle rule does.
func TestTruncatedZipPlainMemberIsNotAPickle(t *testing.T) {
	body := []byte("hello\n")
	data := append([]byte{}, localHeader("notes.txt", 0, 0x8, 0, 0)...)
	data = append(data, body...)

	got := scanZip(t, "notes.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-TRUNCATED")
	forbid(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-PARSE-FAILED")
}

// A deflated member inside the slice: the inflater must reach the payload.
func TestTruncatedZipInflatesDeflatedMember(t *testing.T) {
	pkl := gadgetPickle()
	packed := deflate(t, pkl)
	data := append([]byte{}, localHeader("archive/data.pkl", 8, 0, uint32(len(packed)), uint32(len(pkl)))...)
	data = append(data, packed...)

	got := scanZip(t, "best.pt", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-TRUNCATED")
	want(t, got, "SC4N-PICKLE-REDUCE")
	forbid(t, got, "SC4N-PARSE-FAILED")
}

// A zip-shaped prefix that carries no complete local header is still a parse
// failure: recovery must not turn unreadable content into a clean verdict.
func TestTruncatedZipWithNoMemberStaysAParseFailure(t *testing.T) {
	data := []byte{'P', 'K', 3, 4, 20, 0, 0}
	ctx, col := newCtx(t, "tiny.zip", limits.Default())
	ctx.Format = artifact.FormatZip
	if err := archive.Scan(ctx, source.Mem("tiny.zip", data)); err == nil {
		t.Fatal("Scan accepted a truncated prefix with no member")
	}
	if ids(col.Findings())["SC4N-ARCHIVE-TRUNCATED"] {
		t.Fatal("SC4N-ARCHIVE-TRUNCATED emitted without a recovered member")
	}
}
