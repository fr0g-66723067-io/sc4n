package archive_test

import (
	"archive/tar"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
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
		{[]byte("ZF\x00"), archive.CompressorZlibJoblibLegacy},
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
	if !archive.Supported(archive.CompressorGzip) || !archive.Supported(archive.CompressorBzip2) {
		t.Fatal("gzip/bzip2 must be supported")
	}
}

func TestUnwrapRatioCap(t *testing.T) {
	bomb := gzipBytes(t, make([]byte, 1<<20))
	l := limits.Default()
	l.MaxRatio = 2
	_, err := archive.Unwrap(source.Mem("bomb.gz", bomb), l, archive.CompressorGzip)
	var le *archive.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LimitError, got %v", err)
	}
	if le.Limit != "MaxRatio" {
		t.Fatalf("limit = %q, want MaxRatio", le.Limit)
	}
}

// TestUnwrapZeroBudgetIsNotUnlimited: a zero-valued Limits means "unset", not
// "unlimited". Mapping MaxDecompressedBytes to MaxInt64 made the +1 peek wrap to
// MinInt64, io.LimitReader then reported EOF at once, and the payload came back
// empty with a nil error — a silent truncation, which is the one outcome the
// limits design forbids.
func TestUnwrapZeroBudgetIsNotUnlimited(t *testing.T) {
	payload := gadgetPickle()
	got, err := archive.Unwrap(source.Mem("x.gz", gzipBytes(t, payload)), limits.Limits{}, archive.CompressorGzip)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Unwrap returned %d bytes (%q), want the %d-byte payload", len(got), got, len(payload))
	}
}

func TestUnwrapRejectsUnsupported(t *testing.T) {
	_, err := archive.Unwrap(source.Mem("x", []byte{0x28, 0xb5, 0x2f, 0xfd}), limits.Default(), archive.CompressorZstd)
	if !errors.Is(err, archive.ErrUnsupportedCompression) {
		t.Fatalf("err = %v, want ErrUnsupportedCompression", err)
	}
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
