package archive_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestZipSymlinkWithPayloadIsStillScanned(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "data.pkl", data: gadgetPickle(), mode: 0o120777},
	}, false)
	got := scanZip(t, "symlink_payload.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-LINK")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

func TestZipLargeTrailingDataUsesCentralDirectory(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "../evil.txt", data: []byte("x")},
		{name: "archive/data.pkl", data: gadgetPickle(), method: 8},
	}, false)
	// Append 70 KiB (> 64 KiB EOCD window) of trailing data after EOCD.
	data = append(data, bytes.Repeat([]byte("TRAIL"), 14<<10)...)

	got := scanZip(t, "bigtrail.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-TRAILING-DATA")
	want(t, got, "SC4N-ARCHIVE-PATH")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-ARCHIVE-TRUNCATED")
}

func TestZipBzip2Method12Supported(t *testing.T) {
	// bzip2 -9 of gadgetPickle() (same fixed literal as TestGzipBzip2DoubleCompression).
	const h = "425a6839314159265359662104e000000853e015000001100006228c2042040800200022268d34643c90a1a698002815cc87e299053c28b57c5dc914e1424198841380"
	bz, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	pkl := gadgetPickle()
	crc := crc32.ChecksumIEEE(pkl)

	var buf bytes.Buffer
	writeLocal(&buf, 12, crc, uint32(len(bz)), uint32(len(pkl)), "archive/data.pkl")
	buf.Write(bz)
	cdOff := uint32(buf.Len())
	writeCentral(&buf, "archive/data.pkl", 12, crc, uint32(len(bz)), uint32(len(pkl)), 0o100644, 0)
	cdSize := uint32(buf.Len()) - cdOff
	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:], 1)
	binary.LittleEndian.PutUint16(eocd[10:], 1)
	binary.LittleEndian.PutUint32(eocd[12:], cdSize)
	binary.LittleEndian.PutUint32(eocd[16:], cdOff)
	buf.Write(eocd[:])

	got := scanZip(t, "bz2.zip", buf.Bytes(), limits.Default())
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION")

	// Also verify truncated-zip recovery supports method 12.
	trunc := buf.Bytes()[:cdOff]
	gotTrunc := scanZip(t, "bz2_trunc.zip", trunc, limits.Default())
	want(t, gotTrunc, "SC4N-ARCHIVE-TRUNCATED")
	want(t, gotTrunc, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, gotTrunc, "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION")
}

func TestTruncatedZipReportsEncryptedMember(t *testing.T) {
	data := append([]byte{}, localHeader("secret.pkl", 0, 0x1, 16, 16)...)
	data = append(data, bytes.Repeat([]byte{0xaa}, 16)...)
	got := scanZip(t, "enc_trunc.zip", data, limits.Default())
	want(t, got, "SC4N-ARCHIVE-TRUNCATED")
	want(t, got, "SC4N-ARCHIVE-ENCRYPTED")
}

func TestGzipMultistreamFalsePreservesTrailingPayload(t *testing.T) {
	// Gzip member immediately followed by a gadget pickle. With Multistream(true),
	// compress/gzip over-read up to 10 bytes into the pickle and destroyed its header.
	gz := gzipBytes(t, []byte("benign"))
	data := append(gz, gadgetPickle()...)
	got := scanAs(t, "trail.gz", data, artifact.FormatGzip, limits.Default())
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

func TestCompressedScanEnforcesRemainingDecompressedBudget(t *testing.T) {
	// Nested gzip inside zip: outer zip consumes almost all of MaxDecompressedBytes,
	// so the inner gzip must hit SC4N-LIMIT-DECOMPRESSED instead of getting a fresh budget.
	inner := gzipBytes(t, bytes.Repeat([]byte("A"), 8192))
	outer := buildZip(t, []zspec{
		{name: "pad.bin", data: bytes.Repeat([]byte("B"), 2000)},
		{name: "inner.gz", data: inner},
	}, false)
	l := limits.Default()
	l.MaxDecompressedBytes = 2500
	l.MaxRatio = 0
	got := scanZip(t, "nested_gz.zip", outer, l)
	want(t, got, "SC4N-LIMIT-DECOMPRESSED")
}

func TestProcessReaderPreservesCRCAtMaxPlusOneAndDoesNotExhaustSpill(t *testing.T) {
	// Member 1 has length MaxStringBlob+1 and a bad CRC: rerr (errCRC) fires on
	// byte max+1 and must be reported (not lost in Spill).
	body1 := bytes.Repeat([]byte("x"), 1025)
	// Member 2 is > MaxStringBlob and valid, with a bad CRC inside Spill.
	body2 := bytes.Repeat([]byte("y"), 2048)
	// Member 3 is > MaxStringBlob with a gadget pickle; must still be spilled and scanned.
	body3 := append(gadgetPickle(), bytes.Repeat([]byte("z"), 2048)...)
	data := buildZip(t, []zspec{
		{name: "m1.bin", data: body1, method: 8, crc: 0xdeadbeef, crcFixed: true},
		{name: "m2.bin", data: body2, method: 8, crc: 0xbadc0ffe, crcFixed: true},
		{name: "m3.pkl", data: body3, method: 8},
	}, false)
	l := limits.Default()
	l.MaxStringBlob = 1024
	l.MaxSpillBytes = 4096
	l.MaxRatio = 0
	got := scanZip(t, "crc_spill.zip", data, l)
	want(t, got, "SC4N-ARCHIVE-CRC")
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-LIMIT-SPILL")
}

func rawV7TarHeader(name string, size int64) []byte {
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
	h[156] = 0 // V7 TypeRegA
	// Leave bytes 257..265 zeroed (no "ustar" magic).
	var sum int
	for _, b := range h {
		sum += int(b)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return h
}

func TestV7TarAndTrailingNonZeroDataAndNameCap(t *testing.T) {
	// Build a genuine V7 tar (no "ustar" magic at offset 257).
	pkl := gadgetPickle()
	var v7 []byte
	v7 = append(v7, rawV7TarHeader("data.pkl", int64(len(pkl)))...)
	v7 = append(v7, padTarBlock(pkl)...)
	v7 = append(v7, make([]byte, 1024)...)
	if string(v7[257:262]) == "ustar" {
		t.Fatal("expected V7 tar without ustar magic")
	}

	// Verify V7 tar is collected and scanned cleanly without false trailing-data findings.
	got := scanAs(t, "v7.tar", v7, artifact.FormatTar, limits.Default())
	want(t, got, "SC4N-PICKLE-GLOBAL-CRITICAL")
	forbid(t, got, "SC4N-ARCHIVE-TRAILING-DATA")

	// All-zero padding after tar EOF blocks is standard tar blocking and must be clean.
	padded := append(bytes.Clone(v7), make([]byte, 4096)...)
	forbid(t, scanAs(t, "padded.tar", padded, artifact.FormatTar, limits.Default()), "SC4N-ARCHIVE-TRAILING-DATA")

	// Non-zero bytes after tar EOF blocks must emit SC4N-ARCHIVE-TRAILING-DATA.
	trailing := append(bytes.Clone(v7), []byte("HIDDEN-PAYLOAD")...)
	want(t, scanAs(t, "trailing.tar", trailing, artifact.FormatTar, limits.Default()), "SC4N-ARCHIVE-TRAILING-DATA")

	// collectTar must enforce MaxRetainedText on member names.
	l := limits.Default()
	l.MaxRetainedText = 4
	gotCap := scanAs(t, "cap.tar", v7, artifact.FormatTar, l)
	want(t, gotCap, "SC4N-LIMIT-RETAINED")
	want(t, gotCap, "SC4N-ARCHIVE-MEMBER-SKIPPED")
}

func TestZlibShapeRejectsInvalidCINFO(t *testing.T) {
	// 0x88 0x17: CM=8, CINFO=8 (>7, invalid RFC 1950), (0x8817)%31 == 0.
	if _, ok := archive.DetectCompressor(source.Mem("bad.z", []byte{0x88, 0x17, 0x00, 0x00}), limits.Default()); ok {
		t.Fatal("DetectCompressor accepted RFC 1950 CINFO=8 (>7) as zlib")
	}
}
