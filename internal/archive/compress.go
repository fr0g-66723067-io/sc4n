package archive

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Compressor identifies a single-stream compression wrapper by magic. It is a
// superset of the formats sc4n can decompress: the ones without a standard-library
// decoder are still *named*, because an artifact wrapped in them has a payload
// that was not scanned and that fact must be reported (SC4N-ARCHIVE-UNSUPPORTED-
// COMPRESSION), never silently ignored.
type Compressor uint8

const (
	CompressorNone Compressor = iota
	CompressorZlib
	CompressorGzip
	CompressorBzip2
	CompressorXz
	CompressorLzma
	CompressorLz4
	CompressorZstd
	CompressorZlibJoblibLegacy
	CompressorSevenZip
	CompressorRar
)

// String names the algorithm as it appears in evidence.
func (c Compressor) String() string {
	switch c {
	case CompressorZlib:
		return "zlib"
	case CompressorGzip:
		return "gzip"
	case CompressorBzip2:
		return "bzip2"
	case CompressorXz:
		return "xz"
	case CompressorLzma:
		return "lzma"
	case CompressorLz4:
		return "lz4"
	case CompressorZstd:
		return "zstd"
	case CompressorZlibJoblibLegacy:
		return "joblib-legacy-zf"
	case CompressorSevenZip:
		return "7z"
	case CompressorRar:
		return "rar"
	default:
		return "none"
	}
}

// Format returns the artifact.Format a bare stream of c is sniffed as.

// ErrUnsupportedCompression is returned by Unwrap for a compressor with no
// standard-library decoder.
var ErrUnsupportedCompression = errors.New("archive: unsupported compression")

// Supported reports whether sc4n can decompress c with the standard library.
func Supported(c Compressor) bool {
	switch c {
	case CompressorZlib, CompressorGzip, CompressorBzip2:
		return true
	default:
		return false
	}
}

// DetectCompressor identifies a single-stream compression wrapper by magic. It
// reads at most 32 leading bytes and never allocates from a length in them.
func DetectCompressor(s source.Source, l limits.Limits) (Compressor, bool) {
	if s == nil || s.Size() < 2 {
		return CompressorNone, false
	}
	// 32 bytes: enough for the widest header any check here inspects — the
	// legacy joblib frame's 21-byte header plus the two zlib bytes after it. A
	// 16-byte probe could never see that far, so a real legacy frame was not
	// detected at all.
	n := s.Size()
	if n > 32 {
		n = 32
	}
	b, err := s.Bytes(0, n)
	if len(b) < 2 {
		_ = err
		return CompressorNone, false
	}
	return detectCompressorBytes(b)
}

func detectCompressorBytes(b []byte) (Compressor, bool) {
	switch {
	case len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd:
		return CompressorZstd, true
	case len(b) >= 4 && b[0] == 0x04 && b[1] == 0x22 && b[2] == 0x4d && b[3] == 0x18:
		return CompressorLz4, true
	case len(b) >= 6 && string(b[:6]) == "\xfd7zXZ\x00":
		return CompressorXz, true
	case len(b) >= 6 && string(b[:6]) == "7z\xbc\xaf\x27\x1c":
		return CompressorSevenZip, true
	case len(b) >= 8 && string(b[:8]) == "Rar!\x1a\x07\x01\x00":
		return CompressorRar, true
	case len(b) >= 7 && string(b[:7]) == "Rar!\x1a\x07\x00":
		return CompressorRar, true
	case len(b) >= 3 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h':
		return CompressorBzip2, true
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return CompressorGzip, true
	case len(b) >= 2 && b[0] == 'Z' && b[1] == 'F' && JoblibLegacyShape(b):
		return CompressorZlibJoblibLegacy, true
	case len(b) >= 2 && zlibShape(b):
		// The check described in RFC 1950 rather than a fixed list of FLG bytes.
		return CompressorZlib, true
	case lzmaShape(b):
		return CompressorLzma, true
	}
	return CompressorNone, false
}

// JoblibLegacyShape validates the frame joblib wrote before 0.10 (write_zfile in
// joblib 0.9.4): "ZF", then the *uncompressed* length as a hex string with a "0x"
// prefix, space-padded to 19 characters, then a zlib stream. The two magic bytes
// are ordinary text, so a file that merely starts with "ZF" must not be called a
// joblib archive: the header and the zlib stream both have to be plausible.
func JoblibLegacyShape(b []byte) bool {
	// "ZF" + len("0x10000000000000000") = 21; a joblib <= 0.8.4 header written
	// under Python 2 is one byte wider, which is why the zlib stream is looked
	// for at either offset.
	const header = 21
	if len(b) < header+2 {
		return false
	}
	hexLen := strings.TrimRight(string(b[2:header]), " ")
	if len(hexLen) < 3 || hexLen[0] != '0' || hexLen[1] != 'x' {
		return false
	}
	for i := 2; i < len(hexLen); i++ {
		c := hexLen[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return zlibShape(b[header:]) || (b[header] == ' ' && zlibShape(b[header+1:]))
}

// zlibShape is RFC 1950's two-byte check: CMF low nibble 8 (deflate) and a valid
// FCHECK, so that CMF*256+FLG is a multiple of 31.
func zlibShape(b []byte) bool {
	return len(b) >= 2 && b[0]&0x0f == 8 && (int(b[0])<<8|int(b[1]))%31 == 0
}

// lzmaShape applies the header sanity check the plan requires: the 2-byte "\x5d\x00"
// magic collides with ordinary data, so the properties byte, the dictionary size
// and the declared uncompressed size must all be plausible before the stream is
// called lzma.
func lzmaShape(b []byte) bool {
	if len(b) < 13 || b[0] != 0x5d {
		return false
	}
	dict := uint32(b[1]) | uint32(b[2])<<8 | uint32(b[3])<<16 | uint32(b[4])<<24
	if dict < 1<<12 || dict > 1<<31 {
		return false
	}
	// The 8-byte uncompressed size is either the "unknown" sentinel or a value
	// no larger than the artifact cap could ever reach; anything else is not a
	// real lzma header.
	uncomp := uint64(b[5]) | uint64(b[6])<<8 | uint64(b[7])<<16 | uint64(b[8])<<24 |
		uint64(b[9])<<32 | uint64(b[10])<<40 | uint64(b[11])<<48 | uint64(b[12])<<56
	if uncomp == math.MaxUint64 {
		return true
	}
	return uncomp <= 1<<40
}

// LimitError reports that a decompression cap fired. It carries the rule and the
// observed value so the caller emits the same SC4N-LIMIT-* evidence the limits
// package produces everywhere else.
type LimitError struct {
	Rule   *report.Rule
	Limit  string
	Value  int64
	Cap    int64
	Detail string
}

func (e *LimitError) Error() string {
	return "archive: " + e.Limit + " exceeded (" + strconv.FormatInt(e.Value, 10) + " > " + strconv.FormatInt(e.Cap, 10) + ")"
}

// decompressionCap returns the effective byte cap for one layer and the rule that
// fires when it is hit: the smaller of MaxDecompressedBytes and
// compressed*MaxRatio.
func decompressionCap(compressed int64, l limits.Limits) (int64, *report.Rule) {
	capBytes := l.MaxDecompressedBytes
	rule := limits.RuleDecompressed
	if capBytes <= 0 {
		// A zero budget means "unset", exactly as maxBlob and spillCap read it.
		// Mapping it to MaxInt64 is worse than useless here: the cap is compared
		// against a running total, so a wrap would make the comparison report the
		// budget as exhausted and silently truncate the payload.
		capBytes = limits.Default().MaxDecompressedBytes
	}
	if l.MaxRatio > 0 && compressed > 0 {
		ratioCap := mulCap(compressed, l.MaxRatio)
		if ratioCap < capBytes {
			return ratioCap, limits.RuleRatio
		}
	}
	return capBytes, rule
}

// mulCap multiplies without overflow, clamping to MaxInt64.
func mulCap(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// getBuf returns a zero-length scratch buffer.
func getBuf() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

// putBuf returns b to the pool when it has not grown past a sane ceiling, so one
// pathological member cannot pin a huge buffer forever.
func putBuf(b *bytes.Buffer) {
	if b.Cap() <= 1<<20 {
		b.Reset()
		bufPool.Put(b)
	}
}

func limitName(r *report.Rule) string {
	switch r {
	case limits.RuleRatio:
		return "MaxRatio"
	case limits.RuleDecompressed:
		return "MaxDecompressedBytes"
	case limits.RuleString:
		return "MaxStringBlob"
	case limits.RuleEntries:
		return "MaxEntries"
	default:
		return r.ID
	}
}

// compressorForFormat maps a core compression format to its Compressor.
func compressorForFormat(f artifact.Format) (Compressor, bool) {
	switch f {
	case artifact.FormatGzip:
		return CompressorGzip, true
	case artifact.FormatZlib:
		return CompressorZlib, true
	case artifact.FormatBzip2:
		return CompressorBzip2, true
	case artifact.FormatXz:
		return CompressorXz, true
	case artifact.FormatLzma:
		return CompressorLzma, true
	case artifact.FormatLz4:
		return CompressorLz4, true
	case artifact.FormatZstd:
		return CompressorZstd, true
	case artifact.FormatZlibJoblibLegacy:
		return CompressorZlibJoblibLegacy, true
	case artifact.FormatSevenZip:
		return CompressorSevenZip, true
	case artifact.FormatRar:
		return CompressorRar, true
	default:
		return CompressorNone, false
	}
}
