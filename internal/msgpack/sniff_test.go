package msgpack

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// TestSniffRequiresCoverage pins the F31 invariant: a sniffer must not accept a
// document that its own parser reports as structurally invalid. `0x90` is a
// complete one-byte MessagePack value (an empty array), so the shape check alone
// claimed a ten-megabyte Chromium data table that happened to start with it.
func TestSniffRequiresCoverage(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		// A one-byte document is below the sniffer's size floor (a one-byte file
		// has nothing to analyse), so it is declined for that reason, not for
		// coverage.
		{"empty array alone is below the size floor", []byte{0x90}, false},
		{"small document that consumes both bytes", []byte{0x91, 0x90}, true},
		{"empty map alone is below the size floor", []byte{0x80}, false},
		{"empty array then padding", append([]byte{0x90}, make([]byte, 4096)...), false},
		{"one byte then other data", []byte{0x90, 0x00, 0x01, 0x02}, false},
		// A 3-byte artifact is below msgpackMinTruncatedSize: a truncated document
		// that small carries nothing.
		{"truncated map", []byte{0x82, 0xa1, 'a'}, false},
		{"invalid marker after a header", []byte{0x81, 0xc1, 0x01}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := source.Mem("f.msgpack", c.data)
			defer src.Close()
			f, ok := sniff(src, limits.Default())
			if ok != c.want {
				t.Fatalf("sniff(% x) = %v,%v, want %v", c.data, f, ok, c.want)
			}
		})
	}
}

// A container count the file cannot possibly hold is binary data that begins
// with a container header, not a truncated document. The measured shape is a
// torch storage blob: df 10 48 3c 12 opens a map32 of 273,102,866 entries in a
// 256 KiB file, and claiming it turned the artifact into a medium
// "msgpack: truncated value" instead of scanning it as binary.
func TestSniffRejectsImpossibleContainerCount(t *testing.T) {
	blob := make([]byte, 256<<10)
	copy(blob, []byte{0xdf, 0x10, 0x48, 0x3c, 0x12})
	src := source.Mem("data/102646816", blob)
	defer src.Close()
	if f, ok := sniff(src, limits.Default()); ok {
		t.Fatalf("sniff claimed a 273M-entry map32 in a 256 KiB file as %v", f)
	}
}

// A plausible count that the probe cannot satisfy is still a truncated document
// and must keep being claimed, provided the artifact is large enough and the walk
// decoded a real prefix.
func TestSniffAcceptsPlausibleTruncatedCount(t *testing.T) {
	// map32 of two entries whose first key decodes, then an array16 of 2000
	// values, then a str32 that declares far more than is present: the walk
	// decodes ~2 KiB of a 4 KiB artifact before it runs out.
	doc := []byte{0xdf, 0, 0, 0, 2, 0xa1, 'a', 0xc0, 0xa1, 'b', 0xdc, 0x07, 0xd1}
	for range 2000 {
		doc = append(doc, 0x01)
	}
	doc = append(doc, 0xdb, 0x00, 0x01, 0x00, 0x00, 'x')
	doc = append(doc, make([]byte, 4096-len(doc))...)
	src := source.Mem("m.msgpack", doc)
	defer src.Close()
	if len(doc) != 4096 {
		t.Fatalf("fixture is %d bytes, want 4096", len(doc))
	}
	if f, ok := sniff(src, limits.Default()); !ok || f != artifact.FormatMsgpack {
		t.Fatalf("sniff = %v,%v; want msgpack,true", f, ok)
	}
}

// A probe that fails within its first bytes has proved nothing: MessagePack has no
// magic, so the claim rests on how far the parse got. The measured shape is a torch
// storage blob claimed as a truncated document after decoding one byte.
func TestSniffRequiresDecodedProgressWhenTruncated(t *testing.T) {
	// 0x93 (fixarray 3) followed by an impossible string length, then zeros: the
	// walk fails at byte 2.
	blob := make([]byte, 4096)
	blob[0], blob[1], blob[2], blob[3], blob[4] = 0x93, 0xd9, 0xff, 0xff, 0xff
	src := source.Mem("data/1017", blob)
	defer src.Close()
	if f, ok := sniff(src, limits.Default()); ok {
		t.Fatalf("sniff claimed a blob whose parse failed at byte 2 as %v", f)
	}

	// A document that decodes a real prefix before running out is still claimed,
	// and it must clear both the 4 KiB size floor and the quarter-prefix ratio: an
	// array16 of 2000 decoded fixints (a 3-byte header plus 2000 values) followed
	// by a str32 that declares 65535 bytes with 3 present, padded to 4096 bytes.
	// The walk decodes ~2005 bytes of the 4096-byte probe before it faults.
	doc := []byte{0xdc, 0x07, 0xd1}
	for range 2000 {
		doc = append(doc, 0x01)
	}
	doc = append(doc, 0xdb, 0x00, 0x00, 0xff, 0xff, 'x', 'y', 'z')
	doc = append(doc, make([]byte, 4096-len(doc))...)
	src2 := source.Mem("truncated.msgpack", doc)
	defer src2.Close()
	if len(doc) != 4096 {
		t.Fatalf("fixture is %d bytes, want 4096", len(doc))
	}
	if f, ok := sniff(src2, limits.Default()); !ok {
		t.Fatalf("sniff declined a decoded prefix (format %v)", f)
	}

	// The measured shape of best/data/106: a 96-byte storage blob starting 0x92
	// whose walk reaches 83 bytes. Below the size floor, so declined.
	small := make([]byte, 96)
	small[0], small[1], small[2] = 0x92, 0xa9, 'a'
	src3 := source.Mem("data/106", small)
	defer src3.Close()
	if f, ok := sniff(src3, limits.Default()); ok {
		t.Fatalf("sniff claimed a 96-byte truncated blob as %v", f)
	}
}
