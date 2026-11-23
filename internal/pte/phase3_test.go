package pte

import (
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestSniffRejectsRootOffsetOutsideFile(t *testing.T) {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:], 8)
	copy(data[4:], "ET12")
	if f, ok := sniff(source.Mem("x.pte", data), limits.Default()); ok || f != artifact.FormatUnknown {
		t.Fatalf("out-of-range root sniffed as %v, %v", f, ok)
	}
}

func TestEmbeddedNativeAtWindowBoundaryIsReported(t *testing.T) {
	segment := make([]byte, nativeWindow+128)
	copy(segment[nativeWindow-16:], tinyELF())
	fs := parse(t, "m.pte", build("ET12", "eh12", 0, segment))
	if !hasRule(fs, RuleNative.ID) {
		t.Fatalf("an ELF at a window boundary was not reported; findings=%v", fs)
	}
}

func TestSegmentScanIsBounded(t *testing.T) {
	segment := make([]byte, maxSegmentScanBytes+64)
	fs := parse(t, "m.pte", build("ET12", "eh12", 0, segment))
	if !hasRule(fs, "SC4N-LIMIT-ENTRIES") {
		t.Fatalf("segment scan cap was silent; findings=%v", fs)
	}
}
