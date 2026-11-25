package polyglot

import (
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// TestFatMachOMagicOnlyIsReported pins the fat (universal) Mach-O magic: the
// dispatcher claimed it as a native artifact, but the magic walk did not know the
// magic, so the file produced NO finding at all — not even the informational one a
// thin Mach-O gets from the same four bytes. FAT_MAGIC is also the Java class-file
// magic, so the claim must stay a header-shape claim: a file that only starts with
// it is reported at info, never as a validated program.
func TestFatMachOMagicOnlyIsReported(t *testing.T) {
	// A header that cannot validate: four zero bytes declare zero architectures
	// and the junk after them is not one either.
	fat := append([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x00"), []byte("junkjunk")...)
	got := ids(run(t, "Thing.dylib", fat, artifact.FormatNative, 0))
	if !got["SC4N-POLYGLOT-MAGIC-ONLY"] {
		t.Fatalf("a bare FAT_MAGIC produced no finding; findings=%v", got)
	}
	if got["SC4N-POLYGLOT-NATIVE"] || got["SC4N-NATIVE-VALID"] {
		t.Fatalf("a bare FAT_MAGIC was reported as a validated executable; findings=%v", got)
	}
}

// TestThinMachOMagicOnlyIsReported is the control for the test above: the thin
// magic was already recognised, and adding the fat magic must not change it.
func TestThinMachOMagicOnlyIsReported(t *testing.T) {
	thin := append([]byte("\xcf\xfa\xed\xfe\x00\x00\x00\x00"), []byte("junkjunk")...)
	got := ids(run(t, "Thing.dylib", thin, artifact.FormatNative, 0))
	if !got["SC4N-POLYGLOT-MAGIC-ONLY"] {
		t.Fatalf("a bare thin Mach-O magic produced no finding; findings=%v", got)
	}
}

func TestFatMachOArchCountIsBounded(t *testing.T) {
	// FAT_MAGIC with a claimed 65 architectures and no table.
	bad := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41}
	if _, ok := ValidateNativeHeader(source.Mem("fat", bad), 8, 0); ok {
		t.Fatal("a fat header with 65 architectures validated")
	}
}

func TestMachoLoadCommandSizeIsBounded(t *testing.T) {
	// Thin 64-bit little-endian Mach header, one command, a size larger than
	// the bound.
	bad := make([]byte, 64)
	copy(bad, []byte{0xcf, 0xfa, 0xed, 0xfe})
	binary.LittleEndian.PutUint32(bad[16:], 1)
	binary.LittleEndian.PutUint32(bad[20:], 16<<20+1)
	if _, ok := ValidateNativeHeader(source.Mem("thin", bad), int64(len(bad)), 0); ok {
		t.Fatal("a Mach-O load-command table above the bound validated")
	}
}

func TestFatMachOBoundsCheckedWhenOffsetNonZero(t *testing.T) {
	// Case 1: arch table extends past EOF when embedded at off > 0.
	// Total size = 120, off = 100, remaining = 20 (< 8 + 20 = 28).
	// The old check (at+entry > off+size -> 128 > 220) wrongly let this pass.
	buf1 := make([]byte, 120)
	be := binary.BigEndian
	be.PutUint32(buf1[100:], 0xcafebabe)
	be.PutUint32(buf1[104:], 1)
	s1 := source.Mem("embed1", buf1)
	defer s1.Close()
	if fatMachHeadersPlausible(s1, s1.Size(), 100) {
		t.Fatal("fatMachHeadersPlausible accepted arch table extending past EOF when off > 0")
	}

	// Case 2: archOff points past remaining slice (off+archOff+24 > size), even
	// though archOff+24 <= size.
	buf2 := make([]byte, 200)
	be.PutUint32(buf2[100:], 0xcafebabe)
	be.PutUint32(buf2[104:], 1)
	be.PutUint32(buf2[108+8:], 90) // relative to off=100 -> abs 190, 190+24=214 > 200
	s2 := source.Mem("embed2", buf2)
	defer s2.Close()
	if fatMachHeadersPlausible(s2, s2.Size(), 100) {
		t.Fatal("fatMachHeadersPlausible accepted archOff extending past EOF when off > 0")
	}

	// Case 3: valid fat Mach-O embedded at off = 100 validates cleanly.
	thin := macho64WithImports([]string{"_system"})
	const archOff = 32
	fat := make([]byte, archOff+len(thin))
	be.PutUint32(fat[0:], 0xcafebabe)
	be.PutUint32(fat[4:], 1)
	be.PutUint32(fat[8:], 0x01000007)
	be.PutUint32(fat[12:], 3)
	be.PutUint32(fat[16:], archOff)
	be.PutUint32(fat[20:], uint32(len(thin)))
	be.PutUint32(fat[24:], 3)
	copy(fat[archOff:], thin)

	buf3 := append(make([]byte, 100), fat...)
	s3 := source.Mem("embed3", buf3)
	defer s3.Close()
	if _, ok := ValidateNativeHeader(s3, s3.Size(), 100); !ok {
		t.Fatal("valid embedded fat Mach-O at off=100 failed ValidateNativeHeader")
	}
}
