package polyglot

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
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
