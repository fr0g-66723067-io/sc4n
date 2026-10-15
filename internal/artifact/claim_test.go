package artifact_test

import (
	"bytes"
	"testing"

	// Imported for their inits: internal/formats pulls in every parser package,
	// which is what registers the real sniffer set (internal/content's text
	// classifier, internal/polyglot's native-header validator) that the CLI runs.
	// A test with only artifact's built-in sniffers would assert a registry the
	// binary does not use.
	_ "github.com/fr0g-66723067-io/sc4n/internal/formats"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// TestSniffClaimsTextWithAppendedNUL pins the fix for a silent miss: a text
// document with a NUL appended used to be dispatched "unknown", and an artifact
// with no format has no parser and no indicator pass, so a config.json plus one
// NUL byte produced an empty finding list — a clean-looking result for a file
// nothing had read.
func TestSniffClaimsTextWithAppendedNUL(t *testing.T) {
	doc := []byte("{\n  \"model_type\": \"llama\",\n  \"auto_map\": {\"AutoModel\": \"modeling_x.M\"}\n}")
	if got, _ := artifact.Sniff(source.Mem("config.json", doc), limits.Default()); got != artifact.FormatJSON {
		t.Fatalf("unpadded document dispatching as %v, want json", got)
	}
	padded := append(append([]byte{}, doc...), 0)
	got, sniffer := artifact.Sniff(source.Mem("config.json", padded), limits.Default())
	if got != artifact.FormatText {
		t.Fatalf("NUL-padded document dispatched as %v (by %q), want text so the content layer "+
			"reports SC4N-CONTENT-NOT-UTF8 and still runs the byte-safe indicators", got, sniffer)
	}
	// The boundary: a prefix shorter than minTextPrefix is not evidence of a
	// document, so it stays unclaimed and nothing is reported for it.
	short := append(bytes.Repeat([]byte("x"), 8), 0)
	if got, _ := artifact.Sniff(source.Mem("short.bin", short), limits.Default()); got != artifact.FormatUnknown {
		t.Fatalf("8-byte prefix: dispatched as %v, want unknown", got)
	}
}

// TestSniffLeavesBinaryUnknown pins the other half of the contract: an artifact
// that is binary from the start must stay unclaimed, because the content layer
// would otherwise run prose-shaped rules over a symbol table and manufacture
// findings. The noise is the same PRNG stream internal/polyglot's benign test uses.
func TestSniffLeavesBinaryUnknown(t *testing.T) {
	b := make([]byte, 2048)
	state := uint32(0x1234567)
	for i := range b {
		state = state*1664525 + 1013904223
		b[i] = byte(state >> 24)
	}
	if got, _ := artifact.Sniff(source.Mem("random.bin", b), limits.Default()); got != artifact.FormatUnknown {
		t.Fatalf("random bytes dispatched as %v, want unknown", got)
	}
}

// TestSniffBareNativeMagicIsNotAClaim pins the second silent miss: a native magic
// that does not validate is a two-byte prefix, not a program. Dispatching on it
// meant the format parser never ran on the file, so "MZ" in front of a chat
// template or a config.json hid everything the format's own rules would report.
func TestSniffBareNativeMagicIsNotAClaim(t *testing.T) {
	tmpl := []byte("{% for m in messages %}{{ m.__class__ }}{% endfor %}\n")
	prefixed := append([]byte("MZ"), tmpl...)
	got, sniffer := artifact.Sniff(source.Mem("chat.jinja", prefixed), limits.Default())
	if got == artifact.FormatNative {
		t.Fatalf("a bare MZ prefix was claimed as native by %q", sniffer)
	}
	if got != artifact.FormatJinja && got != artifact.FormatText {
		t.Fatalf("MZ-prefixed template dispatched as %v, want a text format", got)
	}
	// With nothing else to claim it, the bare magic is still the dispatch: the
	// universal layer reports it as a magic-only polyglot rather than dropping it.
	binary := append([]byte("MZ"), bytes.Repeat([]byte{0x00, 0x11, 0x22}, 40)...)
	if got, _ := artifact.Sniff(source.Mem("thing.bin", binary), limits.Default()); got != artifact.FormatNative {
		t.Fatalf("bare magic with no other claim dispatched as %v, want native", got)
	}
	// A Java class file shares the FAT_MAGIC prefix and is not a program either;
	// it must not be announced as a validated executable.
	class := append([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x41"), bytes.Repeat([]byte{0x0a, 0x00}, 40)...)
	if got, _ := artifact.Sniff(source.Mem("Thing.class", class), limits.Default()); got != artifact.FormatNative {
		t.Fatalf("class file dispatched as %v, want native (bare magic, unclaimed)", got)
	}
}
