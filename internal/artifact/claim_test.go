package artifact_test

import (
	"bytes"
	"compress/zlib"
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

// TestWeakMagicDoesNotOutrankAModel pins the zlib/lzma magic demotion. A
// safetensors file's first eight bytes are a little-endian header length, the
// official writer pads the header to a multiple of 8, and a header of 376, 40056 or
// 55928 bytes puts 78 01, 78 9c or 78 da at offset 0 — the zlib magic. Claimed at
// the magic sniffer's priority, such a file was dispatched as zlib: two medium
// findings about a zlib stream that was not there, and *no* SC4N-SAFETENSORS-* at
// all, because the parser that understands the file never ran.
func TestWeakMagicDoesNotOutrankAModel(t *testing.T) {
	body := []byte(`{"__metadata__":{"format":"pt"},"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}`)
	for len(body) < 376 {
		body = append(body, ' ')
	}
	if len(body) != 0x178 || body[0] != '{' {
		t.Fatalf("fixture header is %d bytes, want 376", len(body))
	}
	sf := append([]byte{0x78, 0x01, 0, 0, 0, 0, 0, 0}, body...)
	sf = append(sf, make([]byte, 8)...)
	got, sniffer := artifact.Sniff(source.Mem("model.safetensors", sf), limits.Default())
	if got != artifact.FormatSafetensors {
		t.Fatalf("a safetensors file whose header length starts 78 01 dispatched as %v (by %q); the "+
			"weak magic must not outrank a structured format", got, sniffer)
	}

	// The demotion must not cost the weak magics their own files: a real zlib stream
	// still dispatches as zlib, below every structured sniffer and above the text
	// fallback.
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte("{\"a\": 1}")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got, _ := artifact.Sniff(source.Mem("blob.bin", buf.Bytes()), limits.Default()); got != artifact.FormatZlib {
		t.Fatalf("a real zlib stream dispatched as %v, want zlib", got)
	}
}

// TestLeadingContainerMagic is the predicate the pickle sniffer consults before
// claiming a stream found behind a prefix: a file that opens with a magic a
// container parser unwraps is that container, not a prefixed pickle, even when the
// container's bytes carry a pickle verbatim (zlib's stored blocks do).
func TestLeadingContainerMagic(t *testing.T) {
	yes := [][]byte{
		[]byte("PK\x03\x04"), []byte("\x1f\x8b\x08"), []byte("\x78\x9c"), []byte("\x78\x01"),
		[]byte("\x78\xda"), []byte("BZh9"), []byte("\xfd7zXZ\x00"), []byte("\x5d\x00\x00"),
		[]byte("\x04\x22\x4d\x18"), []byte("\x28\xb5\x2f\xfd"), []byte("7z\xbc\xaf\x27\x1c"),
		[]byte("Rar!\x1a\x07"),
	}
	for _, b := range yes {
		if !artifact.LeadingContainerMagic(b) {
			t.Errorf("LeadingContainerMagic(%q) = false, want true", b)
		}
	}
	no := [][]byte{
		[]byte("\x80\x04"), []byte("junk"), []byte("MZ"), []byte("\x7fELF"),
		[]byte(`{"a": 1}`), nil,
	}
	for _, b := range no {
		if artifact.LeadingContainerMagic(b) {
			t.Errorf("LeadingContainerMagic(%q) = true, want false", b)
		}
	}
}
