package artifact

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func sniff(t *testing.T, name string, b []byte) (Format, string) {
	t.Helper()
	s := source.Mem(name, b)
	defer s.Close()
	return Sniff(s, limits.Default())
}

func TestSniffByContentNotExtension(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Format
	}{
		// A torch 7z-in-.pt: the name says checkpoint, the bytes say 7z.
		{"model.pt", []byte("7z\xbc\xaf\x27\x1caaaaaaaaaaaaaaaa"), FormatSevenZip},
		// A gzip file named .safetensors.
		{"model.safetensors", append([]byte{0x1f, 0x8b, 0x08, 0x00}, make([]byte, 32)...), FormatGzip},
		{"a.pkl", []byte("\x80\x04\x95\x00\x00"), FormatPickle},
		{"a.bin", []byte("GGUF\x03\x00\x00\x00"), FormatGGUF},
		{"a.npy", append([]byte("\x93NUMPY"), 0x01, 0x00), FormatNPY},
		{"x.h5", []byte("\x89HDF\r\n\x1a\n"), FormatHDF5},
		{"x.tflite", append([]byte{0x1c, 0x00, 0x00, 0x00}, []byte("TFL3")...), FormatTFLite},
		{"x.ubj", []byte("UBJ\x82"), FormatXGBoostUBJ},
		{"x.pte", []byte{'E', 'T', 0x00, 0x00, '1', '2', 0x00}, FormatPTE},
		{"x.so", []byte("\x7fELF\x02\x01\x01"), FormatNative},
		{"x.exe", []byte("MZ\x90\x00"), FormatNative},
		{"x.tar", append(append(make([]byte, 257), []byte("ustar")...), make([]byte, 100)...), FormatTar},
		{"x.xz", []byte("\xfd7zXZ\x00"), FormatXz},
		{"x.zst", []byte("\x28\xb5\x2f\xfd"), FormatZstd},
		{"x.lz4", []byte("\x04\x22\x4d\x18"), FormatLz4},
		{"x.json", []byte(`{"a": 1}`), FormatJSON},
		{"x.txt", []byte("just some plain text\n"), FormatText},
	}
	for _, tc := range cases {
		got, _ := sniff(t, tc.name, tc.data)
		if got != tc.want {
			t.Errorf("Sniff(%s): got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestSniffUnknownForOpqaqueBinary(t *testing.T) {
	// NUL bytes and no magic: nothing structural recognises it, and the text
	// fallback must refuse binary content rather than claim it is text.
	got, sniffer := sniff(t, "blob.bin", []byte{0x00, 0x11, 0x22, 0x00, 0x33, 0x44, 0xff, 0x00})
	if got != FormatUnknown {
		t.Fatalf("Sniff = %s (%s), want unknown", got, sniffer)
	}
}

// TestSniffIsDeterministic guards the property the whole report depends on: the
// sniffer order is a function of the registered set, not of map iteration.
func TestSniffIsDeterministic(t *testing.T) {
	data := []byte("\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00")
	first, firstSniffer := sniff(t, "a.pkl", data)
	for range 50 {
		got, sn := sniff(t, "a.pkl", data)
		if got != first || sn != firstSniffer {
			t.Fatalf("Sniff is not deterministic: %s/%s then %s/%s", first, firstSniffer, got, sn)
		}
	}
}

func TestExtensionPlausible(t *testing.T) {
	cases := []struct {
		path string
		f    Format
		want bool
	}{
		{"model.pt", FormatSevenZip, true}, // a .pt really is sometimes a 7z
		{"model.pt", FormatNative, false},  // but never an ELF
		{"model.safetensors", FormatGzip, false},
		{"weights.bin", FormatSafetensors, true},
		{"weights.bin", FormatPickle, true},
		{"model.gguf", FormatGGUF, true},
		{"notes.unknown-ext", FormatNative, true}, // nothing to contradict
		{"noext", FormatNative, true},
		{"trailing.", FormatNative, true},
	}
	for _, tc := range cases {
		if got := ExtensionPlausible(tc.path, tc.f); got != tc.want {
			t.Errorf("ExtensionPlausible(%q, %s) = %v, want %v", tc.path, tc.f, got, tc.want)
		}
	}
}

func TestFormatTableHasNoGaps(t *testing.T) {
	seen := map[Format]bool{}
	for _, i := range AllFormats() {
		if seen[i.Format] {
			t.Fatalf("format %s appears twice", i.Format)
		}
		seen[i.Format] = true
		if i.Notes == "" {
			t.Fatalf("format %s has no capability note", i.Format)
		}
	}
	if !seen[FormatUnknown] {
		t.Fatal("FormatUnknown must be described so `sc4n formats` explains what an unmatched file gets")
	}
}

// TestRegisterFormatRejectsDuplicate pins the safety property: a forgotten Format
// field collides with the explicit FormatUnknown row rather than silently
// attaching capability text to the wrong format.
func TestRegisterFormatRejectsDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("RegisterFormat accepted a duplicate")
		}
	}()
	RegisterFormat(Info{Format: FormatUnknown, Notes: "duplicate"})
}

func TestMemberDepthBudget(t *testing.T) {
	sess := NewSession(nil, "", limits.Limits{MaxDepth: 1})
	ctx := sess.NewCtx("root", limits.Limits{MaxDepth: 1})
	child, ok := ctx.Member("a", FormatZip)
	if !ok {
		t.Fatal("first member rejected")
	}
	if _, ok := child.Member("b", FormatZip); ok {
		t.Fatal("second nested member accepted with MaxDepth 1")
	}
}

func TestFormatStringIsStable(t *testing.T) {
	if FormatSafetensors.String() != "safetensors" {
		t.Fatalf("FormatSafetensors.String() = %q", FormatSafetensors.String())
	}
	if got := Format(250).String(); got != "format(250)" {
		t.Fatalf("unregistered format renders as %q", got)
	}
}

func FuzzSniffNeverPanics(f *testing.F) {
	seeds := [][]byte{
		[]byte("\x80\x04\x95\x00\x00"),
		[]byte("GGUF\x03"),
		[]byte("PK\x03\x04"),
		[]byte("\x93NUMPY\x01\x00"),
		[]byte("\x1f\x8b\x08"),
		[]byte("ET12h"),
		{0x00, 0x01, 0x02},
		[]byte("ustar"),
		[]byte(`{"a":`),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s := source.Mem("fuzz", data)
		defer s.Close()
		got, _ := Sniff(s, limits.Default())
		// Determinism under fuzz as well: a format that flips between runs would
		// make the report non-reproducible.
		if again, _ := Sniff(s, limits.Default()); again != got {
			t.Fatalf("Sniff is not deterministic: %s then %s", got, again)
		}
	})
}
