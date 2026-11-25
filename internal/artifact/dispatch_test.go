package artifact_test

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"

	// Registers the ExecuTorch content sniffer (priority 72) that owns FormatPTE
	// now that the generic offset-0 probe this package used to carry is gone.
	// Deliberately not internal/formats: this test needs only the pte sniffer,
	// and linking every format would make the table below depend on siblings'
	// sniffers.
	_ "github.com/fr0g-66723067-io/sc4n/internal/pte"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func makeTar(t *testing.T, format tar.Format, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Format:   format,
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sniff(t *testing.T, name string, b []byte) (artifact.Format, string) {
	t.Helper()
	s := source.Mem(name, b)
	defer s.Close()
	return artifact.Sniff(s, limits.Default())
}

func TestSniffByContentNotExtension(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want artifact.Format
	}{
		// A torch 7z-in-.pt: the name says checkpoint, the bytes say 7z.
		{"model.pt", []byte("7z\xbc\xaf\x27\x1caaaaaaaaaaaaaaaa"), artifact.FormatSevenZip},
		// A gzip file named .safetensors.
		{"model.safetensors", append([]byte{0x1f, 0x8b, 0x08, 0x00}, make([]byte, 32)...), artifact.FormatGzip},
		{"a.pkl", []byte("\x80\x04\x95\x00\x00"), artifact.FormatPickle},
		// Bare "GGUF" text or "TFL3" text without validated structure must not
		// be claimed by the generic magic table.
		{"gguf.txt", []byte("GGUF documentation text\n"), artifact.FormatText},
		{"tflite.txt", []byte("abcdTFL3 plain text\n"), artifact.FormatText},
		{"a.npy", append([]byte("\x93NUMPY"), 0x01, 0x00), artifact.FormatNPY},
		{"x.h5", []byte("\x89HDF\r\n\x1a\n"), artifact.FormatHDF5},
		// UBJSON has no file identifier, so a bare "UBJ" prefix is not
		// evidence of the format: only internal/xgb's walk claims a real
		// document. Text that merely begins "UBJ" is not UBJSON.
		{"x.ubj", []byte("UBJ hello world"), artifact.FormatText},
		// Real .pte shape: a root uint32 at offset 0 and "ET" + two ASCII
		// version digits at offset 4. Claimed by internal/pte's content sniffer,
		// not by any table in this package.
		{"x.pte", []byte{0x04, 0x00, 0x00, 0x00, 'E', 'T', '1', '2'}, artifact.FormatPTE},
		// Text that merely begins "ET," is not a .pte: the magic lives at
		// offset 4, so claiming it from offset 0 would dispatch ordinary text
		// to the flatbuffer parser.
		{"x.pte", []byte("ET,01234\n"), artifact.FormatText},
		// A bare ELF magic is not a validated header; the text fallback is
		// allowed to claim content that only looks like a program. The
		// polyglot layer still reports the magic-only shape.
		{"x.so", []byte("\x7fELF\x02\x01\x01"), artifact.FormatText},
		{"x.exe", []byte("MZ\x90\x00"), artifact.FormatNative},
		{"x.tar", makeTar(t, tar.FormatUSTAR, "hello.txt", []byte("hi")), artifact.FormatTar},
		{"x.bz2", []byte{'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x00}, artifact.FormatBzip2},
		{"x.xz", []byte("\xfd7zXZ\x00"), artifact.FormatXz},
		{"x.zst", []byte("\x28\xb5\x2f\xfd"), artifact.FormatZstd},
		{"x.lz4", []byte("\x04\x22\x4d\x18"), artifact.FormatLz4},
		{"x.json", []byte(`{"a": 1}`), artifact.FormatJSON},
		{"x.txt", []byte("just some plain text\n"), artifact.FormatText},
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
	if got != artifact.FormatUnknown {
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
		f    artifact.Format
		want bool
	}{
		{"model.pt", artifact.FormatSevenZip, true}, // a .pt really is sometimes a 7z
		{"model.pt", artifact.FormatNative, false},  // but never an ELF
		{"model.safetensors", artifact.FormatGzip, false},
		{"weights.bin", artifact.FormatSafetensors, true},
		{"weights.bin", artifact.FormatPickle, true},
		{"model.gguf", artifact.FormatGGUF, true},
		{"notes.unknown-ext", artifact.FormatNative, true}, // nothing to contradict
		{"noext", artifact.FormatNative, true},
		{"trailing.", artifact.FormatNative, true},
	}
	for _, tc := range cases {
		if got := artifact.ExtensionPlausible(tc.path, tc.f); got != tc.want {
			t.Errorf("ExtensionPlausible(%q, %s) = %v, want %v", tc.path, tc.f, got, tc.want)
		}
	}
}

func TestFormatTableHasNoGaps(t *testing.T) {
	seen := map[artifact.Format]bool{}
	for _, i := range artifact.AllFormats() {
		if seen[i.Format] {
			t.Fatalf("format %s appears twice", i.Format)
		}
		seen[i.Format] = true
		if i.Notes == "" {
			t.Fatalf("format %s has no capability note", i.Format)
		}
	}
	if !seen[artifact.FormatUnknown] {
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
	artifact.RegisterFormat(artifact.Info{Format: artifact.FormatUnknown, Notes: "duplicate"})
}

func TestMemberDepthBudget(t *testing.T) {
	sess := artifact.NewSession(nil, "", limits.Limits{MaxDepth: 1})
	ctx := sess.NewCtx("root", limits.Limits{MaxDepth: 1})
	child, ok := ctx.Member("a", artifact.FormatZip)
	if !ok {
		t.Fatal("first member rejected")
	}
	if _, ok := child.Member("b", artifact.FormatZip); ok {
		t.Fatal("second nested member accepted with MaxDepth 1")
	}
}

func TestFormatStringIsStable(t *testing.T) {
	if artifact.FormatSafetensors.String() != "safetensors" {
		t.Fatalf("FormatSafetensors.String() = %q", artifact.FormatSafetensors.String())
	}
	if got := artifact.Format(250).String(); got != "format(250)" {
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
		got, _ := artifact.Sniff(s, limits.Default())
		// Determinism under fuzz as well: a format that flips between runs would
		// make the report non-reproducible.
		if again, _ := artifact.Sniff(s, limits.Default()); again != got {
			t.Fatalf("Sniff is not deterministic: %s then %s", got, again)
		}
	})
}

func TestInvalidNativeMagicDoesNotSuppressTextRules(t *testing.T) {
	data := []byte("MZ instructions: import os\nos.system('id')\n")
	got, _ := sniff(t, "instructions.bin", data)
	if got != artifact.FormatText {
		t.Fatalf("MZ-prefixed instructions dispatched as %s, want text", got)
	}
}

func TestSniffBzip2ValidatesHeader(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want artifact.Format
	}{
		{"block-magic", []byte{'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59}, artifact.FormatBzip2},
		{"eos-magic", []byte{'B', 'Z', 'h', '1', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90}, artifact.FormatBzip2},
		{"bare-text", []byte("BZh9hello world plain text\n"), artifact.FormatText},
		{"bad-level", []byte{'B', 'Z', 'h', '0', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59}, artifact.FormatText},
		{"short", []byte("BZh9\x31\x41"), artifact.FormatText},
	}
	for _, tc := range cases {
		got, sn := sniff(t, tc.name, tc.data)
		if got != tc.want {
			t.Errorf("%s: Sniff = %s (%q), want %s", tc.name, got, sn, tc.want)
		}
	}
}

func TestSniffTarValidatesChecksumAndSupportsV7(t *testing.T) {
	// Valid USTAR and GNU tar archives pass checksum verification.
	for _, tc := range []struct {
		name string
		fmt  tar.Format
	}{
		{"ustar", tar.FormatUSTAR},
		{"gnu", tar.FormatGNU},
	} {
		data := makeTar(t, tc.fmt, "dir/file.txt", []byte("payload"))
		if got, _ := sniff(t, tc.name+".tar", data); got != artifact.FormatTar {
			t.Errorf("%s tar: got %s, want tar", tc.name, got)
		}
	}

	// Classic V7 tar header: bytes 257..261 all NUL, valid octal header checksum.
	v7 := make([]byte, 512)
	copy(v7[0:], "oldfile.txt")
	copy(v7[100:], "0000644\x00")
	copy(v7[108:], "0001000\x00")
	copy(v7[116:], "0001000\x00")
	copy(v7[124:], "00000000000\x00")
	copy(v7[136:], "00000000000\x00")
	v7[156] = 0 // V7 regular file
	var sum int64
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			sum += ' '
		} else {
			sum += int64(v7[i])
		}
	}
	copy(v7[148:156], fmt.Sprintf("%06o\x00 ", sum))
	if got, _ := sniff(t, "v7.tar", v7); got != artifact.FormatTar {
		t.Fatalf("V7 tar: got %s, want tar", got)
	}

	// Signed checksum convention (SunOS/V7 signed-char tar with high-bit bytes in filename).
	signedTar := make([]byte, 512)
	copy(signedTar[0:], "caf\xc3\xa9.txt")
	copy(signedTar[100:], "0000644\x00")
	copy(signedTar[124:], "00000000000\x00")
	signedTar[156] = '0'
	copy(signedTar[257:], "ustar\x00")
	var signedSum int64
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			signedSum += ' '
		} else {
			signedSum += int64(int8(signedTar[i]))
		}
	}
	copy(signedTar[148:156], fmt.Sprintf("%06o\x00 ", signedSum))
	if got, _ := sniff(t, "signed.tar", signedTar); got != artifact.FormatTar {
		t.Fatalf("signed-checksum tar: got %s, want tar", got)
	}

	// A Python/text file containing literal "ustar" at byte 257 must NOT be claimed as tar.
	py := bytes.Repeat([]byte("a"), 257)
	py = append(py, []byte("ustar")...)
	py = append(py, bytes.Repeat([]byte("b"), 300)...)
	if got, _ := sniff(t, "script.py", py); got == artifact.FormatTar {
		t.Fatalf("text with literal 'ustar' at byte 257 was misclassified as tar")
	}

	// A 512-byte zeroed block with "ustar" at 257 and no checksum must NOT be tar.
	fakeUstar := make([]byte, 512)
	copy(fakeUstar[257:], "ustar")
	if got, _ := sniff(t, "fake.bin", fakeUstar); got == artifact.FormatTar {
		t.Fatalf("zero-checksum ustar block was misclassified as tar")
	}

	// A V7-checksummed block with empty filename must NOT be claimed as tar.
	emptyV7 := make([]byte, 512)
	copy(emptyV7[100:], "0000644\x00")
	copy(emptyV7[124:], "00000000000\x00")
	emptyV7[156] = '0'
	var esum int64
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			esum += ' '
		} else {
			esum += int64(emptyV7[i])
		}
	}
	copy(emptyV7[148:156], fmt.Sprintf("%06o\x00 ", esum))
	if got, _ := sniff(t, "empty.bin", emptyV7); got == artifact.FormatTar {
		t.Fatalf("empty-name V7 block was misclassified as tar")
	}
}

func TestWeakMagicPriorityBelowStructuredSniffers(t *testing.T) {
	// Register a synthetic structured sniffer at priority 50 (msgpack's priority)
	// matching a payload that starts with the 2-byte zlib weak magic 0x78 0x9c.
	// With magic-weak lowered to 45, the priority-50 sniffer must win.
	sentinel := []byte("\x78\x9cSC4N_PRIORITY50_TEST")
	artifact.RegisterSniffer("test-prio50-probe", 50, func(s source.Source, _ limits.Limits) (artifact.Format, bool) {
		head, _ := s.Bytes(0, int64(len(sentinel)))
		if bytes.Equal(head, sentinel) {
			return artifact.FormatMsgpack, true
		}
		return artifact.FormatUnknown, false
	})
	got, sn := sniff(t, "probe.bin", sentinel)
	if got != artifact.FormatMsgpack {
		t.Fatalf("magic-weak outranked priority-50 sniffer: got %s (%q), want msgpack", got, sn)
	}
}

func TestSniffTextUTF8AndOccasionalNUL(t *testing.T) {
	// UTF-8 BOM + non-ASCII runes in the first 64 bytes with NUL + binary trailer.
	bomDoc := append([]byte("\xef\xbb\xbf# 日本語モデルカード — safe UTF-8 documentation prefix exceeding sixty-four bytes\n"), 0x00, 0xff, 0xfe)
	if got, sn := sniff(t, "README.md", bomDoc); got != artifact.FormatText && got != artifact.FormatMarkdown {
		t.Fatalf("UTF-8 BOM markdown with trailing NUL dispatched as %s (%q), want text/markdown", got, sn)
	}

	// UTF-8 Jinja template with a NUL byte inside the first 64 bytes.
	jinjaNul := []byte("\x00{% for m in messages %}日本語: {{ m['content'] }} — template body padding{% endfor %}\n")
	if got, sn := sniff(t, "chat.jinja", jinjaNul); got != artifact.FormatText && got != artifact.FormatJinja {
		t.Fatalf("UTF-8 Jinja template with leading NUL dispatched as %s (%q), want text/jinja", got, sn)
	}

	// UTF-8 markdown with a NUL byte at offset 12 inside the first 64 bytes.
	mdMidNul := []byte("# Model Card\x00 — 日本語の説明文とモデルの使い方ガイド。This card describes the checkpoint.\n")
	if got, sn := sniff(t, "card.md", mdMidNul); got != artifact.FormatText && got != artifact.FormatMarkdown {
		t.Fatalf("UTF-8 markdown with mid-prefix NUL dispatched as %s (%q), want text/markdown", got, sn)
	}

	// Binary with frequent NUL bytes must stay unclaimed.
	nulHeavy := bytes.Repeat([]byte{'A', 0x00, 'B', 0x00}, 40)
	if got, sn := sniff(t, "heavy.bin", nulHeavy); got == artifact.FormatText {
		t.Fatalf("NUL-heavy binary was claimed as text by %q", sn)
	}

	// Invalid UTF-8 bytes with a NUL must stay unclaimed.
	badUTF8 := append([]byte{0x00, 0xff, 0xfe, 0x80}, bytes.Repeat([]byte("a"), 100)...)
	if got, sn := sniff(t, "badutf8.bin", badUTF8); got == artifact.FormatText {
		t.Fatalf("invalid-UTF8 binary was claimed as text by %q", sn)
	}
}

func TestSessionIsPartialPathScoping(t *testing.T) {
	// Bare -partial filename matches direct/filesystem paths, never container members.
	s1 := artifact.NewSession(nil, "/repo", limits.Default())
	s1.SetPartial([]string{"model.onnx"})
	if !s1.IsPartial("model.onnx") {
		t.Error("expected bare model.onnx to match")
	}
	if !s1.IsPartial("/repo/model.onnx") {
		t.Error("expected /repo/model.onnx to match")
	}
	if s1.IsPartial("evil.zip:sub/model.onnx") {
		t.Error("bare -partial model.onnx must NOT match archive member evil.zip:sub/model.onnx")
	}
	if s1.IsPartial("evil.zip:model.onnx") {
		t.Error("bare -partial model.onnx must NOT match archive member evil.zip:model.onnx")
	}

	// Path-qualified -partial entry must NOT fall back to bare basename.
	s2 := artifact.NewSession(nil, "/repo", limits.Default())
	s2.SetPartial([]string{"sub/model.onnx"})
	if !s2.IsPartial("sub/model.onnx") {
		t.Error("expected sub/model.onnx to match")
	}
	if !s2.IsPartial("./sub/model.onnx") {
		t.Error("expected ./sub/model.onnx to match")
	}
	if !s2.IsPartial("/repo/sub/model.onnx") {
		t.Error("expected /repo/sub/model.onnx to match via Root")
	}
	if s2.IsPartial("other/model.onnx") {
		t.Error("sub/model.onnx must NOT match other/model.onnx")
	}
	if s2.IsPartial("model.onnx") {
		t.Error("sub/model.onnx must NOT match bare model.onnx")
	}
	if s2.IsPartial("evil.zip:sub/model.onnx") {
		t.Error("sub/model.onnx must NOT match evil.zip:sub/model.onnx")
	}

	// Absolute -partial entry matches relative path under Root.
	s3 := artifact.NewSession(nil, "/repo", limits.Default())
	s3.SetPartial([]string{"/repo/sub/model.onnx"})
	if !s3.IsPartial("sub/model.onnx") {
		t.Error("expected sub/model.onnx to match /repo/sub/model.onnx under Root")
	}
	if s3.IsPartial("other/model.onnx") {
		t.Error("/repo/sub/model.onnx must NOT match other/model.onnx")
	}
}

func TestScanMemberNilSessionEmitsLimitDepthWithoutPanic(t *testing.T) {
	c := report.NewCollector(16)
	ctx := &artifact.Ctx{
		Session: nil,
		Sink:    c.For("root.zip"),
		Limits:  limits.Limits{MaxDepth: 0},
		Depth:   2,
	}
	if _, err := artifact.ScanMemberBytes(ctx, "inner.bin", []byte("data")); err != nil {
		t.Fatalf("ScanMemberBytes returned error: %v", err)
	}
	fs := c.Findings()
	if len(fs) != 1 || fs[0].RuleID != "SC4N-LIMIT-DEPTH" {
		t.Fatalf("expected SC4N-LIMIT-DEPTH finding, got %+v", fs)
	}
}
