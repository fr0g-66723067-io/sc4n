package polyglot

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// tinyELF builds the smallest ELF64 header+program-header that Go's debug/elf
// accepts. It is the "validated native header" the tests need, and it uses no host
// file so the test is reproducible anywhere.
func tinyELF() []byte {
	b := make([]byte, 64+56)
	copy(b, "\x7fELF")
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // ELFDATA2LSB
	b[6] = 1 // EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], 3)    // e_type ET_DYN
	le.PutUint16(b[18:], 0x3e) // e_machine x86-64
	le.PutUint32(b[20:], 1)    // e_version
	le.PutUint64(b[32:], 64)   // e_phoff
	le.PutUint16(b[52:], 64)   // e_ehsize
	le.PutUint16(b[54:], 56)   // e_phentsize
	le.PutUint16(b[56:], 1)    // e_phnum
	le.PutUint16(b[58:], 64)   // e_shentsize
	ph := b[64:]
	le.PutUint32(ph[0:], 1)               // p_type PT_LOAD
	le.PutUint32(ph[4:], 5)               // p_flags
	le.PutUint64(ph[32:], uint64(len(b))) // p_filesz
	le.PutUint64(ph[40:], uint64(len(b))) // p_memsz
	le.PutUint64(ph[48:], 0x1000)         // p_align
	return b
}

// safetensorsWithELF builds a conforming safetensors header (8-byte LE header
// length, space-padded JSON, tensor byte buffer) whose tensor body carries a
// validated ELF in the middle. It is the "model file that is also an executable"
// shape.
func safetensorsWithELF() []byte {
	header := []byte(`{"t":{"dtype":"F32","shape":[40],"data_offsets":[0,160]}}`)
	for len(header)%8 != 0 {
		header = append(header, ' ')
	}
	data := make([]byte, 160)
	// Put the ELF at a non-zero, mid-body offset.
	off := 16
	copy(data[off:], tinyELF())

	var buf bytes.Buffer
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(header)))
	buf.Write(n[:])
	buf.Write(header)
	buf.Write(data)
	return buf.Bytes()
}

// deterministicNoise produces pseudo-random bytes with a fixed seed.
func deterministicNoise(n int) []byte {
	b := make([]byte, n)
	state := uint32(0x1234567)
	for i := range b {
		state = state*1664525 + 1013904223
		b[i] = byte(state >> 24)
	}
	return b
}

// zipWithTarAnchor builds a real zip whose 232-byte member name places the tar
// ustar magic at file offset 257, so the bytes are a valid zip and carry the tar
// header anchor. archive/zip reads it; the tar anchor is where a container
// polyglot hides a second header.
func zipWithTarAnchor() []byte {
	const nameLen = 232
	name := make([]byte, nameLen)
	for i := range name {
		name[i] = 'a'
	}
	copy(name[227:], "ustar")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: string(name), Method: zip.Store})
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte("sc4n polyglot zip+tar fixture")); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func run(t *testing.T, name string, data []byte, f artifact.Format, depth int) []report.Finding {
	t.Helper()
	c := report.NewCollector(4096)
	sess := artifact.NewSession(c, "", limits.Default())
	ctx := sess.NewCtx(name, limits.Default())
	ctx.Depth = depth
	s := source.Mem(name, data)
	defer s.Close()
	Scan(ctx, s, f)
	return c.Findings()
}

func ids(fs []report.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.RuleID] = true
	}
	return out
}

func TestValidatedNativeInSafetensorsIsReported(t *testing.T) {
	got := ids(run(t, "model.safetensors", safetensorsWithELF(), artifact.FormatSafetensors, 0))
	if !got["SC4N-POLYGLOT-NATIVE"] {
		t.Fatalf("a validated ELF inside a safetensors artifact was not reported; findings=%v", got)
	}
	if got["SC4N-POLYGLOT-MAGIC-ONLY"] {
		t.Fatalf("a validated header must not also be reported as magic-only; findings=%v", got)
	}
}

func TestLeadingValidatedNativeIsReported(t *testing.T) {
	// A file dispatched as something else that actually begins with an ELF.
	got := ids(run(t, "weights.bin", tinyELF(), artifact.FormatSafetensors, 0))
	if !got["SC4N-POLYGLOT-NATIVE"] {
		t.Fatalf("a leading validated native header was not reported; findings=%v", got)
	}
}

func TestMagicWithoutValidHeaderIsInfoOnly(t *testing.T) {
	// "\x7fELF" followed by zeros: the magic is there, the header is not.
	data := append([]byte("\x7fELF"), make([]byte, 200)...)
	got := ids(run(t, "polyglot_magic_only.bin", data, artifact.FormatNative, 0))
	if !got["SC4N-POLYGLOT-MAGIC-ONLY"] {
		t.Fatalf("a bare native magic was not reported; findings=%v", got)
	}
	if got["SC4N-POLYGLOT-NATIVE"] {
		t.Fatalf("an unvalidated magic must not be reported as a native executable; findings=%v", got)
	}
}

func TestValidNativeArtifactIsNotPolyglot(t *testing.T) {
	// The native parser owns a native artifact; the universal layer must not also
	// call its own header a polyglot finding.
	got := ids(run(t, "lib.so", tinyELF(), artifact.FormatNative, 0))
	if got["SC4N-POLYGLOT-NATIVE"] || got["SC4N-POLYGLOT-MAGIC-ONLY"] {
		t.Fatalf("a valid native artifact must not be reported by the polyglot layer; findings=%v", got)
	}
}

func TestBenignRandomBytesAreClean(t *testing.T) {
	data := deterministicNoise(2048)
	if bytes.Contains(data, []byte("ustar")) {
		t.Fatal("fixture noise accidentally carries the tar anchor")
	}
	got := ids(run(t, "random.bin", data, artifact.FormatUnknown, 0))
	if len(got) != 0 {
		t.Fatalf("random bytes produced findings: %v", got)
	}
}

func TestContainerPolyglotZipTar(t *testing.T) {
	z := zipWithTarAnchor()
	if string(z[257:262]) != "ustar" {
		t.Fatalf("fixture construction is wrong: %q", z[257:262])
	}
	got := ids(run(t, "polyglot_zip_tar.zip", z, artifact.FormatZip, 0))
	if !got["SC4N-POLYGLOT-CONTAINER"] {
		t.Fatalf("a zip that is also a tar was not reported; findings=%v", got)
	}
}

func TestPlainContainerIsNotPolyglot(t *testing.T) {
	z := zipWithTarAnchor()
	z = z[:257] // truncate before the tar anchor
	got := ids(run(t, "plain.zip", z, artifact.FormatZip, 0))
	if got["SC4N-POLYGLOT-CONTAINER"] {
		t.Fatalf("a single-container file must not be reported; findings=%v", got)
	}
}

func TestExtensionMismatchAtTopLevelOnly(t *testing.T) {
	got := ids(run(t, "model.safetensors", zipWithTarAnchor(), artifact.FormatZip, 0))
	if !got["SC4N-FORMAT-EXTENSION-MISMATCH"] {
		t.Fatalf("a .safetensors that is a zip was not reported; findings=%v", got)
	}
	// The same bytes as a nested member must not re-report the signal.
	got = ids(run(t, "model.bin", zipWithTarAnchor(), artifact.FormatZip, 1))
	if got["SC4N-FORMAT-EXTENSION-MISMATCH"] {
		t.Fatalf("the mismatch must fire only at Depth 0; findings=%v", got)
	}
	// A plausible extension is silent.
	got = ids(run(t, "archive.zip", zipWithTarAnchor(), artifact.FormatZip, 0))
	if got["SC4N-FORMAT-EXTENSION-MISMATCH"] {
		t.Fatalf("a .zip that is a zip must not be reported; findings=%v", got)
	}
}

func TestUnknownFormatIsNotAnExtensionMismatch(t *testing.T) {
	got := ids(run(t, "weights.bin", deterministicNoise(2048), artifact.FormatUnknown, 0))
	if got["SC4N-FORMAT-EXTENSION-MISMATCH"] {
		t.Fatalf("an unidentified artifact must not be reported as a mismatch; findings=%v", got)
	}
}

func TestShebangOnlyForNonTextFormats(t *testing.T) {
	script := []byte("#!/bin/sh\necho hi\n")
	got := ids(run(t, "payload.bin", script, artifact.FormatUnknown, 0))
	if !got["SC4N-POLYGLOT-SHEBANG"] {
		t.Fatalf("a shebang at the head of a binary artifact was not reported; findings=%v", got)
	}
	for _, f := range []artifact.Format{artifact.FormatPython, artifact.FormatText, artifact.FormatMarkdown} {
		got = ids(run(t, "setup.py", script, f, 0))
		if got["SC4N-POLYGLOT-SHEBANG"] {
			t.Fatalf("a shebang in a %s file must not be reported; findings=%v", f, got)
		}
	}
}

func TestTailWindowIsScanned(t *testing.T) {
	// An ELF appended more than 1 MiB in, so only the tail window can see it.
	data := deterministicNoise(2 * WindowBytes)
	copy(data[len(data)-len(tinyELF()):], tinyELF())
	got := ids(run(t, "big.bin", data, artifact.FormatSafetensors, 0))
	if !got["SC4N-POLYGLOT-NATIVE"] {
		t.Fatalf("a validated ELF in the tail window was not reported; findings=%v", got)
	}
}

func TestNoWholeFileScan(t *testing.T) {
	// An ELF buried strictly in the middle (beyond head and tail windows) is out
	// of scope by design: the layer must stay bounded. This asserts the bound is
	// the documented one so a later change that starts scanning the whole file
	// fails loudly.
	middle := 2 * WindowBytes
	data := deterministicNoise(4 * WindowBytes)
	copy(data[middle:], tinyELF())
	got := ids(run(t, "huge.bin", data, artifact.FormatSafetensors, 0))
	if got["SC4N-POLYGLOT-NATIVE"] {
		t.Fatalf("a middle-of-file payload was reported, so the layer scans the whole file; findings=%v", got)
	}
}

func TestEvidenceIsBounded(t *testing.T) {
	for _, f := range run(t, "model.safetensors", safetensorsWithELF(), artifact.FormatSafetensors, 0) {
		if len(f.Evidence) > 256 {
			t.Fatalf("evidence exceeds 256 bytes: %q", f.Evidence)
		}
		if strings.Contains(f.Evidence, "\n") {
			t.Fatalf("evidence must be single-line: %q", f.Evidence)
		}
	}
}

// TestMagicWindowsNeverOverlap pins the window bound. The tail range is
// [size-WindowBytes, size) and the head's is [0, WindowBytes), so below two
// windows the tail is a subset of the head: emitting it scanned the same bytes
// twice and reported every indicator in the overlap once per window at the same
// offset — a 1.5 MiB native artifact with one webhook produced two identical
// SC4N-STRING-C2 findings. At exactly two windows the two are disjoint and the
// tail is still needed, so the bound is "at least two windows", not "more than".
func TestMagicWindowsNeverOverlap(t *testing.T) {
	sizes := []int64{
		0, 1, WindowBytes - 1, WindowBytes, WindowBytes + 1,
		2*WindowBytes - 1, 2 * WindowBytes, 2*WindowBytes + 1,
	}
	for _, size := range sizes {
		src := source.Mem("w.bin", deterministicNoise(int(size)))
		ws := MagicWindows(src, size)
		src.Close()
		var ranges [][2]int64
		for _, w := range ws {
			ranges = append(ranges, [2]int64{w.Base, w.Base + int64(len(w.Data))})
		}
		for i := range ranges {
			for j := i + 1; j < len(ranges); j++ {
				if ranges[i][0] < ranges[j][1] && ranges[j][0] < ranges[i][1] {
					t.Errorf("size %d: windows %v overlap", size, ranges)
				}
			}
		}
	}

	// The second window of an exactly-two-window artifact must still be scanned:
	// an ELF at the very end is reported.
	data := deterministicNoise(2 * WindowBytes)
	copy(data[len(data)-len(tinyELF()):], tinyELF())
	got := ids(run(t, "two.bin", data, artifact.FormatSafetensors, 0))
	if !got["SC4N-POLYGLOT-NATIVE"] {
		t.Fatalf("the second window of a two-window artifact was not scanned; findings=%v", got)
	}
}

func TestAppendedZipAfterValidNativeIsScanned(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "archive/data.pkl", Method: zip.Deflate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("cos\nsystem\n(S'id'\ntR.")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := append(tinyELF(), buf.Bytes()...)
	got := ids(run(t, "lib.so", data, artifact.FormatNative, 0))
	if !got["SC4N-PICKLE-GLOBAL-CRITICAL"] || !got["SC4N-POLYGLOT-CONTAINER"] {
		t.Fatalf("an appended zip was not dispatched as a container; findings=%v", got)
	}
}
