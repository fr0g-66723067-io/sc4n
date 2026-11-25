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
	fs := run(t, "lib.so", data, artifact.FormatNative, 0)
	got := ids(fs)
	if !got["SC4N-PICKLE-GLOBAL-CRITICAL"] || !got["SC4N-POLYGLOT-CONTAINER"] {
		t.Fatalf("an appended zip was not dispatched as a container; findings=%v", got)
	}
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-GLOBAL-CRITICAL" {
			wantArtifact := "lib.so:!zip:archive/data.pkl"
			if f.Artifact != wantArtifact {
				t.Fatalf("appended zip member artifact = %q, want %q", f.Artifact, wantArtifact)
			}
		}
	}
}

func TestAppendedZipEmitsLimitDepthWhenExhausted(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "a.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := append(tinyELF(), buf.Bytes()...)

	c := report.NewCollector(4096)
	l := limits.Default()
	l.MaxDepth = 0
	sess := artifact.NewSession(c, "", l)
	ctx := sess.NewCtx("lib.so", l)
	s := source.Mem("lib.so", data)
	defer s.Close()
	Scan(ctx, s, artifact.FormatNative)

	got := ids(c.Findings())
	if !got["SC4N-LIMIT-DEPTH"] {
		t.Fatalf("exhausted MaxDepth on appended zip did not emit SC4N-LIMIT-DEPTH; findings=%v", got)
	}
	if !got["SC4N-POLYGLOT-CONTAINER"] {
		t.Fatalf("appended zip did not emit SC4N-POLYGLOT-CONTAINER; findings=%v", got)
	}
}

func TestEmbeddedExecutableSpanningWindowBoundaryIsValidated(t *testing.T) {
	// Place a valid ELF header inside the head window whose program-header table
	// sits past WindowBytes: truncated window validation would fail, while full
	// source validation via ValidateNativeHeader succeeds.
	const elfStart = WindowBytes - 128
	const phOff = 256 // relative to elfStart -> absolute WindowBytes + 128
	const elfLen = phOff + 56
	data := deterministicNoise(elfStart + elfLen)

	elfBytes := data[elfStart : elfStart+elfLen]
	for i := range elfBytes {
		elfBytes[i] = 0
	}
	copy(elfBytes, "\x7fELF")
	elfBytes[4] = 2
	elfBytes[5] = 1
	elfBytes[6] = 1
	le := binary.LittleEndian
	le.PutUint16(elfBytes[16:], 3)
	le.PutUint16(elfBytes[18:], 0x3e)
	le.PutUint32(elfBytes[20:], 1)
	le.PutUint64(elfBytes[32:], phOff)
	le.PutUint16(elfBytes[52:], 64)
	le.PutUint16(elfBytes[54:], 56)
	le.PutUint16(elfBytes[56:], 1)
	le.PutUint16(elfBytes[58:], 64)
	ph := elfBytes[phOff:]
	le.PutUint32(ph[0:], 1)
	le.PutUint32(ph[4:], 5)
	le.PutUint64(ph[32:], elfLen)
	le.PutUint64(ph[40:], elfLen)
	le.PutUint64(ph[48:], 0x1000)

	fs := run(t, "model.safetensors", data, artifact.FormatSafetensors, 0)
	found := false
	for _, f := range fs {
		if f.RuleID == "SC4N-POLYGLOT-NATIVE" && f.Offset == elfStart {
			found = true
		}
	}
	if !found {
		t.Fatalf("embedded ELF spanning head window boundary at %d was missed; findings=%v", elfStart, ids(fs))
	}
}

func elfWithDynSyms(names []string) []byte {
	var strtab bytes.Buffer
	strtab.WriteByte(0)
	offs := make([]uint32, len(names))
	for i, n := range names {
		offs[i] = uint32(strtab.Len())
		strtab.WriteString(n)
		strtab.WriteByte(0)
	}
	strBytes := strtab.Bytes()
	symCount := 1 + len(names) // entry 0 is STN_UNDEF
	symBytes := make([]byte, symCount*24)
	le := binary.LittleEndian
	for i, off := range offs {
		ent := symBytes[(i+1)*24:]
		le.PutUint32(ent[0:], off)
		ent[4] = (1 << 4) | 2    // STB_GLOBAL | STT_FUNC
		le.PutUint16(ent[6:], 0) // SHN_UNDEF
	}

	const ehSize = 64
	strOff := ehSize
	symOff := (strOff + len(strBytes) + 7) &^ 7
	shOff := (symOff + len(symBytes) + 7) &^ 7
	const shNum = 3 // NULL, .dynstr, .dynsym
	total := shOff + shNum*64
	b := make([]byte, total)
	copy(b, "\x7fELF")
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // ELFDATA2LSB
	b[6] = 1 // EV_CURRENT
	le.PutUint16(b[16:], 3)
	le.PutUint16(b[18:], 0x3e)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[40:], uint64(shOff))
	le.PutUint16(b[52:], ehSize)
	le.PutUint16(b[58:], 64)
	le.PutUint16(b[60:], shNum)
	le.PutUint16(b[62:], 0) // SHN_UNDEF shstrndx

	copy(b[strOff:], strBytes)
	copy(b[symOff:], symBytes)

	// Section 1: .dynstr (SHT_STRTAB = 3)
	sh1 := b[shOff+64:]
	le.PutUint32(sh1[4:], 3)
	le.PutUint64(sh1[24:], uint64(strOff))
	le.PutUint64(sh1[32:], uint64(len(strBytes)))

	// Section 2: .dynsym (SHT_DYNSYM = 11), linked to section 1
	sh2 := b[shOff+128:]
	le.PutUint32(sh2[4:], 11)
	le.PutUint64(sh2[24:], uint64(symOff))
	le.PutUint64(sh2[32:], uint64(len(symBytes)))
	le.PutUint32(sh2[40:], 1) // sh_link = .dynstr
	le.PutUint64(sh2[56:], 24)
	return b
}

func peWithImports(dll string, names []string) []byte {
	const (
		peOff      = 0x40
		optOff     = peOff + 4 + 20
		optSize    = 240
		secHdrOff  = optOff + optSize
		rawDataOff = 0x200
		secRVA     = 0x1000
		rawDataSz  = 0x400
	)
	b := make([]byte, rawDataOff+rawDataSz)
	copy(b[0:], "MZ")
	le := binary.LittleEndian
	le.PutUint32(b[0x3c:], peOff)
	copy(b[peOff:], "PE\x00\x00")
	le.PutUint16(b[peOff+4:], 0x8664) // AMD64
	le.PutUint16(b[peOff+6:], 1)      // NumberOfSections
	le.PutUint16(b[peOff+20:], optSize)
	le.PutUint16(b[peOff+22:], 0x0002)

	// OptionalHeader64
	le.PutUint16(b[optOff:], 0x020b) // PE32+
	le.PutUint32(b[optOff+108:], 16) // NumberOfRvaAndSizes
	// DataDirectory[1] = Import Table
	le.PutUint32(b[optOff+112+8:], secRVA)
	le.PutUint32(b[optOff+112+12:], 40)

	// SectionHeader ".idata"
	copy(b[secHdrOff:], ".idata\x00\x00")
	le.PutUint32(b[secHdrOff+8:], rawDataSz)
	le.PutUint32(b[secHdrOff+12:], secRVA)
	le.PutUint32(b[secHdrOff+16:], rawDataSz)
	le.PutUint32(b[secHdrOff+20:], rawDataOff)

	// Import directory inside .idata
	sec := b[rawDataOff:]
	iltRel := uint32(0x40)
	dllRel := uint32(0x100)
	ibnRel := uint32(0x140)
	le.PutUint32(sec[0:], secRVA+iltRel)  // OriginalFirstThunk
	le.PutUint32(sec[12:], secRVA+dllRel) // Name
	le.PutUint32(sec[16:], secRVA+iltRel) // FirstThunk
	copy(sec[dllRel:], dll+"\x00")

	cur := ibnRel
	for i, n := range names {
		le.PutUint64(sec[iltRel+uint32(i)*8:], uint64(secRVA+cur))
		le.PutUint16(sec[cur:], 0)
		copy(sec[cur+2:], n+"\x00")
		cur += uint32(2 + len(n) + 1)
		if cur%2 != 0 {
			cur++
		}
	}
	return b
}

func macho64WithImports(names []string) []byte {
	var strtab bytes.Buffer
	strtab.WriteByte(0)
	offs := make([]uint32, len(names))
	for i, n := range names {
		offs[i] = uint32(strtab.Len())
		strtab.WriteString(n)
		strtab.WriteByte(0)
	}
	strBytes := strtab.Bytes()
	const (
		hdrSize = 32
		cmdSize = 24
		symOff  = 64
	)
	strOff := symOff + len(names)*16
	b := make([]byte, strOff+len(strBytes))
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(b[4:], 0x01000007) // CPU_TYPE_X86_64
	le.PutUint32(b[8:], 3)
	le.PutUint32(b[12:], 2) // MH_EXECUTE
	le.PutUint32(b[16:], 1) // ncmds
	le.PutUint32(b[20:], cmdSize)

	// LC_SYMTAB (cmd = 2, len = 24)
	le.PutUint32(b[32:], 2)
	le.PutUint32(b[36:], cmdSize)
	le.PutUint32(b[40:], symOff)
	le.PutUint32(b[44:], uint32(len(names)))
	le.PutUint32(b[48:], uint32(strOff))
	le.PutUint32(b[52:], uint32(len(strBytes)))

	for i, off := range offs {
		ent := b[symOff+i*16:]
		le.PutUint32(ent[0:], off)
		ent[4] = 0x01 // N_EXT | N_UNDF
		ent[5] = 0    // NO_SECT
	}
	copy(b[strOff:], strBytes)
	return b
}

func TestExecImportNamesELFPEAndMachO(t *testing.T) {
	elfBin := elfWithDynSyms([]string{"printf", "memfd_create", "posix_spawnp", "posix_spawn", "execvpe", "fexecve"})
	sElf := source.Mem("a.so", elfBin)
	defer sElf.Close()
	gotElf := ExecImportNames(sElf, sElf.Size(), 0)
	wantElf := []string{"execvpe", "fexecve", "memfd_create", "posix_spawn", "posix_spawnp"}
	if strings.Join(gotElf, ",") != strings.Join(wantElf, ",") {
		t.Fatalf("ELF ExecImportNames = %v, want %v", gotElf, wantElf)
	}

	peBin := peWithImports("KERNEL32.dll", []string{
		"ExitProcess", "URLDownloadToFileW", "VirtualAllocEx",
		"LoadLibraryA", "ShellExecuteExA", "WinExec", "CreateProcessW",
	})
	sPE := source.Mem("a.exe", peBin)
	defer sPE.Close()
	gotPE := ExecImportNames(sPE, sPE.Size(), 0)
	wantPE := []string{"CreateProcessW", "LoadLibraryA", "ShellExecuteExA", "URLDownloadToFileW", "VirtualAllocEx", "WinExec"}
	if strings.Join(gotPE, ",") != strings.Join(wantPE, ",") {
		t.Fatalf("PE ExecImportNames = %v, want %v", gotPE, wantPE)
	}

	machBin := macho64WithImports([]string{"_printf", "_posix_spawnp", "_dlopen", "_system", "_posix_spawn"})
	sMach := source.Mem("a.dylib", machBin)
	defer sMach.Close()
	gotMach := ExecImportNames(sMach, sMach.Size(), 0)
	wantMach := []string{"_dlopen", "_posix_spawn", "_posix_spawnp", "_system"}
	if strings.Join(gotMach, ",") != strings.Join(wantMach, ",") {
		t.Fatalf("Mach-O ExecImportNames = %v, want %v", gotMach, wantMach)
	}

	// Fat Mach-O wrapping the thin binary.
	const archOff = 32
	fat := make([]byte, archOff+len(machBin))
	be := binary.BigEndian
	be.PutUint32(fat[0:], 0xcafebabe)
	be.PutUint32(fat[4:], 1)
	be.PutUint32(fat[8:], 0x01000007)
	be.PutUint32(fat[12:], 3)
	be.PutUint32(fat[16:], archOff)
	be.PutUint32(fat[20:], uint32(len(machBin)))
	be.PutUint32(fat[24:], 3)
	copy(fat[archOff:], machBin)
	sFat := source.Mem("uni.dylib", fat)
	defer sFat.Close()
	gotFat := ExecImportNames(sFat, sFat.Size(), 0)
	if strings.Join(gotFat, ",") != strings.Join(wantMach, ",") {
		t.Fatalf("Fat Mach-O ExecImportNames = %v, want %v", gotFat, wantMach)
	}
}
