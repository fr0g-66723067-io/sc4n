package native

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/polyglot"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// tinyELF builds the smallest ELF64 header+program-header that Go's debug/elf
// accepts, with no dependency on a host file.
func tinyELF() []byte {
	b := make([]byte, 64+56)
	copy(b, "\x7fELF")
	b[4] = 2
	b[5] = 1
	b[6] = 1
	le := binary.LittleEndian
	le.PutUint16(b[16:], 3)
	le.PutUint16(b[18:], 0x3e)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], 64)
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 1)
	le.PutUint16(b[58:], 64)
	ph := b[64:]
	le.PutUint32(ph[0:], 1)
	le.PutUint32(ph[4:], 5)
	le.PutUint64(ph[32:], uint64(len(b)))
	le.PutUint64(ph[40:], uint64(len(b)))
	le.PutUint64(ph[48:], 0x1000)
	return b
}

func parse(t *testing.T, name string, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(4096)
	sess := artifact.NewSession(c, "", limits.Default())
	ctx := sess.NewCtx(name, limits.Default())
	ctx.Format = artifact.FormatNative
	s := source.Mem(name, data)
	defer s.Close()
	if err := (parser{}).Parse(ctx, s); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c.Findings()
}

func byID(fs []report.Finding) map[string][]report.Finding {
	out := map[string][]report.Finding{}
	for _, f := range fs {
		out[f.RuleID] = append(out[f.RuleID], f)
	}
	return out
}

func TestNativeValidAndEmbeddedPayload(t *testing.T) {
	outer := tinyELF()
	data := append(append([]byte{}, outer...), tinyELF()...)
	got := byID(parse(t, "native_embedded.so", data))
	if len(got["SC4N-NATIVE-VALID"]) != 1 {
		t.Fatalf("expected exactly one SC4N-NATIVE-VALID, got %v", got)
	}
	emb := got["SC4N-NATIVE-EMBEDDED-PAYLOAD"]
	if len(emb) != 1 {
		t.Fatalf("expected one embedded payload finding, got %v", got)
	}
	if emb[0].Offset != int64(len(outer)) {
		t.Fatalf("embedded payload offset = %d, want %d", emb[0].Offset, len(outer))
	}
}

func TestNativeSingleExecutableHasNoEmbeddedFinding(t *testing.T) {
	got := byID(parse(t, "lib.so", tinyELF()))
	if len(got["SC4N-NATIVE-VALID"]) != 1 {
		t.Fatalf("expected SC4N-NATIVE-VALID, got %v", got)
	}
	if len(got["SC4N-NATIVE-EMBEDDED-PAYLOAD"]) != 0 {
		t.Fatalf("a single ELF must not report an embedded payload: %v", got)
	}
}

func TestNativeIndicatorScanOverHeadWindow(t *testing.T) {
	// A raw-IP URL appended to the executable must reach the shared indicator
	// engine, which is what makes an embedded binary's obvious strings visible.
	data := append(tinyELF(), []byte("\nhttp://10.0.0.7/payload\n")...)
	got := byID(parse(t, "lib.so", data))
	if len(got["SC4N-STRING-RAW-IP-URL"]) == 0 {
		t.Fatalf("the indicator engine did not report a raw-IP URL in the head window: %v", got)
	}
}

func TestNativeMalformedHeaderIsSilent(t *testing.T) {
	// The invalid-magic case is the polyglot layer's SC4N-POLYGLOT-MAGIC-ONLY; the
	// native parser itself must not claim a valid executable.
	data := append([]byte("\x7fELF"), make([]byte, 200)...)
	got := byID(parse(t, "fake.so", data))
	if len(got["SC4N-NATIVE-VALID"]) != 0 || len(got["SC4N-NATIVE-EMBEDDED-PAYLOAD"]) != 0 {
		t.Fatalf("a malformed header must not be reported as valid: %v", got)
	}
}

func TestNativeEmbeddedPayloadSpanningWindowBoundary(t *testing.T) {
	const innerOff = polyglot.WindowBytes - 128
	const phOff = 256
	const innerLen = phOff + 56
	data := make([]byte, innerOff+innerLen)
	copy(data, tinyELF())

	inner := data[innerOff : innerOff+innerLen]
	copy(inner, "\x7fELF")
	inner[4] = 2
	inner[5] = 1
	inner[6] = 1
	le := binary.LittleEndian
	le.PutUint16(inner[16:], 3)
	le.PutUint16(inner[18:], 0x3e)
	le.PutUint32(inner[20:], 1)
	le.PutUint64(inner[32:], phOff)
	le.PutUint16(inner[52:], 64)
	le.PutUint16(inner[54:], 56)
	le.PutUint16(inner[56:], 1)
	le.PutUint16(inner[58:], 64)
	ph := inner[phOff:]
	le.PutUint32(ph[0:], 1)
	le.PutUint32(ph[4:], 5)
	le.PutUint64(ph[32:], innerLen)
	le.PutUint64(ph[40:], innerLen)
	le.PutUint64(ph[48:], 0x1000)

	got := byID(parse(t, "dropper.so", data))
	emb := got["SC4N-NATIVE-EMBEDDED-PAYLOAD"]
	if len(emb) != 1 || emb[0].Offset != innerOff {
		t.Fatalf("expected embedded payload at %d, got %+v", innerOff, emb)
	}
}

func TestNativeExecImportsPEAndMachO(t *testing.T) {
	// Minimal PE32+ importing CreateProcessA and URLDownloadToFileA.
	const (
		peOff      = 0x40
		optOff     = peOff + 4 + 20
		optSize    = 240
		secHdrOff  = optOff + optSize
		rawDataOff = 0x200
		secRVA     = 0x1000
		rawDataSz  = 0x300
	)
	peBin := make([]byte, rawDataOff+rawDataSz)
	copy(peBin[0:], "MZ")
	le := binary.LittleEndian
	le.PutUint32(peBin[0x3c:], peOff)
	copy(peBin[peOff:], "PE\x00\x00")
	le.PutUint16(peBin[peOff+4:], 0x8664)
	le.PutUint16(peBin[peOff+6:], 1)
	le.PutUint16(peBin[peOff+20:], optSize)
	le.PutUint16(peBin[peOff+22:], 0x0002)
	le.PutUint16(peBin[optOff:], 0x020b)
	le.PutUint32(peBin[optOff+108:], 16)
	le.PutUint32(peBin[optOff+112+8:], secRVA)
	le.PutUint32(peBin[optOff+112+12:], 40)
	copy(peBin[secHdrOff:], ".idata\x00\x00")
	le.PutUint32(peBin[secHdrOff+8:], rawDataSz)
	le.PutUint32(peBin[secHdrOff+12:], secRVA)
	le.PutUint32(peBin[secHdrOff+16:], rawDataSz)
	le.PutUint32(peBin[secHdrOff+20:], rawDataOff)
	sec := peBin[rawDataOff:]
	le.PutUint32(sec[0:], secRVA+0x40)
	le.PutUint32(sec[12:], secRVA+0x100)
	le.PutUint32(sec[16:], secRVA+0x40)
	copy(sec[0x100:], "KERNEL32.dll\x00")
	le.PutUint64(sec[0x40:], secRVA+0x140)
	copy(sec[0x142:], "URLDownloadToFileA\x00")
	le.PutUint64(sec[0x48:], secRVA+0x160)
	copy(sec[0x162:], "CreateProcessA\x00")

	gotPE := byID(parse(t, "dropper.exe", peBin))
	if len(gotPE["SC4N-NATIVE-VALID"]) != 1 {
		t.Fatalf("PE missing SC4N-NATIVE-VALID: %+v", gotPE)
	}
	if len(gotPE["SC4N-NATIVE-EXEC-IMPORTS"]) != 1 || gotPE["SC4N-NATIVE-EXEC-IMPORTS"][0].Extra["symbols"] != "CreateProcessA,URLDownloadToFileA" {
		t.Fatalf("PE SC4N-NATIVE-EXEC-IMPORTS = %+v, want CreateProcessA,URLDownloadToFileA", gotPE["SC4N-NATIVE-EXEC-IMPORTS"])
	}

	// Minimal 64-bit Mach-O importing _posix_spawn and _system.
	var strtab bytes.Buffer
	strtab.WriteByte(0)
	o1 := uint32(strtab.Len())
	strtab.WriteString("_system\x00")
	o2 := uint32(strtab.Len())
	strtab.WriteString("_posix_spawn\x00")
	strBytes := strtab.Bytes()
	const symOff = 64
	strOff := symOff + 2*16
	machBin := make([]byte, strOff+len(strBytes))
	le.PutUint32(machBin[0:], 0xfeedfacf)
	le.PutUint32(machBin[4:], 0x01000007)
	le.PutUint32(machBin[8:], 3)
	le.PutUint32(machBin[12:], 2)
	le.PutUint32(machBin[16:], 1)
	le.PutUint32(machBin[20:], 24)
	le.PutUint32(machBin[32:], 2) // LC_SYMTAB
	le.PutUint32(machBin[36:], 24)
	le.PutUint32(machBin[40:], symOff)
	le.PutUint32(machBin[44:], 2)
	le.PutUint32(machBin[48:], uint32(strOff))
	le.PutUint32(machBin[52:], uint32(len(strBytes)))
	le.PutUint32(machBin[symOff:], o1)
	machBin[symOff+4] = 0x01
	le.PutUint32(machBin[symOff+16:], o2)
	machBin[symOff+20] = 0x01
	copy(machBin[strOff:], strBytes)

	gotMach := byID(parse(t, "dropper.dylib", machBin))
	if len(gotMach["SC4N-NATIVE-VALID"]) != 1 {
		t.Fatalf("Mach-O missing SC4N-NATIVE-VALID: %+v", gotMach)
	}
	if len(gotMach["SC4N-NATIVE-EXEC-IMPORTS"]) != 1 || gotMach["SC4N-NATIVE-EXEC-IMPORTS"][0].Extra["symbols"] != "_posix_spawn,_system" {
		t.Fatalf("Mach-O SC4N-NATIVE-EXEC-IMPORTS = %+v, want _posix_spawn,_system", gotMach["SC4N-NATIVE-EXEC-IMPORTS"])
	}
}
