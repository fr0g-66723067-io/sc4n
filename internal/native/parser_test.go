package native

import (
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
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
