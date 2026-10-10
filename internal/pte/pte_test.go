package pte

import (
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func build(magic, ext string, progSize int64, seg []byte) []byte {
	b := make([]byte, 40)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 32)
	copy(b[4:], magic)
	copy(b[8:], ext)
	le.PutUint32(b[12:], 40)
	le.PutUint64(b[16:], uint64(progSize))
	if len(seg) == 0 {
		le.PutUint64(b[24:], 48)
		out := make([]byte, 48)
		copy(out, b)
		return out
	}
	le.PutUint64(b[24:], 64)
	le.PutUint64(b[32:], uint64(len(seg)))
	out := make([]byte, 64)
	copy(out, b)
	return append(out, seg...)
}

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
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", limits.Default())
	ctx := sess.NewCtx(name, limits.Default())
	s := source.Mem(name, data)
	defer s.Close()
	if err := (parser{}).Parse(ctx, s); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return c.Findings()
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestValidHeaderAndEmbeddedELF(t *testing.T) {
	fs := parse(t, "m.pte", build("ET12", "eh12", 64, tinyELF()))
	if !hasRule(fs, RuleUnverified.ID) {
		t.Fatalf("expected %s, got %v", RuleUnverified.ID, ids(fs))
	}
	if !hasRule(fs, RuleNative.ID) {
		t.Fatalf("expected %s, got %v", RuleNative.ID, ids(fs))
	}
	if hasRule(fs, RuleStruct.ID) {
		t.Fatalf("valid header reported as %s", RuleStruct.ID)
	}
}

func TestBadMagicReported(t *testing.T) {
	data := build("XX12", "eh12", 64, nil)
	fs := parse(t, "bad.pte", data)
	if !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("expected %s, got %v", RuleStruct.ID, ids(fs))
	}
}

func TestSegmentOutOfRangeReported(t *testing.T) {
	data := build("ET12", "eh12", 64, tinyELF())
	le := binary.LittleEndian
	le.PutUint64(data[24:], 1<<40) // segment base far past the file
	fs := parse(t, "oob.pte", data)
	if !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("expected %s, got %v", RuleStruct.ID, ids(fs))
	}
}

func TestSniffIsContentBased(t *testing.T) {
	data := build("ET10", "eh10", 48, nil)
	// The .ptl extension belongs to TorchScript or PyTorch Mobile; dispatch must
	// not depend on it.
	if _, ok := sniff(source.Mem("model.ptl", data), limits.Default()); !ok {
		t.Fatal("valid pte content under a .ptl name was not recognised")
	}
	if _, ok := sniff(source.Mem("model.pte", []byte("not a pte file")), limits.Default()); ok {
		t.Fatal("non-pte content was claimed")
	}
}

func TestCleanHeaderOnlyUnverified(t *testing.T) {
	fs := parse(t, "clean.pte", build("ET10", "eh10", 48, nil))
	if hasRule(fs, RuleNative.ID) || hasRule(fs, RuleStruct.ID) {
		t.Fatalf("clean pte produced %v", ids(fs))
	}
	if !hasRule(fs, RuleUnverified.ID) {
		t.Fatalf("expected %s", RuleUnverified.ID)
	}
}

func ids(fs []report.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func FuzzPTEHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add(build("ET12", "eh12", 64, tinyELF()))
	f.Add([]byte{0x20, 0, 0, 0, 'E', 'T', '1', '0'})
	f.Add([]byte("ET"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c := report.NewCollector(1000)
		sess := artifact.NewSession(c, "", limits.Default())
		ctx := sess.NewCtx("f.pte", limits.Default())
		s := source.Mem("f.pte", b)
		defer s.Close()
		_ = (parser{}).Parse(ctx, s)
		if _, ok := sniff(source.Mem("f.pte", b), limits.Default()); ok {
			_ = (parser{}).Parse(ctx, s)
		}
	})
}
