package numpy

import (
	"archive/zip"
	"bytes"
	"sort"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func makeZip(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(members[n]); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func parseNPZ(t *testing.T, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	lim := limits.Default()
	sess := artifact.NewSession(c, "", lim)
	ctx := &artifact.Ctx{Session: sess, Sink: c.For("a.npz"), Limits: lim, Format: artifact.FormatNPZ}
	src := source.Mem("a.npz", data)
	defer src.Close()
	if err := (npzParser{}).Parse(ctx, src); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c.Findings()
}

func TestNPZDispatchesNpyMembers(t *testing.T) {
	gadget := []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85,
		0x52,
		0x2e,
	}
	obj := npyV1("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", gadget)
	good := npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (2,)}", make([]byte, 16))
	z := makeZip(t, map[string][]byte{"obj.npy": obj, "good.npy": good})
	fs := parseNPZ(t, z)
	want(t, fs, []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL"}, nil)
}

func TestNPZBenignIsClean(t *testing.T) {
	good := npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (2,)}", make([]byte, 16))
	z := makeZip(t, map[string][]byte{"good.npy": good})
	fs := parseNPZ(t, z)
	want(t, fs, nil, []string{"SC4N-NUMPY-STRUCT", "SC4N-NUMPY-OBJECT-ARRAY"})
}

func TestSniffNPZ(t *testing.T) {
	good := npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (1,)}", make([]byte, 8))
	z := makeZip(t, map[string][]byte{"good.npy": good})
	src := source.Mem("a.npz", z)
	defer src.Close()
	if f, ok := sniffNPZ(src, limits.Default()); !ok || f != artifact.FormatNPZ {
		t.Fatalf("sniffNPZ = %v,%v; want npz,true", f, ok)
	}
	// A zip with no .npy member is not an npz.
	other := makeZip(t, map[string][]byte{"readme.txt": []byte("hello")})
	src2 := source.Mem("b.zip", other)
	defer src2.Close()
	if _, ok := sniffNPZ(src2, limits.Default()); ok {
		t.Fatal("sniffNPZ claimed a zip with no .npy member")
	}
}
