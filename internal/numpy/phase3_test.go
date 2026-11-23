package numpy

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestNPZSpillFailureStillScansReadPrefix(t *testing.T) {
	payload := append([]byte("cos\nsystem\n(S'id'\ntR."), make([]byte, 10<<10)...)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "a.npy", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	l := limits.Default()
	l.MaxStringBlob = 64
	l.MaxSpillBytes = 8
	l.MaxRatio = 0
	col := report.NewCollector(0)
	sess := artifact.NewSession(col, "", l)
	ctx := sess.NewCtx("a.npz", l)
	src := source.Mem("a.npz", buf.Bytes())
	defer src.Close()
	ms, err := archive.Collect(src, l)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms.Members) != 1 {
		t.Fatalf("members = %d", len(ms.Members))
	}
	dispatchMember(ctx, src, ms.Members[0], l.MaxStringBlob)
	got := map[string]bool{}
	for _, f := range col.Findings() {
		got[f.RuleID] = true
	}
	if !got["SC4N-LIMIT-SPILL"] || !got["SC4N-PICKLE-GLOBAL-CRITICAL"] {
		t.Fatalf("spill refusal dropped the read prefix; findings=%v", col.Findings())
	}
}
