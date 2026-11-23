package imgmeta

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func TestMetadataSummaryUsesOneAllocation(t *testing.T) {
	kinds := make([]string, 100)
	for i := range kinds {
		kinds[i] = "tEXt"
	}
	got := joinKinds(kinds)
	if !strings.Contains(got, "(92 more)") {
		t.Fatalf("kind summary = %q", got)
	}
}

func TestOversizedPngTextIsCappedAndReported(t *testing.T) {
	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	im := &image{ctx: sess.NewCtx("x.png", l)}
	got := im.capBytes(0, "test", make([]byte, maxMetaBlob+1))
	if len(got) != maxMetaBlob {
		t.Fatalf("capped %d bytes, want %d", len(got), maxMetaBlob)
	}
	if len(c.Findings()) == 0 {
		t.Fatal("cap was silent")
	}
}
