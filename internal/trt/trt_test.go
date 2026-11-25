package trt

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

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

func passed(t *testing.T, data []byte) bool {
	t.Helper()
	s := source.Mem("e.engine", data)
	defer s.Close()
	f, ok := sniff(s, limits.Default())
	if !ok || f != artifact.FormatTRTEngine {
		t.Fatalf("sniff = %v, %v", f, ok)
	}
	return true
}

func TestSniff(t *testing.T) {
	passed(t, []byte("ftrt\x00\x00\x00\x00"))
	if _, ok := sniff(source.Mem("x", []byte("ftr")), limits.Default()); ok {
		t.Fatal("three bytes sniffed as an engine")
	}
	if _, ok := sniff(source.Mem("x", []byte("FTrt\x00\x00\x00\x00")), limits.Default()); ok {
		t.Fatal("case-folded magic sniffed as an engine")
	}
}

func TestParseReportsUnverified(t *testing.T) {
	fs := parse(t, "e.engine", []byte("ftrt\x00\x00\x00\x00"))
	var got *report.Finding
	for i := range fs {
		if fs[i].RuleID == RuleUnverified.ID {
			got = &fs[i]
		}
	}
	if got == nil {
		t.Fatalf("no %s in %v", RuleUnverified.ID, fs)
	}
	if got.Extra["head_bytes"] != "8" {
		t.Errorf("head_bytes = %q", got.Extra["head_bytes"])
	}
	if got.Extra["tail_bytes"] != "0" {
		t.Errorf("tail_bytes = %q, want 0 when engine fits inside headWindow", got.Extra["tail_bytes"])
	}
}

// A large engine exercises the two-window path: a reachable indicator in the
// head is reported, a marker in the middle of the weight region is not, and a
// marker in the tail is.
func TestWindows(t *testing.T) {
	data := make([]byte, 8<<20)
	copy(data, "ftrt\x00\x00\x00\x00")
	copy(data[1024:], "hooks.slack.com/services/T/B/X")
	copy(data[5<<20:], "discord.com/api/webhooks")
	copy(data[len(data)-1024:], "api.telegram.org")
	fs := parse(t, "big.engine", data)
	var head, mid, tail bool
	for _, f := range fs {
		if f.RuleID == "SC4N-STRING-C2" {
			switch {
			case f.Offset == 1024:
				head = true
			case f.Offset == 5<<20:
				mid = true
			case f.Offset >= int64(len(data))-1024:
				tail = true
			}
		}
	}
	if !head {
		t.Error("indicator at offset 1024 in the head window was not reported")
	}
	if mid {
		t.Error("indicator at offset 5 MiB was reported; the weight region must stay out of scope")
	}
	if !tail {
		t.Error("indicator in the tail window was not reported")
	}
}

func TestNoDuplicateFindingsOnOverlappingSize(t *testing.T) {
	// A 2 MiB engine fits inside headWindow (4 MiB); clamping tailOff to headLen
	// guarantees no duplicate findings from overlapping head and tail windows.
	data := make([]byte, 2<<20)
	copy(data, "ftrt\x00\x00\x00\x00")
	copy(data[(2<<20)-512:], "https://hooks.slack.com/services/T/B/X")
	fs := parse(t, "mid.engine", data)
	c2 := 0
	for _, f := range fs {
		if f.RuleID == "SC4N-STRING-C2" {
			c2++
		}
	}
	if c2 != 1 {
		t.Fatalf("2 MiB engine emitted %d SC4N-STRING-C2 findings, want 1: %v", c2, fs)
	}
}

func TestShortFile(t *testing.T) {
	fs := parse(t, "tiny.engine", []byte("ftrt"))
	if len(fs) != 1 || fs[0].RuleID != RuleUnverified.ID {
		t.Fatalf("findings = %v", fs)
	}
}
