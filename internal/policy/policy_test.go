package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func finding(rule string, sev report.Severity, artifact, evidence string) report.Finding {
	return report.Finding{RuleID: rule, Severity: sev, Artifact: artifact, Evidence: evidence}
}

func TestDecidePrecedence(t *testing.T) {
	cases := []struct {
		name       string
		findings   []report.Finding
		failOn     report.Severity
		unreadable int
		want       int
	}{
		{"clean", nil, report.SeverityHigh, 0, CodeClean},
		{"info only", []report.Finding{finding("R", report.SeverityInfo, "a", "e")}, report.SeverityHigh, 0, CodeClean},
		{"medium below threshold", []report.Finding{finding("R", report.SeverityMedium, "a", "e")}, report.SeverityHigh, 0, CodeClean},
		{"high at threshold", []report.Finding{finding("R", report.SeverityHigh, "a", "e")}, report.SeverityHigh, 0, CodeFindings},
		{"medium at a lowered threshold", []report.Finding{finding("R", report.SeverityMedium, "a", "e")}, report.SeverityMedium, 0, CodeFindings},
		{"unreadable outranks findings", []report.Finding{finding("R", report.SeverityCritical, "a", "e")}, report.SeverityHigh, 1, CodeUnreadable},
		{"unreadable alone", nil, report.SeverityHigh, 2, CodeUnreadable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Decide(tc.findings, tc.failOn, tc.unreadable)
			if v.Code != tc.want {
				t.Fatalf("Decide = %d (%s), want %d", v.Code, v.Reason, tc.want)
			}
			if v.Code != CodeClean && v.Reason == "" {
				t.Fatal("a non-clean verdict must carry a reason")
			}
		})
	}
}

func TestDecideCountsOnlyAtOrAboveThreshold(t *testing.T) {
	fs := []report.Finding{
		finding("A", report.SeverityCritical, "x", "1"),
		finding("B", report.SeverityLow, "x", "2"),
		finding("C", report.SeverityHigh, "x", "3"),
	}
	v := Decide(fs, report.SeverityHigh, 0)
	if v.Count != 2 {
		t.Fatalf("Count = %d, want 2", v.Count)
	}
	if v.Worst != report.SeverityCritical {
		t.Fatalf("Worst = %s", v.Worst)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	c := report.NewCollector(0)
	s := c.For("dir/model.pkl")
	r := report.DefineRule(report.Rule{
		ID: "SC4N-TEST-BASELINE", Title: "t", Severity: report.SeverityHigh,
		Confidence: report.ConfidenceHigh, Class: "test", Description: "d",
	})
	s.Emit(r, 10, "payload here")
	s.Emit(r, 99, "another payload")

	rep := report.Build(report.Tool{Name: "sc4n", Version: "t"}, "", nil, c, report.Limits{}, nil, 0)
	path := filepath.Join(t.TempDir(), "base.json")
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	base, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(base) != 2 {
		t.Fatalf("baseline has %d fingerprints, want 2", len(base))
	}

	// The same findings, with the offsets shifted as if unrelated bytes had been
	// inserted earlier in the file. Both must still be suppressed.
	shifted := []report.Finding{
		finding(r.ID, report.SeverityHigh, "dir/model.pkl", "payload here"),
		finding(r.ID, report.SeverityHigh, "dir/model.pkl", "another payload"),
	}
	kept, suppressed := Unsuppressed(shifted, base)
	if len(kept) != 0 || suppressed != 2 {
		t.Fatalf("kept %d, suppressed %d; want 0, 2", len(kept), suppressed)
	}

	// A genuinely new finding is not suppressed.
	kept, suppressed = Unsuppressed(append(shifted, finding(r.ID, report.SeverityHigh, "dir/other.pkl", "third")), base)
	if len(kept) != 1 || suppressed != 2 {
		t.Fatalf("kept %d, suppressed %d; want 1, 2", len(kept), suppressed)
	}
}

func TestBaselineRejectsNonReports(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"notjson.json": "hello",
		"empty.json":   "{}",
		"array.json":   "[]",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBaseline(p); err == nil {
			t.Fatalf("LoadBaseline accepted %s", name)
		}
	}
	if _, err := LoadBaseline(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("LoadBaseline accepted a missing file")
	}
}

func TestRuleCountsOrdersByCountThenName(t *testing.T) {
	fs := []report.Finding{
		finding("B", report.SeverityHigh, "x", "1"),
		finding("A", report.SeverityHigh, "x", "2"),
		finding("A", report.SeverityHigh, "x", "3"),
		finding("C", report.SeverityHigh, "x", "4"),
	}
	got := RuleCounts(fs)
	if len(got) != 3 || got[0].Rule != "A" || got[0].Count != 2 {
		t.Fatalf("RuleCounts = %+v", got)
	}
	if got[1].Rule != "B" || got[2].Rule != "C" {
		t.Fatalf("ties are not broken by name: %+v", got)
	}
}
