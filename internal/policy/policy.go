// Package policy turns a report into an exit code and applies a baseline.
//
// It is separate from cmd/sc4n so that the decision is testable without a
// subprocess, and separate from internal/report so that the report stays a pure
// data structure with no opinion about what a caller should do with it.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Codes are the documented exit codes. They are declared here rather than in the
// command so that a test can assert the contract without importing main.
const (
	CodeClean      = 0
	CodeFindings   = 1
	CodeUsage      = 2
	CodeUnreadable = 3
)

// Verdict is the exit decision plus the reason, which the command prints.
type Verdict struct {
	Code   int
	Reason string
	// Worst is the highest severity found, for the summary line.
	Worst report.Severity
	// Count is the number of findings at or above the threshold.
	Count int
}

// Decide applies the exit-code policy to a set of findings.
//
// Precedence is usage error, then unreadable scope, then findings. An unreadable
// path outranks a finding because the two mean different things — "the mount is
// missing" versus "your model is malicious" — and a CI job that cannot tell them
// apart will eventually treat one as the other.
func Decide(findings []report.Finding, failOn report.Severity, unreadable int) Verdict {
	v := Verdict{Code: CodeClean, Worst: report.SeverityInfo}
	for _, f := range findings {
		if f.Severity > v.Worst {
			v.Worst = f.Severity
		}
		if f.Severity.AtLeast(failOn) {
			v.Count++
		}
	}
	switch {
	case unreadable > 0:
		v.Code = CodeUnreadable
		v.Reason = fmt.Sprintf("%d path(s) could not be opened, so the requested scope was not fully scanned", unreadable)
	case v.Count > 0:
		v.Code = CodeFindings
		v.Reason = fmt.Sprintf("%d finding(s) at or above %s (worst: %s)", v.Count, failOn, v.Worst)
	}
	return v
}

// baselineReport is the subset of a sc4n JSON report a baseline needs. It is
// decoded into its own struct rather than into report.Report so that a baseline
// written by an older schema version still loads as long as it carries the fields
// the fingerprint needs.
type baselineReport struct {
	SchemaVersion string `json:"schemaVersion"`
	Artifacts     []struct {
		Path string `json:"path"`
	} `json:"artifacts"`
	Findings []struct {
		RuleID   string `json:"ruleId"`
		Artifact string `json:"artifact"`
		Evidence string `json:"evidence"`
	} `json:"findings"`
}

// LoadBaseline reads a previous sc4n JSON report and returns the fingerprint set
// it stands for.
//
// The fingerprint is (rule, artifact, hash of the evidence window) and
// deliberately excludes the byte offset: editing an unrelated part of a file
// shifts every later offset, and a baseline that un-suppresses on such an edit is
// worse than no baseline at all.
func LoadBaseline(path string) (map[string]bool, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc baselineReport
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil, fmt.Errorf("%s: not a sc4n JSON report: %w", path, err)
	}
	if doc.SchemaVersion == "" {
		return nil, fmt.Errorf("%s: not a sc4n JSON report (no schemaVersion)", path)
	}
	out := make(map[string]bool, len(doc.Findings))
	for _, f := range doc.Findings {
		out[report.Fingerprint(report.Finding{
			RuleID:   f.RuleID,
			Artifact: f.Artifact,
			Evidence: f.Evidence,
		})] = true
	}
	return out, nil
}

// Unsuppressed returns the findings that a baseline does not cover, plus the number
// suppressed. It exists for callers that want the split without a Collector.
func Unsuppressed(findings []report.Finding, baseline map[string]bool) ([]report.Finding, int) {
	if len(baseline) == 0 {
		return findings, 0
	}
	kept := make([]report.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if baseline[report.Fingerprint(f)] {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

// RuleCounts summarises findings by rule, worst first, for the -quiet output and
// for the summary line.
func RuleCounts(findings []report.Finding) []struct {
	Rule  string
	Count int
} {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.RuleID]++
	}
	out := make([]struct {
		Rule  string
		Count int
	}, 0, len(counts))
	for k, v := range counts {
		out = append(out, struct {
			Rule  string
			Count int
		}{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}
