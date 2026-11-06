package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Verdict values. The order of the decisions is documented on Row.classify and
// matters: a row can be both invalid (the oracle rejected it) and lack an
// expected rule, and "invalid" is the honest answer because nothing was proven.
const (
	verdictExpected    = "expected"
	verdictGap         = "gap"
	verdictExtra       = "extra"
	verdictInvalid     = "invalid"
	verdictUnavailable = "unavailable"
)

// Row is one mutator's result: what the oracle said about the mutant and what
// the scanner said about the same bytes.
type Row struct {
	Operator   string   `json:"operator"`
	Mutant     string   `json:"mutant,omitempty"`
	Format     string   `json:"format,omitempty"`
	Valid      bool     `json:"valid"`
	OracleNote string   `json:"oracleNote,omitempty"`
	Sc4n       sc4nOut  `json:"sc4n"`
	Expected   []string `json:"expected,omitempty"`
	Forbidden  []string `json:"forbidden,omitempty"`
	// Baseline is the rule set the *unmutated* seed already produced. It exists
	// because a seed is a real artifact and carries its own findings: the graphs
	// profile's only loadable seed is a published lab model with a custom domain
	// and a model-local function, and a row that treated those as "unexpected"
	// would report the seed instead of the mutation.
	Baseline []string `json:"baseline,omitempty"`
	Verdict  string   `json:"verdict"`

	// highUndeclared lists the high and critical rule IDs that fired. Unexported
	// so it stays out of matrix.json; classify compares it with the declared sets.
	highUndeclared []string
}

// sc4nOut is the scanner's answer for one mutant, reduced to what the
// expectation table talks about.
type sc4nOut struct {
	MaxSeverity  string   `json:"maxSeverity"`
	FindingCount int      `json:"findingCount"`
	Rules        []string `json:"rules"`
}

// scanOutcome folds a scan result into the row.
//
// The artifact may be a member of a container, so the finding artifact is not
// compared against the mutant path: a row is about the mutant and everything
// inside it.
func (r *Row) scanOutcome(findings []report.Finding, art report.ArtifactSummary) {
	seen := make(map[string]bool, len(findings))
	seenHigh := make(map[string]bool, len(findings))
	var rules []string
	worst := report.SeverityInfo
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			rules = append(rules, f.RuleID)
		}
		if f.Severity > worst {
			worst = f.Severity
		}
		if f.Severity >= report.SeverityHigh && !seenHigh[f.RuleID] {
			seenHigh[f.RuleID] = true
			r.highUndeclared = append(r.highUndeclared, f.RuleID)
		}
	}
	sort.Strings(rules)
	if rules == nil {
		rules = []string{}
	}
	r.Format = art.Format
	if art.Error != "" && r.Format == "" {
		r.Format = "error"
	}
	r.Sc4n = sc4nOut{
		MaxSeverity:  severityName(worst, len(findings) > 0),
		FindingCount: len(findings),
		Rules:        rules,
	}
}

func severityName(s report.Severity, any bool) string {
	if !any {
		return ""
	}
	return s.String()
}

// classify decides the verdict.
//
//  1. unavailable — the oracle's Available() failed (already set).
//  2. invalid     — the oracle rejected the mutant (already set).
//  3. gap         — an expected rule did not fire.
//  4. extra       — a forbidden rule fired, or a high/critical fired that the
//     row did not declare.
//  5. expected    — otherwise.
//
// Only the *set* of rule IDs is compared, not their offsets: the lab asks
// whether the scanner reports a construct, and the offset is the scanner's own
// statement about where it found it.
func (r *Row) classify() {
	if r.Verdict == verdictUnavailable || r.Verdict == verdictInvalid {
		return
	}
	have := make(map[string]bool, len(r.Sc4n.Rules))
	for _, id := range r.Sc4n.Rules {
		have[id] = true
	}
	for _, id := range r.Expected {
		if !have[id] {
			r.Verdict = verdictGap
			return
		}
	}
	for _, id := range r.Forbidden {
		if have[id] {
			r.Verdict = verdictExtra
			return
		}
	}
	declared := make(map[string]bool, len(r.Expected)+len(r.Forbidden)+len(r.Baseline))
	for _, id := range r.Expected {
		declared[id] = true
	}
	for _, id := range r.Forbidden {
		declared[id] = true
	}
	for _, id := range r.Baseline {
		declared[id] = true
	}
	// An undeclared high or critical is the interesting direction: a real loader
	// accepts the artifact and the scanner says something the plan did not
	// predict. Lower severities are recorded in the row and never fail the run,
	// because the containers profile legitimately produces infos beside its
	// mediums.
	for _, f := range r.highUndeclared {
		if !declared[f] {
			r.Verdict = verdictExtra
			return
		}
	}
	r.Verdict = verdictExpected
}

// Summary is the count block at the end of matrix.json.
type Summary struct {
	Rows        int `json:"rows"`
	Valid       int `json:"valid"`
	Expected    int `json:"expected"`
	Gap         int `json:"gap"`
	Extra       int `json:"extra"`
	Invalid     int `json:"invalid"`
	Unavailable int `json:"unavailable"`
}

type oracle struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
}

type matrix struct {
	Tool    string  `json:"tool"`
	Profile string  `json:"profile"`
	Seed    int64   `json:"seed"`
	Oracle  oracle  `json:"oracle"`
	Rows    []Row   `json:"rows"`
	Summary Summary `json:"summary"`
}

func summarise(rows []Row) Summary {
	var s Summary
	s.Rows = len(rows)
	for _, r := range rows {
		if r.Valid {
			s.Valid++
		}
		switch r.Verdict {
		case verdictExpected:
			s.Expected++
		case verdictGap:
			s.Gap++
		case verdictExtra:
			s.Extra++
		case verdictInvalid:
			s.Invalid++
		case verdictUnavailable:
			s.Unavailable++
		}
	}
	return s
}

// writeMatrix writes matrix.json and matrix.md. Both are replaced atomically:
// a reader that samples the file mid-run must not see a half-written table.
func writeMatrix(out string, m matrix) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, "matrix.json"), append(b, '\n')); err != nil {
		return err
	}
	return writeFile(filepath.Join(out, "matrix.md"), []byte(m.markdown()))
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// markdown renders the human table: one row per operator, then every row whose
// verdict is a defect.
func (m matrix) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# sc4nlab — %s profile\n\n", m.Profile)
	fmt.Fprintf(&b, "seed %d, oracle %s (available: %t)\n\n", m.Seed, m.Oracle.Name, m.Oracle.Available)
	b.WriteString("| operator | valid | sc4n max | rules | expected | verdict |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range m.Rows {
		rules := "—"
		if len(r.Sc4n.Rules) > 0 {
			rules = strings.Join(r.Sc4n.Rules, ", ")
		}
		exp := "—"
		if len(r.Expected) > 0 {
			exp = strings.Join(r.Expected, ", ")
		}
		max := r.Sc4n.MaxSeverity
		if max == "" {
			max = "—"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n",
			r.Operator, validWord(r.Valid), max, codeOrDash(rules), codeOrDash(exp), r.Verdict)
	}
	var defects []Row
	for _, r := range m.Rows {
		if r.Verdict == verdictGap || r.Verdict == verdictExtra {
			defects = append(defects, r)
		}
	}
	if len(defects) > 0 {
		b.WriteString("\n## gaps\n\n")
		for _, r := range defects {
			fmt.Fprintf(&b, "- `%s` (%s): expected %v, forbidden %v, sc4n reported %v\n",
				r.Operator, r.Verdict, r.Expected, r.Forbidden, r.Sc4n.Rules)
		}
	}
	fmt.Fprintf(&b, "\n%d rows, %d valid, %d expected, %d gap, %d extra, %d invalid, %d unavailable.\n",
		m.Summary.Rows, m.Summary.Valid, m.Summary.Expected, m.Summary.Gap,
		m.Summary.Extra, m.Summary.Invalid, m.Summary.Unavailable)
	return b.String()
}

func codeOrDash(s string) string {
	if s == "—" || s == "" {
		return "—"
	}
	return "`" + s + "`"
}
