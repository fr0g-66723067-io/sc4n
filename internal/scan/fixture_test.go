package scan_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	// Registers every format parser with internal/artifact.
	_ "github.com/fr0g-66723067-io/sc4n/internal/formats"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

const fixtureRoot = "../../testdata/fixtures"

type expectation struct {
	Expect []string `json:"expect"`
	Forbid []string `json:"forbid"`
	Notes  string   `json:"notes"`
}

type expectationFile struct {
	Version  int                    `json:"version"`
	Fixtures map[string]expectation `json:"fixtures"`
	Benign   map[string]expectation `json:"benign"`
}

func loadExpectations(t *testing.T) expectationFile {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join(fixtureRoot, "expectations.json"))
	if err != nil {
		t.Fatalf("read expectations: %v", err)
	}
	var ef expectationFile
	if err := json.Unmarshal(blob, &ef); err != nil {
		t.Fatalf("parse expectations: %v", err)
	}
	if ef.Version != 1 {
		t.Fatalf("expectations version = %d", ef.Version)
	}
	return ef
}

// scanPaths runs the engine over the given paths and returns the findings.
func scanPaths(t *testing.T, paths ...string) []report.Finding {
	t.Helper()
	res, err := scan.Run(context.Background(), scan.Config{
		Paths:  paths,
		Limits: limits.Default(),
	})
	if err != nil {
		t.Fatalf("scan %v: %v", paths, err)
	}
	return res.Collector.Findings()
}

func ids(fs []report.Finding) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		out[f.RuleID] = true
	}
	return out
}

// TestFixtureExpectations is the rule-coverage gate: for every fixture with a
// contract, the scanner's rule set must be a superset of `expect` and disjoint from
// `forbid`.
func TestFixtureExpectations(t *testing.T) {
	ef := loadExpectations(t)
	all := map[string]expectation{}
	for k, v := range ef.Fixtures {
		all[k] = v
	}
	for k, v := range ef.Benign {
		all[k] = v
	}

	// Every fixture on disk must have a contract, so a new fixture cannot be added
	// without stating what it is for.
	err := filepath.WalkDir(fixtureRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == "expectations.json" {
			return nil
		}
		rel, rerr := filepath.Rel(fixtureRoot, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if _, ok := all[rel]; !ok {
			t.Errorf("fixture %s has no entry in expectations.json", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}

	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, rel := range keys {
		exp := all[rel]
		path := filepath.Join(fixtureRoot, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expectation for %s but the fixture is missing: %v", rel, err)
			continue
		}
		t.Run(rel, func(t *testing.T) {
			got := ids(scanPaths(t, path))
			var missing []string
			for _, want := range exp.Expect {
				if !got[want] {
					missing = append(missing, want)
				}
			}
			if len(missing) > 0 {
				have := make([]string, 0, len(got))
				for id := range got {
					have = append(have, id)
				}
				sort.Strings(have)
				t.Fatalf("%s: missing %v; findings were %v\nnotes: %s", rel, missing, have, exp.Notes)
			}
			var forbidden []string
			for _, no := range exp.Forbid {
				if got[no] {
					forbidden = append(forbidden, no)
				}
			}
			if len(forbidden) > 0 {
				t.Fatalf("%s: reported %v, which the contract forbids\nnotes: %s", rel, forbidden, exp.Notes)
			}
		})
	}
}

// TestBenignFixturesAreClean is the false-positive gate. A scanner that fires on a
// real-structure torch state dict is not usable as a CI gate, so this is an
// assertion about the whole benign set at once rather than per file.
func TestBenignFixturesAreClean(t *testing.T) {
	benign := filepath.Join(fixtureRoot, "benign")
	if _, err := os.Stat(benign); err != nil {
		t.Skip("no benign corpus")
	}
	findings := scanPaths(t, benign)
	var bad []string
	for _, f := range findings {
		if f.Severity.AtLeast(report.SeverityHigh) {
			bad = append(bad, f.Severity.String()+" "+f.RuleID+" "+f.Artifact+" "+f.Evidence)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("benign corpus produced %d high/critical finding(s):\n%s", len(bad), strings.Join(bad, "\n"))
	}
	// Informational findings are allowed on a benign artifact (a legitimate chat
	// template is still worth telling the reader about), but they must be
	// reported, so this is where a reviewer looks when the count changes.
	if len(findings) > 0 {
		t.Logf("benign corpus produced %d informational finding(s), which the gate allows", len(findings))
	}
}

// TestDeterministicOutput hashes the JSON of two runs over the whole corpus and
// asserts equality. This is the property a CI gate needs: two runs of the same
// commit must not produce a diff.
func TestDeterministicOutput(t *testing.T) {
	render := func() string {
		res, err := scan.Run(context.Background(), scan.Config{
			Paths:  []string{fixtureRoot},
			Limits: limits.Default(),
			Jobs:   4,
		})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		rep := report.Build(report.Tool{Name: "sc4n", Version: "test"}, "", res.Artifacts, res.Collector, report.Limits{}, nil, 0)
		var buf bytes.Buffer
		if err := rep.WriteJSON(&buf); err != nil {
			t.Fatalf("write JSON: %v", err)
		}
		return buf.String()
	}
	a := render()
	b := render()
	if a != b {
		t.Fatalf("two runs differ:\n--- first ---\n%s\n--- second ---\n%s", a, b)
	}
	if !strings.Contains(a, "SC4N-PICKLE") {
		t.Fatalf("the corpus scan produced no pickle finding, so the determinism check proved nothing")
	}
}

// TestEveryFindingNamesARegisteredRule is the bridge between the fixture corpus and
// the rule catalogue: a finding whose rule is not registered would be dropped by
// GitHub code scanning and would have no severity in `sc4n rules`.
func TestEveryFindingNamesARegisteredRule(t *testing.T) {
	findings := scanPaths(t, fixtureRoot)
	if len(findings) == 0 {
		t.Fatal("no findings in the corpus")
	}
	for _, f := range findings {
		if _, ok := report.RuleByID(f.RuleID); !ok {
			t.Errorf("finding names unregistered rule %s", f.RuleID)
		}
		if f.Severity.String() == "unknown" {
			t.Errorf("finding %s has no severity", f.RuleID)
		}
	}
}

// TestFixtureEvidenceIsValidUTF8: every evidence string and extra value in a
// report over the whole fixture corpus must be valid UTF-8. The truncate helpers
// cut at a byte offset, which splits a multi-byte rune and leaves a dangling
// sequence in the report; the helpers now back off to a rune boundary, and this
// holds that.
func TestFixtureEvidenceIsValidUTF8(t *testing.T) {
	findings := scanPaths(t, fixtureRoot)
	if len(findings) == 0 {
		t.Fatal("the fixture corpus produced no findings, so this proves nothing")
	}
	for _, f := range findings {
		if !utf8.ValidString(f.Evidence) {
			t.Errorf("%s on %s has invalid UTF-8 evidence: %q", f.RuleID, f.Artifact, f.Evidence)
		}
		for k, v := range f.Extra {
			if !utf8.ValidString(v) {
				t.Errorf("%s on %s has invalid UTF-8 in extra[%s]: %q", f.RuleID, f.Artifact, k, v)
			}
		}
	}
}
