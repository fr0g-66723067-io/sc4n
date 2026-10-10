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

// benignAllowlist is the explicit, reasoned exception list for the benign gate: a
// rule ID that may report on a benign fixture, with the reason. It is empty, because
// nothing the benign corpus contains is a finding above info. An entry is how a
// legitimately-reported fixture gets in — with a reason a reviewer can disagree
// with — rather than by raising the bar for everything.
var benignAllowlist = map[string]string{}

// TestRound3FixtureCounts pins the two round-3 properties the set-based gate cannot
// express. A contract of rule IDs says "this rule fires"; it cannot say "and only
// once", nor "at this offset", and both are the point of the fixtures below: the
// memo-alias finding is emitted once per stream rather than once per rebinding, and
// the msgpack NaN finding is located at the blob's offset in the artifact rather
// than at its index inside the blob.
func TestRound3FixtureCounts(t *testing.T) {
	t.Run("memo alias is emitted once", func(t *testing.T) {
		fs := scanPaths(t, filepath.Join(fixtureRoot, "round3", "pickle_rebind.pkl"))
		var aliases []report.Finding
		for _, f := range fs {
			if f.RuleID == "SC4N-PICKLE-MEMO-ALIAS" {
				aliases = append(aliases, f)
			}
		}
		if len(aliases) != 1 {
			t.Fatalf("two rebindings produced %d SC4N-PICKLE-MEMO-ALIAS finding(s), want 1: %v", len(aliases), aliases)
		}
		// The one finding must carry the final count, not the count at the first
		// rebinding, or a reader cannot tell a single rebinding from a stream of them.
		if !strings.Contains(aliases[0].Evidence, "2 rebinding(s)") {
			t.Fatalf("the finding does not carry the final rebinding count: %q", aliases[0].Evidence)
		}
	})

	t.Run("a tokenizer document's finding is emitted once", func(t *testing.T) {
		fs := scanPaths(t, filepath.Join(fixtureRoot, "tokenizer_dedup", "tokenizer_config.json"))
		var c2 int
		for _, f := range fs {
			if f.RuleID == "SC4N-STRING-C2" {
				c2++
			}
		}
		if c2 != 1 {
			t.Fatalf("the webhook in the special token produced %d SC4N-STRING-C2 finding(s), want 1: %v", c2, fs)
		}
	})

	t.Run("msgpack NaN offset is the blob's offset", func(t *testing.T) {
		fs := scanPaths(t, filepath.Join(fixtureRoot, "round3", "msgpack_nan.msgpack"))
		var found bool
		for _, f := range fs {
			if f.RuleID != "SC4N-MSGPACK-NAN-PAYLOAD" {
				continue
			}
			found = true
			// The map header is 3 bytes, the bin8 header is 2, so the blob starts
			// at 5; the NaN bytes are the first two bytes of that blob.
			if f.Offset != 5 {
				t.Fatalf("SC4N-MSGPACK-NAN-PAYLOAD offset = %d, want 5 (the blob's offset in the artifact)", f.Offset)
			}
		}
		if !found {
			t.Fatal("the NaN payload was not reported at all")
		}
	})
}

// TestBenignFixturesAreClean is the false-positive gate. A scanner that fires on a
// real-structure torch state dict is not usable as a CI gate, so this is an
// assertion about the whole benign set at once rather than per file.
//
// The threshold is "anything above info", not "high or critical". The weaker gate
// passed while SC4N-ARCHIVE-NAME-MISMATCH was reported at medium on the committed
// benign/model.npz — a false positive on a fixture this gate exists to protect,
// invisible because a medium finding sat below the bar.
func TestBenignFixturesAreClean(t *testing.T) {
	benign := filepath.Join(fixtureRoot, "benign")
	if _, err := os.Stat(benign); err != nil {
		t.Skip("no benign corpus")
	}
	findings := scanPaths(t, benign)
	var bad []string
	for _, f := range findings {
		if f.Severity <= report.SeverityInfo {
			continue
		}
		// An allowlist entry excuses a medium finding, never a high one: the
		// high/critical bar is the subset of this gate that no entry can lift.
		if _, ok := benignAllowlist[f.RuleID]; ok && !f.Severity.AtLeast(report.SeverityHigh) {
			continue
		}
		bad = append(bad, f.Severity.String()+" "+f.RuleID+" "+f.Artifact+" "+f.Evidence)
	}
	if len(bad) > 0 {
		t.Fatalf("benign corpus produced %d finding(s) above info:\n%s", len(bad), strings.Join(bad, "\n"))
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
