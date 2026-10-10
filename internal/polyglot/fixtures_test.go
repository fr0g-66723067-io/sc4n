package polyglot_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// Registers the universal (polyglot) layer and the native parser, which is
	// exactly what these fixtures need. Deliberately not internal/formats: this
	// test must keep passing while sibling format packages are still in flight.
	_ "github.com/fr0g-66723067-io/sc4n/internal/native"
	_ "github.com/fr0g-66723067-io/sc4n/internal/polyglot"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

const fixtureDir = "../../testdata/fixtures"

// scanOne runs the real engine over one fixture path and returns the findings.
func scanOne(t *testing.T, rel string) []report.Finding {
	t.Helper()
	path := filepath.Join(fixtureDir, filepath.FromSlash(rel))
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture %s missing (run `go run ./tools/sc4nfixtures`): %v", rel, err)
	}
	res, err := scan.Run(context.Background(), scan.Config{
		Paths:  []string{path},
		Limits: limits.Default(),
	})
	if err != nil {
		t.Fatalf("scan %s: %v", rel, err)
	}
	return res.Collector.Findings()
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// TestPolyglotFixtureContract runs the same assertions the shared corpus gate
// makes, scoped to this step's five fixtures, so the contract is enforced even
// before every sibling parser is linked in.
func TestPolyglotFixtureContract(t *testing.T) {
	cases := []struct {
		rel    string
		expect []string
		forbid []string
	}{
		{
			rel:    "polyglot_magic_only.bin",
			expect: []string{"SC4N-POLYGLOT-MAGIC-ONLY"},
			forbid: []string{"SC4N-POLYGLOT-NATIVE", "SC4N-NATIVE-VALID"},
		},
		{
			rel:    "polyglot_zip_tar.zip",
			expect: []string{"SC4N-POLYGLOT-CONTAINER"},
			forbid: []string{"SC4N-POLYGLOT-NATIVE"},
		},
		{
			rel:    "native_embedded.so",
			expect: []string{"SC4N-NATIVE-VALID", "SC4N-NATIVE-EMBEDDED-PAYLOAD"},
		},
		{
			rel:    "extension_mismatch.safetensors",
			expect: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			forbid: []string{"SC4N-POLYGLOT-NATIVE"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.rel, func(t *testing.T) {
			fs := scanOne(t, tc.rel)
			for _, id := range tc.expect {
				if !hasRule(fs, id) {
					t.Errorf("expected %s; findings were %v", id, ruleIDs(fs))
				}
			}
			for _, id := range tc.forbid {
				if hasRule(fs, id) {
					t.Errorf("forbidden %s; findings were %v", id, ruleIDs(fs))
				}
			}
		})
	}
}

// TestBenignRandomFixtureIsClean is the false-positive half for this step's
// fixture: deterministic noise must not trip any high/critical rule.
func TestBenignRandomFixtureIsClean(t *testing.T) {
	fs := scanOne(t, "benign/random.bin")
	for _, f := range fs {
		if f.Severity.AtLeast(report.SeverityHigh) {
			t.Errorf("benign random bytes produced %s %s: %s", f.Severity, f.RuleID, f.Evidence)
		}
		if strings.HasPrefix(f.RuleID, "SC4N-POLYGLOT-") {
			t.Errorf("benign random bytes produced a polyglot finding: %s", f.RuleID)
		}
	}
}

func ruleIDs(fs []report.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}
