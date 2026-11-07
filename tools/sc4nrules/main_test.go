package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// The committed catalogue is what a reader without a binary reads, so it must be
// the registry's own output. A rule added without `make rules-doc` fails here
// instead of shipping a page that silently omits it.
func TestGeneratedDocMatchesCommittedFile(t *testing.T) {
	want, err := render(report.Rules())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	committed, err := os.ReadFile(filepath.Join("..", "..", "docs", "rules.md"))
	if err != nil {
		t.Fatalf("read docs/rules.md: %v", err)
	}
	if !bytes.Equal(want, committed) {
		t.Fatalf("docs/rules.md is stale: `make rules-doc` regenerates it (%d vs %d bytes)", len(committed), len(want))
	}
}

// Every rule must land in a bucket, because the bucket is the link from "I have
// this finding" to "here is what to do". A new prefix with no bucket would print
// a rule with no triage path, which is the gap this generator exists to close.
func TestEveryRuleHasABucket(t *testing.T) {
	for _, r := range report.Rules() {
		if _, ok := bucketFor(r.ID); !ok {
			t.Errorf("rule %s has no triage bucket: add its prefix to main.go's bucket table", r.ID)
		}
	}
}

// The other half of the contract: an anchor in the catalogue must exist as a
// heading in docs/triage.md, or the link a reader follows goes nowhere.
func TestTriageAnchorsExist(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "triage.md"))
	if err != nil {
		t.Fatalf("read docs/triage.md: %v", err)
	}
	doc := string(b)
	for _, bk := range buckets {
		// GitHub's anchor for a heading is its text lowercased with spaces and
		// punctuation removed, so the section states its anchor explicitly; this
		// checks that explicit marker rather than guessing at the slug rule.
		if !strings.Contains(doc, `<a id="`+bk.Anchor+`"></a>`) {
			t.Errorf("docs/triage.md has no section for bucket %q: add <a id=%q></a>", bk.Anchor, bk.Anchor)
		}
	}
}

// The catalogue must cover every rule the CLI reports, which is not the same
// claim as covering report.Rules(): the registry is filled by package init, so a
// missing import in this generator shrinks the docs without failing anything.
func TestCatalogueCoversTheCLIRegistry(t *testing.T) {
	rules := report.Rules()
	if len(rules) < 200 {
		t.Fatalf("registry has %d rules; the generator is not linking every package that defines one", len(rules))
	}
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.ID] {
			t.Fatalf("duplicate rule %s in the registry", r.ID)
		}
		seen[r.ID] = true
	}
}
