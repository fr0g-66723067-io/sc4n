package report

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Rule is the single source of truth for a detector's metadata. Parsers hold a
// *Rule and emit through Sink.Emit, so a rule's severity, CWE and help text can
// never disagree between the catalogue (`sc4n rules`), the JSON report and the
// SARIF descriptor for the same finding.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Confidence  Confidence
	CWE         []string
	Class       string
	Description string
	// Refs are the upstream advisories, papers or specifications the rule's
	// comment cites. They become SARIF help URIs and appear in `sc4n rules`.
	Refs []string
	// Tags are extra SARIF properties.tags beyond the CWE and class tags that
	// the encoder derives.
	Tags []string
}

var (
	rulesMu  sync.RWMutex
	rulesReg = map[string]*Rule{}
	rulesAll []*Rule
)

// DefineRule registers r and returns it. It panics on a malformed or duplicate
// rule, because both are programmer errors that would otherwise surface as a
// silently missing catalogue entry: an ID collision means one of two detectors
// is invisible in `sc4n rules` and mis-described in SARIF.
func DefineRule(r Rule) *Rule {
	if !strings.HasPrefix(r.ID, "SC4N-") || len(r.ID) < len("SC4N-X") {
		panic(fmt.Sprintf("report: rule ID %q must be of the form SC4N-...", r.ID))
	}
	if r.Title == "" {
		panic(fmt.Sprintf("report: rule %s has no title", r.ID))
	}
	if r.Class == "" {
		panic(fmt.Sprintf("report: rule %s has no class", r.ID))
	}
	if r.Description == "" {
		panic(fmt.Sprintf("report: rule %s has no description", r.ID))
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	if _, dup := rulesReg[r.ID]; dup {
		panic(fmt.Sprintf("report: duplicate rule ID %s", r.ID))
	}
	rr := &r
	rulesReg[r.ID] = rr
	rulesAll = append(rulesAll, rr)
	return rr
}

// Rules returns every registered rule sorted by ID. The catalogue and the SARIF
// rule index are both built from this, so their order is stable.
func Rules() []*Rule {
	rulesMu.RLock()
	out := make([]*Rule, len(rulesAll))
	copy(out, rulesAll)
	rulesMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RuleByID looks a rule up by ID.
func RuleByID(id string) (*Rule, bool) {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	r, ok := rulesReg[id]
	return r, ok
}

// CWEList renders the CWE list for human output.
func (r *Rule) CWEList() string { return strings.Join(r.CWE, ", ") }
