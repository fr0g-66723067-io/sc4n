// Package malice grades what a loader does with an artifact's bytes, as opposed
// to what the bytes could reach.
//
// The grade is carried by findings rather than by a new report field, because
// report.SchemaVersion is pinned by consumers and a rule ID is already
// queryable in every encoder, testable through testdata/fixtures/expectations.json
// and subject to the same severity discipline as the capability rules it grades.
//
// This package imports internal/report and the standard library only. The
// payload predicates that need a pickle stack value live in internal/pickle,
// because a Global and a Val are that package's types; keeping them here would
// make internal/pickle import this package and this package import internal/pickle.
package malice

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// Constructed emits the constructed grade at off. family is one of the Family*
// constants; claim is one sentence naming the sink and the payload, and it is
// the whole value of the finding, so an empty claim is refused rather than
// emitted as a finding whose evidence says nothing.
//
// extra carries the machine-readable detail (callable, module, payload, chain).
// The caller's map is copied, and family is set from the argument, so an emitter
// cannot produce a finding whose family disagrees with its extra.
func Constructed(s *report.Sink, off int64, family, claim string, extra map[string]string) {
	if s == nil || claim == "" || family == "" {
		return
	}
	s.EmitExtra(RuleConstructed, off, claim, withFamily(family, extra))
}

// Demonstrated emits the dynamic grade at off.
func Demonstrated(s *report.Sink, off int64, claim string, extra map[string]string) {
	if s == nil || claim == "" {
		return
	}
	s.EmitExtra(RuleDemonstrated, off, claim, withFamily("attested", extra))
}

// withFamily copies extra and stamps the family, so the two always agree.
func withFamily(family string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(extra)+1)
	for k, v := range extra {
		out[k] = v
	}
	out["family"] = family
	return out
}
