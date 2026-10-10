package main

import "sort"

// contributors are the per-step fixture writers. Each parser package's step adds
// one file here rather than editing a shared table, so the generator can grow
// without a merge conflict and a new format's fixtures cannot be forgotten: the
// registry is the list of everything the corpus contains.
type contributor struct {
	// name orders the contributors deterministically.
	name string
	// fixtures writes the fixture bytes.
	fixtures func(*fixtureSet)
	// expectations returns the malicious and benign rule contracts, keyed by
	// fixture path relative to the fixture root.
	expectations func() (malicious, benign map[string]expectation)
}

var contributors []contributor

// register adds a contributor. It panics on a duplicate name, because two
// contributors with one name would make the corpus depend on init order.
func register(c contributor) {
	if c.name == "" || c.fixtures == nil || c.expectations == nil {
		panic("sc4nfixtures: incomplete contributor")
	}
	for _, existing := range contributors {
		if existing.name == c.name {
			panic("sc4nfixtures: contributor " + c.name + " registered twice")
		}
	}
	contributors = append(contributors, c)
}

// runContributors writes every fixture and merges the expectation maps, failing
// loudly on a duplicate key so that two steps cannot silently disagree about the
// same file.
func runContributors(f *fixtureSet) (malicious, benign map[string]expectation) {
	malicious = map[string]expectation{}
	benign = map[string]expectation{}
	ordered := make([]contributor, len(contributors))
	copy(ordered, contributors)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })
	for _, c := range ordered {
		c.fixtures(f)
		m, b := c.expectations()
		for k, v := range m {
			if _, dup := malicious[k]; dup {
				panic("sc4nfixtures: expectation for " + k + " declared twice")
			}
			malicious[k] = v
		}
		for k, v := range b {
			if _, dup := benign[k]; dup {
				panic("sc4nfixtures: benign expectation for " + k + " declared twice")
			}
			benign[k] = v
		}
	}
	return malicious, benign
}
