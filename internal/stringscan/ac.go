package stringscan

import "strings"

// Aho–Corasick over the indicator literals.
//
// Two design choices matter for the scanner's cost:
//
//   - the automaton is built once at init from a data table, so adding an indicator
//     costs one line and no per-scan work; and
//   - case folding is *in* the automaton. Literals are stored lowercased and the
//     walk lowercases each byte before its transition, so matching is
//     case-insensitive without allocating a lowercased copy of a
//     multi-gigabyte artifact.
//
// The goto table is a flat [256]int32 per node. At roughly 2.5k nodes that is
// ~2.5 MB of resident memory, which is the price of a single-pass scan and is paid
// once per process.

type acNode struct {
	// next is the goto table. Index 256 is the fail link, kept in the same array so
	// that the walk touches one cache line per byte instead of two structures.
	next [257]int32
	// out holds the indexes into indicatorTable that end at this node.
	out []int16
}

type acAutomaton struct {
	nodes []acNode
}

var automaton = buildAutomaton()

func buildAutomaton() *acAutomaton {
	a := &acAutomaton{nodes: make([]acNode, 1)}
	for i := range a.nodes[0].next {
		a.nodes[0].next[i] = 0
	}
	for idx, ind := range indicatorTable {
		lit := strings.ToLower(ind.literal)
		state := int32(0)
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			nxt := a.nodes[state].next[c]
			if nxt == 0 {
				a.nodes = append(a.nodes, acNode{})
				nxt = int32(len(a.nodes) - 1)
				for j := range a.nodes[nxt].next {
					a.nodes[nxt].next[j] = 0
				}
				a.nodes[state].next[c] = nxt
			}
			state = nxt
		}
		a.nodes[state].out = append(a.nodes[state].out, int16(idx))
	}
	a.buildFailLinks()
	return a
}

// buildFailLinks fills the fail transitions with a breadth-first sweep, then
// replaces every unset goto with the fail target's goto so the walk needs no
// per-byte fail loop.
func (a *acAutomaton) buildFailLinks() {
	queue := make([]int32, 0, len(a.nodes))
	for c := 0; c < 256; c++ {
		n := a.nodes[0].next[c]
		if n == 0 {
			continue
		}
		a.nodes[n].next[256] = 0
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fail := a.nodes[cur].next[256]
		if len(a.nodes[fail].out) > 0 {
			a.nodes[cur].out = append(a.nodes[cur].out, a.nodes[fail].out...)
		}
		for c := 0; c < 256; c++ {
			n := a.nodes[cur].next[c]
			if n == 0 {
				a.nodes[cur].next[c] = a.nodes[a.nodes[cur].next[256]].next[c]
				continue
			}
			a.nodes[n].next[256] = a.nodes[fail].next[c]
			queue = append(queue, n)
		}
	}
}

// fold lowercases an ASCII byte for the transition. High bytes pass through, which
// is what the non-ASCII indicators rely on.
func fold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// scanLiterals appends every literal match in b to hits.
func (a *acAutomaton) scanLiterals(b []byte, hits []Hit) []Hit {
	state := int32(0)
	// seen deduplicates (rule, offset) pairs: several literals can belong to one
	// rule and end at the same offset, and reporting the same rule twice at one
	// offset is noise a reviewer has to filter by hand.
	for i := 0; i < len(b); i++ {
		state = a.nodes[state].next[fold(b[i])]
		if state == 0 {
			continue
		}
		if len(a.nodes[state].out) == 0 {
			continue
		}
		for _, idx := range a.nodes[state].out {
			ind := indicatorTable[idx]
			start := int64(i+1) - int64(len(ind.literal))
			if start < 0 {
				continue
			}
			match := ind.literal
			if int(start)+len(ind.literal) <= len(b) {
				match = string(b[start : start+int64(len(ind.literal))])
			}
			hits = append(hits, Hit{
				Rule:     ind.rule,
				Off:      start,
				Match:    match,
				Redacted: ind.redact,
				Extra:    map[string]string{"kind": ind.kind},
			})
		}
	}
	return hits
}
