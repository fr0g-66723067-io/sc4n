package stringscan

import "strings"

// Aho–Corasick over the indicator literals.
//
// Three design choices matter for the scanner's cost:
//
//   - the automaton is built once at init from a data table, so adding an indicator
//     costs one line and no per-scan work;
//   - case folding is *in* the automaton: literals are stored lowercased and the
//     walk lowercases each byte before its transition, so matching is
//     case-insensitive without allocating a lowercased copy of a multi-gigabyte
//     artifact; and
//   - the goto table is *class-compressed*.
//
// The class compression is the non-obvious one. The textbook encoding is a
// [256]int32 per node, which is a kilobyte per node and, on a 2.5k-node automaton,
// 2.5 MB of resident memory: every byte then costs a jump into L3 or RAM, and the
// measured rate on the reference host was 74 MB/s. Only the bytes that actually
// appear inside some indicator ever have an edge, though — about seventy of the 256
// — and a byte that appears in no indicator can never match anything at any node,
// so its transition is always the root. So bytes are mapped to classes (0 means "no
// indicator contains this byte"), each node carries one int16 per class, and fail
// transitions are materialised at build time. The walk is then two dependent loads
// and a multiply with no fail loop, and the whole table is a few hundred kilobytes:
// the shallow states that running text actually visits stay in L1.

type acAutomaton struct {
	// class maps a *lowercased* byte to its column in table; 0 is "never matches".
	class [256]byte
	// cols is the number of columns in table (classes + the zero class).
	cols int
	// table is nodes x cols, flattened, with materialised fail transitions.
	table []int16
	// out holds the indexes into indicatorTable that end at each node, including
	// those inherited from the fail chain.
	out [][]int16
}

var automaton = buildAutomaton()

func buildAutomaton() *acAutomaton {
	// Build on a sparse representation first: a map per node. This is build-time
	// only, so its cost does not matter; only the flattened table does.
	edges := []map[byte]int32{{}}
	out := make([][]int16, 1)
	state := int32(0)
	for idx := range indicatorTable {
		lit := strings.ToLower(indicatorTable[idx].literal)
		state = 0
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			next, ok := edges[state][c]
			if !ok {
				edges = append(edges, map[byte]int32{})
				out = append(out, nil)
				next = int32(len(edges) - 1)
				edges[state][c] = next
			}
			state = next
		}
		out[state] = append(out[state], int16(idx))
	}

	a := &acAutomaton{out: make([][]int16, len(edges))}
	for i := range edges {
		if len(out[i]) > 0 {
			a.out[i] = out[i]
		}
	}

	// Class table: one column per byte value that occurs somewhere in the
	// indicators, plus column 0 for everything else.
	for i := range indicatorTable {
		lit := strings.ToLower(indicatorTable[i].literal)
		for j := 0; j < len(lit); j++ {
			if a.class[lit[j]] == 0 {
				a.class[lit[j]] = byte(a.cols)
				a.cols++
			}
		}
	}
	a.cols++ // column 0
	var value [256]byte
	for c := 0; c < 256; c++ {
		if a.class[c] != 0 {
			value[a.class[c]] = byte(c)
		}
	}

	// Failure links, breadth-first, over the sparse edges.
	fail := make([]int32, len(edges))
	queue := make([]int32, 0, len(edges))
	for _, next := range sortedTargets(edges[0]) {
		fail[next] = 0
		queue = append(queue, next)
	}
	step := func(from int32, c byte) int32 {
		for {
			if next, ok := edges[from][c]; ok {
				return next
			}
			if from == 0 {
				return 0
			}
			from = fail[from]
		}
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, e := range sortedEdges(edges[cur]) {
			fail[e.next] = step(fail[cur], e.c)
			if inherited := a.out[fail[e.next]]; len(inherited) > 0 {
				a.out[e.next] = append(a.out[e.next], inherited...)
			}
			queue = append(queue, e.next)
		}
	}

	// Flatten with every transition materialised, in BFS order so that the fail
	// target's row is already written when a node's row is filled.
	a.table = make([]int16, len(edges)*a.cols)
	for col := 1; col < a.cols; col++ {
		c := value[col]
		if next, ok := edges[0][c]; ok {
			a.table[col] = int16(next)
		}
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		base := int(cur) * a.cols
		failBase := int(fail[cur]) * a.cols
		copy(a.table[base:base+a.cols], a.table[failBase:failBase+a.cols])
		for _, e := range sortedEdges(edges[cur]) {
			a.table[base+int(a.class[e.c])] = int16(e.next)
		}
	}
	return a
}

type acEdge struct {
	c    byte
	next int32
}

func sortedEdges(m map[byte]int32) []acEdge {
	out := make([]acEdge, 0, len(m))
	for c, next := range m {
		out = append(out, acEdge{c, next})
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].c < out[j-1].c; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func sortedTargets(m map[byte]int32) []int32 {
	es := sortedEdges(m)
	out := make([]int32, len(es))
	for i, e := range es {
		out[i] = e.next
	}
	return out
}

// lowerASCII lowercases an ASCII byte. High bytes pass through, which is what the
// non-ASCII indicators rely on.
func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// scanLiterals appends every literal match in b to hits.
func (a *acAutomaton) scanLiterals(b []byte, hits []Hit) []Hit {
	state := 0
	for i := 0; i < len(b); i++ {
		state = int(a.table[state*a.cols+int(a.class[lowerASCII(b[i])])])
		out := a.out[state]
		if len(out) == 0 {
			continue
		}
		for _, idx := range out {
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
