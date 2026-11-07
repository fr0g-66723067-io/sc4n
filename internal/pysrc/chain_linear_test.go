package pysrc

import (
	"strings"
	"testing"
	"time"
)

// analyzeTime is one Analyze run, timed.
func analyzeTime(t *testing.T, data []byte) time.Duration {
	t.Helper()
	ctx, _ := newTestCtx(t)
	start := time.Now()
	Analyze(ctx, data)
	return time.Since(start)
}

// TestDottedChainIsLinear guards the single-walk chain scan in Calls and
// rangeSource. `a.` repeated 200000 times is one 400 KB dotted chain; when Calls
// and the taint scan re-walked the chain once per element the analysis took over
// 120 s.
//
// The guard compares the same shape at two sizes rather than one absolute wall
// clock: `go test ./...` runs twenty-odd packages concurrently and was measured
// inflating a 0.15 s linear analysis to 13.8 s in a sibling package, so a 10 s
// bound flakes on a linear implementation. A 4x size costs ~4x when linear and
// ~16x when quadratic; the absolute bound stays as a catastrophic backstop.
func TestDottedChainIsLinear(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector inflates this timing budget; the untagged pass guards it")
	}
	big := analyzeTime(t, []byte(strings.Repeat("a.", 200000)))
	if big > 45*time.Second {
		t.Fatalf("analysing a 400 KB dotted chain took %v; the chain walk is quadratic again", big)
	}
	small := analyzeTime(t, []byte(strings.Repeat("a.", 50000)))
	if small < 5*time.Millisecond {
		t.Skipf("the 100 KB dotted chain took %s, below the measurable floor", small)
	}
	ratio := float64(big) / float64(small)
	t.Logf("100 KB %s, 400 KB %s, ratio %.1f", small, big, ratio)
	if ratio > 9 {
		t.Errorf("4x the chain multiplied the time by %.1f (%s -> %s); the chain walk is meant to be linear", ratio, small, big)
	}
}

// nestedCalls builds a statement of n nested exec( calls.
func nestedCalls(n int) []byte {
	return []byte("x = " + strings.Repeat("exec(", n) + "1" + strings.Repeat(")", n) + "\n")
}

// TestNestedCallsAreBounded guards the call-analysis budget. parseArgs scans from
// a call's `(` to the end of the statement, so a statement of n nested calls cost
// O(n^2): 20000 nested `exec(` (120 KB) measured 16.6 s and 60000 (360 KB) over
// 120 s, and no deadline check runs inside a parser, so -timeout could not bound
// it either.
//
// A quadratic statement is bounded by the entry budget rather than by wall clock,
// so this test asserts the budget fired and still compares the same shape at two
// sizes: the absolute bound alone flakes under `go test ./...`'s parallelism.
func TestNestedCallsAreBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector inflates this timing budget; the untagged pass guards it")
	}
	big := analyzeTime(t, nestedCalls(60000))
	if big > 45*time.Second {
		t.Fatalf("analysing 60000 nested calls took %v; the call analysis is quadratic again", big)
	}
	small := analyzeTime(t, nestedCalls(15000))
	if small >= 5*time.Millisecond {
		ratio := float64(big) / float64(small)
		t.Logf("15000 nested calls %s, 60000 nested calls %s, ratio %.1f", small, big, ratio)
		if ratio > 9 {
			t.Errorf("4x the nesting multiplied the time by %.1f (%s -> %s); the call analysis is meant to be truncated by its budget", ratio, small, big)
		}
	}
	ctx, c := newTestCtx(t)
	Analyze(ctx, nestedCalls(60000))
	// The truncation must be visible: a file whose call analysis stopped is not
	// the same as a file with nothing to find.
	if !ids(c)["SC4N-LIMIT-ENTRIES"] {
		t.Fatalf("call-analysis truncation was not reported; findings: %v", keys(ids(c)))
	}
}
