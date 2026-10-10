package pysrc

import (
	"strings"
	"testing"
	"time"
)

// TestDottedChainIsLinear guards the single-walk chain scan in Calls and
// rangeSource. `a.` repeated 200000 times is one 400 KB dotted chain; when Calls
// and the taint scan re-walked the chain once per element the analysis took over
// 120 s. The bound is deliberately generous (10 s) so it fails only on a return
// to quadratic behaviour, not on a slow host.
func TestDottedChainIsLinear(t *testing.T) {
	data := []byte(strings.Repeat("a.", 200000))
	ctx, _ := newTestCtx(t)
	start := time.Now()
	Analyze(ctx, data)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("analysing a 400 KB dotted chain took %v; the chain walk is quadratic again", elapsed)
	}
}

// TestNestedCallsAreBounded guards the call-analysis budget. parseArgs scans from
// a call's `(` to the end of the statement, so a statement of n nested calls cost
// O(n^2): 20000 nested `exec(` (120 KB) measured 16.6 s and 60000 (360 KB) over
// 120 s, and no deadline check runs inside a parser, so -timeout could not bound
// it either. The bound is generous (10 s) so it fails only on a return to
// quadratic behaviour, not on a slow host.
func TestNestedCallsAreBounded(t *testing.T) {
	data := []byte("x = " + strings.Repeat("exec(", 60000) + "1" + strings.Repeat(")", 60000) + "\n")
	ctx, c := newTestCtx(t)
	start := time.Now()
	Analyze(ctx, data)
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("analysing 60000 nested calls took %v; the call analysis is quadratic again", elapsed)
	}
	// The truncation must be visible: a file whose call analysis stopped is not
	// the same as a file with nothing to find.
	if !ids(c)["SC4N-LIMIT-ENTRIES"] {
		t.Fatalf("call-analysis truncation was not reported; findings: %v", keys(ids(c)))
	}
}
