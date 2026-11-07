package pysrc

import (
	"strings"
	"testing"
)

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
// The property is the budget, not the speed: a quadratic statement must stop at
// the entry cap and say so. That assertion is deterministic — the entry count is
// a function of the input — so it holds on any machine.
func TestNestedCallsAreBounded(t *testing.T) {
	ctx, c := newTestCtx(t)
	Analyze(ctx, nestedCalls(60000))
	// The truncation must be visible: a file whose call analysis stopped is not
	// the same as a file with nothing to find.
	if !ids(c)["SC4N-LIMIT-ENTRIES"] {
		t.Fatalf("call-analysis truncation was not reported; findings: %v", keys(ids(c)))
	}
}
