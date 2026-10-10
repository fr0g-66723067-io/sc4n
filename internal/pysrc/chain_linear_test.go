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
