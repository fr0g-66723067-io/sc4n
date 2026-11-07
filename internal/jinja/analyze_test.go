package jinja

import (
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// analyzeTimes runs Analyze over a document and returns how long it took.
func analyzeTime(doc string) time.Duration {
	c := report.NewCollector(0)
	start := time.Now()
	Analyze(c.For("t.jinja"), 0, "t.jinja", doc)
	return time.Since(start)
}

// concatChain builds `{{ 'x'+'x'+… }}` with n elements.
func concatChain(n int) string {
	var b strings.Builder
	b.WriteString("{{ ")
	for i := range n {
		if i > 0 {
			b.WriteByte('+')
		}
		b.WriteString("'x'")
	}
	b.WriteString(" }}")
	return b.String()
}

// TestAnalyzeIsLinear guards the expression pass against the two quadratic runs
// it replaced: a 400000-element string-literal chain took 19.6 s to analyse while
// the concatenation was built with +=, and a tag of 200000 separate string tokens
// took 55 s while each one walked backwards to the raise_exception opener.
//
// An absolute wall-clock bound is the wrong instrument for that, and it was
// measured flaking: this package takes 0.15 s idle and took 13.8 s under `make
// test`, where `go test ./...` runs twenty-odd packages at once, with no change to
// this package. So the guard measures the same shape at two sizes and compares the
// times — a 4x size costs ~4x when the analysis is linear — and keeps a generous
// absolute bound as a backstop for a regression that is catastrophic at one size.
func TestAnalyzeIsLinear(t *testing.T) {
	t.Run("concat", func(t *testing.T) {
		const small, big = 100000, 400000
		d := analyzeTime(concatChain(big))
		t.Logf("%d-element chain: %s", big, d)
		if d > 45*time.Second {
			t.Fatalf("analysing a %d-element chain took %v; the join is quadratic again", big, d)
		}
		small4 := analyzeTime(concatChain(small))
		if small4 < 5*time.Millisecond {
			// Too fast to time reliably; the absolute bound above covers it.
			t.Skipf("the %d-element chain took %s, below the measurable floor", small, small4)
		}
		// 4x the elements is 4x the work when linear and 16x when quadratic. The
		// bound is loose enough for allocation noise and tight enough to fail on
		// the regression this test exists for.
		ratio := float64(d) / float64(small4)
		t.Logf("%d elements %s, %d elements %s, ratio %.1f", small, small4, big, d, ratio)
		if ratio > 9 {
			t.Errorf("4x the elements multiplied the time by %.1f (%s -> %s); the join is meant to be linear", ratio, small4, d)
		}
	})

	t.Run("many-strings", func(t *testing.T) {
		const small, big = 50000, 200000
		d := analyzeTime("{{ " + strings.Repeat("'a' ", big) + "}}")
		t.Logf("%d string tokens: %s", big, d)
		if d > 45*time.Second {
			t.Fatalf("analysing %d separate string tokens took %v; the raise_exception scan is quadratic again", big, d)
		}
		small4 := analyzeTime("{{ " + strings.Repeat("'a' ", small) + "}}")
		if small4 < 5*time.Millisecond {
			t.Skipf("%d string tokens took %s, below the measurable floor", small, small4)
		}
		ratio := float64(d) / float64(small4)
		t.Logf("%d tokens %s, %d tokens %s, ratio %.1f", small, small4, big, d, ratio)
		if ratio > 9 {
			t.Errorf("4x the tokens multiplied the time by %.1f (%s -> %s); the raise_exception scan is meant to be linear", ratio, small4, d)
		}
	})
}
