package jinja

import (
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// TestAnalyzeIsLinear guards the expression pass against the two quadratic runs
// it replaced: a 400000-element string-literal chain took 19.6 s to analyse
// while the concatenation was built with +=, and a tag of 200000 separate string
// tokens took 55 s while each one walked backwards to the raise_exception opener.
// The bounds are deliberately generous so a slow machine does not flake.
func TestAnalyzeIsLinear(t *testing.T) {
	t.Run("concat", func(t *testing.T) {
		const n = 400000
		var b strings.Builder
		b.WriteString("{{ ")
		for i := range n {
			if i > 0 {
				b.WriteByte('+')
			}
			b.WriteString("'x'")
		}
		b.WriteString(" }}")

		c := report.NewCollector(0)
		start := time.Now()
		Analyze(c.For("t.jinja"), 0, "t.jinja", b.String())
		if d := time.Since(start); d > 10*time.Second {
			t.Fatalf("analysing a %d-element chain took %v; the join is quadratic again", n, d)
		}
	})

	t.Run("many-strings", func(t *testing.T) {
		const n = 200000
		tmpl := "{{ " + strings.Repeat("'a' ", n) + "}}"

		c := report.NewCollector(0)
		start := time.Now()
		Analyze(c.For("t.jinja"), 0, "t.jinja", tmpl)
		if d := time.Since(start); d > 10*time.Second {
			t.Fatalf("analysing %d separate string tokens took %v; the raise_exception scan is quadratic again", n, d)
		}
	})
}
