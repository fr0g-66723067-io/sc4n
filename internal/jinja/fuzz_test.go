package jinja

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// FuzzJinjaAnalyze asserts the template analyser never panics on arbitrary text.
// A chat template is attacker-controlled in the model-repository threat model:
// the whole point of the rule family is that a repository can ship a template
// that reaches the interpreter, so the analyser must be total on its input.
func FuzzJinjaAnalyze(f *testing.F) {
	f.Add("{{ ''.__class__.__mro__[1].__subclasses__() }}")
	f.Add("{% set x = '__g' + 'lobals__' %}{{ x }}")
	f.Add("{% for m in messages %}<|{{ m.role }}|>\n{% endfor %}")
	f.Add("{# a comment #}")
	f.Add("{{")
	f.Add("{%-")
	f.Add("")

	f.Fuzz(func(t *testing.T, tmpl string) {
		if len(tmpl) > 1<<20 {
			t.Skip()
		}
		Analyze(report.NewCollector(0).For("t.jinja"), 0, "t.jinja", tmpl)
	})
}
