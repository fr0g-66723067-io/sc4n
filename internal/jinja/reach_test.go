package jinja

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func maliceEvidence(fs []report.Finding) string {
	for _, f := range fs {
		if f.RuleID == "SC4N-MALICE-CONSTRUCTED" {
			return f.Evidence
		}
	}
	return ""
}

// TestCalledReachSeparatesCallFromRead pins the two grades: a template that reads
// an attribute through a Python object is a capability, and one that calls
// through it runs code when rendered.
func TestCalledReachSeparatesCallFromRead(t *testing.T) {
	called := []string{
		"{{ c.__init__.__globals__.os.popen('id').read() }}",
		"{{ a.__class__.__mro__[1].__subclasses__() }}",
		"{{ lipsum['__globals__']['os'].popen('id').read() }}",
		"{{ x|attr('__init__')() }}",
	}
	for _, tmpl := range called {
		fs := analyze(t, tmpl)
		if maliceEvidence(fs) == "" {
			t.Fatalf("%s: no constructed grade; findings %v", tmpl, ruleIDs(fs))
		}
	}
	readOnly := []string{
		"{{ c.__class__ }}",
		"{{ a.__init__ }}",
		"{{ lipsum.__globals__ }}",
		"{{ x|attr('__class__') }}",
		"{{ 'ordinary' }}",
	}
	for _, tmpl := range readOnly {
		fs := analyze(t, tmpl)
		if ev := maliceEvidence(fs); ev != "" {
			t.Fatalf("%s: constructed grade %q, want none", tmpl, ev)
		}
	}
}

// TestCalledReachOncePerTemplate pins the count: the decision is about the
// template, so two called chains produce one finding.
func TestCalledReachOncePerTemplate(t *testing.T) {
	fs := analyze(t, "{{ a.__class__.__subclasses__() }}{{ b.__class__.__subclasses__() }}")
	n := 0
	for _, f := range fs {
		if f.RuleID == "SC4N-MALICE-CONSTRUCTED" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("constructed grade x%d, want exactly 1", n)
	}
}

func ruleIDs(fs []report.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.RuleID + " ")
	}
	return b.String()
}
