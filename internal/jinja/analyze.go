package jinja

import (
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// dunderNames is the introspection set. Every entry is a name a real chat
// template has no reason to contain; reaching one is the first step of every
// published Jinja2 SSTI chain.
var dunderNames = map[string]bool{
	"__class__":        true,
	"__mro__":          true,
	"__subclasses__":   true,
	"__globals__":      true,
	"__builtins__":     true,
	"__import__":       true,
	"__init__":         true,
	"__reduce__":       true,
	"__getattribute__": true,
	"__dict__":         true,
	"__code__":         true,
	"__loader__":       true,
}

// dangerousGlobals are the Jinja2 globals whose attribute walk reaches
// __globals__. The bare constructor (namespace(a=1), range(3)) is normal
// template style and is only reported when used as an attribute/subscript
// receiver.
var dangerousGlobals = map[string]bool{
	"lipsum":    true,
	"cycler":    true,
	"joiner":    true,
	"namespace": true,
	"dict":      true,
	"range":     true,
}

// knownFilters is the allowlist that lets {% set x = messages | tojson %} stay
// clean: a value built only from a literal, a name and known filters is ordinary
// template style, while anything else is a computed right-hand side.
var knownFilters = map[string]bool{
	"tojson": true, "fromjson": true, "trim": true, "length": true, "count": true,
	"upper": true, "lower": true, "title": true, "capitalize": true, "string": true,
	"int": true, "float": true, "abs": true, "round": true, "default": true,
	"join": true, "first": true, "last": true, "list": true, "reverse": true,
	"sort": true, "unique": true, "items": true, "keys": true, "values": true,
	"replace": true, "format": true, "map": true, "select": true, "reject": true,
	"selectattr": true, "rejectattr": true, "sum": true, "min": true, "max": true,
	"escape": true, "e": true, "safe": true, "urlencode": true, "wordcount": true,
	"truncate": true, "center": true, "indent": true, "batch": true, "slice": true,
	"groupby": true, "dictsort": true, "pprint": true, "striptags": true,
}

// templatePhrases are the model-directed instructions reported by
// SC4N-TEMPLATE-INJECTION. This is deliberately not the shared pseudo-tag table:
// [INST], <|im_start|> and <|user|> are what a legitimate template is made of.
var templatePhrases = []string{
	"ignore previous instructions",
	"ignore all previous",
	"ignore the previous",
	"disregard previous",
	"disregard all previous",
	"do not tell the user",
	"don't tell the user",
	"do not inform the user",
	"do not mention this",
	"do not reveal",
	"never reveal",
	"without telling the user",
	"override your instructions",
	"ignore your instructions",
	"new instructions:",
	"system prompt:",
	"exfiltrate",
	"send the conversation",
	"send the chat history",
	"send all messages",
	"hidden instruction",
	"you must obey",
}

// Analyze scans one Jinja2 template and reports every finding through sink at
// offsets derived from base. name is used for evidence only.
func Analyze(sink *report.Sink, base int64, name, template string) {
	if template == "" {
		return
	}
	a := &analyzer{sink: sink, base: base, name: name, toks: lex(template)}
	a.structure()
	a.expressions()
}

type analyzer struct {
	sink *report.Sink
	base int64
	name string
	toks []token
}

func (a *analyzer) emit(r *report.Rule, off int, ev string) {
	if a.name != "" {
		ev += " (in " + a.name + ")"
	}
	a.sink.Emit(r, a.base+int64(off), ev)
}

// structure walks the token stream once for the block-level and text-level
// rules: text/comment/raw instructions, {% include %} and {% set %}.
func (a *analyzer) structure() {
	toks := a.toks
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case kindText:
			if p, at := phraseIn(t.val); p != "" {
				a.emit(ruleTemplateInjection, t.off+at, "template text contains the instruction "+strconv.Quote(p))
			}
		case kindComment:
			if p, at := phraseIn(t.val); p != "" {
				a.emit(ruleTemplateInjection, t.off+at, "a {# comment #} contains the instruction "+strconv.Quote(p))
			}
		case kindRaw:
			a.emit(ruleRaw, t.off, "{% raw %} hides "+strconv.Itoa(len(t.val))+" bytes from a {{ }} scanner")
			if p, at := phraseIn(t.val); p != "" {
				a.emit(ruleTemplateInjection, t.off+at, "a {% raw %} block contains the instruction "+strconv.Quote(p))
			}
		case kindTag:
			if t.val != "{%" {
				continue
			}
			j := i + 1
			for j < len(toks) && toks[j].kind != kindTagEnd {
				j++
			}
			if i+1 < j && toks[i+1].kind == kindName {
				switch toks[i+1].val {
				case "include", "import", "extends", "from":
					a.emit(ruleInclude, toks[i+1].off, "{% "+toks[i+1].val+" %} makes the template load another file")
				case "set":
					a.analyzeSet(toks[i+1 : j])
				}
			}
			i = j
		}
	}
}

// analyzeSet reports a {% set %} whose right-hand side is computed rather than
// a literal, a name or a known filter chain. inner starts at the "set" keyword
// and excludes the closing tag.
func (a *analyzer) analyzeSet(inner []token) {
	eq := -1
	for k := range inner {
		if inner[k].kind == kindOp && inner[k].val == "=" {
			eq = k
			break
		}
	}
	if eq < 0 || eq+1 >= len(inner) || len(inner) == 0 {
		return
	}
	if simpleRHS(inner[eq+1:]) {
		return
	}
	a.emit(ruleDynamicName, inner[0].off,
		"{% set %} builds its value with a computed right-hand side, which hides the construction from a literal scan")
}

// simpleRHS reports whether rhs is exactly the allowlisted shape: one literal,
// number or name optionally followed by `| knownfilter` chains.
func simpleRHS(rhs []token) bool {
	if len(rhs) == 0 {
		return true
	}
	if rhs[0].kind != kindString && rhs[0].kind != kindNumber && rhs[0].kind != kindName {
		return false
	}
	k := 1
	for k < len(rhs) {
		if rhs[k].kind != kindOp || rhs[k].val != "|" || k+1 >= len(rhs) || rhs[k+1].kind != kindName || !knownFilters[rhs[k+1].val] {
			return false
		}
		k += 2
		if k < len(rhs) && rhs[k].kind == kindOp && rhs[k].val == "(" {
			depth := 0
			for k < len(rhs) {
				if rhs[k].kind == kindOp && rhs[k].val == "(" {
					depth++
				} else if rhs[k].kind == kindOp && rhs[k].val == ")" {
					depth--
					if depth == 0 {
						k++
						break
					}
				}
				k++
			}
			if depth != 0 {
				return false
			}
		}
	}
	return true
}

// expressions walks the token stream once for the expression-level rules:
// introspection names, dangerous-global receivers, the attr filter, dynamic
// names and instruction strings.
func (a *analyzer) expressions() {
	toks := a.toks
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case kindString:
			if !a.inRaiseException(i) {
				if p, _ := phraseIn(t.val); p != "" {
					a.emit(ruleTemplateInjection, t.off, "a template string contains the instruction "+strconv.Quote(p))
				}
			}
			joined, next, ok := a.concatAt(i)
			if ok {
				if strings.Contains(joined, "__") {
					a.emit(ruleDynamicName, t.off, "string concatenation builds "+strconv.Quote(truncate(joined, 80))+
						", which hides a dunder name from a literal scanner")
				}
				i = next - 1
			}

		case kindName:
			if dunderNames[t.val] {
				if i > 0 && toks[i-1].kind == kindOp && (toks[i-1].val == "." || toks[i-1].val == "[") {
					break // the attribute/subscript passes already reported it
				}
				a.emit(rulePyObject, t.off, "template reaches the Python name "+t.val)
			}
			if dangerousGlobals[t.val] && i+1 < len(toks) && toks[i+1].kind == kindOp &&
				(toks[i+1].val == "." || toks[i+1].val == "[") {
				a.emit(ruleDangerousGlobal, t.off, t.val+" is used as the receiver of attribute/subscript access")
			}

		case kindOp:
			switch t.val {
			case ".":
				if i+1 < len(toks) && toks[i+1].kind == kindName && dunderNames[toks[i+1].val] {
					a.emit(rulePyObject, toks[i+1].off, "attribute access ."+toks[i+1].val)
				}
			case "[":
				if i+2 < len(toks) && toks[i+1].kind == kindString && toks[i+2].kind == kindOp &&
					toks[i+2].val == "]" && dunderNames[toks[i+1].val] {
					a.emit(rulePyObject, t.off, "subscript access ["+strconv.Quote(toks[i+1].val)+"]")
				}
			case "|":
				a.attrFilter(i)
			}
		}
	}
}

// attrFilter handles `|attr(...)`. A leading-underscore argument is either the
// introspection name (reported by PY-OBJECT) or a private name reached through
// the filter (reported as the dangerous-global form); a computed argument is
// the dynamic-name evasion.
func (a *analyzer) attrFilter(i int) {
	toks := a.toks
	if i+2 >= len(toks) || toks[i+1].kind != kindName || toks[i+1].val != "attr" ||
		toks[i+2].kind != kindOp || toks[i+2].val != "(" {
		return
	}
	if i+3 < len(toks) && toks[i+3].kind == kindString {
		s := toks[i+3].val
		switch {
		case strings.HasPrefix(s, "__"):
			a.emit(rulePyObject, toks[i+1].off, "attr filter selects "+strconv.Quote(s))
		case strings.HasPrefix(s, "_"):
			a.emit(ruleDangerousGlobal, toks[i+1].off, "attr filter selects the private name "+strconv.Quote(s))
		}
		return
	}
	a.emit(ruleDynamicName, toks[i+1].off, "attr filter is applied to a computed name")
}

// concatAt returns the value of a run of string literals joined by + or ~,
// starting at i, the index just past the run, and whether a run was found.
func (a *analyzer) concatAt(i int) (string, int, bool) {
	toks := a.toks
	if toks[i].kind != kindString {
		return "", i, false
	}
	joined := toks[i].val
	k := i + 1
	count := 0
	for k+1 < len(toks) && toks[k].kind == kindOp && (toks[k].val == "+" || toks[k].val == "~") &&
		toks[k+1].kind == kindString {
		joined += toks[k+1].val
		k += 2
		count++
	}
	if count == 0 {
		return "", i, false
	}
	return joined, k, true
}

// inRaiseException reports whether the string at index i is an argument of a
// raise_exception() call. raise_exception is provided by Transformers and is
// legitimate, so its message text is never treated as an injection.
func (a *analyzer) inRaiseException(i int) bool {
	toks := a.toks
	depth := 0
	for j := i - 1; j >= 0; j-- {
		t := toks[j]
		if t.kind == kindTag || t.kind == kindTagEnd {
			return false
		}
		if t.kind != kindOp {
			continue
		}
		switch t.val {
		case ")":
			depth++
		case "(":
			if depth == 0 {
				return j > 0 && toks[j-1].kind == kindName && toks[j-1].val == "raise_exception"
			}
			depth--
		}
	}
	return false
}

// phraseIn reports the first template phrase in s (case-insensitively) and its
// byte offset, or "" and 0.
func phraseIn(s string) (string, int) {
	low := strings.ToLower(s)
	for _, p := range templatePhrases {
		if at := strings.Index(low, p); at >= 0 {
			return p, at
		}
	}
	return "", 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
