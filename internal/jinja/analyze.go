package jinja

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/malice"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
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
	"ignore the above",
	"disregard the above",
	"forget the above",
	"forget all previous",
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

// overridePhrases are the phrases that exist only to replace the application's own
// instructions: they are the attack's own words. The rest of the table is the
// concealment class ("do not tell the user", "do not mention this"), which is also
// how a legitimate tool-use instruction reads — measured on llama.cpp's 71 real
// chat templates, three of them say "do not tell the user about function calls".
// That is the whole reason the rule has two severities.
var overridePhrases = map[string]bool{
	"ignore previous instructions": true,
	"ignore all previous":          true,
	"ignore the previous":          true,
	"disregard previous":           true,
	"disregard all previous":       true,
	"ignore the above":             true,
	"disregard the above":          true,
	"forget the above":             true,
	"forget all previous":          true,
	"override your instructions":   true,
	"ignore your instructions":     true,
	"new instructions:":            true,
	"system prompt:":               true,
	"exfiltrate":                   true,
	"send the conversation":        true,
	"send the chat history":        true,
	"send all messages":            true,
	"hidden instruction":           true,
	"you must obey":                true,
}

// OverrideDirective reports whether a matched phrase belongs to the override
// class: an instruction that has no legitimate reading in a chat template. A
// concealment phrase is not one, and a caller that reports a phrase (this package
// for templates, internal/gguf for GGUF chat templates) uses this to choose
// between its high-severity rule and its weak one.
func OverrideDirective(phrase string) bool {
	return overridePhrases[strings.ToLower(strings.TrimSpace(phrase))]
}

// Analyze scans one Jinja2 template and reports every finding through sink at
// offsets derived from base. name is used for evidence only.
func Analyze(sink *report.Sink, base int64, name, template string) {
	if template == "" {
		return
	}
	toks, truncatedAt := lex(template)
	a := &analyzer{
		sink:         sink,
		base:         base,
		name:         name,
		tmpl:         template,
		toks:         toks,
		corroborated: corroborated(template),
		chainBudget:  8*len(toks) + 1024,
		aliasValue:   map[string]string{},
		aliasGlobal:  map[string]string{},
	}
	if truncatedAt > 0 {
		limits.Emit(sink, limits.RuleEntries, "MaxJinjaTokens", int64(len(toks)+1), maxJinjaTokens, "template token stream")
	}
	a.structure()
	a.expressions()
	// The phrase findings are emitted last, because whether one deserves the
	// high-severity rule depends on the rest of the template — including whether
	// the template is a Python-object payload, which only the expression pass
	// knows. The report orders findings by (artifact, offset), so deferring them
	// changes nothing a reader sees.
	for _, p := range a.pending {
		if a.corroborated || a.ssti || OverrideDirective(p.phrase) {
			a.emit(ruleTemplateInjection, p.off, p.ev)
			continue
		}
		a.emit(ruleTemplateInjectionWeak, p.off, p.ev+
			"; nothing else in the template corroborates it (no URL, hidden comment, invisible run, base64 blob or Python-object walk)")
	}
}

type analyzer struct {
	sink *report.Sink
	base int64
	name string
	toks []token
	// tmpl is the template source the tokens index into. It is kept so a chain
	// can be quoted from the template rather than rebuilt from tokens, which is
	// what makes the constructed grade's evidence readable.
	tmpl string
	// maliceDone records that the constructed grade was emitted for this
	// template: the decision is "rendering this template runs a call", not
	// "this expression runs a call".
	maliceDone bool
	// corroborated records whether the template carries a channel that makes an
	// instruction phrase actionable. It is computed once, over the whole
	// template, because the phrase and its channel are usually in different
	// places (a directive in a comment, a webhook URL in a string).
	corroborated bool
	// ssti records that the expression pass reported a Python-object walk: a
	// template that reaches __class__ or lipsum.__globals__ is a payload, so any
	// instruction sentence in it is part of that payload.
	ssti bool
	// pending holds the model-directed phrases until the rest of the template has
	// been analysed.
	pending []pendingInjection
	// chainBudget bounds the group/chain walk. It is linear in the token count
	// with a fixed allowance, so a template made of bracket soup cannot turn the
	// analyzer into quadratic work.
	chainBudget int
	chainLimit  bool
	// aliasValue and aliasGlobal remember a strict {% set NAME = ... %} binding.
	// They are how `{% set g = '__g' %}{{ g + 'lobals__' }}` and a computed
	// subscript stay visible without building a general interpreter.
	aliasValue  map[string]string
	aliasGlobal map[string]string
}

// pendingInjection is one phrase awaiting its severity decision.
type pendingInjection struct {
	off    int
	ev     string
	phrase string
}

// emitInjection queues a model-directed phrase. An override directive is the
// attack's own words and is always reported at high severity; a concealment
// phrase needs corroboration, because "do not tell the user about function calls"
// is how a legitimate tool-use instruction reads. The decision is made in
// Analyze, once the whole template has been analysed.
func (a *analyzer) emitInjection(off int, ev, phrase string) {
	a.pending = append(a.pending, pendingInjection{off: off, ev: ev, phrase: phrase})
}

// corroborated reports whether a template carries a channel that makes a
// model-directed phrase actionable: a reachable secret or endpoint (the shared
// table decides, so there is one definition of "exfil endpoint"), a hidden HTML
// comment, an invisible-character run, or a base64 blob of at least minBase64Blob
// characters. A Python-object walk corroborates too, but that is recorded by the
// expression pass (see analyzer.ssti) rather than guessed from the text.
func corroborated(template string) bool {
	if stringscan.HasSecretHit(template) {
		return true
	}
	if strings.Contains(template, "<!--") {
		return true
	}
	return hasInvisibleRun(template) || hasBase64Blob(template)
}

// minBase64Blob is the shortest base64 run treated as a payload. Below it the
// run is a token, a hash or an ordinary identifier.
const minBase64Blob = 64

// hasInvisibleRun reports whether the template contains three or more
// consecutive characters from the zero-width, bidi-override and
// soft-hyphen classes — the Trojan-Source channel (CWE-1007). One such
// character is a formatting artefact; a run of them is a way to hide text.
func hasInvisibleRun(template string) bool {
	run := 0
	for _, r := range template {
		if isInvisible(r) {
			run++
			if run >= 3 {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

func isInvisible(r rune) bool {
	switch {
	case r == 0x00AD || r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF:
		return true
	case r >= 0x200E && r <= 0x200F: // LRM, RLM
		return true
	case r >= 0x202A && r <= 0x202E: // bidi embedding/override
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0x061C: // Arabic letter mark
		return true
	}
	return false
}

// hasBase64Blob reports whether the template contains a base64-alphabet run of at
// least minBase64Blob characters that actually decodes. Requiring a successful
// decode keeps a long identifier or a token from counting.
func hasBase64Blob(template string) bool {
	start := -1
	for i := 0; i <= len(template); i++ {
		if i < len(template) && isBase64Byte(template[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minBase64Blob {
			if _, err := base64.StdEncoding.DecodeString(template[start:i]); err == nil {
				return true
			}
		}
		start = -1
	}
	return false
}

func isBase64Byte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+' || c == '/' || c == '=':
		return true
	}
	return false
}

func (a *analyzer) emit(r *report.Rule, off int, ev string) {
	if r == rulePyObject || r == ruleDangerousGlobal {
		a.ssti = true
	}
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
				a.emitInjection(t.off+at, "template text contains the instruction "+strconv.Quote(p), p)
			}
		case kindComment:
			if p, at := phraseIn(t.val); p != "" {
				a.emitInjection(t.off+at, "a {# comment #} contains the instruction "+strconv.Quote(p), p)
			}
		case kindRaw:
			a.emit(ruleRaw, t.off, "{% raw %} hides "+strconv.Itoa(len(t.val))+" bytes from a {{ }} scanner")
			if p, at := phraseIn(t.val); p != "" {
				a.emitInjection(t.off+at, "a {% raw %} block contains the instruction "+strconv.Quote(p), p)
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

// analyzeSet reports a {% set %} whose right-hand side assembles a *name* out of
// pieces. inner starts at the "set" keyword and excludes the closing tag.
//
// The trigger is deliberately positive rather than "anything not in the
// allowlist". Measured on llama.cpp's 71 real chat templates, the allowlist form
// produced 873 findings for statements like `{% set ns = namespace(...) %}`,
// `{% set a = b + c %}` and `{% set x = y.attr %}` — ordinary template style, and
// a wall of medium findings on every benign repository. What the rule is for is
// the other shape: '__g' + 'lobals__', which exists only to keep a dunder name
// out of a literal scanner.
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
	rhs := inner[eq+1:]
	// A strict simple binding is useful later in the template even when it is
	// benign on its own: `{% set g = '__g' %}` followed by a computed subscript
	// is the alias case. Last assignment wins.
	if len(inner) > 1 && inner[1].kind == kindName {
		name := inner[1].val
		if len(rhs) == 1 && rhs[0].kind == kindString {
			a.aliasValue[name] = rhs[0].val
		} else if len(rhs) == 1 && rhs[0].kind == kindName {
			a.aliasGlobal[name] = rhs[0].val
		}
	}
	if simpleRHS(rhs) || !buildsAName(rhs) {
		return
	}
	a.emit(ruleDynamicName, inner[0].off,
		"{% set %} assembles a name out of literal pieces, which hides it from a literal scan")
}

// buildsAName reports whether rhs constructs a name rather than computing a
// value: a chain of two or more string literals joined by + or ~, or a subscript
// whose index is such a chain.
func buildsAName(rhs []token) bool {
	if stringLiteralChain(rhs) {
		return true
	}
	depth := 0
	for k := range rhs {
		if rhs[k].kind != kindOp {
			continue
		}
		switch rhs[k].val {
		case "[":
			if depth == 0 {
				if end := matchingBracket(rhs, k); end > 0 && stringLiteralChain(rhs[k+1:end]) {
					return true
				}
			}
			depth++
		case "]":
			depth--
		}
	}
	return false
}

// matchingBracket returns the index of the ] that closes the [ at k, or -1.
func matchingBracket(rhs []token, k int) int {
	depth := 0
	for j := k; j < len(rhs); j++ {
		if rhs[j].kind != kindOp {
			continue
		}
		switch rhs[j].val {
		case "[":
			depth++
		case "]":
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// stringLiteralChain reports whether toks is two or more string literals joined
// by + or ~ — the '__g' + 'lobals__' shape. A bare list of literals is not a
// chain: the lexer drops commas, so `['a', 'b']` and `'a' + 'b'` have the same
// literal count and only the presence of a join tells them apart. A single
// literal, or a literal concatenated with a variable, is ordinary style.
func stringLiteralChain(toks []token) bool {
	literals, joins := 0, 0
	for k := range toks {
		switch {
		case toks[k].kind == kindString:
			literals++
		case toks[k].kind == kindOp && (toks[k].val == "+" || toks[k].val == "~"):
			joins++
		default:
			return false
		}
	}
	return literals >= 2 && joins >= 1
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
	raiseArg := a.raiseArgs()
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case kindString:
			if t.opaque {
				a.emit(ruleDynamicName, t.off, "a \\N{...} escape names a character sc4n cannot decode")
			}
			if !raiseArg[i] {
				if p, _ := phraseIn(t.val); p != "" {
					a.emitInjection(t.off, "a template string contains the instruction "+strconv.Quote(p), p)
				}
			}
			joined, next, ok := a.concatAt(i)
			if ok {
				if strings.Contains(joined, "__") {
					a.emit(ruleDynamicName, t.off, "string concatenation builds "+strconv.Quote(report.TruncateEvidence(joined, 80))+
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
				a.calledReach(i, i)
			}
			recv := t.val
			if v, ok := a.aliasGlobal[recv]; ok {
				recv = v
			}
			if dangerousGlobals[recv] && i+1 < len(toks) && toks[i+1].kind == kindOp &&
				(toks[i+1].val == "." || toks[i+1].val == "[") {
				a.emit(ruleDangerousGlobal, t.off, t.val+" is used as the receiver of attribute/subscript access")
			}

		case kindOp:
			switch t.val {
			case ".":
				if i+1 < len(toks) && toks[i+1].kind == kindName && dunderNames[toks[i+1].val] {
					a.emit(rulePyObject, toks[i+1].off, "attribute access ."+toks[i+1].val)
					a.calledReach(i+1, i+1)
				}
			case "[":
				if i+2 < len(toks) && toks[i+1].kind == kindString && toks[i+2].kind == kindOp &&
					toks[i+2].val == "]" && dunderNames[toks[i+1].val] {
					a.emit(rulePyObject, t.off, "subscript access ["+strconv.Quote(toks[i+1].val)+"]")
					a.calledReach(i, i+2)
				} else if i+2 < len(toks) && toks[i+1].kind == kindName && toks[i+2].kind == kindOp && toks[i+2].val == "]" {
					a.checkComputedIndex(i, toks[i+1])
				}
			case "|":
				a.attrFilter(i)
				a.attrPathFilters(i)
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
	if i+3 < len(toks) && (toks[i+3].kind == kindString || toks[i+3].kind == kindName) {
		s := toks[i+3].val
		if v, ok := a.aliasValue[s]; ok {
			s = v
		}
		switch {
		case strings.HasPrefix(s, "__"):
			a.emit(rulePyObject, toks[i+1].off, "attr filter selects "+strconv.Quote(s))
			if end, ok := a.skipGroup(i+2, "(", ")"); ok {
				a.calledReach(i+1, end-1)
			}
		case strings.HasPrefix(s, "_"):
			a.emit(ruleDangerousGlobal, toks[i+1].off, "attr filter selects the private name "+strconv.Quote(s))
		case toks[i+3].kind == kindName:
			a.emit(ruleDynamicName, toks[i+1].off, "attr filter is applied to a computed name")
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
	// The pieces are written into one Builder rather than joined with += : a
	// chain of n literals rebuilt the accumulated string on every step, which
	// made a 400000-element chain quadratic (measured 19.6 s; the Builder takes
	// it under 2 s).
	var b strings.Builder
	b.WriteString(toks[i].val)
	k := i + 1
	count := 0
	for k+1 < len(toks) && toks[k].kind == kindOp && (toks[k].val == "+" || toks[k].val == "~") &&
		toks[k+1].kind == kindString {
		b.WriteString(toks[k+1].val)
		k += 2
		count++
	}
	if count == 0 {
		return "", i, false
	}
	return b.String(), k, true
}

// raiseArgs marks, for every token index, whether the innermost enclosing
// parenthesis belongs to a raise_exception() call. raise_exception is provided
// by Transformers and is legitimate, so its message text is never treated as an
// injection.
//
// The mark is computed in one forward pass: a stack of open parenthesis indices
// is kept per tag (a tag boundary clears it, matching the earlier rule that a
// reference is never attributed across a tag), and the innermost open
// parenthesis is the stack top. Walking backwards to the opener for every
// string token made a tag of n strings quadratic.
func (a *analyzer) raiseArgs() []bool {
	toks := a.toks
	out := make([]bool, len(toks))
	var stack []int
	for i := range toks {
		t := toks[i]
		if t.kind == kindTag || t.kind == kindTagEnd {
			stack = stack[:0]
			continue
		}
		if t.kind == kindOp {
			switch t.val {
			case "(":
				stack = append(stack, i)
			case ")":
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		}
		if len(stack) > 0 {
			j := stack[len(stack)-1]
			out[i] = j > 0 && toks[j-1].kind == kindName && toks[j-1].val == "raise_exception"
		}
	}
	return out
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

// calledReach emits the constructed grade when a Python-object reach is invoked.
//
// SC4N-JINJA-PY-OBJECT says the template reaches an object; whether rendering it
// *runs* something is the difference between a template that reads __class__ and
// one that calls os.popen through __globals__. from is the first token of the
// reach and last the last, so the chain can be quoted from the template.
func (a *analyzer) calledReach(from, last int) {
	if a.maliceDone {
		return
	}
	end, called := a.chainCall(last)
	if !called {
		return
	}
	a.maliceDone = true
	chain := a.tmpl[a.toks[from].off:a.toks[end].end]
	ev := "the template calls " + report.TruncateEvidence(chain, 80) +
		"; rendering the template executes it"
	extra := map[string]string{"chain": report.TruncateEvidence(chain, 80)}
	if a.name != "" {
		ev += " (in " + a.name + ")"
		extra["template"] = a.name
	}
	malice.Constructed(a.sink, a.base+int64(a.toks[from].off), malice.FamilyTemplateCall, ev, extra)
}

// chainCall walks the dotted/subscript chain that starts at last+1 and reports
// the index of the closing token of the first call in it. A chain that is only
// read, or that ends at a non-call operator, is not a call.
func (a *analyzer) chainCall(last int) (int, bool) {
	toks := a.toks
	k := last + 1
	for k < len(toks) && toks[k].kind == kindOp {
		if !a.chargeChain() {
			return k, false
		}
		switch toks[k].val {
		case ".":
			if k+1 >= len(toks) || toks[k+1].kind != kindName {
				return k, false
			}
			k += 2
		case "[":
			next, ok := a.skipGroup(k, "[", "]")
			if !ok {
				return k, false
			}
			k = next
		case "(":
			next, ok := a.skipGroup(k, "(", ")")
			if !ok {
				return k, true
			}
			return next - 1, true
		default:
			return k, false
		}
	}
	return k, false
}

// chargeChain spends one unit of the chain/group budget. Overflow is reported
// once and stops the walk that asked.
func (a *analyzer) chargeChain() bool {
	if a.chainBudget <= 0 {
		if !a.chainLimit {
			a.chainLimit = true
			limits.Emit(a.sink, limits.RuleEntries, "MaxJinjaChainTokens", 0, 0, "Jinja chain analysis")
		}
		return false
	}
	a.chainBudget--
	return true
}

// checkComputedIndex resolves a name used as a subscript index through the
// strict {% set %} alias table.
func (a *analyzer) checkComputedIndex(i int, idx token) {
	v, ok := a.aliasValue[idx.val]
	if !ok {
		return
	}
	switch {
	case strings.HasPrefix(v, "__"):
		a.emit(rulePyObject, idx.off, "computed subscript selects "+strconv.Quote(v))
		a.calledReach(i, i+2)
	case strings.HasPrefix(v, "_"):
		a.emit(ruleDangerousGlobal, idx.off, "computed subscript selects the private name "+strconv.Quote(v))
	default:
		a.emit(ruleDynamicName, idx.off, "computed subscript selects "+strconv.Quote(v))
	}
}

// attrPathFilters reports a dunder or private attribute named inside a filter's
// attribute= (or dictsort's by=) argument. Those filters read an attribute by
// name just like attr, so leaving them out bypassed the same check.
var attrPathFilters = map[string]bool{
	"map": true, "selectattr": true, "rejectattr": true, "sort": true, "unique": true,
	"min": true, "max": true, "sum": true, "join": true, "groupby": true, "dictsort": true,
}

func (a *analyzer) attrPathFilters(i int) {
	toks := a.toks
	if i+2 >= len(toks) || toks[i+1].kind != kindName || !attrPathFilters[toks[i+1].val] ||
		toks[i+2].kind != kindOp || toks[i+2].val != "(" {
		return
	}
	end, ok := a.skipGroup(i+2, "(", ")")
	if !ok {
		return
	}
	for k := i + 3; k+2 < end; k++ {
		if toks[k].kind != kindName || (toks[k].val != "attribute" && toks[k].val != "by") ||
			toks[k+1].kind != kindOp || toks[k+1].val != "=" {
			continue
		}
		if toks[k+2].kind != kindString {
			a.emit(ruleDynamicName, toks[k].off, "filter "+toks[i+1].val+" reads a computed attribute name")
			continue
		}
		a.checkPathValue(toks[k+2])
	}
}

func (a *analyzer) checkPathValue(tok token) {
	for _, part := range strings.Split(tok.val, ",") {
		for _, seg := range strings.Split(part, ".") {
			switch {
			case dunderNames[seg]:
				a.emit(rulePyObject, tok.off, "filter attribute path selects "+strconv.Quote(seg))
			case strings.HasPrefix(seg, "_"):
				a.emit(ruleDangerousGlobal, tok.off, "filter attribute path selects the private name "+strconv.Quote(seg))
			}
		}
	}
}

// skipGroup returns the index just past the group that opens at k, and whether
// the group was terminated. It charges the chain budget once per visited token.
func (a *analyzer) skipGroup(k int, open, close string) (int, bool) {
	depth := 0
	for i := k; i < len(a.toks); i++ {
		if !a.chargeChain() {
			return k, false
		}
		if a.toks[i].kind != kindOp {
			continue
		}
		switch a.toks[i].val {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return k, false
}
