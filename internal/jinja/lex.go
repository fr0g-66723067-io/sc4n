package jinja

import "strings"

// tokenKind classifies one token of a template.
type tokenKind uint8

const (
	kindText    tokenKind = iota // literal template text, outside every tag
	kindComment                  // the body of a {# … #}
	kindRaw                      // the body of a {% raw %}…{% endraw %}
	kindTag                      // an opener: "{{" or "{%"
	kindTagEnd                   // a closer: "}}" or "%}"
	kindName                     // an identifier
	kindString                   // a string literal; val is the decoded value
	kindNumber                   // a numeric literal
	kindOp                       // an operator or delimiter
)

// token is a half-open [off,end) byte range of the template. val carries the
// decoded string value for kindString and the literal text otherwise.
type token struct {
	kind   tokenKind
	off    int
	end    int
	val    string
	opaque bool // a \N{...} escape whose name sc4n cannot decode
}

// lex splits a Jinja2 template into a flat token stream: literal text, comment
// bodies, raw-block bodies, tag delimiters and the expression tokens inside
// {{ }} and {% %}. It is a lexer and not a parser on purpose: the rules need
// names, string values and adjacency, not a tree, and a token stream is the part
// a scanner can afford to build for a template that arrived inside a GGUF.
func lex(src string) ([]token, int) {
	var toks []token
	n := len(src)
	textStart := 0
	// stop reports the truncation point and releases the oversized backing
	// array. The budget is enforced while tokenising, not after: checking the
	// length once at the end meant a dense template was fully tokenised into
	// millions of structs before `toks[:maxJinjaTokens]` threw most of them away,
	// and the slice kept the whole array alive through analysis.
	stop := func() ([]token, int) {
		at := n
		if len(toks) > maxJinjaTokens {
			at = toks[maxJinjaTokens].off
		}
		if len(toks) >= maxJinjaTokens && cap(toks) > maxJinjaTokens {
			out := make([]token, maxJinjaTokens)
			copy(out, toks)
			toks = out
		}
		return toks, at
	}
	flush := func(end int) {
		if end > textStart {
			toks = append(toks, token{kind: kindText, off: textStart, end: end, val: src[textStart:end]})
		}
	}
	i := 0
	for i < n {
		if src[i] != '{' || i+1 >= n {
			i++
			continue
		}
		open := src[i+1]
		if open != '{' && open != '%' && open != '#' {
			i++
			continue
		}
		flush(i)
		if len(toks) >= maxJinjaTokens {
			return stop()
		}
		switch open {
		case '#':
			start := i + 2
			if start < n && src[start] == '-' {
				start++
			}
			j := strings.Index(src[start:], "#}")
			if j < 0 {
				toks = append(toks, token{kind: kindComment, off: start, end: n, val: src[start:]})
				i = n
				break
			}
			end := start + j
			if end > start && src[end-1] == '-' {
				end--
			}
			toks = append(toks, token{kind: kindComment, off: start, end: end, val: src[start:end]})
			i = start + j + 2

		case '{':
			lo := i + 2
			if lo < n && src[lo] == '-' {
				lo++
			}
			j := findTagClose(src, lo, "}}")
			if j < 0 {
				toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{{"})
				toks = append(toks, lexExpr(src, lo, n, maxJinjaTokens-len(toks))...)
				i = n
				break
			}
			hi := lo + j
			if hi > lo && src[hi-1] == '-' {
				hi--
			}
			toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{{"})
			toks = append(toks, lexExpr(src, lo, hi, maxJinjaTokens-len(toks))...)
			toks = append(toks, token{kind: kindTagEnd, off: hi, end: hi + 2, val: "}}"})
			i = lo + j + 2

		case '%':
			lo := i + 2
			lo = skipMark(src, lo, n)
			j := findTagClose(src, lo, "%}")
			if j < 0 {
				toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{%"})
				toks = append(toks, lexExpr(src, lo, n, maxJinjaTokens-len(toks))...)
				i = n
				break
			}
			hi := trimMarkEnd(src, lo, lo+j)
			inner := lexExpr(src, lo, hi, maxJinjaTokens-len(toks))
			toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{%"})
			toks = append(toks, inner...)
			toks = append(toks, token{kind: kindTagEnd, off: hi, end: hi + 2, val: "%}"})
			i = lo + j + 2
			// A raw/verbatim block swallows everything up to its matching end
			// tag, so the body must be captured whole rather than tokenised.
			if len(inner) > 0 && inner[0].kind == kindName && (inner[0].val == "raw" || inner[0].val == "verbatim") {
				bodyStart := i
				closeStart, ok := findEndBlock(src, i, "end"+inner[0].val)
				if !ok {
					toks = append(toks, token{kind: kindRaw, off: bodyStart, end: n, val: src[bodyStart:]})
					i = n
					break
				}
				toks = append(toks, token{kind: kindRaw, off: bodyStart, end: closeStart, val: src[bodyStart:closeStart]})
				clo := skipMark(src, closeStart+2, n)
				cj := findTagClose(src, clo, "%}")
				if cj < 0 {
					i = n
					break
				}
				chi := trimMarkEnd(src, clo, clo+cj)
				toks = append(toks, token{kind: kindTag, off: closeStart, end: closeStart + 2, val: "{%"})
				toks = append(toks, lexExpr(src, clo, chi, maxJinjaTokens-len(toks))...)
				toks = append(toks, token{kind: kindTagEnd, off: chi, end: chi + 2, val: "%}"})
				i = clo + cj + 2
			}
		}
		textStart = i
		if len(toks) >= maxJinjaTokens {
			return stop()
		}
	}
	flush(n)
	if len(toks) > maxJinjaTokens {
		return stop()
	}
	return toks, 0
}

// maxJinjaTokens bounds the flat token stream one template can produce. A
// template is metadata, not a program; a million tokens is already far above a
// real chat template and keeps the analyzer's quadratic-looking walks bounded.
const maxJinjaTokens = 1 << 20

// findTagClose returns the index of closer relative to lo, ignoring occurrences
// inside single- or double-quoted string literals (respecting backslash escapes).
func findTagClose(src string, lo int, closer string) int {
	var quote byte
	n := len(src)
	clen := len(closer)
	for i := lo; i < n; i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' && i+1 < n {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if i+clen <= n && src[i:i+clen] == closer {
			return i - lo
		}
	}
	return -1
}

// skipMark advances over a whitespace-control mark after a block opener or
// closer. Jinja accepts both '-' and '+'.
func skipMark(src string, p, n int) int {
	if p < n && (src[p] == '-' || src[p] == '+') {
		return p + 1
	}
	return p
}

// trimMarkEnd removes a trailing whitespace-control mark before a block closer.
func trimMarkEnd(src string, lo, hi int) int {
	if hi > lo && (src[hi-1] == '-' || src[hi-1] == '+') {
		return hi - 1
	}
	return hi
}

// findEndBlock returns the offset of the "{%" that opens the block named kw,
// searching from from. It is deliberately shallow: raw bodies cannot contain a
// "{% endraw %}" (that would end the block), so the first matching block wins.
func findEndBlock(src string, from int, kw string) (int, bool) {
	pos := from
	for pos < len(src) {
		k := strings.Index(src[pos:], "{%")
		if k < 0 {
			return 0, false
		}
		abs := pos + k
		p := skipMark(src, abs+2, len(src))
		for p < len(src) && (src[p] == ' ' || src[p] == '\t' || src[p] == '\n' || src[p] == '\r') {
			p++
		}
		start := p
		for p < len(src) && isNameChar(src[p]) {
			p++
		}
		if src[start:p] == kw {
			return abs, true
		}
		pos = abs + 2
	}
	return 0, false
}

// lexExpr tokenises src[lo:hi] on the off chance it is an expression, recording
// offsets relative to the full template so a finding points at real bytes. limit
// is the tokens this expression may still add to the template's budget.
func lexExpr(src string, lo, hi, limit int) []token {
	var toks []token
	i := lo
	for i < hi && len(toks) < limit {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++

		case c == '\'' || c == '"':
			val, next, opaque := decodeString(src, i, hi)
			toks = append(toks, token{kind: kindString, off: i, end: next, val: val, opaque: opaque})
			i = next

		case c >= '0' && c <= '9':
			start := i
			i = scanNumber(src, i, hi)
			toks = append(toks, token{kind: kindNumber, off: start, end: i, val: src[start:i]})

		case isNameStart(c):
			start := i
			for i < hi && isNameChar(src[i]) {
				i++
			}
			toks = append(toks, token{kind: kindName, off: start, end: i, val: src[start:i]})

		default:
			if i+1 < hi {
				two := src[i : i+2]
				switch two {
				case "==", "!=", "<=", ">=", "**", "//", "->":
					toks = append(toks, token{kind: kindOp, off: i, end: i + 2, val: two})
					i += 2
					continue
				}
			}
			toks = append(toks, token{kind: kindOp, off: i, end: i + 1, val: string(c)})
			i++
		}
	}
	return toks
}

// decodeString decodes the string literal whose opening quote is src[i].
// src[i] MUST be a quote and i < hi. It returns the decoded value and the index
// just past the closing quote (or hi when the literal is unterminated, in which
// case the opening quote is treated as literal text by the rules anyway).
func decodeString(src string, i, hi int) (string, int, bool) {
	q := src[i]
	var b strings.Builder
	opaque := false
	i++
	for i < hi {
		if src[i] == '\\' && i+1 < hi {
			b.WriteString(unescape(src, &i, hi, &opaque))
			continue
		}
		if src[i] == q {
			return b.String(), i + 1, opaque
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String(), hi, opaque
}

// unescape decodes one backslash escape starting at src[*i] (which is the
// backslash) and advances *i past it. Unknown escapes keep the escaped byte, as
// Jinja does.
func unescape(src string, i *int, hi int, opaque *bool) string {
	if *i+1 >= hi {
		*i = hi
		return ""
	}
	c := src[*i+1]
	*i += 2
	switch c {
	case '\n', '\r':
		if c == '\r' && *i < hi && src[*i] == '\n' {
			*i++
		}
		return ""
	case 'a':
		return "\a"
	case 'b':
		return "\b"
	case 'f':
		return "\f"
	case 'v':
		return "\v"
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '\\', '\'', '"', '/':
		return string(c)
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v := int(c - '0')
		for k := 0; k < 2 && *i < hi && src[*i] >= '0' && src[*i] <= '7'; k++ {
			v = v*8 + int(src[*i]-'0')
			*i++
		}
		if v > 0o377 {
			v = 0o377
		}
		return string(rune(v))
	case 'x':
		if *i+2 > hi || !isHex(src[*i]) || !isHex(src[*i+1]) {
			return "\\x"
		}
		v := hexVal(src[*i])<<4 | hexVal(src[*i+1])
		*i += 2
		return string(rune(v))
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if *i+n > hi {
			return "\\" + string(c)
		}
		var r rune
		for k := 0; k < n; k++ {
			if !isHex(src[*i+k]) {
				return "\\" + string(c)
			}
			r = r<<4 | rune(hexVal(src[*i+k]))
		}
		*i += n
		if r > 0x10FFFF || r >= 0xD800 && r <= 0xDFFF {
			return "\uFFFD"
		}
		return string(r)
	case 'N':
		if *i < hi && src[*i] == '{' {
			end := strings.IndexByte(src[*i+1:hi], '}')
			if end >= 0 {
				name := src[*i+1 : *i+1+end]
				*i += end + 2
				if r, ok := asciiUnicodeName(name); ok {
					return string(r)
				}
				if opaque != nil {
					*opaque = true
				}
				return ""
			}
		}
		return "\\N"
	}
	return "\\" + string(c)
}

// asciiUnicodeName decodes the small, printable set of \N{...} names a template
// might use. Anything else is left opaque rather than guessed at: the analyzer
// reports the undecoded escape as a dynamic name.
func asciiUnicodeName(name string) (rune, bool) {
	switch name {
	case "SPACE":
		return ' ', true
	case "HYPHEN-MINUS":
		return '-', true
	case "FULL STOP":
		return '.', true
	case "COLON":
		return ':', true
	case "LOW LINE":
		return '_', true
	}
	if strings.HasPrefix(name, "LATIN SMALL LETTER ") || strings.HasPrefix(name, "LATIN CAPITAL LETTER ") {
		rest := name[strings.LastIndexByte(name, ' ')+1:]
		if len(rest) == 1 && rest[0] >= 'A' && rest[0] <= 'Z' {
			if strings.HasPrefix(name, "LATIN SMALL") {
				return rune(rest[0] - 'A' + 'a'), true
			}
			return rune(rest[0]), true
		}
	}
	if strings.HasPrefix(name, "DIGIT ") {
		words := map[string]rune{"ZERO": '0', "ONE": '1', "TWO": '2', "THREE": '3', "FOUR": '4', "FIVE": '5', "SIX": '6', "SEVEN": '7', "EIGHT": '8', "NINE": '9'}
		if r, ok := words[name[len("DIGIT "):]]; ok {
			return r, true
		}
	}
	return 0, false
}

// scanNumber consumes a Jinja numeric literal starting at i < hi. It stops
// before a '.' followed by a non-digit (so `1.0.__class__` leaves `.__class__`
// intact) and accepts hex digits only after a `0x`/`0X` prefix.
func scanNumber(src string, i, hi int) int {
	if i+1 < hi && src[i] == '0' {
		switch src[i+1] {
		case 'x', 'X':
			j := i + 2
			for j < hi && (isHex(src[j]) || (src[j] == '_' && j+1 < hi && isHex(src[j+1]))) {
				j++
			}
			return j
		case 'o', 'O':
			j := i + 2
			for j < hi && ((src[j] >= '0' && src[j] <= '7') || (src[j] == '_' && j+1 < hi && src[j+1] >= '0' && src[j+1] <= '7')) {
				j++
			}
			return j
		case 'b', 'B':
			j := i + 2
			for j < hi && ((src[j] == '0' || src[j] == '1') || (src[j] == '_' && j+1 < hi && (src[j+1] == '0' || src[j+1] == '1'))) {
				j++
			}
			return j
		}
	}
	j := i
	for j < hi && (isDigit(src[j]) || (src[j] == '_' && j+1 < hi && isDigit(src[j+1]))) {
		j++
	}
	if j+1 < hi && src[j] == '.' && isDigit(src[j+1]) {
		j++
		for j < hi && (isDigit(src[j]) || (src[j] == '_' && j+1 < hi && isDigit(src[j+1]))) {
			j++
		}
	}
	if j < hi && (src[j] == 'e' || src[j] == 'E') {
		k := j + 1
		if k < hi && (src[k] == '+' || src[k] == '-') {
			k++
		}
		if k < hi && isDigit(src[k]) {
			j = k
			for j < hi && (isDigit(src[j]) || (src[j] == '_' && j+1 < hi && isDigit(src[j+1]))) {
				j++
			}
		}
	}
	return j
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isNameStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isNameChar(c byte) bool {
	return isNameStart(c) || c >= '0' && c <= '9'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}
