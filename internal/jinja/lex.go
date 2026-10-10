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
	kind tokenKind
	off  int
	end  int
	val  string
}

// lex splits a Jinja2 template into a flat token stream: literal text, comment
// bodies, raw-block bodies, tag delimiters and the expression tokens inside
// {{ }} and {% %}. It is a lexer and not a parser on purpose: the rules need
// names, string values and adjacency, not a tree, and a token stream is the part
// a scanner can afford to build for a template that arrived inside a GGUF.
func lex(src string) []token {
	var toks []token
	n := len(src)
	textStart := 0
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
			j := strings.Index(src[lo:], "}}")
			if j < 0 {
				toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{{"})
				toks = append(toks, lexExpr(src, lo, n)...)
				i = n
				break
			}
			hi := lo + j
			if hi > lo && src[hi-1] == '-' {
				hi--
			}
			toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{{"})
			toks = append(toks, lexExpr(src, lo, hi)...)
			toks = append(toks, token{kind: kindTagEnd, off: hi, end: hi + 2, val: "}}"})
			i = lo + j + 2

		case '%':
			lo := i + 2
			if lo < n && src[lo] == '-' {
				lo++
			}
			j := strings.Index(src[lo:], "%}")
			if j < 0 {
				toks = append(toks, token{kind: kindTag, off: i, end: i + 2, val: "{%"})
				toks = append(toks, lexExpr(src, lo, n)...)
				i = n
				break
			}
			hi := lo + j
			if hi > lo && src[hi-1] == '-' {
				hi--
			}
			inner := lexExpr(src, lo, hi)
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
				clo := closeStart + 2
				if clo < n && src[clo] == '-' {
					clo++
				}
				cj := strings.Index(src[clo:], "%}")
				chi := clo + cj
				if chi > clo && src[chi-1] == '-' {
					chi--
				}
				toks = append(toks, token{kind: kindTag, off: closeStart, end: closeStart + 2, val: "{%"})
				toks = append(toks, lexExpr(src, clo, chi)...)
				toks = append(toks, token{kind: kindTagEnd, off: chi, end: chi + 2, val: "%}"})
				i = clo + cj + 2
			}
		}
		textStart = i
	}
	flush(n)
	return toks
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
		p := abs + 2
		if p < len(src) && src[p] == '-' {
			p++
		}
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
// offsets relative to the full template so a finding points at real bytes.
func lexExpr(src string, lo, hi int) []token {
	var toks []token
	i := lo
	for i < hi {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++

		case c == '\'' || c == '"':
			val, next := decodeString(src, i, hi)
			toks = append(toks, token{kind: kindString, off: i, end: next, val: val})
			i = next

		case c >= '0' && c <= '9':
			start := i
			for i < hi && (src[i] >= '0' && src[i] <= '9' || src[i] == '.' || src[i] == '_' ||
				src[i] == 'x' || src[i] == 'X' || isHex(src[i])) {
				i++
			}
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
func decodeString(src string, i, hi int) (string, int) {
	q := src[i]
	var b strings.Builder
	i++
	for i < hi {
		if src[i] == '\\' && i+1 < hi {
			b.WriteString(unescape(src, &i, hi))
			continue
		}
		if src[i] == q {
			return b.String(), i + 1
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String(), hi
}

// unescape decodes one backslash escape starting at src[*i] (which is the
// backslash) and advances *i past it. Unknown escapes keep the escaped byte, as
// Jinja does.
func unescape(src string, i *int, hi int) string {
	c := src[*i+1]
	*i += 2
	switch c {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '0':
		return "\x00"
	case '\\', '\'', '"', '/':
		return string(c)
	case 'x':
		if *i+2 <= hi {
			v := hexVal(src[*i])<<4 | hexVal(src[*i+1])
			*i += 2
			return string(rune(v))
		}
	case 'u':
		if *i+4 <= hi {
			var r rune
			for k := 0; k < 4; k++ {
				r = r<<4 | rune(hexVal(src[*i+k]))
			}
			*i += 4
			if r >= 0xD800 && r <= 0xDFFF {
				// A surrogate escape is not a valid rune on its own; keep it as
				// the replacement character rather than emitting invalid UTF-8.
				return "\uFFFD"
			}
			return string(r)
		}
	}
	return string(c)
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
