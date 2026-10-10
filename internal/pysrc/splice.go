// Statement splicing and call indexing.
//
// There is deliberately no AST and no type inference here. The scanner cannot
// know that `f` is a file object or that `mod` is `subprocess`, so taint is
// tracked at statement granularity (`x = os.getenv(...)` marks `x`, and a sink in
// a later statement of the same function that mentions `x` is reported) and not
// across function boundaries or through containers. That trade is the reason
// sc4n can analyse Python with no Python on the host at all, and every rule
// description states it, so a clean result is not read as a proof of safety.
package pysrc

import "strings"

// Span is a byte range in the source. It is how an argument or a value is handed
// to a rule without copying its text.
type Span struct {
	Off int32
	End int32
}

// Bytes returns the span's bytes, which alias src.
func (s Span) Bytes(src []byte) []byte {
	if s.Off < 0 || s.End > int32(len(src)) || s.Off > s.End {
		return nil
	}
	return src[s.Off:s.End]
}

// Text returns the span's text.
func (s Span) Text(src []byte) string {
	return string(s.Bytes(src))
}

// Call is one call expression found in a statement.
type Call struct {
	// Dotted is the callee's dotted name as written, for example `os.system` or
	// `base64.b64decode`. A call through an expression receiver (for example
	// `"".join([...])` or `obj.method(...)`) is reported under the method name
	// alone, because resolving the receiver is type inference sc4n does not do.
	Dotted string
	// Off and End bound the callee name in the source.
	Off int32
	End int32
	// Args are the positional arguments in order.
	Args []Span
	// Kwargs maps a keyword argument name to its value span.
	Kwargs map[string]Span

	// argToks and kwToks are the token-index ranges backing Args and Kwargs,
	// used by the taint engine to test whether an argument expresses a source.
	argToks [][2]int32
	kwToks  map[string][2]int32
}

// Statements groups the token stream into statements, splitting at logical
// newlines, `;` and INDENT/DEDENT transitions. Comments, blank lines and the end
// sentinel are dropped. The returned slices reference toks.
func Statements(src []byte, toks []Token) [][]Token {
	var out [][]Token
	var cur []Token
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
	}
	for i := range toks {
		t := toks[i]
		switch t.Kind {
		case TokEnd, TokComment:
			continue
		case TokNewline, TokIndent, TokDedent:
			flush()
		case TokOp:
			if t.Len() == 1 && t.Bytes(src)[0] == ';' {
				flush()
				continue
			}
			cur = append(cur, t)
		default:
			cur = append(cur, t)
		}
	}
	flush()
	return out
}

// Calls indexes the call expressions in one statement. A call is a dotted name
// immediately followed by `(`. Every token of the callee's chain is consumed, so
// that `os.system` yields one call (`os.system`) rather than two (`os.system` and
// `system`), while a call nested inside another call's arguments is still found
// because the scan does not skip the argument tokens. A chain that is not a call
// is consumed as well, because none of its elements can be a call either and the
// alternative re-walks the whole chain once per element.
func Calls(src []byte, stmt []Token) []Call {
	var calls []Call
	if len(stmt) == 0 {
		return nil
	}
	consumed := make([]bool, len(stmt))
	for i := range stmt {
		if consumed[i] {
			continue
		}
		t := stmt[i]
		if t.Kind != TokName && t.Kind != TokKeyword {
			continue
		}
		j := chainEnd(src, stmt, i)
		parts := make([]string, 0, (j-i)/2+1)
		for k := i; k <= j; k += 2 {
			parts = append(parts, stmt[k].Text(src))
		}
		// Mark the whole chain consumed whether or not it is a call. A chain
		// that is not followed by `(` has no call at any of its elements
		// either (a suffix reaches the same final token), so without this the
		// outer loop would re-walk the chain once per element; on a long dotted
		// chain that is quadratic (measured: `a.` x 200000 > 120 s).
		for k := i; k <= j; k++ {
			consumed[k] = true
		}
		if j+1 >= len(stmt) || !isOpenParen(src, stmt[j+1]) {
			continue
		}
		c := Call{
			Dotted: strings.Join(parts, "."),
			Off:    stmt[i].Off,
			End:    stmt[j].End,
		}
		c.Args, c.Kwargs, c.argToks, c.kwToks = parseArgs(src, stmt, j+1)
		calls = append(calls, c)
	}
	return calls
}

// parseArgs parses the argument list whose `(` is at stmt[open].
func parseArgs(src []byte, stmt []Token, open int) (args []Span, kwargs map[string]Span, argToks [][2]int32, kwToks map[string][2]int32) {
	kwargs = map[string]Span{}
	kwToks = map[string][2]int32{}

	add := func(s, e int) {
		if s > e || s >= len(stmt) || e >= len(stmt) {
			return
		}
		// A keyword argument is a name followed by a single `=`.
		if (stmt[s].Kind == TokName || stmt[s].Kind == TokKeyword) && s+1 <= e && isAssignOp(src, stmt[s+1]) {
			name := stmt[s].Text(src)
			vs := s + 2
			if vs <= e {
				kwargs[name] = Span{stmt[vs].Off, stmt[e].End}
				kwToks[name] = [2]int32{int32(vs), int32(e)}
			}
			return
		}
		args = append(args, Span{stmt[s].Off, stmt[e].End})
		argToks = append(argToks, [2]int32{int32(s), int32(e)})
	}

	depth := 0
	start := open + 1
	for k := open + 1; k < len(stmt); k++ {
		t := stmt[k]
		if t.Kind != TokOp {
			continue
		}
		b := t.Bytes(src)
		if len(b) == 0 {
			continue
		}
		switch b[0] {
		case '(', '[', '{':
			depth++
		case ')':
			if depth == 0 {
				add(start, k-1)
				return
			}
			depth--
		case ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				add(start, k-1)
				start = k + 1
			}
		}
	}
	// Unterminated call: report the arguments seen rather than dropping them.
	add(start, len(stmt)-1)
	return
}

func isDot(src []byte, t Token) bool {
	return t.Kind == TokOp && t.Len() == 1 && t.Bytes(src)[0] == '.'
}

func isOpenParen(src []byte, t Token) bool {
	return t.Kind == TokOp && t.Len() == 1 && t.Bytes(src)[0] == '('
}

func isAssignOp(src []byte, t Token) bool {
	return t.Kind == TokOp && t.Len() == 1 && t.Bytes(src)[0] == '='
}

// chainEnd returns the token index of the last element of the dotted chain that
// begins at stmt[k], which must be a name or a keyword. The chain is a name
// followed by any number of `.name` pairs; the walk visits each pair once, so a
// caller that walks k..chainEnd is linear in the chain length. (The previous
// chainAt called strings.Join for every element-aligned suffix, which was
// quadratic on a long dotted chain.)
func chainEnd(src []byte, stmt []Token, k int) int {
	j := k
	for j+2 < len(stmt) && isDot(src, stmt[j+1]) && (stmt[j+2].Kind == TokName || stmt[j+2].Kind == TokKeyword) {
		j += 2
	}
	return j
}

func dottedLast(d string) string {
	if i := strings.LastIndexByte(d, '.'); i >= 0 {
		return d[i+1:]
	}
	return d
}

func dottedHasPackage(d, pkg string) bool {
	return d == pkg || strings.HasPrefix(d, pkg+".")
}
