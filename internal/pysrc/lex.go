// Package pysrc analyses the Python and notebook code that surrounds a model
// artifact: the model-loading code shipped in the repository, the repository
// files that execute at install or interpreter start, and the code cells of a
// notebook. It is a hand-written lexer plus a statement-level, taint-ish rule
// engine rather than an AST:
//
//   - the scan host has no Python and no parser library, and adding one would be
//     a dependency the plan forbids;
//   - the questions the rules ask ("does a value that came from the network reach
//     exec?") are answerable at statement granularity, and a partial answer that
//     is honest about its limits beats a full parse that has to be maintained
//     against every Python point release.
//
// The lexer is the one place that understands Python's surface syntax; everything
// else works on the token stream it produces. It follows the lexical rules of
// Python 3.14 (grammar: https://docs.python.org/3.14/reference/lexical_analysis.html):
// comments, every string prefix combination (r/b/u/f, case-insensitive,
// triple-quoted, and f-strings that nest expressions and further strings),
// numbers, unicode identifiers, operators and delimiters, explicit (`\`) and
// implicit (bracket) line joining, INDENT/DEDENT via an indentation stack,
// `;`-separated simple statements, decorators, and the soft keywords `match`,
// `case` and `type`.
//
// Tokens are offset views into the source (Token is 12 bytes, holding no string),
// so lexing allocates only the token slice. String literal *values* are unescaped
// lazily and under a cap by the callers that need a value, never by the lexer.
package pysrc

// Kind classifies a token. It is deliberately coarse: the rules care about
// whether a token is a name, a string, a keyword or an operator, not about which
// operator, beyond comparing the few bytes at [Off:End).
type Kind uint8

const (
	// TokEnd is the sentinel appended at end of input.
	TokEnd Kind = iota
	// TokNewline is a logical end-of-line as the `tokenize` module models it: a
	// physical newline that ends a statement (not one inside brackets or after an
	// explicit backslash join).
	TokNewline
	// TokIndent is emitted when indentation increases.
	TokIndent
	// TokDedent is emitted once per level when indentation decreases.
	TokDedent
	// TokName is an identifier (including non-ASCII).
	TokName
	// TokKeyword is one of the reserved or soft keywords.
	TokKeyword
	// TokNumber is a numeric literal.
	TokNumber
	// TokString is any string literal, including its prefix and quotes.
	TokString
	// TokOp is an operator or delimiter.
	TokOp
	// TokComment is a `#` comment (text after the `#`, not including the newline).
	TokComment
)

func (k Kind) String() string {
	switch k {
	case TokEnd:
		return "end"
	case TokNewline:
		return "newline"
	case TokIndent:
		return "indent"
	case TokDedent:
		return "dedent"
	case TokName:
		return "name"
	case TokKeyword:
		return "keyword"
	case TokNumber:
		return "number"
	case TokString:
		return "string"
	case TokOp:
		return "op"
	case TokComment:
		return "comment"
	}
	return "kind?"
}

// Token is a half-open byte range [Off, End) into the source.
type Token struct {
	Kind Kind
	Off  int32
	End  int32
}

// Len is the token's byte length.
func (t Token) Len() int32 { return t.End - t.Off }

// Bytes returns the token's raw bytes. The slice aliases src and MUST NOT be
// mutated.
func (t Token) Bytes(src []byte) []byte {
	if t.Off < 0 || t.End > int32(len(src)) || t.Off > t.End {
		return nil
	}
	return src[t.Off:t.End]
}

// Text returns the token's raw text.
func (t Token) Text(src []byte) string {
	if t.Off < 0 || t.End > int32(len(src)) || t.Off > t.End {
		return ""
	}
	return string(src[t.Off:t.End])
}

// keywords is the reserved-word set plus the soft keywords, which are listed
// because a statement beginning `match ` or `case ` should be recognisable even
// though both remain valid identifiers.
var keywords = map[string]bool{
	"and": true, "as": true, "assert": true, "async": true, "await": true,
	"break": true, "class": true, "continue": true, "def": true, "del": true,
	"elif": true, "else": true, "except": true, "finally": true, "for": true,
	"from": true, "global": true, "if": true, "import": true, "in": true,
	"is": true, "lambda": true, "nonlocal": true, "not": true, "or": true,
	"pass": true, "raise": true, "return": true, "try": true, "while": true,
	"with": true, "yield": true,
	"True": true, "False": true, "None": true,
	// Soft keywords.
	"match": true, "case": true, "type": true,
}

// Lex tokenises src. The result always ends with a TokEnd token, and a logical
// TokNewline is synthesised before it when the final line is not newline
// terminated, so every statement a caller sees is terminated.
func Lex(src []byte) []Token {
	lx := lexer{src: src, indentTop: 0}
	lx.run()
	return lx.toks
}

type lexer struct {
	src  []byte
	i    int
	toks []Token

	// indent is the indentation stack; indent[0] is always 0.
	indent []int32
	// indentTop caches indent[len(indent)-1].
	indentTop int32

	// parens is the open-bracket depth; inside it a newline is a non-logical
	// newline and does not end a statement.
	parens int
	// logicalStart is true at the beginning of a logical line, where indentation
	// is significant.
	logicalStart bool
	// blankLine is true on a line that contains only whitespace and/or a comment,
	// where indentation is ignored.
	blankLine bool
}

func (l *lexer) emit(k Kind, s, e int) {
	l.toks = append(l.toks, Token{Kind: k, Off: int32(s), End: int32(e)})
}

func (l *lexer) run() {
	n := len(l.src)
	l.indent = append(l.indent, 0)
	l.logicalStart = true

	for l.i < n {
		if l.logicalStart && l.parens == 0 {
			if l.handleIndent() {
				continue
			}
			if l.i >= n {
				break
			}
		}

		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\f' || c == '\v':
			l.i++
		case c == '\r':
			// A CR not followed by LF is a (rare) newline on its own.
			if l.i+1 < n && l.src[l.i+1] == '\n' {
				l.i++
				continue
			}
			l.newline()
		case c == '\n':
			l.newline()
		case c == '\\' && l.i+1 < n && (l.src[l.i+1] == '\n' || l.src[l.i+1] == '\r'):
			// Explicit line join: consume the backslash and the newline.
			l.i++
			if l.src[l.i] == '\r' {
				l.i++
			}
			if l.i < n && l.src[l.i] == '\n' {
				l.i++
			}
			l.blankLine = false
		case c == '#':
			j := l.i
			for j < n && l.src[j] != '\n' && l.src[j] != '\r' {
				j++
			}
			l.emit(TokComment, l.i, j)
			l.i = j
		default:
			if l.scanToken() == 0 {
				// Defensive: never stall. consume one byte.
				l.i++
			}
		}
	}

	l.finish()
}

// handleIndent measures and applies the indentation of a logical line. It returns
// true when it consumed the line (so the caller re-tests the loop), false when
// the caller should continue scanning from the new position.
func (l *lexer) handleIndent() bool {
	n := len(l.src)
	j := l.i
	var width int32
	for j < n {
		switch l.src[j] {
		case ' ':
			width++
			j++
		case '\t':
			width += 8 - width%8
			j++
		case '\f', '\v':
			j++
		default:
			goto measured
		}
	}
measured:
	if j >= n {
		l.i = j
		return true
	}
	switch l.src[j] {
	case '\n', '\r', '#':
		// Blank or comment-only line: no INDENT/DEDENT.
		l.i = j
		l.logicalStart = false
		l.blankLine = true
		return true
	}

	cur := width
	if cur > l.indentTop {
		l.indent = append(l.indent, cur)
		l.indentTop = cur
		l.emit(TokIndent, l.i, j)
	} else if cur < l.indentTop {
		for cur < l.indentTop && len(l.indent) > 1 {
			l.indent = l.indent[:len(l.indent)-1]
			l.indentTop = l.indent[len(l.indent)-1]
			l.emit(TokDedent, l.i, j)
		}
		if cur != l.indentTop {
			// Inconsistent dedent: real Python raises IndentationError. sc4n keeps
			// going with the nearest enclosing level rather than aborting the lex,
			// because a file we cannot finish lexing is a file we cannot report on.
			l.indent = append(l.indent, cur)
			l.indentTop = cur
		}
	}
	l.i = j
	l.logicalStart = false
	return true
}

// newline handles a physical newline at l.i.
func (l *lexer) newline() {
	switch {
	case l.parens > 0:
		// Implicit line join inside brackets: no token, line continues.
		l.i++
	case l.blankLine:
		l.blankLine = false
		l.i++
		l.logicalStart = true
	default:
		l.emit(TokNewline, l.i, l.i+1)
		l.i++
		l.logicalStart = true
	}
}

// finish appends the synthesised trailing newline, the outstanding DEDENTs and
// the end sentinel.
func (l *lexer) finish() {
	n := len(l.src)
	if len(l.toks) > 0 {
		switch l.toks[len(l.toks)-1].Kind {
		case TokNewline, TokIndent, TokComment:
			// A trailing comment normally has its newline except at EOF; emit one
			// so the last statement is terminated.
			if l.toks[len(l.toks)-1].Kind == TokComment {
				l.emit(TokNewline, n, n)
			}
		default:
			l.emit(TokNewline, n, n)
		}
	}
	for len(l.indent) > 1 {
		l.indent = l.indent[:len(l.indent)-1]
		l.emit(TokDedent, n, n)
	}
	l.emit(TokEnd, n, n)
}

// scanToken lexes one token at l.i and returns the number of bytes consumed (0 on
// no progress).
func (l *lexer) scanToken() int {
	start := l.i
	c := l.src[l.i]

	// String literal, with or without a prefix.
	if pl, ok := stringPrefixAt(l.src, l.i); ok {
		end := scanStringBody(l.src, l.i, pl)
		l.emit(TokString, start, end)
		l.i = end
		return end - start
	}

	switch {
	case isIdentStart(c):
		j := l.i + 1
		for j < len(l.src) && isIdentCont(l.src[j]) {
			j++
		}
		word := string(l.src[l.i:j])
		k := TokName
		if keywords[word] {
			k = TokKeyword
		}
		l.emit(k, l.i, j)
		l.i = j
		return j - start
	case isDigit(c) || (c == '.' && l.i+1 < len(l.src) && isDigit(l.src[l.i+1])):
		j := scanNumber(l.src, l.i)
		l.emit(TokNumber, l.i, j)
		l.i = j
		return j - start
	default:
		j := scanOp(l.src, l.i)
		l.emit(TokOp, l.i, j)
		// Track bracket depth for implicit line joining.
		switch c {
		case '(', '[', '{':
			l.parens++
		case ')', ']', '}':
			if l.parens > 0 {
				l.parens--
			}
		}
		l.i = j
		return j - start
	}
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b >= 0x80
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || isDigit(b)
}

// stringPrefixAt reports the length of the string prefix starting at i when the
// bytes there are a (possibly empty) string prefix immediately followed by a
// quote. A prefix im mediately followed by something other than a quote means the
// bytes are an ordinary identifier, so this reports false.
func stringPrefixAt(src []byte, i int) (int, bool) {
	j := i
	for k := 0; k < 3 && j < len(src); k++ {
		switch lowerByte(src[j]) {
		case 'r', 'b', 'u', 'f':
			j++
			continue
		}
		break
	}
	if j < len(src) && (src[j] == '\'' || src[j] == '"') {
		return j - i, true
	}
	return 0, false
}

// scanStringBody returns the index just past the string literal that begins at
// start (where src[start+prefixLen] is the opening quote). It understands
// triple-quoting, backslash escapes, and f-string replacement fields, which may
// themselves contain strings, nested braces and further f-strings.
func scanStringBody(src []byte, start, prefixLen int) int {
	n := len(src)
	qpos := start + prefixLen
	if qpos >= n {
		return n
	}
	q := src[qpos]
	triple := qpos+2 < n && src[qpos+1] == q && src[qpos+2] == q
	isF := false
	for k := start; k < qpos; k++ {
		if lowerByte(src[k]) == 'f' {
			isF = true
		}
	}
	i := qpos + 1
	if triple {
		i = qpos + 3
	}
	for i < n {
		c := src[i]
		if c == '\\' {
			i += 2
			continue
		}
		if triple {
			if c == q && i+2 < n && src[i+1] == q && src[i+2] == q {
				return i + 3
			}
		} else {
			if c == q {
				return i + 1
			}
			if c == '\n' || c == '\r' {
				return i // unterminated single-line string
			}
		}
		if isF && c == '{' {
			if i+1 < n && src[i+1] == '{' {
				i += 2
				continue
			}
			i = scanFExpr(src, i+1)
			continue
		}
		i++
	}
	return n
}

// scanFExpr scans the inside of an f-string replacement field, beginning just
// after its `{`, and returns the index just past the matching `}`.
func scanFExpr(src []byte, i int) int {
	n := len(src)
	depth := 1
	for i < n {
		c := src[i]
		if c == '\\' {
			i += 2
			continue
		}
		if pl, ok := stringPrefixAt(src, i); ok {
			i = scanStringBody(src, i, pl)
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return n
}

// scanNumber consumes a numeric literal. It is permissive (it accepts the union
// of the integer, float, hexadecimal, octal, binary, exponent and imaginary
// forms, plus `_` separators) because the rules never depend on a number's value,
// only on it being a single token.
func scanNumber(src []byte, i int) int {
	n := len(src)
	j := i
	// Radix prefix.
	if j+1 < n && src[j] == '0' && (src[j+1] == 'x' || src[j+1] == 'X' || src[j+1] == 'o' || src[j+1] == 'O' || src[j+1] == 'b' || src[j+1] == 'B') {
		j += 2
		for j < n && isIdentCont(src[j]) {
			j++
		}
		return j
	}
	for j < n {
		c := src[j]
		switch {
		case isDigit(c) || c == '_' || c == '.' || c == 'j' || c == 'J':
			j++
		case c == 'e' || c == 'E':
			j++
			if j < n && (src[j] == '+' || src[j] == '-') {
				j++
			}
		case isIdentStart(c):
			// A trailing unit-like suffix we do not know: consume it so we make
			// progress, and stop at the next delimiter.
			j++
		default:
			return j
		}
	}
	return j
}

// threeCharOps and twoCharOps are matched longest-first so that `**=` is one token
// and not `**` followed by `=`.
var (
	threeCharOps = [][]byte{[]byte("**="), []byte("//="), []byte(">>="), []byte("<<="), []byte("...")}
	twoCharOps   = [][]byte{
		[]byte("**"), []byte("//"), []byte(">>"), []byte("<<"),
		[]byte("<="), []byte(">="), []byte("=="), []byte("!="),
		[]byte("+="), []byte("-="), []byte("*="), []byte("/="),
		[]byte("%="), []byte("&="), []byte("|="), []byte("^="),
		[]byte("@="), []byte(":="), []byte("->"),
	}
)

func hasPrefixAt(src []byte, i int, p []byte) bool {
	if i+len(p) > len(src) {
		return false
	}
	for k := range p {
		if src[i+k] != p[k] {
			return false
		}
	}
	return true
}

// scanOp returns the index just past the operator or delimiter at i.
func scanOp(src []byte, i int) int {
	for _, op := range threeCharOps {
		if hasPrefixAt(src, i, op) {
			return i + 3
		}
	}
	for _, op := range twoCharOps {
		if hasPrefixAt(src, i, op) {
			return i + 2
		}
	}
	return i + 1
}

// IsStringToken reports whether t is a string literal with the given prefix
// letter (case-insensitive). An empty prefix reports any string literal.
func IsStringToken(t Token, src []byte, prefix byte) bool {
	if t.Kind != TokString {
		return false
	}
	b := t.Bytes(src)
	qpos := 0
	for qpos < len(b) && b[qpos] != '\'' && b[qpos] != '"' {
		qpos++
	}
	if prefix == 0 {
		return true
	}
	for k := 0; k < qpos; k++ {
		if lowerByte(b[k]) == lowerByte(prefix) {
			return true
		}
	}
	return false
}

// StringValue returns the decoded content of a string token, capped at max bytes
// (max <= 0 means the source length). It unescapes the backslash escapes the
// indicator rules care about; unknown escapes are kept verbatim. It never
// allocates more than the cap.
func StringValue(t Token, src []byte, max int) string {
	b := t.Bytes(src)
	if len(b) == 0 {
		return ""
	}
	qpos := 0
	for qpos < len(b) && b[qpos] != '\'' && b[qpos] != '"' {
		qpos++
	}
	if qpos >= len(b) {
		return ""
	}
	q := b[qpos]
	body := b[qpos+1:]
	if len(body) >= 2 && body[0] == q && body[1] == q {
		if len(body) >= 6 && body[len(body)-3] == q && body[len(body)-2] == q && body[len(body)-1] == q {
			body = body[3 : len(body)-3]
		}
	} else if len(body) >= 1 && body[len(body)-1] == q {
		body = body[:len(body)-1]
	}
	limit := len(body)
	if max > 0 && max < limit {
		limit = max
	}
	out := make([]byte, 0, limit)
	for i := 0; i < len(body) && len(out) < limit; i++ {
		c := body[i]
		if c != '\\' || i+1 >= len(body) {
			out = append(out, c)
			continue
		}
		n := body[i+1]
		switch n {
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case '\\':
			out = append(out, '\\')
		case '\'':
			out = append(out, '\'')
		case '"':
			out = append(out, '"')
		case 'x':
			if i+3 < len(body) {
				if v, ok := hexByte(body[i+2], body[i+3]); ok {
					out = append(out, v)
					i += 3
					continue
				}
			}
			out = append(out, '\\', n)
		default:
			out = append(out, '\\', n)
		}
		i++
	}
	return string(out)
}

func hexByte(a, b byte) (byte, bool) {
	hi, ok1 := hexVal(a)
	lo, ok2 := hexVal(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexVal(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}
