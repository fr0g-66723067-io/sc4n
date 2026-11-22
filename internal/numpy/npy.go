// Package numpy parses the NumPy on-disk formats and the joblib pickle shape.
//
// Three artifacts live here:
//
//   - .npy: magic "\x93NUMPY", a major/minor version byte pair, a
//     2-byte (v1.0) or 4-byte (v2.0/v3.0) little-endian header length, a
//     space-padded literal dict with exactly the keys descr, fortran_order and
//     shape, then the array bytes. The dict is decoded with a literal reader —
//     never eval — so a crafted header cannot run while being scanned. When
//     descr names the object kind 'O' — as a '|O' string or as an object field
//     inside a dtype.descr list — the data section is a pickle stream and is
//     dispatched to the pickle engine (the allow_pickle=True RCE path).
//   - .npz: a zip whose members are .npy files. The container rules come from
//     internal/archive and each member is dispatched through artifact.ScanMember,
//     so a member's own format decides its parser.
//   - joblib: a pickle container whose ndarrays are `NumpyArrayWrapper` (legacy
//     `NDArrayWrapper`/`ZNDArrayWrapper`) objects with the raw array bytes
//     written into the file immediately after each wrapper and before the
//     stream's STOP (the wrapper's declared dtype/shape bounds the payload). Each
//     payload is located at its wrapper's own position, masked out of the
//     object-graph walk so weight bytes are not read as opcodes, and dispatched
//     as a member; an object-dtype payload is a nested pickle and reaches the
//     pickle engine the same way.
//
// Nothing here executes, extracts or writes anything, and no length is trusted
// before it is checked against the bytes remaining.
package numpy

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// npyMagic is the 6-byte signature every .npy file starts with.
var npyMagic = []byte{0x93, 'N', 'U', 'M', 'P', 'Y'}

// errBadNPY is returned by parseNPY for a header that cannot be parsed. The
// corresponding SC4N-NUMPY-STRUCT finding is emitted before the error escapes.
var errBadNPY = errors.New("numpy: malformed .npy header")

// npyHeader is the decoded literal dict plus the offset at which the array bytes
// begin.
type npyHeader struct {
	dtype   string
	fortran bool
	shape   []int64
	// structured records that descr was written as a list rather than a string,
	// which numpy does whenever the dtype has fields (dtype.descr is a list).
	// Such a dtype has no single element size, so dtype is left empty and the
	// declared length is not verified. fields holds the type descriptor of every
	// field the list named, including nested structured fields; an 'O' in any of
	// them means the data section is a pickle stream, exactly as for a bare '|O'
	// string descr.
	structured bool
	fields     []string
	// unknown lists top-level keys that are not one of descr, fortran_order,
	// shape. numpy never writes any, so their presence is a structural finding.
	unknown []string
}

// npyParser is the registered parser for a bare .npy artifact.
type npyParser struct{}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatNPY,
		Magic:  "\\x93NUMPY",
		Depth:  artifact.DepthDeep,
		Notes: "the v1.0/v2.0/v3.0 header is decoded with a literal dict reader (never eval) and the " +
			"declared shape is checked against the bytes remaining; a descr naming the object kind 'O' — " +
			"as a string or as an object field inside a dtype.descr list — means the data section is a " +
			"pickle stream, which is dispatched to the pickle engine (the numpy.load(allow_pickle=True) " +
			"path). Structured/comma dtypes have no single element size, so their declared length is not " +
			"verified.",
	})
	artifact.RegisterParser(artifact.FormatNPY, npyParser{})
}

// Parse decodes one .npy artifact.
func (npyParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	return parseNPY(ctx, s)
}

// parseNPY decodes the header of s and validates the declared array.
//
// A malformed header is both an SC4N-NUMPY-STRUCT finding and a returned error
// (the artifact is genuinely unreadable); a header that parses but whose
// declared shape exceeds the remaining bytes is a finding with no error, because
// the structure itself is well formed.
func parseNPY(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	if size < 10 {
		return structErr(ctx, 0, "file is "+strconv.FormatInt(size, 10)+" bytes, shorter than the smallest .npy header")
	}
	prefix, err := s.Bytes(0, min64(size, 12))
	if err != nil && int64(len(prefix)) < min64(size, 12) {
		return structErr(ctx, 0, "cannot read the .npy signature")
	}
	if len(prefix) < 6 || !bytesEqual(prefix[:6], npyMagic) {
		return structErr(ctx, 0, "missing \\x93NUMPY signature")
	}
	major, minor := prefix[6], prefix[7]

	var headerStart, headerLen int64
	switch major {
	case 1:
		if len(prefix) < 10 {
			return structErr(ctx, 8, "version 1.0 header length is truncated")
		}
		headerStart = 10
		headerLen = int64(prefix[8]) | int64(prefix[9])<<8
	case 2, 3:
		if len(prefix) < 12 {
			return structErr(ctx, 8, "version "+strconv.Itoa(int(major))+" header length is truncated")
		}
		headerStart = 12
		headerLen = int64(prefix[8]) | int64(prefix[9])<<8 | int64(prefix[10])<<16 | int64(prefix[11])<<24
	default:
		return structErr(ctx, 6, "unknown .npy major version "+strconv.Itoa(int(major)))
	}
	_ = minor

	cap := ctx.Limits.MaxHeaderBytes
	if cap <= 0 {
		cap = limits.Default().MaxHeaderBytes
	}
	if headerLen > cap {
		limits.Emit(ctx.Sink, limits.RuleHeader, "MaxHeaderBytes", headerLen, cap, ".npy header length")
		return structErr(ctx, headerStart, "header length "+strconv.FormatInt(headerLen, 10)+
			" exceeds MaxHeaderBytes")
	}
	remaining := size - headerStart
	if headerLen > remaining {
		return structErr(ctx, headerStart, "header length "+strconv.FormatInt(headerLen, 10)+
			" exceeds the "+strconv.FormatInt(remaining, 10)+" bytes remaining")
	}
	hdrBytes, err := s.Bytes(headerStart, headerLen)
	if err != nil && int64(len(hdrBytes)) < headerLen {
		return structErr(ctx, headerStart, "header is truncated")
	}

	h, perr := parseNPYHeader(hdrBytes, ctx.Limits, ctx.Sink)
	if perr != nil {
		return structErr(ctx, headerStart, "header is not the literal {descr, fortran_order, shape} dict: "+perr.Error())
	}
	for _, k := range h.unknown {
		structErr(ctx, headerStart, "unexpected header key "+strconv.Quote(k))
	}

	dataOff := headerStart + headerLen
	dataLen := size - dataOff

	// Object dtype: the data section is a pickle stream. Dispatch it rather than
	// pretending it is an array of pointers. A dtype with fields is written as
	// dtype.descr (a list), so the object kind is looked for in the field
	// descriptors too; numpy's own loader unpickles the data section whenever
	// dtype.hasobject, and hasobject is true when any field names the object kind.
	objField := objectField(h.fields)
	if isObjectDtype(h.dtype) || objField != "" {
		desc := h.dtype
		detail := "descr " + strconv.Quote(desc)
		if desc == "" {
			desc = objField
			detail = "dtype.descr field " + strconv.Quote(objField)
		}
		ctx.Sink.EmitExtra(RuleObjectArray, dataOff,
			detail+" is an object array; the data section is a pickle stream that "+
				"numpy.load reaches only with allow_pickle=True",
			map[string]string{"dtype": desc, "operation": "pickle-load"})
		if dataLen > 0 {
			data, berr := s.Bytes(dataOff, dataLen)
			if berr != nil && int64(len(data)) == 0 {
				// The mapping is unavailable; nothing to hand to the engine.
				return nil
			}
			artifact.ScanMemberBytes(ctx, "object-array.pkl", data)
		}
		return nil
	}

	if h.structured {
		// descr was a list (dtype.descr): a dtype with fields, whose element
		// size is the sum of its fields and so is not a single number. The
		// declared length is not verified, but the element count is still taken
		// from shape so that an unsizeable shape is reported.
		if _, ok := shapeElems(h.shape); !ok {
			return structErr(ctx, headerStart, "shape "+shapeString(h.shape)+" cannot be sized without overflow")
		}
		return nil
	}

	esize, ok := dtypeSize(h.dtype)
	if !ok {
		// A structure we cannot size (void, an unrecognised descriptor): skip
		// the length check rather than guess a wrong one. A descriptor whose
		// element size overflows int64 is a structural violation in its own
		// right, so it is reported rather than skipped.
		if dtypeSizeOverflows(h.dtype) {
			return structErr(ctx, headerStart, "the element size of dtype "+strconv.Quote(h.dtype)+" overflows")
		}
		return nil
	}
	elems, ok := shapeElems(h.shape)
	if !ok {
		return structErr(ctx, headerStart, "shape "+shapeString(h.shape)+" cannot be sized without overflow")
	}
	want, ok := mulOverflow(elems, esize)
	if !ok {
		return structErr(ctx, headerStart, "declared array size overflows")
	}
	if dataLen < want {
		structErr(ctx, dataOff, "shape "+shapeString(h.shape)+" x "+strconv.FormatInt(esize, 10)+
			" needs "+strconv.FormatInt(want, 10)+" bytes but only "+strconv.FormatInt(dataLen, 10)+" remain")
		return nil
	}
	if dataLen > want {
		ctx.Sink.EmitExtra(RuleTrailing, dataOff+want,
			strconv.FormatInt(dataLen-want, 10)+" undeclared bytes after the "+strconv.FormatInt(want, 10)+
				"-byte array",
			map[string]string{
				"declared_bytes": strconv.FormatInt(want, 10),
				"file_bytes":     strconv.FormatInt(dataLen, 10),
			})
	}
	return nil
}

// structErr emits RuleStruct and returns errBadNPY (or the specific error).
func structErr(ctx *artifact.Ctx, off int64, detail string) error {
	ctx.Sink.Emit(RuleStruct, off, detail)
	return errors.New("numpy: " + detail)
}

// parseNPYHeader decodes the literal dict numpy writes.
//
// Grammar accepted (the subset numpy emits): a braces dict whose keys are
// quoted strings and whose values are a quoted string (descr), a list
// (dtype.descr, written whenever the dtype has fields), True/False
// (fortran_order), or a parenthesised/bracketed tuple of integers (shape). A
// trailing comma is allowed. Nothing is evaluated, so a header such as
// `{'descr': __import__('os').system('id')}` parses to an error rather than
// running.
func parseNPYHeader(b []byte, l limits.Limits, sink *report.Sink) (npyHeader, error) {
	p := newLitParser(b, l, sink)
	var h npyHeader
	p.ws()
	if !p.eat('{') {
		return h, errors.New("does not start with '{'")
	}
	seen := map[string]bool{}
	for {
		p.ws()
		if p.eat('}') {
			break
		}
		key, ok := p.str()
		if !ok {
			return h, errors.New("expected a quoted key")
		}
		p.ws()
		if !p.eat(':') {
			return h, errors.New("expected ':' after key " + headerQuote(key))
		}
		p.ws()
		switch key {
		case "descr":
			// numpy writes a string for a simple dtype and dtype.descr — a list —
			// whenever the dtype has fields, and the format docs define the key as
			// "an object that can be passed as an argument to numpy.dtype". Both
			// shapes are accepted; a list is consumed without being interpreted.
			if s, ok := p.str(); ok {
				h.dtype = s
			} else if fields, ok := p.descrFields(); ok {
				h.structured = true
				h.fields = fields
			} else if p.list() {
				h.structured = true
			} else {
				return h, errors.New("descr is neither a string nor a list")
			}
		case "fortran_order":
			v, ok := p.boolLit()
			if !ok {
				return h, errors.New("fortran_order is not True/False")
			}
			h.fortran = v
		case "shape":
			sh, ok := p.tuple()
			if !ok {
				return h, errors.New("shape is not a tuple of integers")
			}
			h.shape = sh
		default:
			if !p.skipScalar() {
				return h, errors.New("unparseable value for key " + headerQuote(key))
			}
			h.unknown = append(h.unknown, key)
		}
		seen[key] = true
		p.ws()
		if p.eat(',') {
			continue
		}
		if p.eat('}') {
			break
		}
		return h, errors.New("expected ',' or '}' after key " + headerQuote(key))
	}
	if !seen["descr"] {
		return h, errors.New("no descr key")
	}
	if !seen["shape"] {
		return h, errors.New("no shape key")
	}
	if p.rankOverflow {
		return h, errors.New("shape has more than 32 dimensions")
	}
	if p.fieldsOverflow {
		return h, errors.New("descr has more than 1024 fields")
	}
	return h, nil
}

func headerQuote(s string) string {
	return strconv.Quote(report.TruncateEvidence(s, 64))
}

// litParser is a position-holding literal reader. It only ever reads; it has no
// eval path.
type litParser struct {
	b    []byte
	i    int
	sink *report.Sink
	// maxString and maxRetained are the per-string and total text budgets.
	maxString      int64
	maxRetained    int64
	retained       int64
	reported       bool
	rankOverflow   bool
	fieldsOverflow bool
	// depth is the current literal nesting depth. The reader recurses through a
	// descr written as dtype.descr (a list can hold tuples, which can hold nested
	// field lists), and Go's 1 GB goroutine stack limit turns an unbounded
	// recursion into an uncatchable `fatal error: stack overflow` rather than a
	// panic — a crafted header could therefore kill the process instead of being
	// reported as malformed. maxLitDepth bounds it; a descriptor nested deeper
	// than that is not a dtype, so refusing there is exact, not a heuristic.
	depth int
}

// maxLitDepth bounds litParser's recursion. Real dtype descriptors nest a
// handful of levels ([('a', [('x', '<i4')])] is three), so 64 is far above
// anything numpy writes and far below the depth that overflows the stack.
const maxLitDepth = 64

const (
	maxNPYRank   = 32
	maxNPYFields = 1024
)

func newLitParser(b []byte, l limits.Limits, sink *report.Sink) *litParser {
	maxString := l.MaxStringBlob
	if maxString <= 0 {
		maxString = limits.Default().MaxStringBlob
	}
	maxRetained := l.MaxRetainedText
	if maxRetained <= 0 {
		maxRetained = limits.Default().MaxRetainedText
	}
	return &litParser{b: b, sink: sink, maxString: maxString, maxRetained: maxRetained}
}

func (p *litParser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}

func (p *litParser) eat(c byte) bool {
	if p.i < len(p.b) && p.b[p.i] == c {
		p.i++
		return true
	}
	return false
}

// str reads a single- or double-quoted string, decoding only backslash escapes.
// A value larger than MaxStringBlob is consumed but retained only to the cap; the
// total retained text is bounded by MaxRetainedText.
func (p *litParser) str() (string, bool) {
	if p.i >= len(p.b) || (p.b[p.i] != '\'' && p.b[p.i] != '"') {
		return "", false
	}
	quote := p.b[p.i]
	p.i++
	var sb strings.Builder
	full := int64(0)
	for p.i < len(p.b) {
		c := p.b[p.i]
		if c == quote {
			p.i++
			s := sb.String()
			if full > int64(len(s)) && !p.reported && p.sink != nil {
				p.reported = true
				limits.Emit(p.sink, limits.RuleString, "MaxStringBlob", full, p.maxString, ".npy header string")
			}
			p.retained += int64(len(s))
			if p.retained > p.maxRetained {
				if p.sink != nil {
					limits.Emit(p.sink, limits.RuleRetained, "MaxRetainedText", p.retained, p.maxRetained, ".npy header")
				}
				return "", true
			}
			return s, true
		}
		if c == '\\' && p.i+1 < len(p.b) {
			p.i++
			c = p.b[p.i]
		}
		full++
		if int64(sb.Len()) < p.maxString {
			sb.WriteByte(c)
		}
		p.i++
	}
	return "", false
}

func (p *litParser) boolLit() (bool, bool) {
	if p.has("True") {
		p.i += 4
		return true, true
	}
	if p.has("False") {
		p.i += 5
		return false, true
	}
	return false, false
}

func (p *litParser) has(word string) bool {
	return p.i+len(word) <= len(p.b) && string(p.b[p.i:p.i+len(word)]) == word
}

// tuple reads (1, 2, 3) or [1, 2, 3], allowing a trailing comma and the empty
// form ().
func (p *litParser) tuple() ([]int64, bool) {
	var close byte
	switch {
	case p.eat('('):
		close = ')'
	case p.eat('['):
		close = ']'
	default:
		return nil, false
	}
	var out []int64
	for {
		p.ws()
		if p.eat(close) {
			return out, true
		}
		n, ok := p.intLit()
		if !ok {
			return nil, false
		}
		if len(out) < maxNPYRank {
			out = append(out, n)
		} else {
			p.rankOverflow = true
		}
		p.ws()
		if p.eat(',') {
			continue
		}
		if p.eat(close) {
			return out, true
		}
		return nil, false
	}
}

// list reads a bracketed list of literals, consuming it without interpreting
// the elements. It is what a descr written as dtype.descr is: a list of field
// tuples such as [('a', '<i4'), ('b', '<f8')] or [('a', '<i4', (2,))].
func (p *litParser) list() bool {
	if p.i >= len(p.b) || p.b[p.i] != '[' {
		return false
	}
	return p.group()
}

// group consumes a bracketed or parenthesised sequence of literals, including
// the ('name', '<dtype') field tuples and nested field lists inside dtype.descr.
// Nothing it reads is returned or interpreted.
func (p *litParser) group() bool {
	if p.i >= len(p.b) || (p.b[p.i] != '[' && p.b[p.i] != '(') {
		return false
	}
	if p.depth >= maxLitDepth {
		return false
	}
	p.depth++
	defer func() { p.depth-- }()
	close := byte(']')
	if p.b[p.i] == '(' {
		close = ')'
	}
	p.i++
	for {
		p.ws()
		if p.eat(close) {
			return true
		}
		if !p.skipValue() {
			return false
		}
		p.ws()
		if p.eat(',') {
			continue
		}
		if p.eat(close) {
			return true
		}
		return false
	}
}

// skipValue consumes one literal value: a quoted string, a bracketed list, a
// parenthesised tuple, a bool or a bare integer. It is used only to walk past
// descr contents, so nothing it reads is returned or interpreted.
func (p *litParser) skipValue() bool {
	p.ws()
	if p.i >= len(p.b) {
		return false
	}
	switch p.b[p.i] {
	case '\'', '"':
		_, ok := p.str()
		return ok
	case '[', '(':
		return p.group()
	}
	if _, ok := p.boolLit(); ok {
		return true
	}
	_, ok := p.intLit()
	return ok
}

// intLit reads a decimal integer, tolerating a leading + and the Python 2 'L'
// suffix that a very old producer may emit.
func (p *litParser) intLit() (int64, bool) {
	start := p.i
	if p.i < len(p.b) && (p.b[p.i] == '-' || p.b[p.i] == '+') {
		p.i++
	}
	digits := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	if p.i == digits {
		p.i = start
		return 0, false
	}
	if p.i < len(p.b) && p.b[p.i] == 'L' {
		p.i++
	}
	n, err := strconv.ParseInt(string(p.b[start:p.i]), 10, 64)
	if err != nil {
		p.i = start
		return 0, false
	}
	return n, true
}

// skipScalar consumes one scalar value (string, bool or integer) for an unknown
// key so that the rest of the dict can still be read.
func (p *litParser) skipScalar() bool {
	if _, ok := p.str(); ok {
		return true
	}
	if _, ok := p.boolLit(); ok {
		return true
	}
	if _, ok := p.intLit(); ok {
		return true
	}
	return false
}

// descrFields reads a descr written as dtype.descr — a bracketed list of field
// tuples such as [('a', '<i4'), ('b', '<f8')] or [('a', '<i4', (2,))] — and
// returns the type descriptor of every field, including the fields of a nested
// structured dtype. It is the list counterpart of the string form: numpy writes
// dtype.descr whenever the dtype has fields, and its loader unpickles the data
// section whenever dtype.hasobject, which is true when any field names the object
// kind, so an 'O' field anywhere in the list is the same RCE path as a bare '|O'.
//
// On failure the position is left unchanged, so the caller can fall back to the
// plain group() consumption for a list shape this reader does not model.
func (p *litParser) descrFields() ([]string, bool) {
	start := p.i
	fields, ok := p.descrFieldsAt()
	if !ok {
		p.i = start
		return nil, false
	}
	return fields, true
}

func (p *litParser) descrFieldsAt() ([]string, bool) {
	if p.i >= len(p.b) || p.b[p.i] != '[' {
		return nil, false
	}
	if p.depth >= maxLitDepth {
		return nil, false
	}
	p.depth++
	defer func() { p.depth-- }()
	p.i++
	var out []string
	for {
		p.ws()
		if p.eat(']') {
			return out, true
		}
		if len(out) >= maxNPYFields {
			p.fieldsOverflow = true
			return nil, false
		}
		if p.i >= len(p.b) || p.b[p.i] != '(' {
			return nil, false
		}
		p.i++
		p.ws()
		// The first element is the field name; a titled field writes it as a
		// ('title', 'name') tuple instead of a bare string.
		if _, ok := p.str(); !ok {
			if p.i >= len(p.b) || p.b[p.i] != '(' || !p.group() {
				return nil, false
			}
		}
		p.ws()
		if !p.eat(',') {
			return nil, false
		}
		p.ws()
		// The second element is the field's dtype: a string, or a nested
		// dtype.descr list for a nested structured field.
		if s, ok := p.str(); ok {
			out = append(out, s)
		} else if nested, ok := p.descrFieldsAt(); ok {
			out = append(out, nested...)
		} else {
			return nil, false
		}
		// An optional third element is the sub-array shape, e.g. ('a', '<i4', (2,)).
		p.ws()
		if p.eat(',') {
			p.ws()
			if !p.skipValue() {
				return nil, false
			}
			p.ws()
		}
		if !p.eat(')') {
			return nil, false
		}
		p.ws()
		if p.eat(',') {
			continue
		}
		if p.eat(']') {
			return out, true
		}
		return nil, false
	}
}

// isObjectDtype reports whether a descriptor names the object kind. numpy writes
// '|O' for object arrays; the check is a substring so the endianness prefix and
// the optional size digit do not matter.
func isObjectDtype(dtype string) bool {
	return strings.ContainsRune(dtype, 'O')
}

// objectField returns the first field descriptor in a dtype.descr list that names
// the object kind, or "". It is how an object field inside a structured dtype is
// found: the list form has no single dtype string for isObjectDtype to inspect.
func objectField(fields []string) string {
	for _, f := range fields {
		if isObjectDtype(f) {
			return f
		}
	}
	return ""
}

// dtypeSize returns the byte size of one element of a simple numpy descriptor,
// or ok=false for object kinds and anything whose size is not a single number
// (structured dtypes, sub-array fields, void with a comma). A descriptor whose
// element size would overflow int64 is also ok=false; dtypeSizeOverflows
// distinguishes that case so the caller can report it.
func dtypeSize(dtype string) (int64, bool) {
	s := dtype
	if s == "" {
		return 0, false
	}
	if s[0] == '<' || s[0] == '>' || s[0] == '=' || s[0] == '|' {
		s = s[1:]
	}
	if s == "" || strings.ContainsAny(s, ",[]()") {
		return 0, false
	}
	kind := s[0]
	num, err := strconv.Atoi(s[1:])
	if err != nil || num <= 0 {
		return 0, false
	}
	switch kind {
	case 'f', 'i', 'u', 'b', 'c', 'V', 'S':
		return int64(num), true
	case 'U':
		if int64(num) > math.MaxInt64/4 {
			return 0, false
		}
		return 4 * int64(num), true
	default:
		return 0, false
	}
}

// dtypeSizeOverflows reports whether a simple descriptor's element size is too
// large for int64 to hold. A 'U' descriptor stores four bytes per character, so
// a count above MaxInt64/4 overflows the byte size; numpy's own dtype rejects
// such a descriptor, which makes it a structural violation rather than a
// structure whose size is merely unknown (which dtypeSize reports as ok=false).
func dtypeSizeOverflows(dtype string) bool {
	s := dtype
	if s == "" {
		return false
	}
	if s[0] == '<' || s[0] == '>' || s[0] == '=' || s[0] == '|' {
		s = s[1:]
	}
	if len(s) < 2 || s[0] != 'U' || strings.ContainsAny(s, ",[]()") {
		return false
	}
	num, err := strconv.Atoi(s[1:])
	return err == nil && int64(num) > math.MaxInt64/4
}

// shapeElems returns the product of the dimensions, or ok=false on a negative
// dimension or overflow.
func shapeElems(shape []int64) (int64, bool) {
	var p int64 = 1
	for _, d := range shape {
		if d < 0 {
			return 0, false
		}
		if p != 0 && d > math.MaxInt64/p {
			return 0, false
		}
		p *= d
	}
	return p, true
}

func mulOverflow(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a > math.MaxInt64/b {
		return 0, false
	}
	return a * b, true
}

// shapeString renders a shape for evidence text.
func shapeString(shape []int64) string {
	var sb strings.Builder
	sb.WriteByte('(')
	for i, d := range shape {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(strconv.FormatInt(d, 10))
	}
	if len(shape) == 1 {
		sb.WriteByte(',')
	}
	sb.WriteByte(')')
	return sb.String()
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
