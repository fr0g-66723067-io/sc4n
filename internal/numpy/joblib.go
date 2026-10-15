package numpy

import (
	"bytes"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/pickle"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// joblibWrapperNames are the ndarray wrapper classes joblib writes: the current
// `NumpyArrayWrapper` and the pre-0.10 `NDArrayWrapper`/`ZNDArrayWrapper`. Their
// names appear as bytes whether the GLOBAL is written as text or assembled by
// STACK_GLOBAL from string constants, which is what makes a byte search a safe
// content test.
var joblibWrapperNames = [][]byte{
	[]byte("NumpyArrayWrapper"),
	[]byte("NDArrayWrapper"),
	[]byte("ZNDArrayWrapper"),
}

// sniffWindow bounds how much of a candidate is searched for a wrapper name.
const sniffWindow = 4 << 20

// joblibParser is the registered parser for a joblib artifact.
type joblibParser struct{}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatJoblib,
		Magic:  "a pickle stream naming a joblib.ndarray wrapper (NumpyArrayWrapper / NDArrayWrapper / ZNDArrayWrapper)",
		Depth:  artifact.DepthDeep,
		Notes: "joblib writes each ndarray as a wrapper object (NumpyArrayWrapper, or the legacy " +
			"NDArrayWrapper/ZNDArrayWrapper) with the raw array bytes written into the file immediately " +
			"after the wrapper and before the stream's STOP: a one-byte padding length, that many 0xff " +
			"bytes and then dtype.itemsize x count raw bytes, or a nested pickle for an object-dtype " +
			"array. Each payload region is located from its wrapper's own position, masked out of the " +
			"object-graph walk so the weight bytes are not read as opcodes, and dispatched as a member " +
			"so its content is still scanned. A producer that appends the array bytes after a complete " +
			"pickle is handled as well. Compression (zlib/gzip/bz2) is unwrapped by internal/archive " +
			"before this parser runs.",
	})
	// Priority 97 is just above the pickle-walk sniffer's 95 and below the magic
	// table's 100, so a joblib-named pickle is claimed as joblib instead of as a
	// bare pickle while every format with a real magic still wins. A zlib/gzip/
	// bzip2-wrapped joblib is unwrapped by internal/archive and re-sniffed here
	// on the decompressed bytes; this parser never decompresses anything itself.
	artifact.RegisterSniffer("joblib", 97, sniffJoblib)
	// The pre-0.10 "ZF" frame is joblib's other on-disk shape. It is claimed here
	// rather than by the two-byte magic table, because "ZF" is ordinary text: a
	// shape-checked frame is a joblib archive, a file that merely starts with
	// those letters is not.
	artifact.RegisterSniffer("joblib-legacy", 96, sniffJoblibLegacy)
	artifact.RegisterParser(artifact.FormatJoblib, joblibParser{})

	// The three ndarray wrappers are first-class allowlist entries. Every benign
	// joblib array is serialised through one of them, so a name-based verdict on
	// the wrapper alone is worthless: the wrapper is how joblib represents an
	// array, and the payload it carries is what this package walks — including
	// the nested object-dtype pickle. Registering them silences the wrapper's
	// own REDUCE/BUILD findings while leaving any malicious payload inside the
	// wrapper fully reportable.
	pickle.RegisterAllowedGlobal("joblib.numpy_pickle", "NumpyArrayWrapper")
	pickle.RegisterAllowedGlobal("joblib.numpy_pickle", "NDArrayWrapper")
	pickle.RegisterAllowedGlobal("joblib.numpy_pickle", "ZNDArrayWrapper")
}

// sniffJoblibLegacy claims joblib's pre-0.10 "ZF" frame: the magic, the
// uncompressed length as a padded hex string, and a zlib stream.
func sniffJoblibLegacy(s source.Source, l limits.Limits) (artifact.Format, bool) {
	head, err := s.Bytes(0, 32)
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	if !archive.JoblibLegacyShape(head) {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatZlibJoblibLegacy, true
}

// sniffJoblib claims a stream that names a joblib wrapper class and opens as a
// pickle. It scans only the first sniffWindow bytes and never allocates from
// file-controlled lengths.
//
// The opening test is not decoration: joblib's own format is a pickle from byte 0,
// while a *compressed* joblib (joblib.dump's default is zlib) opens with 78 9c and
// still contains the wrapper name and a PROTO byte verbatim inside its stored
// blocks. Without the test, this sniffer claimed such a file at priority 97 and the
// joblib parser walked the compressed bytes as opcodes: measured on the committed
// benign fixture, the result was a high SC4N-PICKLE-PREFIX ("7 bytes precede the
// first pickle opcode") on a file that is a perfectly ordinary compressed joblib.
// The zlib sniffer unwraps it and walks the real pickle, which is why the compressed
// case must fall through to it.
func sniffJoblib(s source.Source, l limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 8 {
		return artifact.FormatUnknown, false
	}
	n := size
	if n > sniffWindow {
		n = sniffWindow
	}
	head, err := s.Bytes(0, n)
	if err != nil && int64(len(head)) == 0 {
		return artifact.FormatUnknown, false
	}
	if !pickle.OpensAsPickle(head) {
		return artifact.FormatUnknown, false
	}
	for _, name := range joblibWrapperNames {
		if bytes.Contains(head, name) {
			return artifact.FormatJoblib, true
		}
	}
	return artifact.FormatUnknown, false
}

// Parse walks the joblib object pickle and the array bodies joblib interleaves
// with it.
//
// joblib's own source says the file "does not follow the pickle format": it
// pickles a wrapper object, then writes the array bytes straight into the file
// (pickle.format's framing: a padding-length byte, that many 0xff bytes and then
// itemsize x count raw bytes), and only then lets the outer pickler continue or
// write STOP. Its unpickler reads the payload back in load_build, i.e. from the
// wrapper's own position. The walk below locates each payload there, masks it
// out of the object-graph walk so weight bytes are not read as opcodes (the
// spurious unknown-opcode/INCOMPLETE noise), and dispatches it as a member so
// its content is scanned. A producer that instead appends the array bytes after
// a complete pickle (the form the fixtures use) is handled by the tail path.
func (joblibParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	data, err := s.Bytes(0, s.Size())
	if err != nil && len(data) == 0 {
		return err
	}

	wrappers := walkWrappers(data)

	// Mask every inline payload out of the copy handed to the pickle engine.
	var masked []byte
	for _, w := range wrappers {
		if !w.inline {
			continue
		}
		if masked == nil {
			masked = append([]byte(nil), data...)
		}
		maskPayload(masked[w.payloadStart:w.payloadEnd])
	}
	walkSrc := s
	if masked != nil {
		mem := source.Mem(s.Name(), masked)
		defer mem.Close()
		walkSrc = mem
	}

	stream, werr := pickle.Walk(ctx, walkSrc, pickle.Options{
		TrailingIsStorage:  true,
		StorageDescription: "joblib array payload",
	})
	if werr != nil && stream == nil {
		return werr
	}

	inline := false
	for _, w := range wrappers {
		if w.inline {
			inline = true
			break
		}
	}
	if inline {
		// A wrapper whose payload could not be located at its own position is a
		// framing violation, unless the walk simply stopped at the stream's STOP
		// (the last wrapper of the after-STOP layout) or the declared size was
		// not computable (a structured dtype).
		for _, w := range wrappers {
			if w.inline || !w.sized {
				continue
			}
			if int(w.payloadStart) < len(data) && data[w.payloadStart] == jbStop {
				continue
			}
			ctx.Sink.EmitExtra(RuleJoblibMismatch, w.payloadStart,
				"the array payload at this offset does not begin with the [padding][0xff x padding][data] "+
					"framing the wrapper's declared dtype and shape describe",
				map[string]string{"dtype": w.dtype, "shape": shapeString(w.shape)})
		}
		dispatchInline(ctx, data, wrappers)
		return nil
	}
	// No payload was located at the first wrapper's own position. If the bytes
	// there are not a STOP, the stream is the inline layout and its framing is
	// broken; report it only when the declared size was computable, so an
	// unsizeable (structured) dtype is not turned into a false violation.
	if len(wrappers) > 0 && int(wrappers[0].payloadStart) < len(data) &&
		data[wrappers[0].payloadStart] != jbStop {
		if wrappers[0].sized {
			w := wrappers[0]
			ctx.Sink.EmitExtra(RuleJoblibMismatch, w.payloadStart,
				"the array payload at this offset does not begin with the [padding][0xff x padding][data] framing "+
					"the wrapper's declared dtype and shape describe",
				map[string]string{"dtype": w.dtype, "shape": shapeString(w.shape)})
		}
		return nil
	}

	// The array bytes follow a complete object pickle: compare the declared size
	// with that tail, and dispatch an object array's nested pickle.
	decl, decoded := declFrom(wrappers)
	tail := tailFrom(data, stream)
	single := wrapperCount(stream) == 1

	if decoded {
		payload, padding, framed := payloadRegion(tail)
		switch {
		case !single:
			// More than one wrapper in the stream: the tail is a concatenation
			// of array payloads with no per-array boundary the walker exposes, so
			// a length comparison would be meaningless. Object payloads are still
			// dispatched below.
			if decl.object && len(payload) > 0 {
				artifact.ScanMemberBytes(ctx, "object-array.pkl", payload)
			}
		case framed && decl.object:
			if len(payload) > 0 {
				artifact.ScanMemberBytes(ctx, "object-array.pkl", payload)
			}
		case framed && decl.itemsize > 0 && decl.elems >= 0:
			want, ok := mulOverflow(decl.elems, decl.itemsize)
			if ok && int64(len(payload)) != want {
				ctx.Sink.EmitExtra(RuleJoblibMismatch, 0,
					"wrapper declares "+shapeString(decl.shape)+" x "+strconv.FormatInt(decl.itemsize, 10)+
						" = "+strconv.FormatInt(want, 10)+" bytes but the payload is "+
						strconv.FormatInt(int64(len(payload)), 10)+" bytes (padding "+strconv.Itoa(padding)+")",
					map[string]string{
						"declared_bytes": strconv.FormatInt(want, 10),
						"payload_bytes":  strconv.FormatInt(int64(len(payload)), 10),
						"dtype":          decl.dtype,
						"shape":          shapeString(decl.shape),
					})
			}
		default:
			ctx.Sink.EmitExtra(RuleJoblibMismatch, 0,
				"joblib array payload does not begin with the [padding][0xff x padding][data] framing",
				map[string]string{"dtype": decl.dtype, "shape": shapeString(decl.shape)})
		}
	} else if len(tail) > 0 {
		// The wrapper arguments could not be decoded. If the tail still starts a
		// pickle after a plausible padding frame, hand it to the engine so an
		// object array's payload is not lost just because the wrapper's dtype
		// could not be read.
		payload, _, _ := payloadRegion(tail)
		if looksLikePickleStart(payload) {
			artifact.ScanMemberBytes(ctx, "object-array.pkl", payload)
		}
	}
	return nil
}

// dispatchInline scans the payload of every inline wrapper as a member. An
// object-dtype payload is a nested pickle; a numeric payload is the raw array
// bytes after the padding frame.
func dispatchInline(ctx *artifact.Ctx, data []byte, wrappers []joblibWrapper) {
	n := 0
	for _, w := range wrappers {
		if !w.inline {
			continue
		}
		start, end := int(w.payloadStart), int(w.payloadEnd)
		if start < 0 || end > len(data) || start >= end {
			continue
		}
		var body []byte
		var name string
		if w.object {
			body = data[start:end]
			name = "object-array.pkl"
		} else {
			off := start + 1 + w.padding
			if off > end {
				continue
			}
			body = data[off:end]
			name = "array-" + strconv.Itoa(n) + ".bin"
		}
		if len(body) > 0 {
			artifact.ScanMemberBytes(ctx, name, body)
		}
		n++
	}
}

// maskPayload overwrites b in place with opcodes that stay inside the weights-only
// set and keep the operand stack where the pickle engine expects it: "MARK TUPLE"
// pairs, which are depth-neutral (MARK pushes a mark, TUPLE pops back to it and
// pushes the tuple), plus a trailing NONE when the length is odd, which leaves one
// surplus value. The walker bounds the operand stack (MaxStackDepth), so a mask that
// grew it without bound would report a legitimate large payload as a stack overflow;
// one leftover value is harmless, because the walker diagnoses stack underflow and
// not a value nobody consumed. The mask used to write "NONE POP" pairs, and POP
// (0x30) is *not* in the weights-only set, so masking an inline payload made the
// scanner's own injection set RequiresUnsafeLoader and a joblib file whose opcodes
// were all accepted was reported as SC4N-PICKLE-REQUIRES-UNSAFE-LOADER.
func maskPayload(b []byte) {
	for i := 0; i+1 < len(b); i += 2 {
		b[i], b[i+1] = jbMark, jbTuple
	}
	if len(b)%2 == 1 {
		b[len(b)-1] = jbNone
	}
}

// wrapperCount counts the joblib ndarray wrapper globals the pickle engine saw.
func wrapperCount(stream *pickle.Stream) int {
	if stream == nil {
		return 0
	}
	n := 0
	for _, g := range stream.Globals {
		if isJoblibWrapper(g.Module + "." + g.Name) {
			n++
		}
	}
	return n
}

// tailFrom returns the bytes after the pickle stream's first STOP.
func tailFrom(data []byte, stream *pickle.Stream) []byte {
	if stream == nil {
		return nil
	}
	end := stream.EndOffset
	if end < 0 || end > int64(len(data)) {
		return nil
	}
	return data[end:]
}

// payloadRegion decodes joblib's array payload framing: one byte giving the
// padding length, that many 0xff bytes, then the raw array bytes (or, for an
// object array, a nested pickle stream). framed is false when the prefix does
// not match, in which case data is the whole region.
func payloadRegion(tail []byte) (data []byte, padding int, framed bool) {
	if len(tail) == 0 {
		return nil, 0, false
	}
	p := int(tail[0])
	if p == 0 {
		return tail[1:], 0, true
	}
	if 1+p > len(tail) {
		return tail, 0, false
	}
	for _, b := range tail[1 : 1+p] {
		if b != 0xff {
			return tail, 0, false
		}
	}
	return tail[1+p:], p, true
}

// looksLikePickleStart reports whether b begins with a pickle protocol marker,
// which is the cheap gate before handing a region to artifact.ScanMemberBytes.
func looksLikePickleStart(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x80 && b[1] >= 1 && b[1] <= 5
}

// joblibDecl is the declared array shape extracted from a wrapper.
type joblibDecl struct {
	dtype    string
	shape    []int64
	elems    int64
	itemsize int64
	object   bool
}

// declFrom builds the declaration used by the after-STOP comparison from the
// first wrapper the walk found.
func declFrom(wrappers []joblibWrapper) (joblibDecl, bool) {
	if len(wrappers) == 0 {
		return joblibDecl{}, false
	}
	w := wrappers[0]
	if w.dtype == "" || !w.haveShape {
		return joblibDecl{}, false
	}
	decl := joblibDecl{dtype: w.dtype, shape: w.shape, object: w.object}
	if !decl.object {
		if sz, ok := dtypeSize(w.dtype); ok {
			if elems, ok2 := shapeElems(w.shape); ok2 {
				decl.itemsize = sz
				decl.elems = elems
			}
		}
	}
	return decl, true
}

func isJoblibWrapper(name string) bool {
	for _, w := range []string{"joblib.numpy_pickle.NumpyArrayWrapper", "joblib.numpy_pickle.NDArrayWrapper", "joblib.numpy_pickle.ZNDArrayWrapper"} {
		if name == w {
			return true
		}
	}
	return false
}

// --- opcode walk -------------------------------------------------------------

// Opcode bytes the walk needs. The full table lives in internal/pickle's
// generated opcodes.go; only the opcodes a joblib stream actually carries are
// named here.
const (
	jbBinint          = 0x4a
	jbBinint1         = 0x4b
	jbBinint2         = 0x4d
	jbLong1           = 0x8a
	jbLong4           = 0x8b
	jbBinfloat        = 0x47
	jbBinbytes        = 0x42
	jbShortBinbytes   = 0x43
	jbBinbytes8       = 0x8e
	jbBinstring       = 0x54
	jbShortBinstring  = 0x55
	jbBinunicode      = 0x58
	jbShortBinunicode = 0x8c
	jbBinunicode8     = 0x8d
	jbEmptyList       = 0x5d
	jbEmptyDict       = 0x7d
	jbList            = 0x6c
	jbDict            = 0x64
	jbSetitem         = 0x73
	jbSetitems        = 0x75
	jbAppend          = 0x61
	jbAppends         = 0x65
	jbGlobal          = 0x63
	jbStackGlobal     = 0x93
	jbNewobj          = 0x81
	jbNewobjEx        = 0x92
	jbInst            = 0x69
	jbObj             = 0x6f
	jbReduce          = 0x52
	jbBuild           = 0x62
	jbMemoize         = 0x94
	jbBinput          = 0x71
	jbLongBinput      = 0x72
	jbBinget          = 0x68
	jbLongBinget      = 0x6a
	jbPut             = 0x70
	jbGet             = 0x67
	jbProto           = 0x80
	jbFrame           = 0x95
	jbStop            = 0x2e
	jbMark            = 0x28
	jbEmptyTuple      = 0x29
	jbTuple           = 0x74
	jbTuple1          = 0x85
	jbTuple2          = 0x86
	jbTuple3          = 0x87
	jbPop             = 0x30
	jbPopMark         = 0x31
	jbDup             = 0x32
	jbNone            = 0x4e
	jbNewtrue         = 0x88
	jbNewfalse        = 0x89
)

// jkind is the shape of a value on the walk's shadow stack.
type jkind uint8

const (
	jNone jkind = iota
	jInt
	jStr
	jBytes
	jBool
	jTuple
	jGlobal
	jMark
	jDict
	jInstance
	jOther
)

// jval is one shadow-stack value. Only what the wrapper decode needs is kept:
// the name of a global/instance, tuple elements, dict entries and integer
// leaves.
type jval struct {
	kind jkind
	i    int64
	s    string
	t    []jval
	m    map[string]jval
}

// joblibWrapper is one ndarray wrapper found by the opcode walk, with its
// declared dtype/shape and the payload region that follows it.
type joblibWrapper struct {
	dtype     string
	shape     []int64
	haveShape bool
	object    bool

	// payloadStart is the offset at which the array payload begins — immediately
	// after the wrapper's BUILD, the position joblib's own unpickler reads from.
	payloadStart int64
	// inline reports that a well-formed payload was found at payloadStart (the
	// layout joblib writes, where the payload precedes the stream's STOP).
	inline bool
	// payloadEnd is the exclusive end of the inline payload region.
	payloadEnd int64
	// padding is the number of 0xff bytes in the numeric framing.
	padding int
	// sized reports that the declared dtype and shape gave a computable byte
	// size, so a payload was expected at payloadStart with a known length. A
	// structured or otherwise unsizeable dtype leaves this false and no framing
	// violation is claimed for it.
	sized bool
}

// jwalk walks a joblib pickle stream. It is total: an unknown or truncated
// opcode sets err and ends the walk, and no input makes it panic or run
// unbounded.
type jwalk struct {
	data     []byte
	i        int
	stack    []jval
	memo     map[int]jval
	next     int
	wrappers []joblibWrapper
	stopAt   int
	locate   bool
	err      bool
}

const (
	jMaxStack = 1 << 16
	jMaxMemo  = 1 << 16
)

// walkWrappers walks the whole stream and returns every ndarray wrapper, with
// its inline payload located.
func walkWrappers(data []byte) []joblibWrapper {
	d := &jwalk{data: data, memo: map[int]jval{}, stopAt: -1, locate: true}
	d.run()
	return d.wrappers
}

// nestedPickleLen returns the length of a complete nested pickle starting at
// start, which is how long an object-dtype array's payload is.
func nestedPickleLen(data []byte, start int) (int, bool) {
	if start < 0 || start >= len(data) || !looksLikePickleStart(data[start:]) {
		return 0, false
	}
	n := &jwalk{data: data[start:], memo: map[int]jval{}, stopAt: -1}
	n.run()
	if n.err || n.stopAt < 0 {
		return 0, false
	}
	return n.stopAt + 1, true
}

func (d *jwalk) run() {
	for d.i < len(d.data) && !d.err {
		d.step()
	}
}

func (d *jwalk) push(v jval) {
	if len(d.stack) >= jMaxStack {
		d.err = true
		return
	}
	d.stack = append(d.stack, v)
}

func (d *jwalk) top() (jval, bool) {
	if len(d.stack) == 0 {
		return jval{}, false
	}
	return d.stack[len(d.stack)-1], true
}

func (d *jwalk) pop() (jval, bool) {
	v, ok := d.top()
	if ok {
		d.stack = d.stack[:len(d.stack)-1]
	}
	return v, ok
}

func (d *jwalk) popN(n int) []jval {
	if n < 0 || n > len(d.stack) {
		d.err = true
		return nil
	}
	items := append([]jval(nil), d.stack[len(d.stack)-n:]...)
	d.stack = d.stack[:len(d.stack)-n]
	return items
}

func (d *jwalk) popToMark() ([]jval, bool) {
	for i := len(d.stack) - 1; i >= 0; i-- {
		if d.stack[i].kind == jMark {
			items := append([]jval(nil), d.stack[i+1:]...)
			d.stack = d.stack[:i]
			return items, true
		}
	}
	return nil, false
}

// step decodes one opcode and advances i. It mirrors the operand effects of the
// pickle engine only as far as the wrapper decode needs.
func (d *jwalk) step() {
	op := d.data[d.i]
	d.i++
	switch op {
	case jbProto:
		d.skip(1)
	case jbFrame:
		d.skip(8)
	case jbStop:
		d.stopAt = d.i - 1
		d.i = len(d.data)
	case jbMark:
		d.push(jval{kind: jMark})
	case jbPop:
		d.pop()
	case jbPopMark:
		if _, ok := d.popToMark(); !ok {
			d.err = true
		}
	case jbDup:
		if v, ok := d.top(); ok {
			d.push(v)
		} else {
			d.err = true
		}
	case jbNone:
		d.push(jval{kind: jNone})
	case jbNewtrue:
		d.push(jval{kind: jBool, i: 1})
	case jbNewfalse:
		d.push(jval{kind: jBool})
	case jbBinint:
		if v, ok := d.readIntLE(4); ok {
			d.push(jval{kind: jInt, i: v})
		}
	case jbBinint1:
		if v, ok := d.readUintLE(1); ok {
			d.push(jval{kind: jInt, i: int64(v)})
		}
	case jbBinint2:
		if v, ok := d.readUintLE(2); ok {
			d.push(jval{kind: jInt, i: int64(v)})
		}
	case jbLong1:
		if n, ok := d.readUintLE(1); ok {
			if body, ok2 := d.take(int(n)); ok2 {
				d.push(jval{kind: jInt, i: leSigned(body)})
			}
		}
	case jbLong4:
		if n, ok := d.readUintLE(4); ok {
			if n > uint64(len(d.data)) {
				d.err = true
				break
			}
			if body, ok2 := d.take(int(n)); ok2 {
				d.push(jval{kind: jInt, i: leSigned(body)})
			}
		}
	case jbBinfloat:
		if _, ok := d.take(8); ok {
			d.push(jval{kind: jOther})
		}
	case jbBinbytes:
		d.readBlob(4, false)
	case jbBinstring, jbBinunicode:
		d.readBlob(4, true)
	case jbBinbytes8:
		d.readBlob(8, false)
	case jbBinunicode8:
		d.readBlob(8, true)
	case jbShortBinbytes:
		d.readBlob(1, false)
	case jbShortBinstring, jbShortBinunicode:
		d.readBlob(1, true)
	case jbEmptyTuple:
		d.push(jval{kind: jTuple})
	case jbTuple:
		items, ok := d.popToMark()
		if !ok {
			d.err = true
			break
		}
		d.push(jval{kind: jTuple, t: items})
	case jbTuple1:
		d.push(jval{kind: jTuple, t: d.popN(1)})
	case jbTuple2:
		d.push(jval{kind: jTuple, t: d.popN(2)})
	case jbTuple3:
		d.push(jval{kind: jTuple, t: d.popN(3)})
	case jbEmptyList:
		d.push(jval{kind: jOther})
	case jbEmptyDict:
		d.push(jval{kind: jDict, m: map[string]jval{}})
	case jbList, jbDict:
		if _, ok := d.popToMark(); !ok {
			d.err = true
			break
		}
		if op == jbDict {
			d.push(jval{kind: jDict, m: map[string]jval{}})
		} else {
			d.push(jval{kind: jOther})
		}
	case jbSetitem:
		val, ok1 := d.pop()
		key, ok2 := d.pop()
		if !ok1 || !ok2 || !d.setInto(key, val) {
			d.err = true
		}
	case jbAppend:
		if _, ok := d.pop(); !ok {
			d.err = true
		}
	case jbAppends:
		if _, ok := d.popToMark(); !ok {
			d.err = true
		}
	case jbSetitems:
		items, ok := d.popToMark()
		if !ok {
			d.err = true
			break
		}
		if !d.setItems(items) {
			d.err = true
		}
	case jbGlobal:
		mod, ok1 := d.readLine()
		name, ok2 := d.readLine()
		if !ok1 || !ok2 {
			d.err = true
			break
		}
		d.push(jval{kind: jGlobal, s: mod + "." + name})
	case jbStackGlobal:
		name, ok1 := d.pop()
		mod, ok2 := d.pop()
		if !ok1 || !ok2 || mod.kind != jStr || name.kind != jStr {
			d.err = true
			break
		}
		d.push(jval{kind: jGlobal, s: mod.s + "." + name.s})
	case jbNewobj:
		args, ok1 := d.pop()
		cls, ok2 := d.pop()
		if !ok1 || !ok2 {
			d.err = true
			break
		}
		d.push(jval{kind: jInstance, s: cls.s, t: args.t})
	case jbNewobjEx:
		_, ok1 := d.pop()
		args, ok2 := d.pop()
		cls, ok3 := d.pop()
		if !ok1 || !ok2 || !ok3 {
			d.err = true
			break
		}
		d.push(jval{kind: jInstance, s: cls.s, t: args.t})
	case jbInst:
		mod, ok1 := d.readLine()
		name, ok2 := d.readLine()
		if !ok1 || !ok2 {
			d.err = true
			break
		}
		if _, ok := d.popToMark(); !ok {
			d.err = true
			break
		}
		d.push(jval{kind: jInstance, s: mod + "." + name})
	case jbObj:
		items, ok := d.popToMark()
		if !ok {
			d.err = true
			break
		}
		s := ""
		if len(items) > 0 {
			s = items[0].s
		}
		d.push(jval{kind: jInstance, s: s})
	case jbReduce:
		args, ok1 := d.pop()
		callee, ok2 := d.pop()
		if !ok1 || !ok2 {
			d.err = true
			break
		}
		d.push(jval{kind: jInstance, s: callee.s, t: args.t})
	case jbBuild:
		state, ok1 := d.pop()
		inst, ok2 := d.pop()
		if !ok1 || !ok2 {
			d.err = true
			break
		}
		d.maybeWrapper(inst, state)
		d.push(inst)
	case jbMemoize:
		top, ok := d.top()
		if !ok {
			d.err = true
			break
		}
		d.memoPut(d.next, top)
		d.next++
	case jbBinput, jbLongBinput:
		w := memoArgWidth(op)
		idx, ok := d.readUintLE(w)
		if !ok {
			break
		}
		if idx >= jMaxMemo {
			d.err = true
			break
		}
		top, ok2 := d.top()
		if !ok2 {
			d.err = true
			break
		}
		d.memoPut(int(idx), top)
		if int(idx) >= d.next {
			d.next = int(idx) + 1
		}
	case jbBinget, jbLongBinget:
		w := memoArgWidth(op)
		idx, ok := d.readUintLE(w)
		if !ok {
			break
		}
		if v, found := d.memo[int(idx)]; found {
			d.push(v)
		} else {
			d.push(jval{kind: jOther})
		}
	case jbPut, jbGet:
		idx, ok := d.readLineInt()
		if !ok {
			break
		}
		if idx < 0 || idx >= jMaxMemo {
			d.err = true
			break
		}
		if op == jbPut {
			top, ok2 := d.top()
			if !ok2 {
				d.err = true
				break
			}
			d.memoPut(idx, top)
			if idx >= d.next {
				d.next = idx + 1
			}
		} else if v, found := d.memo[idx]; found {
			d.push(v)
		} else {
			d.push(jval{kind: jOther})
		}
	default:
		d.err = true
	}
}

// memoArgWidth returns the width of a memo opcode's index, mirroring the
// argument kinds in internal/pickle's generated opcode table: BINPUT (0x71) and
// BINGET (0x68) carry a one-byte index, LONG_BINPUT (0x72) and LONG_BINGET
// (0x6a) a four-byte one. Treating all four as four bytes desynchronised every
// protocol <= 3 stream that used BINPUT/BINGET.
func memoArgWidth(op byte) int {
	switch op {
	case jbBinput, jbBinget:
		return 1
	case jbLongBinput, jbLongBinget:
		return 4
	}
	return 0
}

func (d *jwalk) memoPut(idx int, v jval) {
	if idx < 0 || idx >= jMaxMemo {
		d.err = true
		return
	}
	d.memo[idx] = v
}

// setInto stores one key/value pair in the dict on top of the stack.
func (d *jwalk) setInto(key, val jval) bool {
	top, ok := d.top()
	if !ok || top.kind != jDict {
		return false
	}
	top.m[key.s] = val
	return true
}

// setItems stores the key/value pairs collected by SETITEMS in the dict on top
// of the stack.
func (d *jwalk) setItems(items []jval) bool {
	top, ok := d.top()
	if !ok || top.kind != jDict {
		return false
	}
	for i := 0; i+1 < len(items); i += 2 {
		top.m[items[i].s] = items[i+1]
	}
	return true
}

// maybeWrapper records a wrapper instance whose BUILD just completed, locates
// its payload and skips it so the walk continues after it.
func (d *jwalk) maybeWrapper(inst, state jval) {
	if !d.locate || !isJoblibWrapper(inst.s) {
		return
	}
	w := joblibWrapper{payloadStart: int64(d.i)}
	if state.kind == jDict {
		if v, ok := state.m["dtype"]; ok {
			w.dtype = dtypeOf(v)
		}
		if v, ok := state.m["shape"]; ok {
			if sh, ok := intTupleOf(v); ok {
				w.shape, w.haveShape = sh, true
			}
		}
	}
	if w.dtype == "" {
		// Legacy form: the dtype/shape are the wrapper's REDUCE arguments.
		for _, a := range inst.t {
			if w.dtype == "" && a.kind == jStr {
				w.dtype = a.s
				continue
			}
			if !w.haveShape && a.kind == jTuple {
				if sh, ok := intTupleOf(a); ok {
					w.shape, w.haveShape = sh, true
				}
			}
		}
	}
	w.object = isObjectDtype(w.dtype)
	d.locatePayload(&w)
	d.wrappers = append(d.wrappers, w)
	if w.inline {
		d.i = int(w.payloadEnd)
	}
}

// locatePayload finds the array bytes at the wrapper's own position. The framing
// is [padding byte][padding x 0xff][itemsize x count data] for a numeric array,
// or a nested pickle for an object array; the walk skips whatever it finds so it
// resumes at the next opcode rather than inside the array.
func (d *jwalk) locatePayload(w *joblibWrapper) {
	start := d.i
	if start < 0 || start >= len(d.data) {
		return
	}
	if w.object {
		if n, ok := nestedPickleLen(d.data, start); ok {
			w.inline = true
			w.payloadEnd = int64(start + n)
		}
		return
	}
	if w.dtype == "" || !w.haveShape {
		return
	}
	sz, ok := dtypeSize(w.dtype)
	if !ok {
		return
	}
	elems, ok := shapeElems(w.shape)
	if !ok {
		return
	}
	total, ok := mulOverflow(elems, sz)
	if !ok {
		return
	}
	// A computable declared size means a payload is expected here; if the
	// framing below does not match, that is a violation worth reporting.
	w.sized = true
	p := int(d.data[start])
	if start+1+p > len(d.data) {
		return
	}
	for _, b := range d.data[start+1 : start+1+p] {
		if b != 0xff {
			return
		}
	}
	rem := int64(len(d.data)) - int64(start) - 1 - int64(p)
	if rem < 0 || total > rem {
		return
	}
	w.inline = true
	w.padding = p
	w.payloadEnd = int64(start) + 1 + int64(p) + total
}

// dtypeOf extracts a simple dtype string from a wrapper state value: a string,
// or a numpy.dtype(...) REDUCE result whose first string argument is the
// descriptor (for example 'f8' in numpy.dtype('f8', False, True)).
func dtypeOf(v jval) string {
	switch v.kind {
	case jStr:
		return v.s
	case jInstance:
		for _, a := range v.t {
			if a.kind == jStr {
				return a.s
			}
		}
	}
	return ""
}

// intTupleOf reads a tuple of integers, reporting false when any element is not
// an integer. An empty tuple is a valid, empty shape.
func intTupleOf(v jval) ([]int64, bool) {
	if v.kind != jTuple {
		return nil, false
	}
	out := make([]int64, 0, len(v.t))
	for _, e := range v.t {
		if e.kind != jInt {
			return nil, false
		}
		out = append(out, e.i)
	}
	return out, true
}

// skip advances past n bytes without decoding them.
func (d *jwalk) skip(n int) {
	if _, ok := d.take(n); !ok {
		d.err = true
	}
}

// take consumes n bytes and returns them, or ok=false (and err) when they run
// past the end.
func (d *jwalk) take(n int) ([]byte, bool) {
	if n < 0 || d.i+n > len(d.data) {
		d.err = true
		return nil, false
	}
	b := d.data[d.i : d.i+n]
	d.i += n
	return b, true
}

func (d *jwalk) readUintLE(n int) (uint64, bool) {
	b, ok := d.take(n)
	if !ok {
		return 0, false
	}
	var v uint64
	for k := range n {
		v |= uint64(b[k]) << (8 * k)
	}
	return v, true
}

func (d *jwalk) readIntLE(n int) (int64, bool) {
	v, ok := d.readUintLE(n)
	if !ok {
		return 0, false
	}
	shift := uint(64 - 8*n)
	return int64(v<<shift) >> shift, true
}

// readBlob reads a length-prefixed blob and pushes it as a value. text selects a
// string value (for the unicode/binststring opcodes) over an opaque bytes value.
// Only a bounded prefix is retained: the walk needs names and descriptors, not
// payloads.
func (d *jwalk) readBlob(width int, text bool) {
	const maxText = 4096
	n, ok := d.readUintLE(width)
	if !ok {
		return
	}
	if n > uint64(len(d.data)) {
		d.err = true
		return
	}
	body, ok := d.take(int(n))
	if !ok {
		return
	}
	if !text {
		d.push(jval{kind: jBytes})
		return
	}
	if len(body) > maxText {
		body = body[:maxText]
	}
	d.push(jval{kind: jStr, s: string(body)})
}

// readLine reads a newline-terminated text line.
func (d *jwalk) readLine() (string, bool) {
	idx := bytes.IndexByte(d.data[d.i:], '\n')
	if idx < 0 {
		d.err = true
		return "", false
	}
	s := string(d.data[d.i : d.i+idx])
	d.i += idx + 1
	return s, true
}

// readLineInt reads a newline-terminated decimal integer (PUT/GET).
func (d *jwalk) readLineInt() (int, bool) {
	s, ok := d.readLine()
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		d.err = true
		return 0, false
	}
	return n, true
}

// leSigned interprets a little-endian two's-complement body as an int64.
func leSigned(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	if len(b) < 8 && b[len(b)-1]&0x80 != 0 {
		v |= ^int64(0) << (8 * uint(len(b)))
	}
	return v
}
