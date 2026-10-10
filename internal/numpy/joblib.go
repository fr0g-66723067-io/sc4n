package numpy

import (
	"bytes"
	"strconv"

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
		Notes: "the object pickle is walked by the pickle engine with the appended array bodies treated as " +
			"container payload rather than an attack suffix; the wrapper's declared shape/dtype is " +
			"compared with the payload length (SC4N-JOBLIB-WRAPPER-MISMATCH) and an object-dtype payload " +
			"is a nested pickle stream, which is dispatched to the pickle engine. Compression (zlib/gzip/" +
			"bz2) is unwrapped by internal/archive before this parser runs.",
	})
	// Priority 97 is just above the pickle-walk sniffer's 95 and below the magic
	// table's 100, so a joblib-named pickle is claimed as joblib instead of as a
	// bare pickle while every format with a real magic still wins. A zlib/gzip/
	// bzip2-wrapped joblib is unwrapped by internal/archive and re-sniffed here
	// on the decompressed bytes; this parser never decompresses anything itself.
	artifact.RegisterSniffer("joblib", 97, sniffJoblib)
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

// sniffJoblib claims a stream that names a joblib wrapper class. It scans only
// the first sniffWindow bytes and never allocates from file-controlled lengths.
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
	for _, name := range joblibWrapperNames {
		if bytes.Contains(head, name) {
			return artifact.FormatJoblib, true
		}
	}
	return artifact.FormatUnknown, false
}

// Parse walks the joblib object pickle and its appended array bodies.
func (joblibParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	data, err := s.Bytes(0, s.Size())
	if err != nil && len(data) == 0 {
		return err
	}
	stream, werr := pickle.Walk(ctx, s, pickle.Options{
		TrailingIsStorage:  true,
		StorageDescription: "joblib array payload",
	})
	if werr != nil && stream == nil {
		return werr
	}

	decl, decoded := decodeWrapper(data)
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

// joblibDecl is the declared array shape extracted from the wrapper's REDUCE
// arguments.
type joblibDecl struct {
	dtype    string
	shape    []int64
	elems    int64
	itemsize int64
	object   bool
}

// decodeWrapper extracts the declared dtype and shape from the first joblib
// ndarray wrapper's REDUCE arguments.
//
// It is a deliberately small, total opcode walk over a stack of values: it
// understands only the opcodes joblib and CPython's pickler emit for the wrapper
// and its argument tuple, and abandons the decode (ok=false) on anything else
// rather than risk a wrong shape. The pickle engine already validated the
// stream; this pass exists solely because the engine exposes the globals it saw
// but not the REDUCE arguments, and the mismatch rule needs the declared size.
func decodeWrapper(data []byte) (joblibDecl, bool) {
	d := &jdecoder{data: data}
	d.run()
	if !d.found || d.dtype == "" {
		return joblibDecl{}, false
	}
	decl := joblibDecl{dtype: d.dtype, shape: d.shape, object: isObjectDtype(d.dtype)}
	if !decl.object {
		sz, ok := dtypeSize(d.dtype)
		if ok {
			if elems, ok2 := shapeElems(d.shape); ok2 {
				decl.itemsize = sz
				decl.elems = elems
			}
		}
	}
	return decl, true
}

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
	jOther
)

type jval struct {
	kind jkind
	i    int64
	s    string
	t    []jval
}

type jdecoder struct {
	data  []byte
	i     int
	stack []jval
	found bool
	dtype string
	shape []int64
	err   bool
}

func (d *jdecoder) run() {
	for d.i < len(d.data) && !d.err {
		op := d.data[d.i]
		d.i++
		d.step(op)
	}
}

func (d *jdecoder) push(v jval) { d.stack = append(d.stack, v) }
func (d *jdecoder) top() (jval, bool) {
	if len(d.stack) == 0 {
		return jval{}, false
	}
	return d.stack[len(d.stack)-1], true
}
func (d *jdecoder) pop() (jval, bool) {
	v, ok := d.top()
	if ok {
		d.stack = d.stack[:len(d.stack)-1]
	}
	return v, ok
}

func (d *jdecoder) step(op byte) {
	switch op {
	case 0x80: // PROTO
		d.skipN(1)
	case 0x95: // FRAME
		d.skipN(8)
	case 0x2e: // STOP
		d.i = len(d.data)
	case 0x28: // MARK
		d.push(jval{kind: jMark})
	case 0x30: // POP
		d.pop()
	case 0x31: // POP_MARK
		d.popToMark()
	case 0x32: // DUP
		if v, ok := d.top(); ok {
			d.push(v)
		}
	case 0x4e: // NONE
		d.push(jval{kind: jNone})
	case 0x88: // NEWTRUE
		d.push(jval{kind: jBool, i: 1})
	case 0x89: // NEWFALSE
		d.push(jval{kind: jBool})
	case 0x4a: // BININT
		if v, ok := d.readIntLE(4); ok {
			d.push(jval{kind: jInt, i: v})
		}
	case 0x4b: // BININT1
		if d.i < len(d.data) {
			d.push(jval{kind: jInt, i: int64(d.data[d.i])})
			d.i++
		} else {
			d.err = true
		}
	case 0x4d: // BININT2
		if v, ok := d.readUintLE(2); ok {
			d.push(jval{kind: jInt, i: int64(v)})
		}
	case 0x8a: // LONG1
		if d.i >= len(d.data) {
			d.err = true
			return
		}
		n := int(d.data[d.i])
		d.i++
		if d.i+n > len(d.data) {
			d.err = true
			return
		}
		body := d.data[d.i : d.i+n]
		d.i += n
		d.push(jval{kind: jInt, i: leSigned(body)})
	case 0x47: // BINFLOAT
		d.push(jval{kind: jOther})
		d.skipN(8)
	case 0x8c: // SHORT_BINUNICODE
		if d.i >= len(d.data) {
			d.err = true
			return
		}
		n := int(d.data[d.i])
		d.i++
		d.readString(n)
	case 0x58: // BINUNICODE
		if v, ok := d.readUintLE(4); ok {
			d.readString(int(v))
		}
	case 0x8d: // BINUNICODE8
		if v, ok := d.readUintLE(8); ok {
			d.readString(int(v))
		}
	case 0x43: // SHORT_BINBYTES
		if d.i >= len(d.data) {
			d.err = true
			return
		}
		n := int(d.data[d.i])
		d.i++
		d.readBytes(n)
	case 0x42: // BINBYTES
		if v, ok := d.readUintLE(4); ok {
			d.readBytes(int(v))
		}
	case 0x8e: // BINBYTES8
		if v, ok := d.readUintLE(8); ok {
			d.readBytes(int(v))
		}
	case 0x29: // EMPTY_TUPLE
		d.push(jval{kind: jTuple})
	case 0x74: // TUPLE
		d.push(jval{kind: jTuple, t: d.popToMark()})
	case 0x85: // TUPLE1
		d.push(jval{kind: jTuple, t: d.popN(1)})
	case 0x86: // TUPLE2
		d.push(jval{kind: jTuple, t: d.popN(2)})
	case 0x87: // TUPLE3
		d.push(jval{kind: jTuple, t: d.popN(3)})
	case 0x5d, 0x7d: // EMPTY_LIST / EMPTY_DICT
		d.push(jval{kind: jOther})
	case 0x6c, 0x64: // LIST / DICT
		d.popToMark()
		d.push(jval{kind: jOther})
	case 0x63: // GLOBAL (two newline-terminated names)
		mod, ok1 := d.readLine()
		name, ok2 := d.readLine()
		if !ok1 || !ok2 {
			d.err = true
			return
		}
		d.push(jval{kind: jGlobal, s: mod + "." + name})
	case 0x93: // STACK_GLOBAL
		name, ok1 := d.pop()
		mod, ok2 := d.pop()
		if !ok1 || !ok2 {
			d.err = true
			return
		}
		d.push(jval{kind: jGlobal, s: mod.s + "." + name.s})
	case 0x52: // REDUCE
		args, ok1 := d.pop()
		callableV, ok2 := d.pop()
		if !ok1 || !ok2 {
			d.err = true
			return
		}
		d.recordReduce(callableV, args)
	case 0x62: // BUILD
		d.pop()
	case 0x71, 0x72, 0x68, 0x6a: // BINPUT/LONG_BINPUT/BINGET/LONG_BINGET
		d.skipN(4)
	case 0x94: // MEMOIZE
		// no argument
	case 0x70, 0x67: // PUT/GET (newline int)
		d.readLine()
	case 0x73, 0x75, 0x61, 0x65: // SETITEM/SETITEMS/APPEND/APPENDS
		d.err = true
	default:
		d.err = true
	}
}

// recordReduce inspects a REDUCE whose callable is a joblib wrapper and records
// the declared dtype and shape from its arguments.
func (d *jdecoder) recordReduce(callableV, args jval) {
	if callableV.kind != jGlobal || !isJoblibWrapper(callableV.s) {
		return
	}
	if args.kind != jTuple {
		return
	}
	var dtype string
	var shape []int64
	for _, a := range args.t {
		if dtype == "" && a.kind == jStr {
			dtype = a.s
			continue
		}
		if shape == nil && a.kind == jTuple && len(a.t) > 0 {
			ok := true
			var sh []int64
			for _, e := range a.t {
				if e.kind != jInt {
					ok = false
					break
				}
				sh = append(sh, e.i)
			}
			if ok {
				shape = sh
			}
		}
	}
	if dtype == "" || shape == nil {
		return
	}
	d.found = true
	d.dtype = dtype
	d.shape = shape
}

func isJoblibWrapper(name string) bool {
	for _, w := range []string{"joblib.numpy_pickle.NumpyArrayWrapper", "joblib.numpy_pickle.NDArrayWrapper", "joblib.numpy_pickle.ZNDArrayWrapper"} {
		if name == w {
			return true
		}
	}
	return false
}

func (d *jdecoder) skipN(n int) {
	if d.i+n > len(d.data) {
		d.err = true
		d.i = len(d.data)
		return
	}
	d.i += n
}

func (d *jdecoder) readUintLE(n int) (uint64, bool) {
	if d.i+n > len(d.data) {
		d.err = true
		return 0, false
	}
	var v uint64
	for k := range n {
		v |= uint64(d.data[d.i+k]) << (8 * k)
	}
	d.i += n
	return v, true
}

func (d *jdecoder) readIntLE(n int) (int64, bool) {
	v, ok := d.readUintLE(n)
	if !ok {
		return 0, false
	}
	shift := uint(64 - 8*n)
	return int64(v<<shift) >> shift, true
}

func (d *jdecoder) readString(n int) {
	if n < 0 || d.i+n > len(d.data) {
		d.err = true
		return
	}
	d.push(jval{kind: jStr, s: string(d.data[d.i : d.i+n])})
	d.i += n
}

func (d *jdecoder) readBytes(n int) {
	if n < 0 || d.i+n > len(d.data) {
		d.err = true
		return
	}
	d.push(jval{kind: jBytes})
	d.i += n
}

func (d *jdecoder) readLine() (string, bool) {
	idx := bytes.IndexByte(d.data[d.i:], '\n')
	if idx < 0 {
		d.err = true
		return "", false
	}
	s := string(d.data[d.i : d.i+idx])
	d.i += idx + 1
	return s, true
}

func (d *jdecoder) popToMark() []jval {
	for i := len(d.stack) - 1; i >= 0; i-- {
		if d.stack[i].kind == jMark {
			items := append([]jval(nil), d.stack[i+1:]...)
			d.stack = d.stack[:i]
			return items
		}
	}
	d.stack = d.stack[:0]
	return nil
}

func (d *jdecoder) popN(n int) []jval {
	if n > len(d.stack) {
		d.err = true
		return nil
	}
	items := append([]jval(nil), d.stack[len(d.stack)-n:]...)
	d.stack = d.stack[:len(d.stack)-n]
	return items
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
