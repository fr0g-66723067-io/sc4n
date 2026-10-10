package onnx

// wire.go is the protobuf wire-format layer: a forward-only, windowed reader
// over a source.Source, plus the small shape probes the sniffer uses.
//
// Two properties matter more than speed here:
//
//   - no allocation from an attacker-controlled length. A length-delimited field
//     is bounded against the bytes actually remaining in its enclosing message
//     before it is used, and the reader hands out a window of at most readChunk
//     bytes; only a string sc4n is about to scan is materialised, and only after
//     it has been checked against MaxStringBlob.
//   - a nested message is walked in place. raw_data, subgraphs and initializer
//     bodies are skipped by length, so walking a 10 GB graph costs one window at
//     a time rather than 10 GB of RSS.

import (
	"io"

	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// maxVarintLen is the longest a base-128 varint can be, which is the most a
	// tag or a length prefix can occupy.
	maxVarintLen = 10
	// readChunk is the window a reader refills at a time. It is large enough
	// that a node or a tensor walks inside one window and small enough that a
	// hundred concurrent artifacts stay inside the memory budget.
	readChunk = 64 << 10
	// probeBytes bounds the shape probes to the first few fields of a message.
	probeBytes = 4096
)

// reader walks one protobuf message in place over a Source. pos advances
// monotonically; the window is refilled from pos, so skipping a multi-gigabyte
// field costs nothing. A read past r.end (or a malformed tag/varint) sets err
// and every later read returns nothing.
type reader struct {
	s      source.Source
	pos    int64
	end    int64
	buf    []byte
	bufOff int64
	err    error
}

// newReader returns a reader over [start, end) of s. end must already be valid
// for s: callers establish it from a validated length prefix or from Size.
func newReader(s source.Source, start, end int64) *reader {
	return &reader{s: s, pos: start, end: end}
}

// newProbe returns a reader over [start, start+n) clamped to the end of the
// source, for the sniffers' bounded look at a message it does not intend to walk.
func newProbe(s source.Source, start, n int64) *reader {
	end := start + n
	if size := s.Size(); end > size {
		end = size
	}
	if end < start {
		end = start
	}
	return newReader(s, start, end)
}

func (r *reader) remaining() int64 { return r.end - r.pos }

// fill ensures the window covers r.pos..r.pos+n as far as the message allows.
func (r *reader) fill(n int) {
	if r.err != nil || r.pos >= r.end {
		return
	}
	if r.bufOff <= r.pos && r.pos+int64(n) <= r.bufOff+int64(len(r.buf)) {
		return
	}
	want := int64(readChunk)
	if int64(n) > want {
		want = int64(n)
	}
	if r.pos+want > r.end {
		want = r.end - r.pos
	}
	b, err := r.s.Bytes(r.pos, want)
	if len(b) == 0 {
		if err != nil {
			r.err = err
		} else {
			r.err = io.ErrUnexpectedEOF
		}
		return
	}
	r.buf, r.bufOff = b, r.pos
}

// avail returns up to n bytes from r.pos. It returns nil at the end of the
// message or when the source could not be read; a short slice means the message
// ends sooner than n and is reported through protowire's own truncation codes.
func (r *reader) avail(n int) []byte {
	if r.err != nil {
		return nil
	}
	r.fill(n)
	if r.err != nil || r.pos >= r.end {
		return nil
	}
	i := r.pos - r.bufOff
	if i < 0 || i >= int64(len(r.buf)) {
		return nil
	}
	b := r.buf[i:]
	if len(b) > n {
		b = b[:n]
	}
	return b
}

// next consumes one field tag and returns the field number, its wire type and
// the tag's absolute offset.
func (r *reader) next() (protowire.Number, protowire.Type, int64, bool) {
	off := r.pos
	b := r.avail(maxVarintLen)
	if len(b) == 0 {
		if r.err == nil {
			r.err = io.ErrUnexpectedEOF
		}
		return 0, 0, off, false
	}
	num, typ, n := protowire.ConsumeTag(b)
	if n < 0 {
		r.err = protowire.ParseError(n)
		return 0, 0, off, false
	}
	r.pos += int64(n)
	return num, typ, off, true
}

// varintValue consumes a varint value at the current position.
func (r *reader) varintValue() (uint64, bool) {
	b := r.avail(maxVarintLen)
	if len(b) == 0 {
		if r.err == nil {
			r.err = io.ErrUnexpectedEOF
		}
		return 0, false
	}
	v, n := protowire.ConsumeVarint(b)
	if n < 0 {
		r.err = protowire.ParseError(n)
		return 0, false
	}
	r.pos += int64(n)
	return v, true
}

// fixedValue consumes a fixed32 or fixed64 value.
func (r *reader) fixedValue(size int) bool {
	if r.remaining() < int64(size) {
		r.err = io.ErrUnexpectedEOF
		return false
	}
	r.pos += int64(size)
	return true
}

// bytesValue consumes a length-delimited value and returns its extent without
// reading it. The declared length is checked against the bytes actually
// remaining in the enclosing message before pos moves, so a length of 2^60 on a
// 4 KB message is a parse error, not an allocation.
func (r *reader) bytesValue() (off, n int64, ok bool) {
	b := r.avail(maxVarintLen)
	if len(b) == 0 {
		if r.err == nil {
			r.err = io.ErrUnexpectedEOF
		}
		return 0, 0, false
	}
	l, k := protowire.ConsumeVarint(b)
	if k < 0 {
		r.err = protowire.ParseError(k)
		return 0, 0, false
	}
	r.pos += int64(k)
	if l > uint64(r.remaining()) {
		r.err = io.ErrUnexpectedEOF
		return 0, 0, false
	}
	off = r.pos
	n = int64(l)
	r.pos += n
	return off, n, true
}

// view materialises [off, off+n) from the source. n MUST already be capped by
// the caller. On a mapped source this is a slice into the mapping, not a copy.
func (r *reader) view(off, n int64) []byte {
	if n <= 0 {
		return nil
	}
	b, err := r.s.Bytes(off, n)
	if int64(len(b)) < n {
		if r.err == nil && err != nil {
			r.err = err
		}
		return nil
	}
	return b
}

// skipValue consumes the value of a field sc4n does not interpret.
func (r *reader) skipValue(typ protowire.Type) bool {
	switch typ {
	case protowire.VarintType:
		_, ok := r.varintValue()
		return ok
	case protowire.Fixed32Type:
		return r.fixedValue(4)
	case protowire.Fixed64Type:
		return r.fixedValue(8)
	case protowire.BytesType:
		_, _, ok := r.bytesValue()
		return ok
	default:
		// Groups are not used by onnx.proto3 and are a parsing hazard in every
		// protobuf implementation that has ever tried to support them.
		r.err = errUnexpectedGroup
		return false
	}
}

// probeNode reports whether [off, off+n) looks like a NodeProto body: a valid
// prefix of field records containing an op_type (4) with a non-empty name. It is
// a shape test, not a parse, and it never walks more than probeBytes.
func probeNode(s source.Source, off, n int64) bool {
	r := newProbe(s, off, min64(n, probeBytes))
	for range 32 {
		if r.remaining() <= 0 {
			return false
		}
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if num == 4 {
			if typ != protowire.BytesType {
				return false
			}
			bo, bl, ok := r.bytesValue()
			if !ok {
				return false
			}
			return bl > 0 && printableUTF8(r.view(bo, bl))
		}
		if !r.skipValue(typ) {
			return false
		}
	}
	return false
}

// probeTensor reports whether [off, off+n) looks like a TensorProto body: a
// valid prefix of field records containing a data_type (2) or a dims (1) entry.
func probeTensor(s source.Source, off, n int64) bool {
	r := newProbe(s, off, min64(n, probeBytes))
	for range 32 {
		if r.remaining() <= 0 {
			return false
		}
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		switch num {
		case 2:
			return typ == protowire.VarintType
		case 1:
			return typ == protowire.VarintType || typ == protowire.BytesType
		default:
			if !r.skipValue(typ) {
				return false
			}
		}
	}
	return false
}

// probeValueInfo reports whether [off, off+n) looks like a ValueInfoProto body:
// a valid prefix containing a name (1) string.
func probeValueInfo(s source.Source, off, n int64) bool {
	r := newProbe(s, off, min64(n, probeBytes))
	for range 32 {
		if r.remaining() <= 0 {
			return false
		}
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if num == 1 {
			if typ != protowire.BytesType {
				return false
			}
			bo, bl, ok := r.bytesValue()
			return ok && bl > 0 && printableUTF8(r.view(bo, bl))
		}
		if !r.skipValue(typ) {
			return false
		}
	}
	return false
}

// graphShape reports whether [off, off+n) looks like a GraphProto body, and
// whether the signal is decisive (a node or an initializer shaped like its
// NodeProto/TensorProto counterpart) or weak (only a string field).
func graphShape(s source.Source, off, n int64) (shaped, decisive bool) {
	r := newProbe(s, off, min64(n, probeBytes))
	for range 64 {
		if r.remaining() <= 0 {
			return false, false
		}
		num, typ, _, ok := r.next()
		if !ok {
			return false, false
		}
		switch num {
		case 1: // node
			if typ != protowire.BytesType {
				return false, false
			}
			bo, bl, ok := r.bytesValue()
			if !ok {
				return false, false
			}
			if probeNode(s, bo, bl) {
				return true, true
			}
		case 5: // initializer
			if typ != protowire.BytesType {
				return false, false
			}
			bo, bl, ok := r.bytesValue()
			if !ok {
				return false, false
			}
			if probeTensor(s, bo, bl) {
				return true, true
			}
		case 2, 10: // name, doc_string: a string field on a graph-shaped body
			if typ != protowire.BytesType {
				return false, false
			}
			bo, bl, ok := r.bytesValue()
			if !ok {
				return false, false
			}
			if bl > 0 && printableUTF8(r.view(bo, bl)) {
				return true, false
			}
			return false, false
		case 11, 12, 13: // input, output, value_info
			if typ != protowire.BytesType {
				return false, false
			}
			bo, bl, ok := r.bytesValue()
			if !ok {
				return false, false
			}
			if probeValueInfo(s, bo, bl) {
				return true, false
			}
			return false, false
		default:
			if !r.skipValue(typ) {
				return false, false
			}
		}
	}
	return false, false
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
