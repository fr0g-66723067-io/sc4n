package tfmodel

// wire.go is the protobuf wire-format layer for the TensorFlow family: a
// forward-only, windowed reader over a source.Source plus the shape probes the
// SavedModel/checkpoint sniffers use.
//
// It is deliberately the same shape as internal/onnx/wire.go, for the same two
// reasons:
//
//   - no allocation from an attacker-controlled length. A length-delimited field
//     is bounded against the bytes actually remaining in its enclosing message
//     before it is used, and the reader hands out a window of at most readChunk
//     bytes; only a string sc4n is about to scan is materialised, after it has
//     been checked against MaxStringBlob.
//   - a nested message is walked in place. A multi-gigabyte const tensor or an
//     object-graph body is skipped by length, so walking a graph costs one window
//     at a time rather than the size of the graph in RSS.

import (
	"io"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

const (
	// maxVarintLen is the longest a base-128 varint can be, which is the most a
	// tag or a length prefix can occupy.
	maxVarintLen = 10
	// readChunk is the window a reader refills at a time: large enough that a
	// node walks inside one window, small enough that many concurrent artifacts
	// stay inside the memory budget.
	readChunk = 64 << 10
	// probeBytes bounds the shape probes to the first few fields of a message.
	probeBytes = 4096
)

// pbReader walks one protobuf message in place over a Source. pos advances
// monotonically; the window is refilled from pos, so skipping a large field costs
// nothing. A read past r.end, or a malformed tag/varint, sets err and every later
// read returns nothing.
type pbReader struct {
	s      source.Source
	pos    int64
	end    int64
	buf    []byte
	bufOff int64
	err    error
}

func newPBReader(s source.Source, start, end int64) *pbReader {
	return &pbReader{s: s, pos: start, end: end}
}

// newPBProbe returns a reader over [start, start+n) clamped to the source.
func newPBProbe(s source.Source, start, n int64) *pbReader {
	end := start + n
	if size := s.Size(); end > size {
		end = size
	}
	if end < start {
		end = start
	}
	return newPBReader(s, start, end)
}

func (r *pbReader) remaining() int64 { return r.end - r.pos }

func (r *pbReader) fill(n int) {
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

func (r *pbReader) avail(n int) []byte {
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
func (r *pbReader) next() (protowire.Number, protowire.Type, int64, bool) {
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

func (r *pbReader) varintValue() (uint64, bool) {
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

func (r *pbReader) fixedValue(size int) bool {
	if r.remaining() < int64(size) {
		r.err = io.ErrUnexpectedEOF
		return false
	}
	r.pos += int64(size)
	return true
}

// bytesValue consumes a length-delimited value and returns its extent without
// reading it. The declared length is checked against the bytes remaining in the
// enclosing message before pos moves, so a length of 2^60 on a 4 KB message is a
// parse error, not an allocation.
func (r *pbReader) bytesValue() (off, n int64, ok bool) {
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

// view materialises [off, off+n) from the source. n MUST already be capped by the
// caller.
func (r *pbReader) view(off, n int64) []byte {
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

func (r *pbReader) skipValue(typ protowire.Type) bool {
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
		// Groups are not used by the TensorFlow protos and are a parsing hazard
		// in every implementation that has tried to support them.
		r.err = errUnexpectedGroup
		return false
	}
}

// pbString reads a length-delimited field as a string, under the MaxStringBlob
// cap. ok is false when the field is unreadable or larger than the cap (the
// caller decides whether to report the cap).
func (r *pbReader) pbString(max int64) (string, bool) {
	off, n, ok := r.bytesValue()
	if !ok {
		return "", false
	}
	if max > 0 && n > max {
		return "", false
	}
	b := r.view(off, n)
	if int64(len(b)) < n {
		return "", false
	}
	return string(b), true
}
