package coreml

import (
	"errors"
	"io"

	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"google.golang.org/protobuf/encoding/protowire"
)

var errMalformedGroup = errors.New("coreml: malformed protobuf group")

const (
	maxVarintLen   = 10
	readChunk      = 64 << 10
	maxGroupDepth  = 32
	maxSniffFields = 64
)

// pbReader walks one protobuf message in place over a source.Source. Skipping a
// multi-gigabyte WeightParams or NeuralNetwork field advances pos in O(1)
// without reading or allocating its payload.
type pbReader struct {
	s      source.Source
	pos    int64
	end    int64
	buf    []byte
	bufOff int64
	err    error
}

func newPBReader(s source.Source, start, end int64) *pbReader {
	if size := s.Size(); end > size {
		end = size
	}
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	return &pbReader{s: s, pos: start, end: end}
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

func (r *pbReader) skipGroup(startNum protowire.Number, depth int) bool {
	if depth >= maxGroupDepth {
		r.err = errMalformedGroup
		return false
	}
	for r.remaining() > 0 {
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if typ == protowire.EndGroupType {
			if num == startNum {
				return true
			}
			r.err = errMalformedGroup
			return false
		}
		if !r.skipFieldValue(num, typ, depth+1) {
			return false
		}
	}
	r.err = io.ErrUnexpectedEOF
	return false
}

func (r *pbReader) skipFieldValue(num protowire.Number, typ protowire.Type, depth int) bool {
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
	case protowire.StartGroupType:
		return r.skipGroup(num, depth)
	default:
		r.err = errMalformedGroup
		return false
	}
}

// probeProtoMessage reports whether [start, start+n) is a plausible protobuf
// message without reading more than maxProbe bytes. Small messages are checked
// completely with isProtoMessage; large messages are walked via field headers.
func probeProtoMessage(s source.Source, start, n int64) bool {
	if n <= 0 {
		return false
	}
	if n <= maxProbe {
		b, err := s.Bytes(start, n)
		if err != nil && int64(len(b)) < n {
			return false
		}
		return isProtoMessage(b)
	}
	r := newPBReader(s, start, start+n)
	fields := 0
	for range maxSniffFields {
		if r.remaining() <= 0 {
			break
		}
		num, typ, _, ok := r.next()
		if !ok || num < 1 {
			return false
		}
		if !r.skipFieldValue(num, typ, 0) {
			return false
		}
		fields++
	}
	return fields > 0
}
