package archive

import (
	"compress/flate"
	"errors"
	"hash/crc32"
	"io"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// errCRC is returned by a member reader at end-of-stream when the content does
// not hash to the directory's CRC-32.
var errCRC = errors.New("archive: member crc mismatch")

// zipEntry is one central-directory record. It is kept internal because the
// public Member type is what parsers code against.
type zipEntry struct {
	name     string
	localOff int64
	comp     uint64
	uncomp   uint64
	crc      uint32
	method   uint16
	flags    uint16
	extAttrs uint32
}

const (
	sigLocal   = 0x04034b50
	sigCentral = 0x02014b50
	sigEOCD    = 0x06054b50
	sigZ64Loc  = 0x07064b50
	sigZ64EOCD = 0x06064b50
)

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

// looksZip recognises a zip by its leading magic or, when the file has a
// prefix, by a valid end-of-central-directory record.
func looksZip(s source.Source, l limits.Limits) bool {
	if s.Size() < 4 {
		return false
	}
	if b, err := s.Bytes(0, 4); len(b) == 4 && b[0] == 'P' && b[1] == 'K' &&
		(b[2] == 3 || b[2] == 5 || b[2] == 7) {
		_ = err
		return true
	}
	_, err := findEOCD(s)
	return err == nil
}

// findEOCD returns the absolute offset of the end-of-central-directory record.
//
// Searching backwards for the signature and then requiring the comment length to
// reach exactly the end of the file is what makes this robust against the
// signature occurring inside member data.
func findEOCD(s source.Source) (int64, error) {
	size := s.Size()
	if size < 22 {
		return 0, errors.New("archive: file too small for a zip")
	}
	window := int64(22 + 65535)
	if size < window {
		window = size
	}
	start := size - window
	b, err := s.Bytes(start, window)
	if err != nil && int64(len(b)) < window {
		return 0, err
	}
	for i := len(b) - 22; i >= 0; i-- {
		if le32(b[i:]) != sigEOCD {
			continue
		}
		commentLen := int64(le16(b[i+20:]))
		if start+int64(i)+22+commentLen != size {
			continue
		}
		return start + int64(i), nil
	}
	return 0, errors.New("archive: no end-of-central-directory record")
}

// readZipDirectory parses the central directory without decompressing anything.
// A corrupt container (no EOCD, malformed central record) is an error; a member
// with a corrupt local header is not, and is reported later.
func readZipDirectory(s source.Source, l limits.Limits) ([]zipEntry, bool, error) {
	eocdPos, err := findEOCD(s)
	if err != nil {
		return nil, false, err
	}
	end, err := s.Bytes(eocdPos, 22)
	if err != nil && len(end) < 22 {
		return nil, false, err
	}
	entriesTotal := int64(le16(end[10:]))
	cdSize := int64(le32(end[12:]))
	cdOff := int64(le32(end[16:]))

	z64Pos := int64(-1)
	if entriesTotal == 0xffff || cdSize == 0xffffffff || cdOff == 0xffffffff {
		z64EOCD, z64Size, z64Off, z64Entries, zerr := readZip64(s, eocdPos)
		if zerr == nil {
			entriesTotal, cdSize, cdOff = z64Entries, z64Size, z64Off
			z64Pos = z64EOCD
		}
	}

	// A zip may be prefixed with arbitrary bytes (a self-extracting stub, or
	// torch's "prefixed archive"): every directory offset is then relative to a
	// non-zero base. Derive it the way the reference readers do.
	anchor := eocdPos
	if z64Pos >= 0 {
		anchor = z64Pos
	}
	base := anchor - cdSize - cdOff
	if base < 0 {
		base = 0
	}
	cdStart := base + cdOff
	if cdStart < 0 || cdStart+cdSize > s.Size() {
		// Fall back to the literal offset; the read below reports the failure.
		cdStart = cdOff
	}

	max := l.MaxEntries
	if max <= 0 {
		max = limits.Default().MaxEntries
	}
	truncated := false
	count := entriesTotal
	if count > int64(max) {
		count = int64(max)
		truncated = true
	}

	entries := make([]zipEntry, 0, min64int(count, 4096))
	off := cdStart
	for range count {
		if off+46 > s.Size() {
			return nil, false, errors.New("archive: central directory truncated")
		}
		hdr, err := s.Bytes(off, 46)
		if err != nil && len(hdr) < 46 {
			return nil, false, err
		}
		if le32(hdr) != sigCentral {
			return nil, false, errors.New("archive: bad central directory record signature")
		}
		var e zipEntry
		e.flags = le16(hdr[8:])
		e.method = le16(hdr[10:])
		e.crc = le32(hdr[16:])
		e.comp = uint64(le32(hdr[20:]))
		e.uncomp = uint64(le32(hdr[24:]))
		nameLen := int64(le16(hdr[28:]))
		extraLen := int64(le16(hdr[30:]))
		commentLen := int64(le16(hdr[32:]))
		e.extAttrs = le32(hdr[38:])
		e.localOff = int64(le32(hdr[42:]))
		off += 46

		body, berr := s.Bytes(off, nameLen+extraLen+commentLen)
		if berr != nil && int64(len(body)) < nameLen+extraLen+commentLen {
			return nil, false, berr
		}
		e.name = string(body[:nameLen])
		if nameLen+extraLen <= int64(len(body)) {
			parseZip64Extra(body[nameLen:nameLen+extraLen], &e)
		}
		if base > 0 && e.localOff >= 0 && e.localOff < 1<<62 {
			e.localOff += base
		}
		off += nameLen + extraLen + commentLen

		entries = append(entries, e)
	}
	return entries, truncated, nil
}

// readZip64 parses the zip64 end-of-central-directory record and its locator.
func readZip64(s source.Source, eocdPos int64) (z64Pos, cdSize, cdOff, entries int64, err error) {
	locPos := eocdPos - 20
	if locPos < 0 {
		return 0, 0, 0, 0, errors.New("archive: no zip64 locator")
	}
	loc, lerr := s.Bytes(locPos, 20)
	if lerr != nil && len(loc) < 20 {
		return 0, 0, 0, 0, lerr
	}
	if le32(loc) != sigZ64Loc {
		return 0, 0, 0, 0, errors.New("archive: bad zip64 locator")
	}
	z64Pos = int64(le64(loc[8:]))
	if z64Pos <= 0 || z64Pos+56 > s.Size() {
		return 0, 0, 0, 0, errors.New("archive: bad zip64 end-of-central-directory offset")
	}
	rec, rerr := s.Bytes(z64Pos, 56)
	if rerr != nil && len(rec) < 56 {
		return 0, 0, 0, 0, rerr
	}
	if le32(rec) != sigZ64EOCD {
		return 0, 0, 0, 0, errors.New("archive: bad zip64 signature")
	}
	entries = int64(le64(rec[32:]))
	cdSize = int64(le64(rec[40:]))
	cdOff = int64(le64(rec[48:]))
	return z64Pos, cdSize, cdOff, entries, nil
}

// parseZip64Extra fills in the sizes/offset that the plain record marked with
// 0xFFFFFFFF, in the order the spec fixes: uncompressed, compressed, local
// header offset, disk number.
func parseZip64Extra(extra []byte, e *zipEntry) {
	for i := 0; i+4 <= len(extra); {
		id := le16(extra[i:])
		sz := int(le16(extra[i+2:]))
		i += 4
		if i+sz > len(extra) {
			return
		}
		if id == 0x0001 {
			p := extra[i : i+sz]
			take := func() (uint64, bool) {
				if len(p) < 8 {
					return 0, false
				}
				v := le64(p)
				p = p[8:]
				return v, true
			}
			if e.uncomp == 0xffffffff {
				if v, ok := take(); ok {
					e.uncomp = v
				}
			}
			if e.comp == 0xffffffff {
				if v, ok := take(); ok {
					e.comp = v
				}
			}
			if e.localOff == 0xffffffff {
				if v, ok := take(); ok && v <= 1<<62 {
					e.localOff = int64(v)
				}
			}
			return
		}
		i += sz
	}
}

// resolveLocal reads the local file header to find the member body offset and to
// compare the local name against the central directory name. A disagreement is
// returned as localName; an unreadable local header as errStr.
func resolveLocal(s source.Source, e zipEntry) (bodyOff int64, localName, errStr string) {
	if e.localOff < 0 || e.localOff+30 > s.Size() {
		return 0, "", "local header offset out of range"
	}
	hdr, err := s.Bytes(e.localOff, 30)
	if err != nil && len(hdr) < 30 {
		return 0, "", "local header unreadable"
	}
	if le32(hdr) != sigLocal {
		return 0, "", "local header signature invalid"
	}
	nameLen := int64(le16(hdr[26:]))
	extraLen := int64(le16(hdr[28:]))
	bodyOff = e.localOff + 30 + nameLen + extraLen
	ln, lerr := s.Bytes(e.localOff+30, nameLen)
	if lerr != nil && int64(len(ln)) < nameLen {
		return bodyOff, "", "local header name unreadable"
	}
	if string(ln) != e.name {
		return bodyOff, string(ln), ""
	}
	return bodyOff, "", ""
}

// openZipMember returns a reader over one member's decompressed bytes. It
// enforces the per-member decompression ratio and cumulative caps while reading,
// and validates the member's CRC-32 at end of stream.
func openZipMember(s source.Source, l limits.Limits, m Member) (io.ReadCloser, error) {
	switch m.Method {
	case 0, 8:
	default:
		return nil, &unsupportedMethodError{method: m.Method}
	}
	if m.Encrypted {
		return nil, errors.New("archive: member is encrypted")
	}
	comp := m.CompressedSize
	if comp < 0 {
		comp = 0
	}
	sec := io.NewSectionReader(s, m.dataOff, comp)
	var inner io.Reader
	var closer io.Closer
	switch m.Method {
	case 0:
		inner = sec
	case 8:
		fr := flate.NewReader(sec)
		inner, closer = fr, fr
	}
	capBytes, rule := decompressionCap(comp, l)
	lr := &limitReader{r: inner, remaining: capBytes, rule: rule, limit: limitName(rule), cap: capBytes, detail: "member " + m.Name}
	cr := &crcReader{r: lr, sum: crc32.NewIEEE(), want: m.CRC32}
	return &memberReader{r: cr, c: closer}, nil
}

// unsupportedMethodError names a zip compression method sc4n cannot decode.
type unsupportedMethodError struct{ method uint16 }

func (e *unsupportedMethodError) Error() string {
	return "archive: unsupported zip compression method " + strconv.Itoa(int(e.method)) + " (" + algorithmName(e.method) + ")"
}

func algorithmFor(e *unsupportedMethodError) string { return algorithmName(e.method) }

// limitReader fails once more than cap bytes have been read.
type limitReader struct {
	r         io.Reader
	remaining int64
	read      int64
	rule      *report.Rule
	limit     string
	cap       int64
	detail    string
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		return 0, &LimitError{Rule: l.rule, Limit: l.limit, Value: l.read + 1, Cap: l.cap, Detail: l.detail}
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	l.read += int64(n)
	return n, err
}

// crcReader validates a member's CRC-32 at end of stream.
type crcReader struct {
	r       io.Reader
	sum     hash32
	want    uint32
	checked bool
}

type hash32 interface {
	io.Writer
	Sum32() uint32
}

func (c *crcReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		_, _ = c.sum.Write(p[:n])
	}
	if err == io.EOF && !c.checked {
		c.checked = true
		if c.sum.Sum32() != c.want {
			return n, errCRC
		}
	}
	return n, err
}

// memberReader closes the underlying decompressor on Close.
type memberReader struct {
	r io.Reader
	c io.Closer
}

func (m *memberReader) Read(p []byte) (int, error) { return m.r.Read(p) }
func (m *memberReader) Close() error {
	if m.c != nil {
		return m.c.Close()
	}
	return nil
}

func min64int(a int64, b int) int {
	if a < int64(b) {
		return int(a)
	}
	return b
}
