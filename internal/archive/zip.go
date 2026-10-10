package archive

import (
	"compress/flate"
	"errors"
	"hash/crc32"
	"io"
	"strconv"
	"strings"

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
	_, _, err := findEOCD(s)
	return err == nil
}

// findEOCD returns the absolute offset of the end-of-central-directory record and
// the number of bytes that follow it.
//
// Searching backwards for the signature and then requiring the comment length to
// reach exactly the end of the file is what makes this robust against the
// signature occurring inside member data, so that exact match is tried first. A
// zip with bytes appended after the EOCD (the polyglot shape) has no exact match;
// the second pass accepts a candidate whose comment fits inside the file and
// reports the trailing count so the caller can report it. Both passes scan
// backwards, so the *last* plausible record wins, which is what the reference
// readers do.
func findEOCD(s source.Source) (int64, int64, error) {
	size := s.Size()
	if size < 22 {
		return 0, 0, errors.New("archive: file too small for a zip")
	}
	window := int64(22 + 65535)
	if size < window {
		window = size
	}
	start := size - window
	b, err := s.Bytes(start, window)
	if err != nil && int64(len(b)) < window {
		return 0, 0, err
	}
	trailing := int64(-1)
	pos := int64(-1)
	for i := len(b) - 22; i >= 0; i-- {
		if le32(b[i:]) != sigEOCD {
			continue
		}
		end := start + int64(i) + 22 + int64(le16(b[i+20:]))
		if end > size {
			// The declared comment runs past EOF: not a record.
			continue
		}
		if end == size {
			return start + int64(i), 0, nil
		}
		if trailing < 0 {
			// The last plausible record wins, matching the reference readers.
			pos, trailing = start+int64(i), size-end
		}
	}
	if trailing >= 0 {
		return pos, trailing, nil
	}
	return 0, 0, errors.New("archive: no end-of-central-directory record")
}

// zipDirInfo carries the directory-level facts a caller needs to report.
type zipDirInfo struct {
	// Truncated records that the member cap stopped the directory read.
	Truncated bool
	// Trailing is the number of bytes between the end of the
	// end-of-central-directory record and the end of the file.
	Trailing int64
}

// readZipDirectory parses the central directory without decompressing anything.
// A corrupt container (no EOCD, malformed central record) is an error; a member
// with a corrupt local header is not, and is reported later.
func readZipDirectory(s source.Source, l limits.Limits) ([]zipEntry, zipDirInfo, error) {
	eocdPos, trailing, err := findEOCD(s)
	if err != nil {
		return nil, zipDirInfo{}, err
	}
	info := zipDirInfo{Trailing: trailing}
	end, err := s.Bytes(eocdPos, 22)
	if err != nil && len(end) < 22 {
		return nil, zipDirInfo{}, err
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
	if count < 0 {
		// A negative count can only come from a crafted zip64 field; the range
		// check in readZip64 rejects it, but the allocation below must never be
		// handed a negative capacity even if a future caller changes that.
		count = 0
	}
	if count > int64(max) {
		count = int64(max)
		truncated = true
	}
	// Every central-directory record occupies at least 46 bytes, so a count that
	// cannot fit between cdStart and EOF describes a malformed directory. The
	// loop below would fail on the first record that does not fit anyway; doing
	// the arithmetic once keeps the loop (and the allocation) bounded by the file
	// size rather than by a declared count.
	if count > 0 && cdStart+46*count > s.Size() {
		return nil, zipDirInfo{}, errors.New("archive: central directory truncated")
	}

	entries := make([]zipEntry, 0, min64int(count, 4096))
	off := cdStart
	for range count {
		if off+46 > s.Size() {
			return nil, zipDirInfo{}, errors.New("archive: central directory truncated")
		}
		hdr, err := s.Bytes(off, 46)
		if err != nil && len(hdr) < 46 {
			return nil, zipDirInfo{}, err
		}
		if le32(hdr) != sigCentral {
			return nil, zipDirInfo{}, errors.New("archive: bad central directory record signature")
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
			return nil, zipDirInfo{}, berr
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
	info.Truncated = truncated
	return entries, info, nil
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
	// The three fields are unsigned 64-bit in the spec but must describe a real
	// directory inside this file. A negative (i.e. >= 2^63) or absurdly large
	// value is a crafted record, and letting it through reaches the allocation
	// in readZipDirectory with a nonsensical count.
	const maxZip64 = int64(1) << 40
	if entries < 0 || entries > maxZip64 || cdSize < 0 || cdSize > maxZip64 || cdOff < 0 || cdOff > maxZip64 {
		return 0, 0, 0, 0, errors.New("archive: implausible zip64 end-of-central-directory")
	}
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
// compare the whole record against the central directory's: the name, the
// compression method, the CRC-32 and both sizes. A disagreement is returned as
// localName (the name case) and mismatch (a description of any disagreement); an
// unreadable local header as errStr, in which case bodyOff is meaningless and the
// member must not be read.
func resolveLocal(s source.Source, e zipEntry) (bodyOff int64, localName, mismatch, errStr string) {
	if e.localOff < 0 || e.localOff+30 > s.Size() {
		return 0, "", "", "local header offset out of range"
	}
	hdr, err := s.Bytes(e.localOff, 30)
	if err != nil && len(hdr) < 30 {
		return 0, "", "", "local header unreadable"
	}
	if le32(hdr) != sigLocal {
		return 0, "", "", "local header signature invalid"
	}
	nameLen := int64(le16(hdr[26:]))
	extraLen := int64(le16(hdr[28:]))
	bodyOff = e.localOff + 30 + nameLen + extraLen
	ln, lerr := s.Bytes(e.localOff+30, nameLen)
	if lerr != nil && int64(len(ln)) < nameLen {
		return bodyOff, "", "", "local header name unreadable"
	}
	if string(ln) != e.name {
		localName = string(ln)
		mismatch = "central directory says " + snippet(e.name) + " but local header says " + snippet(localName)
	}
	// The fields a loader uses to find and decompress the data. A disagreement
	// here means the bytes sc4n read are not the bytes a loader would use.
	//
	// Two conformant encodings make the local fields legitimately differ from the
	// central directory's, and both are common, so comparing them literally
	// reported every such archive as a mismatch:
	//
	//   - general-purpose bit 3 (data descriptor): the local header carries no
	//     CRC and no sizes, because the writer did not know them when it wrote it.
	//     Go's archive/zip.Writer sets this by default, and Java and Python set it
	//     for non-seekable or force_zip64 output. The real values follow the member
	//     data and are mirrored in the central directory, which is where this
	//     parser read them.
	//   - per-entry zip64: the local 32-bit fields hold the sentinel 0xFFFFFFFF
	//     and the real values are in the local header's zip64 extra field.
	//
	// The name and method are always present and always compared.
	var diffs []string
	if lm := le16(hdr[8:]); lm != e.method {
		diffs = append(diffs, "method "+itoa(int(lm))+" vs "+itoa(int(e.method)))
	}
	if e.flags&0x8 == 0 {
		lcrc := le32(hdr[14:])
		lcomp := uint64(le32(hdr[18:]))
		luncomp := uint64(le32(hdr[22:]))
		compareSizes := true
		if lcomp == 0xffffffff || luncomp == 0xffffffff {
			// The 32-bit fields are the zip64 sentinel; the local extra field
			// holds the real sizes. Without it there is nothing to compare, and
			// guessing would report a conformant archive.
			if u, c, ok := localZip64Sizes(s, e.localOff, nameLen, extraLen); ok {
				if luncomp == 0xffffffff {
					luncomp = u
				}
				if lcomp == 0xffffffff {
					lcomp = c
				}
			} else {
				compareSizes = false
			}
		}
		if lcrc != e.crc {
			diffs = append(diffs, "crc32 0x"+strconv.FormatUint(uint64(lcrc), 16)+" vs 0x"+strconv.FormatUint(uint64(e.crc), 16))
		}
		if compareSizes {
			if lcomp != e.comp {
				diffs = append(diffs, "compressed size "+itoa64(int64(lcomp))+" vs "+itoa64(int64(e.comp)))
			}
			if luncomp != e.uncomp {
				diffs = append(diffs, "uncompressed size "+itoa64(int64(luncomp))+" vs "+itoa64(int64(e.uncomp)))
			}
		}
	}
	if len(diffs) > 0 {
		extra := "local header disagrees with the central directory about " + strings.Join(diffs, ", ")
		if mismatch != "" {
			mismatch += "; " + extra
		} else {
			mismatch = extra
		}
	}
	return bodyOff, localName, mismatch, ""
}

// localZip64Sizes reads the local file header's zip64 extra field, which holds
// the real uncompressed and compressed sizes when the 32-bit fields carry the
// 0xFFFFFFFF sentinel. ok is false when the field is absent or unreadable, in
// which case the caller must not compare sizes.
func localZip64Sizes(s source.Source, localOff, nameLen, extraLen int64) (uncomp, comp uint64, ok bool) {
	if extraLen <= 0 {
		return 0, 0, false
	}
	off := localOff + 30 + nameLen
	if off+extraLen > s.Size() {
		return 0, 0, false
	}
	b, err := s.Bytes(off, extraLen)
	if err != nil && int64(len(b)) < extraLen {
		return 0, 0, false
	}
	for i := 0; i+4 <= len(b); {
		id := le16(b[i:])
		sz := int(le16(b[i+2:]))
		i += 4
		if i+sz > len(b) {
			return 0, 0, false
		}
		if id == 0x0001 {
			p := b[i : i+sz]
			// The spec fixes the order: uncompressed, compressed, offset, disk.
			if len(p) < 16 {
				return 0, 0, false
			}
			return le64(p), le64(p[8:]), true
		}
		i += sz
	}
	return 0, 0, false
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
		// The cap is spent. Whether that is an overrun depends on whether the
		// member still has content: a member whose length is exactly the cap ends
		// in io.EOF and must be scanned and CRC-checked, not reported as
		// over-cap. Probing costs one byte, and that byte is only consumed on the
		// path that is about to report an overrun anyway.
		more, err := l.peekMore()
		if err != nil {
			return 0, err
		}
		if !more {
			return 0, io.EOF
		}
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

// peekMore reports whether the underlying reader has at least one more byte. A
// reader that keeps returning (0, nil) cannot be told apart from an exhausted
// one, so the probe gives up after a bounded number of attempts rather than
// spinning.
func (l *limitReader) peekMore() (bool, error) {
	var scratch [1]byte
	for range 8 {
		n, err := l.r.Read(scratch[:])
		switch {
		case n > 0:
			return true, nil
		case err == io.EOF:
			return false, nil
		case err != nil:
			return false, err
		}
	}
	return false, nil
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
	if a < 0 {
		return 0
	}
	if a < int64(b) {
		return int(a)
	}
	return b
}
