package archive

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// This file is the fallback for a zip that begins with local file headers but
// has no end-of-central-directory record, which is exactly what a header slice
// of a torch checkpoint looks like: the fetch layer keeps the first N bytes of a
// large artifact, so the member data is present while the directory and the
// EOCD that sits after it are not. Without this walk every such slice ended as a
// parse failure and the pickle engine never saw the payload that the slice
// contains.
//
// Two properties matter more than completeness here:
//
//   - Nothing is invented. A member's span is its declared compressed size when
//     that lies inside the source, else the offset of the next signature, else
//     the end of the source. A member whose CRC-32 was written to a data
//     descriptor is not CRC-checked, because the descriptor is not present.
//   - The artifact stays visible as partial. The caller emits
//     SC4N-ARCHIVE-TRUNCATED, so a clean result on a slice is not mistaken for a
//     clean result on the whole file.

// zipLocalHeaderLen is the fixed part of a local file header.
const zipLocalHeaderLen = 30

// sigScanWindow bounds the memory the forward signature search uses.
const sigScanWindow = 1 << 20

// recoveredMember is one local file header reached without a central directory.
type recoveredMember struct {
	name    string
	method  uint16
	flags   uint16
	dataOff int64
	dataEnd int64
}

// recoverLocalMembers walks local file headers from offset 0 forward. It stops
// at the first offset that is not a local header, at the member cap, or when the
// next header would not fit in the source. capped reports that it stopped at the
// cap rather than at the data, so the caller can emit the entry limit.
func recoverLocalMembers(s source.Source, l limits.Limits) (out []recoveredMember, capped bool) {
	if s == nil {
		return nil, false
	}
	max := l.MaxEntries
	if max <= 0 {
		max = limits.Default().MaxEntries
	}
	size := s.Size()
	for off := int64(0); off+zipLocalHeaderLen <= size; {
		h, err := s.Bytes(off, zipLocalHeaderLen)
		if int64(len(h)) < zipLocalHeaderLen && err != nil {
			break
		}
		if len(h) < zipLocalHeaderLen || le32(h) != sigLocal {
			break
		}
		flags := le16(h[6:])
		method := le16(h[8:])
		comp := int64(le32(h[18:]))
		nameLen := int64(le16(h[26:]))
		extraLen := int64(le16(h[28:]))
		dataOff := off + zipLocalHeaderLen + nameLen + extraLen
		if dataOff >= size {
			break
		}
		name := ""
		if nameLen > 0 {
			if nb, nerr := s.Bytes(off+zipLocalHeaderLen, nameLen); nerr == nil || int64(len(nb)) == nameLen {
				name = string(nb)
			}
		}
		dataEnd := int64(-1)
		switch {
		case comp == 0xFFFFFFFF:
			// Zip64: the real compressed size is in the local extra field.
			if _, c, ok := localZip64Sizes(s, off, nameLen, extraLen); ok && c > 0 && dataOff+int64(c) <= size {
				dataEnd = dataOff + int64(c)
			}
		case comp > 0:
			dataEnd = dataOff + comp
			if dataEnd > size {
				// The slice ends inside the member: scan what is there.
				dataEnd = size
			}
		}
		if dataEnd < 0 {
			// No declared size (a data descriptor follows the payload, as torch
			// writes it), so the member is bounded by the next record signature.
			dataEnd = nextZipSig(s, dataOff, size)
		}
		if dataEnd <= dataOff {
			break
		}
		if len(out) >= max {
			capped = true
			break
		}
		out = append(out, recoveredMember{name: name, method: method, flags: flags, dataOff: dataOff, dataEnd: dataEnd})
		off = dataEnd
	}
	return out, capped
}

// nextZipSig returns the offset of the next local-header, central-directory or
// EOCD signature at or after from, or size when there is none.
func nextZipSig(s source.Source, from, size int64) int64 {
	for off := from; off+4 <= size; {
		n := size - off
		if n > sigScanWindow+3 {
			n = sigScanWindow + 3
		}
		b, err := s.Bytes(off, n)
		if len(b) == 0 {
			_ = err
			return size
		}
		for i := 0; i+4 <= len(b); {
			j := bytes.IndexByte(b[i:], 'P')
			if j < 0 {
				break
			}
			k := i + j
			if k+4 <= len(b) {
				switch le32(b[k:]) {
				case sigLocal, sigCentral, sigEOCD, sigZ64EOCD:
					return off + int64(k)
				}
			}
			i = k + 1
		}
		if int64(len(b)) < n {
			return size
		}
		off += n - 3
	}
	return size
}

// truncatingReader turns the unexpected end of a deflate stream into a clean
// end of the member. The artifact is already reported as truncated, so where the
// slice boundary falls is a property of the fetch, not a member error.
type truncatingReader struct{ r io.Reader }

func (t truncatingReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return n, io.EOF
	}
	return n, err
}

// scanRecovered dispatches every recovered member through the same path the
// directory-driven walk uses, so the caps, the spill and the content rules are
// identical. It returns the member count scanned and the bytes charged to the
// cumulative decompressed budget.
func scanRecovered(ctx *artifact.Ctx, s source.Source, members []recoveredMember) (scanned int, scannedBytes int64) {
	var cumulative int64
	for _, m := range members {
		if m.name != "" {
			checkMemberName(ctx, &Member{Name: m.name})
		}
		span := m.dataEnd - m.dataOff
		if span <= 0 {
			continue
		}
		switch m.method {
		case 0:
			rc := io.NewSectionReader(s, m.dataOff, span)
			cumulative += processReader(ctx, m.name, span, span, rc, nil)
			scanned++
		case 8:
			fr := flate.NewReader(io.NewSectionReader(s, m.dataOff, span))
			r := capReader(truncatingReader{r: fr}, ctx.Limits, span, "member "+snippet(m.name))
			cumulative += processReader(ctx, m.name, -1, span, r, nil)
			_ = fr.Close()
			scanned++
		default:
			EmitOpenError(ctx, m.name, &unsupportedMethodError{method: m.method})
		}
		if exceededDecompressed(ctx, cumulative) {
			return scanned, cumulative
		}
	}
	return scanned, cumulative
}

// recoverTruncatedZip is the fallback a zip with no end-of-central-directory
// record takes. It reports the partial-container rule and scans every member the
// local headers bound; it reports false when no member was found, in which case
// the artifact keeps its parse-failure status.
func recoverTruncatedZip(ctx *artifact.Ctx, s source.Source) bool {
	members, capped := recoverLocalMembers(s, ctx.Limits)
	if len(members) == 0 {
		return false
	}
	if capped {
		max := ctx.Limits.MaxEntries
		if max <= 0 {
			max = limits.Default().MaxEntries
		}
		limits.Emit(ctx.Sink, limits.RuleEntries, "MaxEntries", int64(len(members)), int64(max), "archive member cap reached")
	}
	scanned, bytes := scanRecovered(ctx, s, members)
	ctx.Sink.EmitExtra(ruleArchiveTruncated, 0,
		itoa(len(members))+" member(s) recovered from local headers; "+itoa(scanned)+" scanned",
		map[string]string{
			"members": itoa(len(members)),
			"scanned": itoa(scanned),
			"bytes":   itoa64(bytes),
		})
	return true
}
