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
//     the end of the source, less the data descriptor that follows the payload
//     when the header deferred its sizes to one (general-purpose bit 3, which
//     torch sets on every member). The descriptor is container framing, so a
//     member's span is its payload: leaving the 16 bytes in made every recovered
//     data.pkl end in bytes that are not a pickle. A member whose CRC-32 was
//     written to a descriptor is not CRC-checked, because the descriptor's CRC is
//     what the trim removes.
//   - The artifact stays visible as partial. The caller emits
//     SC4N-ARCHIVE-TRUNCATED, so a clean result on a slice is not mistaken for a
//     clean result on the whole file.

// zipLocalHeaderLen is the fixed part of a local file header.
const zipLocalHeaderLen = 30

// sigScanWindow bounds the memory the forward signature search uses.
const sigScanWindow = 1 << 20

// recoveredMember is one local file header reached without a central directory.
type recoveredMember struct {
	name        string
	method      uint16
	flags       uint16
	dataOff     int64
	dataEnd     int64
	sizeInvalid bool
}

// descriptorLen returns the length of the zip data descriptor that ends at end,
// or 0 when the bytes there are not one. A member whose local header sets
// general-purpose bit 3 (torch sets it on every member) carries, after its
// payload: an optional signature 0x08074b50, a CRC-32, and the compressed and
// uncompressed sizes — 4 bytes each, so 16 with the signature and 12 without; a
// zip64 descriptor carries 8-byte sizes, 24 with the signature.
//
// The compressed-size field is validated against the payload length
// dataOff..end, so arbitrary bytes that happen to end in a plausible signature
// cannot shorten a member. The signature-less 12-byte form can still match 12
// bytes of payload by chance (about 2⁻³² per member); losing 12 trailing bytes
// is invisible to every parser sc4n has, so that is accepted rather than paid for
// with a CRC read the descriptor's own geometry makes redundant.
func descriptorLen(s source.Source, dataOff, end int64) int64 {
	if end-dataOff <= 0 {
		return 0
	}
	// head returns the bytes from at to end, or false when at is outside the
	// member or the source cannot supply them.
	head := func(at int64) ([]byte, bool) {
		if at < dataOff || at >= end {
			return nil, false
		}
		b, err := s.Bytes(at, end-at)
		if int64(len(b)) != end-at {
			_ = err
			return nil, false
		}
		return b, true
	}
	if end-dataOff >= 24 {
		if b, ok := head(end - 24); ok && le32(b) == sigDataDescr && le64(b[8:]) == uint64(end-24-dataOff) {
			return 24
		}
	}
	if end-dataOff >= 16 {
		if b, ok := head(end - 16); ok && le32(b) == sigDataDescr && int64(le32(b[8:])) == end-16-dataOff {
			return 16
		}
	}
	if end-dataOff >= 12 {
		if b, ok := head(end - 12); ok && int64(le32(b[4:])) == end-12-dataOff {
			return 12
		}
	}
	return 0
}

// recoverLocalMembers walks local file headers from offset 0 forward. It stops
// at the first offset that is not a local header, at the member cap, or when the
// next header would not fit in the source. capped reports that it stopped at the
// cap rather than at the data, so the caller can emit the entry limit.
func recoverLocalMembers(s source.Source, l limits.Limits) (out []recoveredMember, capped bool, skipped []string) {
	if s == nil {
		return nil, false, nil
	}
	max := l.MaxEntries
	if max <= 0 {
		max = limits.Default().MaxEntries
	}
	size := s.Size()
	seen := 0
	for off := int64(0); off+zipLocalHeaderLen <= size; {
		h, err := s.Bytes(off, zipLocalHeaderLen)
		if int64(len(h)) < zipLocalHeaderLen && err != nil {
			break
		}
		if len(h) < zipLocalHeaderLen || le32(h) != sigLocal {
			break
		}
		seen++
		if seen > max {
			capped = true
			break
		}
		flags := le16(h[6:])
		method := le16(h[8:])
		comp := int64(le32(h[18:]))
		nameLen := int64(le16(h[26:]))
		extraLen := int64(le16(h[28:]))
		dataOff := off + zipLocalHeaderLen + nameLen + extraLen
		if dataOff > size {
			break
		}
		name := ""
		if nameLen > 0 {
			if nb, nerr := s.Bytes(off+zipLocalHeaderLen, nameLen); nerr == nil || int64(len(nb)) == nameLen {
				name = string(nb)
			}
		}
		dataEnd := int64(-1)
		sizeInvalid := false
		switch {
		case comp == 0xFFFFFFFF:
			// Zip64: the real compressed size is in the local extra field. The
			// declared value is only usable when it stays inside the source and
			// ends on container framing; otherwise a truncated record would make
			// the walk read past its member and hide the next one.
			if _, c, _, okC := localZip64Sizes(s, off, nameLen, extraLen, false, true); okC && c > 0 && dataOff+int64(c) <= size {
				claimEnd := dataOff + int64(c)
				if claimEnd == size || descriptorLen(s, dataOff, claimEnd) > 0 || nextZipSig(s, claimEnd, size) == claimEnd {
					dataEnd = claimEnd
				} else {
					sizeInvalid = true
				}
			} else {
				sizeInvalid = true
			}
		case comp > 0:
			dataEnd = dataOff + comp
			if dataEnd > size {
				// The slice ends inside the member: scan what is there.
				dataEnd = size
			}
		}
		next := dataEnd
		if next < 0 {
			// No declared size (a data descriptor follows the payload, as torch
			// writes it), so the member is bounded by the next record signature.
			next = nextZipSig(s, dataOff, size)
		}
		if next <= off {
			break
		}
		span := next
		if flags&0x8 != 0 {
			// The header deferred its sizes to a descriptor, which is container
			// framing rather than member data. Leaving it in the span made every
			// recovered data.pkl end in 16 bytes that are not a pickle
			// (SC4N-PICKLE-TRAILING, high, on 279 corpus artifacts).
			span = next - descriptorLen(s, dataOff, next)
		}
		if span <= dataOff {
			// The descriptor consumed the whole span: a zero-length member.
			if name != "" {
				skipped = append(skipped, name)
			}
			off = next
			continue
		}
		out = append(out, recoveredMember{name: name, method: method, flags: flags, dataOff: dataOff, dataEnd: span, sizeInvalid: sizeInvalid})
		// The walk advances past the descriptor to the next header, never to the
		// trimmed span end.
		off = next
	}
	return out, capped, skipped
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
	for _, m := range members {
		if m.name != "" {
			checkMemberName(ctx, &Member{Name: m.name})
		}
		if m.sizeInvalid {
			ctx.Sink.EmitExtra(ruleArchiveMemberError, 0,
				"member "+snippet(m.name)+" declares a zip64 size that does not end on container framing",
				map[string]string{"member": m.name, "error": "zip64 size does not end on framing"})
		}
		span := m.dataEnd - m.dataOff
		if span <= 0 {
			continue
		}
		if ctx.RemainingDecompressed() == 0 {
			reportDecompressed(ctx)
			return scanned, scannedBytes
		}
		var n int64
		switch m.method {
		case 0:
			rc := io.NewSectionReader(s, m.dataOff, span)
			n = processReader(ctx, m.name, span, span, rc, nil)
			scanned++
		case 8:
			fr := flate.NewReader(io.NewSectionReader(s, m.dataOff, span))
			r := capReader(truncatingReader{r: fr}, ctx.Limits, span, "member "+snippet(m.name))
			n = processReader(ctx, m.name, -1, span, r, nil)
			_ = fr.Close()
			scanned++
		default:
			EmitOpenError(ctx, m.name, &unsupportedMethodError{method: m.method})
		}
		scannedBytes += n
		if chargeDecompressed(ctx, n) {
			return scanned, scannedBytes
		}
	}
	return scanned, scannedBytes
}

// recoverTruncatedZip is the fallback a zip with no end-of-central-directory
// record takes. It reports the partial-container rule and scans every member the
// local headers bound; it reports false when no member was found, in which case
// the artifact keeps its parse-failure status.
func recoverTruncatedZip(ctx *artifact.Ctx, s source.Source) bool {
	members, capped, skipped := recoverLocalMembers(s, ctx.Limits)
	if len(members) == 0 && !capped {
		return false
	}
	if capped {
		max := ctx.Limits.MaxEntries
		if max <= 0 {
			max = limits.Default().MaxEntries
		}
		limits.Emit(ctx.Sink, limits.RuleEntries, "MaxEntries", int64(len(members)+1), int64(max), "archive member cap reached")
	}
	for _, name := range skipped {
		ctx.Sink.EmitExtra(ruleArchiveMemberSkipped, 0,
			"zero-length member "+snippet(name)+" was not dispatched",
			map[string]string{"member": name, "size": "0"})
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
