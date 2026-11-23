// Package imgmeta reads the text metadata of an image artifact and hands it to
// the shared indicator engine.
//
// The pixels are not the finding surface; the metadata is. A PNG or JPEG model
// card carries tEXt/iTXt chunks or an EXIF/XMP block, and every published
// image-borne prompt-injection example lives there. Before this package an image
// was dispatched "unknown": no parser, no indicator pass, so a JPEG whose EXIF
// UserComment read "ignore previous instructions" produced an empty finding list.
// The HF campaign had 67 PNG and 20 JPEG artifacts in that state.
//
// Only metadata is parsed. Pixel data and entropy-coded segments are skipped by
// their declared lengths, never decoded, and an image with no metadata chunk is
// still reported once (SC4N-IMG-METADATA, info) so that "no findings" cannot mean
// "metadata never read" — the same contract SC4N-PTE-UNVERIFIED carries.
package imgmeta

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
	"github.com/fr0g-66723067-io/sc4n/internal/utf16text"
)

var (
	pngMagic  = []byte("\x89PNG\r\n\x1a\n")
	jpegMagic = []byte("\xff\xd8\xff")
)

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatImageMeta,
		Magic:  "\\x89PNG\\r\\n\\x1a\\n at 0, or \\xff\\xd8\\xff at 0",
		Depth:  artifact.DepthShallow,
		Notes: "PNG tEXt/zTXt/iTXt/eXIf chunks and JPEG APP1 Exif, APP1 XMP and COM segments are " +
			"read and run through the indicator engine, and the result is stated with SC4N-IMG-METADATA. " +
			"Pixels and entropy-coded data are NOT decoded: they are skipped by their declared lengths, " +
			"so a payload hidden in pixel data (steganography) is out of scope, and GIF/WAV/MP4 are not " +
			"covered at all.",
	})
	// Priority 58: below the unambiguous magics, the structured model formats and
	// the UTF-16 text sniffer (62), which rejects these files on their high bytes;
	// above the generic text sniffer (40), which would classify them as binary.
	artifact.RegisterSniffer("image-metadata", 58, sniff)
	artifact.RegisterParser(artifact.FormatImageMeta, parser{})
}

func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	if s.Size() < 8 {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, 8)
	if err != nil && len(head) < 3 {
		return artifact.FormatUnknown, false
	}
	if bytes.HasPrefix(head, pngMagic) || bytes.HasPrefix(head, jpegMagic) {
		return artifact.FormatImageMeta, true
	}
	return artifact.FormatUnknown, false
}

type parser struct{}

func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	if size > ctx.Limits.MaxArtifactBytes && ctx.Limits.MaxArtifactBytes > 0 {
		size = ctx.Limits.MaxArtifactBytes
	}
	b, err := s.Bytes(0, size)
	if err != nil {
		return err
	}
	p := &image{ctx: ctx, data: b}
	if bytes.HasPrefix(b, pngMagic) {
		p.png()
	} else {
		p.jpeg()
	}
	p.report()
	return nil
}

// image holds the state of one image scan.
type image struct {
	ctx    *artifact.Ctx
	data   []byte
	kinds  []string
	values int
}

// report emits the informational finding that states which metadata was read.
func (im *image) report() {
	detail := "no text metadata (tEXt/zTXt/iTXt/eXIf or EXIF/XMP/COM)"
	if len(im.kinds) > 0 {
		detail = "metadata scanned: " + joinKinds(im.kinds)
		if im.values > 0 {
			detail += fmt.Sprintf(" (%d string(s) run through the indicator engine)", im.values)
		}
	}
	im.ctx.Sink.Emit(RuleMetadata, 0, report.TruncateEvidence(detail, 200))
}

func joinKinds(kinds []string) string {
	if len(kinds) > 8 {
		return strings.Join(kinds[:8], ", ") + fmt.Sprintf(" (%d more)", len(kinds)-8)
	}
	return strings.Join(kinds, ", ")
}

// maxMetaBlob bounds one metadata value before any conversion or decode. The
// chunk length is attacker-controlled; a 100 MiB tEXt is not metadata.
const maxMetaBlob = 16 << 20

func (im *image) capBytes(off int64, what string, b []byte) []byte {
	if int64(len(b)) <= maxMetaBlob {
		return b
	}
	limits.Emit(im.ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(b)), maxMetaBlob, what)
	return b[:maxMetaBlob]
}

// text hands one metadata string to the indicator engine and the invisible
// character pass, at its absolute offset in the file.
func (im *image) text(off int64, s string) {
	if len(s) == 0 {
		return
	}
	im.values++
	stringscan.EmitString(im.ctx.Sink, off, s)
	stringscan.EmitUnicodeAnomalies(im.ctx.Sink, off, []byte(s))
}

// structFinding reports metadata framing that does not fit the file.
func (im *image) structFinding(off int64, format string, args ...any) {
	im.ctx.Sink.Emit(RuleStruct, off, report.TruncateEvidence(fmt.Sprintf(format, args...), 200))
}

// png walks the chunk list. Every chunk is length type data crc; the CRC is
// skipped, because it is an integrity value, not a security signal, and checking
// it would cost a pass over the pixel data.
func (im *image) png() {
	data := im.data
	off := int64(len(pngMagic))
	sawIEND := false
	for off+12 <= int64(len(data)) {
		length := int64(binary.BigEndian.Uint32(data[off:]))
		typ := string(data[off+4 : off+8])
		end := off + 12 + length
		if end > int64(len(data)) {
			im.structFinding(off, "PNG chunk %q at offset %d declares %d data bytes but only %d remain",
				typ, off, length, int64(len(data))-off-12)
			return
		}
		body := data[off+8 : off+8+length]
		base := off + 8
		switch typ {
		case "tEXt":
			im.kinds = append(im.kinds, "tEXt")
			if k, ok := splitNUL(body); ok {
				// The value is capped as bytes: converting the chunk first copies
				// the attacker's whole value, which is what the cap exists to
				// prevent.
				voff := base + int64(k) + 1
				im.text(voff, string(im.capBytes(voff, "PNG tEXt value", body[k+1:])))
			}
		case "zTXt":
			im.kinds = append(im.kinds, "zTXt")
			im.pngCompressed(base, body)
		case "iTXt":
			im.kinds = append(im.kinds, "iTXt")
			im.pngInternational(base, body)
		case "eXIf":
			im.kinds = append(im.kinds, "eXIf")
			im.exif(base, body)
		case "IEND":
			sawIEND = true
			off = end
			break
		}
		if sawIEND {
			break
		}
		off = end
	}
	if !sawIEND {
		im.structFinding(off, "PNG chunk list ends at offset %d without an IEND chunk", off)
	}
}

// pngCompressed handles zTXt: keyword NUL method zlib-stream.
func (im *image) pngCompressed(base int64, body []byte) {
	k := bytes.IndexByte(body, 0)
	if k < 0 || k+2 > len(body) {
		im.structFinding(base, "zTXt chunk has no keyword terminator")
		return
	}
	if body[k+1] != 0 {
		im.structFinding(base+int64(k)+1, "zTXt chunk uses compression method %d, only 0 (deflate) is defined", body[k+1])
		return
	}
	im.text(base+int64(k)+2, im.inflate(base+int64(k)+2, body[k+2:]))
}

// pngInternational handles iTXt: keyword NUL flag method lang NUL translated NUL
// text, where the text is deflated when flag is 1.
func (im *image) pngInternational(base int64, body []byte) {
	k := bytes.IndexByte(body, 0)
	if k < 0 || k+3 > len(body) {
		im.structFinding(base, "iTXt chunk has no keyword terminator")
		return
	}
	flag, method := body[k+1], body[k+2]
	_, after := splitAt(body[k+3:])
	if after == nil {
		im.structFinding(base, "iTXt chunk has no language-tag terminator")
		return
	}
	_, text := splitAt(after)
	if text == nil {
		im.structFinding(base, "iTXt chunk has no translated-keyword terminator")
		return
	}
	// The text is the tail of the chunk, so its offset comes from the end rather
	// than from the lengths of the separators before it.
	off := base + int64(len(body)) - int64(len(text))
	switch flag {
	case 0:
		im.text(off, string(im.capBytes(off, "PNG iTXt value", text)))
	case 1:
		if method != 0 {
			im.structFinding(off, "iTXt chunk uses compression method %d, only 0 (deflate) is defined", method)
			return
		}
		im.text(off, im.inflate(off, text))
	default:
		im.structFinding(base+int64(k)+1, "iTXt chunk has compression flag %d, only 0 and 1 are defined", flag)
	}
}

// splitNUL splits keyword NUL text, returning the keyword length; the caller
// slices the value so it can be capped before it is copied.
func splitNUL(b []byte) (int, bool) {
	k := bytes.IndexByte(b, 0)
	if k < 0 || k+1 > len(b) {
		return 0, false
	}
	return k, true
}

// splitAt splits b at the first NUL, returning the part before it and the part
// after. after is nil when there is no NUL.
func splitAt(b []byte) (before, after []byte) {
	k := bytes.IndexByte(b, 0)
	if k < 0 {
		return b, nil
	}
	return b[:k], b[k+1:]
}

// inflate decompresses a zlib stream, bounded by MaxStringBlob. The limit is
// reported rather than silently truncating, and the prefix is still scanned.
func (im *image) inflate(off int64, stream []byte) string {
	max := im.ctx.Limits.MaxStringBlob
	if max <= 0 {
		max = 16 << 20
	}
	r, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		im.structFinding(off, "compressed metadata at offset %d does not start a zlib stream: %v", off, err)
		return ""
	}
	defer r.Close()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, max+1))
	if err != nil {
		im.structFinding(off, "compressed metadata at offset %d fails to inflate: %v", off, err)
	}
	if n > max {
		limits.Emit(im.ctx.Sink, limits.RuleString, "MaxStringBlob", n, max,
			fmt.Sprintf("compressed metadata at offset %d", off))
		return buf.String()[:max]
	}
	return buf.String()
}

// jpeg walks the marker segments. Entropy-coded data after SOS is never read.
func (im *image) jpeg() {
	data := im.data
	// SOI is at 0..1; the first marker follows it. jpegMagic is three bytes for
	// the sniffer only, and starting the walk at its length would land inside the
	// first marker.
	off := int64(2)
	for off+4 <= int64(len(data)) {
		if data[off] != 0xff {
			// The marker stream is not where the parser expects it; stop rather
			// than guess, and say so.
			im.structFinding(off, "JPEG marker stream lost at offset %d", off)
			return
		}
		marker := data[off+1]
		if marker == 0xff {
			off++
			continue
		}
		switch marker {
		case 0xd8, 0x01:
			off += 2
			continue
		case 0xd9, 0xda: // EOI, SOS: metadata is over
			return
		}
		if off+4 > int64(len(data)) {
			im.structFinding(off, "JPEG segment 0x%02x at offset %d has no length", marker, off)
			return
		}
		length := int64(binary.BigEndian.Uint16(data[off+2:]))
		if length < 2 {
			im.structFinding(off, "JPEG segment 0x%02x at offset %d declares length %d", marker, off, length)
			return
		}
		end := off + 2 + length
		if end > int64(len(data)) {
			im.structFinding(off, "JPEG segment 0x%02x at offset %d declares %d bytes but only %d remain",
				marker, off, length, int64(len(data))-off-2)
			return
		}
		body := data[off+4 : end]
		base := off + 4
		switch marker {
		case 0xe1: // APP1: Exif or XMP
			switch {
			case bytes.HasPrefix(body, []byte("Exif\x00\x00")):
				im.kinds = append(im.kinds, "EXIF")
				im.exif(base+6, body[6:])
			case bytes.HasPrefix(body, []byte("http://ns.adobe.com/xap/1.0/\x00")):
				im.kinds = append(im.kinds, "XMP")
				xoff := base + int64(len("http://ns.adobe.com/xap/1.0/\x00"))
				im.text(xoff, string(im.capBytes(xoff, "JPEG XMP", body[len("http://ns.adobe.com/xap/1.0/\x00"):])))
			}
		case 0xfe: // COM
			im.kinds = append(im.kinds, "COM")
			im.text(base, string(im.capBytes(base, "JPEG COM", body)))
		}
		off = end
	}
}

// exif reads the IFD0 text tags, the Exif sub-IFD's UserComment and the XP tags.
// The TIFF byte order applies to the integer fields and to a UNICODE
// UserComment; the XP tags are always little-endian.
func (im *image) exif(base int64, tiff []byte) {
	if len(tiff) < 8 {
		im.structFinding(base, "EXIF block at offset %d is too short for a TIFF header", base)
		return
	}
	var bo binary.ByteOrder
	le := false
	switch {
	case tiff[0] == 'I' && tiff[1] == 'I':
		bo, le = binary.LittleEndian, true
	case tiff[0] == 'M' && tiff[1] == 'M':
		bo = binary.BigEndian
	default:
		im.structFinding(base, "EXIF block at offset %d has no TIFF byte-order mark", base)
		return
	}
	if bo.Uint16(tiff[2:]) != 42 {
		im.structFinding(base, "EXIF block at offset %d has TIFF magic %d, want 42", base, bo.Uint16(tiff[2:]))
		return
	}
	ifd0 := int64(bo.Uint32(tiff[4:]))
	im.ifd(base, tiff, ifd0, bo, le, 0)
}

// maxIFDDepth bounds the Exif sub-IFD recursion.
const maxIFDDepth = 2

// ifd reads one IFD's text tags and follows the Exif pointer one level.
func (im *image) ifd(base int64, tiff []byte, off int64, bo binary.ByteOrder, le bool, depth int) {
	if depth > maxIFDDepth {
		return
	}
	if off < 0 || off+2 > int64(len(tiff)) {
		im.structFinding(base, "EXIF IFD offset %d is outside the block", off)
		return
	}
	count := int(bo.Uint16(tiff[off:]))
	max := im.ctx.Limits.MaxEntries
	if max <= 0 {
		max = 100000
	}
	if count > max {
		limits.Emit(im.ctx.Sink, limits.RuleEntries, "MaxEntries", int64(count), int64(max), "EXIF IFD")
		count = max
	}
	entry := off + 2
	for i := 0; i < count; i++ {
		if entry+12 > int64(len(tiff)) {
			im.structFinding(base, "EXIF IFD entry %d at offset %d runs past the block", i, entry)
			return
		}
		e := tiff[entry:]
		tag := bo.Uint16(e)
		typ := bo.Uint16(e[2:])
		n := bo.Uint32(e[4:])
		valueOff := entry + 8
		size := exifValueSize(typ, n)
		if size > 4 {
			valueOff = int64(bo.Uint32(e[8:]))
		}
		if size < 0 || valueOff+size > int64(len(tiff)) {
			im.structFinding(base, "EXIF tag 0x%04x at offset %d declares %d bytes past the block", tag, entry, size)
			entry += 12
			continue
		}
		val := im.capBytes(base+valueOff, "EXIF tag value", tiff[valueOff:valueOff+size])
		switch tag {
		case 0x010e: // ImageDescription, ASCII
			im.text(base+valueOff, trimNUL(val))
		case 0x013b: // Artist, ASCII
			im.text(base+valueOff, trimNUL(val))
		case 0x9286: // UserComment, UNDEFINED with a charset prefix
			im.kinds = append(im.kinds, "UserComment")
			im.text(base+valueOff, userComment(val, bo))
		case 0x9c9b: // XPTitle, UTF-16LE
			im.kinds = append(im.kinds, "XPTitle")
			im.xp(base+valueOff, val)
		case 0x9c9e: // XPComment, UTF-16LE
			im.kinds = append(im.kinds, "XPComment")
			im.xp(base+valueOff, val)
		case 0x8769: // Exif sub-IFD pointer
			if n == 1 && (typ == 4 || typ == 13) {
				im.ifd(base, tiff, int64(bo.Uint32(e[8:])), bo, le, depth+1)
			}
		}
		entry += 12
	}
}

// exifValueSize is the byte length of an IFD value, or -1 for an unknown type.
func exifValueSize(typ uint16, count uint32) int64 {
	var unit int64
	switch typ {
	case 1, 2, 6, 7: // BYTE, ASCII, SBYTE, UNDEFINED
		unit = 1
	case 3, 8: // SHORT, SSHORT
		unit = 2
	case 4, 9, 11: // LONG, SLONG, FLOAT
		unit = 4
	case 5, 10, 12: // RATIONAL, SRATIONAL, DOUBLE
		unit = 8
	default:
		return -1
	}
	return unit * int64(count)
}

// userComment decodes the 8-byte charset prefix and the text it introduces.
func userComment(b []byte, bo binary.ByteOrder) string {
	if len(b) <= 8 {
		return ""
	}
	prefix := string(b[:8])
	body := b[8:]
	switch {
	case len(prefix) >= 8 && prefix[:8] == "UNICODE\x00":
		order := utf16text.LittleEndian
		if bo == binary.BigEndian {
			order = utf16text.BigEndian
		}
		decoded, err := utf16text.Decode(order, body)
		if err != nil {
			return trimNUL(body)
		}
		return trimNUL(decoded)
	case len(prefix) >= 5 && prefix[:5] == "ASCII":
		return trimNUL(body)
	}
	return trimNUL(body)
}

// xp decodes a UTF-16LE NUL-terminated XP tag.
func (im *image) xp(off int64, b []byte) {
	decoded, err := utf16text.Decode(utf16text.LittleEndian, b)
	if err != nil {
		return
	}
	im.text(off, trimNUL(decoded))
}

// trimNUL cuts a value at its first NUL.
func trimNUL(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
