// Package utf16text recognises a UTF-16 text artifact, decodes it to UTF-8 and
// re-dispatches the decoded bytes through the whole pipeline.
//
// UTF-16 matters because every content heuristic in sc4n is byte-oriented: a
// model card written as UTF-16LE is 50 % NUL bytes, so the text sniffer sees a
// binary artifact, the markdown/card analyser never runs and the indicator engine
// reads the interleaved zero bytes as ordinary data. The bytes are text the model
// will be shown; a scanner that reports "unknown, no findings" for them has a
// blind spot, not a clean result.
//
// The recognition rule is deliberately narrow. A byte-order mark is decisive. Without
// one, the file is claimed only when at least 90 % of its byte pairs are a
// printable ASCII (or tab/newline) byte next to a zero, which is what
// Latin-script UTF-16 without a BOM looks like. Other scripts carry no NUL in
// their code units and are not claimed without a BOM, because a NUL-ratio
// heuristic cannot tell them from binary data; that gap is stated in the format
// notes rather than guessed at.
package utf16text

import (
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// probeWindow is how much of the head the sniffer reads.
const probeWindow = 4096

// Order is a UTF-16 byte order.
type Order uint8

const (
	LittleEndian Order = iota
	BigEndian
)

func (o Order) String() string {
	if o == BigEndian {
		return "UTF-16BE"
	}
	return "UTF-16LE"
}

// ErrOddLength reports a buffer whose byte count is not a whole number of code
// units.
var ErrOddLength = errors.New("utf16text: odd byte count")

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatUTF16,
		Magic:  "\\xff\\xfe (LE) or \\xfe\\xff (BE), or ASCII interleaved with NUL",
		Depth:  artifact.DepthShallow,
		Notes: "the file is decoded from UTF-16 to UTF-8 and re-dispatched, so content sniffing, the " +
			"model-card analyser and the indicator engine all read the text rather than the NUL " +
			"interleaving. Offsets in findings on the decoded text are offsets into the decoded bytes. " +
			"KNOWN GAP: without a byte-order mark only NUL-interleaved Latin-script text is claimed, " +
			"because a NUL-ratio heuristic cannot separate CJK UTF-16 from binary data.",
	})
	// Priority 62: below the unambiguous magics and the structured model formats,
	// above the generic text sniffer (40) that would otherwise see NUL bytes and
	// classify the file as binary or unknown. No other sniffer claims UTF-16.
	artifact.RegisterSniffer("utf16-text", 62, sniff)
	artifact.RegisterParser(artifact.FormatUTF16, parser{})
}

func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 2 {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, min(size, probeWindow))
	if err != nil && len(head) < 2 {
		return artifact.FormatUnknown, false
	}
	if _, ok := detect(head); !ok {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatUTF16, true
}

// detect reports the byte order of a UTF-16 head, or ok=false when the bytes are
// not UTF-16.
func detect(head []byte) (Order, bool) {
	if len(head) < 2 {
		return 0, false
	}
	if head[0] == 0xFF && head[1] == 0xFE {
		// UTF-32LE begins with the same two bytes; its third and fourth are zero.
		if len(head) >= 4 && head[2] == 0 && head[3] == 0 {
			return 0, false
		}
		return LittleEndian, true
	}
	if head[0] == 0xFE && head[1] == 0xFF {
		return BigEndian, true
	}
	// Without a BOM the only shape worth claiming is Latin text: every code unit
	// is one ASCII byte and one zero byte. A minimum length keeps a two-byte
	// coincidence from claiming a binary artifact, a letter ratio keeps a binary
	// that happens to interleave control bytes with NUL (a Java class file's
	// constant-pool tags 9 and 10 are TAB and LF, which are text whitespace) from
	// passing as text, and the zero half must be the high byte for the direction
	// considered.
	if len(head) < 64 {
		return 0, false
	}
	// A head with any high byte in it is not Latin UTF-16 text, whatever its NUL
	// pattern: the SD-metadata JPEGs of the HF campaign carry a multi-KiB EXIF
	// UserComment whose text is UTF-16LE, and the head around it is 0xff 0xd8
	// 0xff 0xe0 plus a JFIF/Exif block. A BOM-less claim is therefore limited to
	// pure ASCII text, which is also why a non-Latin script needs the BOM: a ratio
	// generous enough to admit one accented character admits a container header.
	high := 0
	for _, c := range head {
		if c >= 0x80 {
			high++
		}
	}
	if high > 0 {
		return 0, false
	}
	pairs, le, be, leLetters, beLetters := 0, 0, 0, 0, 0
	for i := 0; i+1 < len(head); i += 2 {
		pairs++
		switch {
		case head[i+1] == 0 && textByte(head[i]):
			le++
			if isLetter(head[i]) {
				leLetters++
			}
		case head[i] == 0 && textByte(head[i+1]):
			be++
			if isLetter(head[i+1]) {
				beLetters++
			}
		}
	}
	if pairs == 0 {
		return 0, false
	}
	if le*10 >= pairs*9 && leLetters*5 >= pairs {
		return LittleEndian, true
	}
	if be*10 >= pairs*9 && beLetters*5 >= pairs {
		return BigEndian, true
	}
	return 0, false
}

// isLetter reports an ASCII letter, the byte that separates text from a binary
// table whose interleaved bytes happen to be whitespace.
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// textByte is what a Latin UTF-16 code unit's non-zero half must be: printable
// ASCII, or the whitespace that separates text.
func textByte(c byte) bool { return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r' }

// Decode converts a UTF-16 buffer to UTF-8 bytes, stripping a byte-order mark.
// An unpaired surrogate is replaced with U+FFFD, as Go's decoder does; the byte
// count must be even.
func Decode(order Order, b []byte) ([]byte, error) {
	if len(b)%2 != 0 {
		return nil, ErrOddLength
	}
	if len(b) >= 2 {
		if order == LittleEndian && b[0] == 0xFF && b[1] == 0xFE {
			b = b[2:]
		}
		if order == BigEndian && b[0] == 0xFE && b[1] == 0xFF {
			b = b[2:]
		}
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		if order == LittleEndian {
			units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		} else {
			units[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
	}
	return []byte(string(utf16.Decode(units))), nil
}

type parser struct{}

func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	n := size
	if cap := ctx.Limits.MaxArtifactBytes; cap > 0 && n > cap {
		n = cap
	}
	if n < 2 {
		return nil
	}
	head, _ := s.Bytes(0, min(n, probeWindow))
	order, ok := detect(head)
	if !ok {
		// The sniffer claimed the file; a re-dispatch of already-decoded text
		// cannot reach this parser. Say so rather than pretending to scan.
		ctx.Sink.Emit(RuleUTF16, 0, "the sniffer claimed UTF-16, but the byte order is not detectable")
		return nil
	}
	b, err := s.Bytes(0, n)
	if err != nil {
		return err
	}
	odd := len(b)%2 != 0
	body := b
	if odd {
		body = b[:len(b)-1]
	}
	decoded, err := Decode(order, body)
	if err != nil {
		return err
	}
	evidence := fmt.Sprintf("%s text, %d bytes decoded to %d UTF-8 bytes and re-dispatched; "+
		"offsets in findings on the decoded text are offsets into the decoded bytes, not into the file",
		order, len(body), len(decoded))
	if odd {
		evidence += fmt.Sprintf("; the trailing byte (%d-byte file) is not part of any code unit", len(b))
	}
	ctx.Sink.Emit(RuleUTF16, 0, evidence)
	artifact.ScanMemberBytes(ctx, s.Name(), decoded)
	return nil
}
