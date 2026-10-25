// Package msgpack parses the MessagePack documents Flax/JAX/MLX use for model
// parameters and metadata.
//
// MessagePack is a binary, self-describing serialisation with no code field, so
// the parser's job is threefold: walk the document with hard bounds (nesting,
// element count, string/blob size) so a crafted length cannot make the scan read
// out of bounds; run the shared string-indicator engine over every string value;
// and dispatch any binary blob that itself sniffs as a pickle or a native image,
// because a blob is the one place a second format can hide.
//
// The walker never allocates from a declared length before validating it against
// the bytes remaining; every cap that fires becomes a limits finding rather than
// a silent stop.
package msgpack

import (
	"errors"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

const (
	// maxDepth bounds value nesting. Real parameter trees are a handful of
	// levels deep; 512 is far above anything a serialiser writes and far below a
	// stack that could overflow the scanner.
	maxDepth = 512
	// maxElements bounds the total number of values walked. It is the same order
	// as the metadata-array cap (Limits.MaxArrayElements, which a caller may
	// lower) and stops a map declaring billions of keys from occupying the
	// scanner even before the byte-length check fires.
	maxElements = 1 << 22
	// sniffBudget bounds how much of a candidate the sniffer parses. A larger
	// document is accepted if its prefix parses cleanly, because the parser runs
	// the full bounded walk afterwards.
	sniffBudget = 1 << 20
)

// errTruncated means the value needs more bytes than are available. For the
// sniffer this is acceptable (the budget may simply be shorter than the file);
// for the parser it is a structural finding.
var errTruncated = errors.New("msgpack: truncated value")

// errCap means a nesting/element cap was hit; the corresponding limits finding
// has already been emitted.
var errCap = errors.New("msgpack: cap reached")

type parser struct{}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatMsgpack,
		Magic:  "a map/array header byte (0x80-0x9f/0xde/0xdf/0xdc/0xdd) whose bounded walk consumes the file",
		Depth:  artifact.DepthDeep,
		Notes: "the document is walked with a nesting, element and string/blob budget; every string value is " +
			"run through the shared indicator engine; NaN runs in binary blobs are reported at info; and a " +
			"blob that sniffs as a pickle or a native image is dispatched to its own engine. MessagePack has " +
			"no code field, so no code is executed and no member is extracted.",
	})
	// Priority 50: below the magic table (100), the format-specific sniffers
	// (safetensors/gguf/pickle/notebook/python), the protobuf sniffer (60) and
	// the archive sniffer (60), and above the text fallback (-100). MessagePack
	// has no magic, so the only content test is a successful bounded parse of a
	// top-level map/array; running after the stronger evidence avoids ever
	// swallowing a file another sniffer can name exactly.
	artifact.RegisterSniffer("msgpack", 50, sniff)
	artifact.RegisterParser(artifact.FormatMsgpack, parser{})
}

// Parse walks the whole document and reports what it finds.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	data, err := s.Bytes(0, s.Size())
	if err != nil && len(data) == 0 {
		return err
	}
	w := &walker{ctx: ctx, data: data, lim: ctx.Limits, emit: true}
	if verr := w.value(0); verr != nil {
		if errors.Is(verr, errCap) {
			return nil
		}
		ctx.Sink.Emit(RuleStruct, int64(w.idx), verr.Error())
		return verr
	}
	if w.idx != len(data) {
		ctx.Sink.Emit(RuleStruct, int64(w.idx), "trailing bytes after the top-level MessagePack value")
	}
	return nil
}

// sniff claims a document whose first byte is a map or array header and whose
// bounded prefix parses without a structural error *and* accounts for the bytes
// it was given.
//
// The coverage requirement is what the shape check alone was missing: `0x90` is a
// complete one-byte MessagePack value (an empty array), so a ten-megabyte Chromium
// data table that happens to start with it was claimed as MessagePack and then
// reported as 10.8 MB of trailing bytes. A sniffer MUST NOT accept a document that
// its own parser reports as structurally invalid.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 2 {
		return artifact.FormatUnknown, false
	}
	n := size
	if n > sniffBudget {
		n = sniffBudget
	}
	head, err := s.Bytes(0, n)
	if err != nil && int64(len(head)) == 0 {
		return artifact.FormatUnknown, false
	}
	if len(head) == 0 || !isContainerHeader(head[0]) {
		return artifact.FormatUnknown, false
	}
	w := &walker{data: head, lim: l, emit: false}
	switch verr := w.value(0); {
	case verr == nil:
		// The value closed. That is MessagePack only if it closed at the end of
		// the bytes read; a value that closes early and leaves the rest of the
		// buffer behind is not this format.
		return artifact.FormatMsgpack, w.idx == len(head)
	case errors.Is(verr, errCap):
		// A cap was reached while the walk was still making sense of the
		// document, so the bytes so far are consistent with MessagePack and the
		// parser has something to report.
		return artifact.FormatMsgpack, true
	case errors.Is(verr, errTruncated):
		// The value needs more bytes than were read, which is legitimate for a
		// slice whose document continues past the probe — unless the top-level
		// container declares far more elements than the file could hold. Every
		// element costs at least one byte, so a count several times the artifact's
		// size is binary data that happens to start with a container header, not a
		// truncated document. Measured: a torch storage blob beginning
		// df 10 48 3c 12 declares a map32 of 273,102,866 entries in a 256 KiB file
		// and was claimed as MessagePack, so the artifact ended in a medium
		// "msgpack: truncated value" instead of being scanned as the binary it is.
		// The factor tolerates a slice whose document continues past the probe.
		if c, ok := firstContainerCount(head); ok && c > 8*uint64(size) {
			return artifact.FormatUnknown, false
		}
		return artifact.FormatMsgpack, true
	default:
		return artifact.FormatUnknown, false
	}
}

// firstContainerCount reads the element count of a top-level map or array
// header. fixarray/fixmap carry it in the low nibble; array16/32 and map16/32 in
// the following big-endian bytes. ok is false for every other first byte or when
// the header is shorter than its count field.
func firstContainerCount(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	switch c := b[0]; {
	case c >= 0x80 && c <= 0x8f, c >= 0x90 && c <= 0x9f:
		return uint64(c & 0x0f), true
	case c == 0xdc, c == 0xde:
		if len(b) < 3 {
			return 0, false
		}
		return uint64(b[1])<<8 | uint64(b[2]), true
	case c == 0xdd, c == 0xdf:
		if len(b) < 5 {
			return 0, false
		}
		return uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4]), true
	}
	return 0, false
}

// isContainerHeader reports whether b is a map or array header byte. Fixints and
// fixstrs are deliberately excluded: they make almost any short binary file look
// like MessagePack, and a real model document is a map or array at the top.
func isContainerHeader(b byte) bool {
	switch {
	case b >= 0x80 && b <= 0x9f:
		return true
	case b == 0xde, b == 0xdf, b == 0xdc, b == 0xdd:
		return true
	}
	return false
}

// walker is one bounded walk over data.
type walker struct {
	ctx  *artifact.Ctx
	data []byte
	idx  int
	// lim is the effective limit set, used for cap findings.
	lim  limits.Limits
	emit bool

	depth    int
	elements int
}

// elementCap is the value budget for one MessagePack document: MaxArrayElements
// when the caller set one, otherwise the package default (the same number).
func (w *walker) elementCap() int64 {
	if w.lim.MaxArrayElements > 0 {
		return int64(w.lim.MaxArrayElements)
	}
	return maxElements
}

func (w *walker) value(depth int) error {
	if depth > maxDepth {
		if w.emitting() {
			limits.Emit(w.ctx.Sink, limits.RuleDepth, "MaxDepth", int64(depth), int64(maxDepth), "msgpack nesting")
		}
		return errCap
	}
	if w.emitting() {
		w.elements++
		if cap := w.elementCap(); int64(w.elements) > cap {
			limits.Emit(w.ctx.Sink, limits.RuleEntries, "MaxArrayElements", int64(w.elements), cap, "msgpack values")
			return errCap
		}
	}
	b, err := w.byte()
	if err != nil {
		return err
	}
	switch {
	case b <= 0x7f || b >= 0xe0: // positive/negative fixint
		return nil
	case b >= 0x80 && b <= 0x8f: // fixmap
		return w.mapping(int(b&0x0f), depth)
	case b >= 0x90 && b <= 0x9f: // fixarray
		return w.array(int(b&0x0f), depth)
	case b >= 0xa0 && b <= 0xbf: // fixstr
		return w.str(int(b & 0x1f))
	case b == 0xc0: // nil
		return nil
	case b == 0xc1:
		return errors.New("msgpack: 0xc1 is never a valid type byte")
	case b == 0xc2 || b == 0xc3: // bool
		return nil
	case b == 0xc4:
		return w.bin(w.len(1))
	case b == 0xc5:
		return w.bin(w.len(2))
	case b == 0xc6:
		return w.bin(w.len(4))
	case b == 0xc7:
		return w.ext(w.len(1))
	case b == 0xc8:
		return w.ext(w.len(2))
	case b == 0xc9:
		return w.ext(w.len(4))
	case b == 0xca:
		return w.skip(4)
	case b == 0xcb:
		return w.skip(8)
	case b == 0xcc:
		return w.skip(1)
	case b == 0xcd:
		return w.skip(2)
	case b == 0xce:
		return w.skip(4)
	case b == 0xcf:
		return w.skip(8)
	case b == 0xd0:
		return w.skip(1)
	case b == 0xd1:
		return w.skip(2)
	case b == 0xd2:
		return w.skip(4)
	case b == 0xd3:
		return w.skip(8)
	case b == 0xd4:
		return w.ext(1)
	case b == 0xd5:
		return w.ext(2)
	case b == 0xd6:
		return w.ext(4)
	case b == 0xd7:
		return w.ext(8)
	case b == 0xd8:
		return w.ext(16)
	case b == 0xd9:
		return w.str(w.len(1))
	case b == 0xda:
		return w.str(w.len(2))
	case b == 0xdb:
		return w.str(w.len(4))
	case b == 0xdc:
		return w.array(w.len(2), depth)
	case b == 0xdd:
		return w.array(w.len(4), depth)
	case b == 0xde:
		return w.mapping(w.len(2), depth)
	case b == 0xdf:
		return w.mapping(w.len(4), depth)
	}
	return errors.New("msgpack: unknown type byte")
}

// len reads an n-byte big-endian length. A length of 0 with a read error is
// returned as 0; the following skip/read will then report the truncation.
func (w *walker) len(n int) int {
	v, err := w.uint(n)
	if err != nil {
		return -1
	}
	if v > uint64(len(w.data)) {
		// Larger than the file: every consumer will fail its bounds check, but
		// clamp so the int conversion cannot overflow.
		return len(w.data) + 1
	}
	return int(v)
}

func (w *walker) array(count, depth int) error {
	if count < 0 {
		return errTruncated
	}
	if count > len(w.data)-w.idx+1 {
		// Each element needs at least one byte, so a count above the remaining
		// byte count cannot be satisfied.
		return errTruncated
	}
	for range count {
		if err := w.value(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) mapping(count, depth int) error {
	if count < 0 {
		return errTruncated
	}
	if count > len(w.data)-w.idx+1 {
		return errTruncated
	}
	for range count {
		if err := w.value(depth + 1); err != nil { // key
			return err
		}
		if err := w.value(depth + 1); err != nil { // value
			return err
		}
	}
	return nil
}

// str reads a string of n bytes and runs the indicator engine over it.
func (w *walker) str(n int) error {
	if n < 0 || n > len(w.data)-w.idx {
		return errTruncated
	}
	body := w.data[w.idx : w.idx+n]
	start := w.idx
	w.idx += n
	if w.emitting() {
		cap := w.maxBlob()
		if int64(len(body)) > cap {
			limits.Emit(w.ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(body)), cap, "msgpack string")
			body = body[:cap]
		}
		stringscan.Emit(w.ctx.Sink, int64(start), body)
	}
	return nil
}

// bin reads a binary blob of n bytes: it flags NaN runs and dispatches the blob
// when it sniffs as a pickle or a native image.
func (w *walker) bin(n int) error {
	if n < 0 || n > len(w.data)-w.idx {
		return errTruncated
	}
	start := w.idx
	body := w.data[w.idx : w.idx+n]
	w.idx += n
	if !w.emitting() {
		return nil
	}
	cap := w.maxBlob()
	if int64(len(body)) > cap {
		limits.Emit(w.ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(body)), cap, "msgpack blob")
	}
	w.nanRuns(start, body)
	// Route a blob that begins with a native magic or a pickle protocol byte to
	// the normal member machinery; the member's own parser validates the header,
	// so a bare magic without a valid executable is not reported as one. Only the
	// header is inspected here — a whole-blob native search would double the cost
	// of every weight blob, and the universal polyglot layer already scans whole
	// artifacts.
	if bytescan.MagicAt(body) != bytescan.NativeNone {
		artifact.ScanMemberBytes(w.ctx, "blob", body)
		return nil
	}
	if len(body) >= 2 && body[0] == 0x80 && body[1] >= 1 && body[1] <= 5 {
		artifact.ScanMemberBytes(w.ctx, "blob", body)
		return nil
	}
	if _, ok := bytescan.ShebangAt(body); ok {
		artifact.ScanMemberBytes(w.ctx, "blob", body)
	}
	return nil
}

// ext skips an extension of payload length n (plus its one-byte type code).
func (w *walker) ext(n int) error {
	if n < 0 {
		return errTruncated
	}
	total := n + 1
	if total > len(w.data)-w.idx {
		return errTruncated
	}
	w.idx += total
	return nil
}

func (w *walker) skip(n int) error {
	if n < 0 || n > len(w.data)-w.idx {
		return errTruncated
	}
	w.idx += n
	return nil
}

func (w *walker) byte() (byte, error) {
	if w.idx >= len(w.data) {
		return 0, errTruncated
	}
	b := w.data[w.idx]
	w.idx++
	return b, nil
}

func (w *walker) uint(n int) (uint64, error) {
	if n <= 0 || n > len(w.data)-w.idx {
		return 0, errTruncated
	}
	var v uint64
	for k := range n {
		v = v<<8 | uint64(w.data[w.idx+k])
	}
	w.idx += n
	return v, nil
}

func (w *walker) emitting() bool { return w.emit && w.ctx != nil && w.ctx.Sink != nil }

func (w *walker) maxBlob() int64 {
	if w.lim.MaxStringBlob > 0 {
		return w.lim.MaxStringBlob
	}
	return limits.Default().MaxStringBlob
}

// nanRuns reports a run of NaN-shaped byte pairs in the blob that begins at base.
// A double NaN has 0x7ff8 or 0xfff8 in its exponent/top-mantissa bytes, so the
// two-byte prefix 0x7f 0xf8 / 0xff 0xf8 can recur at stride two once per value;
// four consecutive pairs is a run, not a single accidental NaN. base is the
// blob's offset in the artifact: every other finding this walker emits carries an
// absolute offset, and a blob-relative one pointed the reader at the container
// header instead of the payload.
func (w *walker) nanRuns(base int, b []byte) {
	pair := func(i int) bool {
		return i+1 < len(b) && (b[i] == 0x7f || b[i] == 0xff) && b[i+1] == 0xf8
	}
	for i := 0; i+1 < len(b); {
		if !pair(i) {
			i++
			continue
		}
		n := 0
		j := i
		for pair(j) {
			n++
			j += 2
		}
		if n >= 4 {
			w.ctx.Sink.EmitExtra(RuleNaNPayload, int64(base+i),
				strconv.Itoa(n)+" NaN-shaped byte pairs at stride two in a MessagePack blob",
				map[string]string{"pairs": strconv.Itoa(n)})
			return
		}
		i = j
	}
}
