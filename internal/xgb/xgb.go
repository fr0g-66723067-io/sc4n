// Package xgb covers the gradient-boosting model families an ML pipeline is most
// likely to find next to an LLM: XGBoost, LightGBM and CatBoost.
//
// The central fact of this package is that only *one* of those shapes is a
// binary format sc4n can parse. Everything else is either an ordinary pickle
// (which the pickle engine owns, at a higher sniffer priority than this package)
// or a data-only file that contains no code at all. Writing that down explicitly
// is the point: "no findings" must never be mistaken for "fully analysed".
//
//   - XGBoost `.json` (since 2.1.0 the default) and `.ubj` (UBJSON, also since
//     2.1.0) are serialised *models*, not code: `XGBoost`'s own documentation
//     states the in-memory snapshot is not secure, but the on-disk JSON/UBJ
//     writers emit data only. The UBJSON walk below (<- this package) is the
//     bounded parse of the `.ubj` dialect; `.json` is handled by the shared JSON
//     parser. Neither can execute anything by itself.
//   - XGBoost `.model` / `.deprecated` legacy files, and any `.pkl` snapshot of an
//     XGBoost `Booster`, ARE pickles: `Booster.__reduce__` hands the loader a
//     stream that deserialises arbitrary objects. sc4n routes them to the pickle
//     engine because they begin with a pickle PROTO opcode, which the
//     `pickle-walk` sniffer (priority 95) claims before this package's sniffer
//     (priority 59) is consulted. There is therefore no XGBoost-specific parser
//     for them and there must not be one: the pickle engine's allowlist and
//     gadget tables are the policy that catches them.
//   - LightGBM: the `.txt` model file is a text model string with no code, but
//     `Booster.__getstate__`/`__setstate__` pickle that string, so a `.pkl` of a
//     LightGBM Booster is a pickle and is routed to the engine the same way.
//   - CatBoost: `.cbm` is not a pickle; the documented `python` export format is
//     a generated `.py` file, which the Python analyzer owns.
//   - scikit-learn: pickle, joblib and cloudpickle artifacts are in scope and
//     handled by those engines. `skops.io` and ONNX are NOT parsed here (ONNX has
//     its own package); a skops file reaches the pickle engine only if its
//     content actually sniffs as a pickle.
//
// The UBJSON parse is bounded and allocation-guarded: string lengths are checked
// against the bytes actually remaining and against MaxStringBlob before a byte is
// allocated, typed numeric arrays are skipped by their computed byte extent
// rather than read element by element, and a structural error is a finding plus a
// clean stop, never a panic.
package xgb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatXGBoostUBJ,
		Magic:  "UBJ, or a UBJSON object/array opener (a bare deep parse follows)",
		Depth:  artifact.DepthStructural,
		Notes: "the UBJSON value stream is walked with protowire-free bounded reads: string and container " +
			"lengths are validated against the bytes remaining and MaxStringBlob before allocation, typed " +
			"numeric arrays are skipped by their computed extent, every string value and object key is run " +
			"through the shared indicator engine, and bytes after the root value are reported as " +
			"SC4N-XGB-UBJ-TRAILING. SHALLOW PATHS, stated explicitly: an XGBoost `.json` model is parsed by " +
			"the JSON parser (data only); a legacy `.model`/`.deprecated` file or a `.pkl` Booster is a " +
			"pickle and is parsed by the pickle engine, not here; a LightGBM `.txt` is data only, but a " +
			"pickled LightGBM Booster is a pickle; a CatBoost `.cbm` is not a pickle (its documented " +
			"`python` export is a `.py` file handled by the Python analyzer); skops.io and ONNX are out of " +
			"scope for this package. UBJSON beyond the root value is not decoded -- an XGBoost model's " +
			"numeric payload is weights, and the only code-bearing field would be a string, which is scanned.",
	})
	// Priority 59: above the shallow text fallback (-100) and below the ONNX
	// protobuf discriminator (60) and the Python/notebook sniffers (66/68). The
	// shape check is deliberately strict so this never claims ordinary JSON: a
	// UBJSON object opens with `{` followed by an integer length marker (i/U/I/l/L)
	// or the `$`/`#` optimisation markers, none of which a JSON object can begin
	// with, and a UBJSON array is accepted only for the markers that JSON arrays
	// cannot start with.
	artifact.RegisterSniffer("xgb-ubj", 59, sniff)
	artifact.RegisterParser(artifact.FormatXGBoostUBJ, parser{})
}

type parser struct{}

// Parse walks the artifact as a UBJSON value stream. A structural error is a
// finding, not a returned error: the parser never panics on malformed bytes and
// stops cleanly at the first unrecoverable one.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	w := &uwalker{
		ctx:  ctx,
		sink: ctx.Sink,
		l:    ctx.Limits,
		size: s.Size(),
		r:    bufio.NewReaderSize(s.Reader(0), ubjWindowSize),
	}
	w.run()
	return nil
}

// ubjWindowSize is the streaming window. The walk never holds more than a window
// plus one string value (itself capped by MaxStringBlob).
const ubjWindowSize = 64 << 10

// maxUBJDepth bounds container nesting independently of the artifact depth
// budget: A UBJSON document is data, and a legitimate XGBoost model nests only a
// handful of levels.
const maxUBJDepth = 64

// UBJSON markers (Draft 12).
const (
	mNull    = 'Z'
	mNoop    = 'N'
	mTrue    = 'T'
	mFalse   = 'F'
	mInt8    = 'i'
	mUint8   = 'U'
	mInt16   = 'I'
	mInt32   = 'l'
	mInt64   = 'L'
	mFloat32 = 'd'
	mFloat64 = 'D'
	mHigh    = 'H'
	mChar    = 'C'
	mString  = 'S'
	mArray   = '['
	mObject  = '{'
	mEndArr  = ']'
	mEndObj  = '}'
	mType    = '$'
	mCount   = '#'
)

var errStop = errors.New("xgb: stop")

// stopKind records how a walk ended, for the sniffer's verdict.
type stopKind uint8

const (
	// stopRunning is the zero value: the walk has not stopped.
	stopRunning stopKind = iota
	// stopExhausted means the bytes available ran out while the document was
	// still consistent. A head-limited sniff of a real (larger) document looks
	// exactly like this, so it is not evidence against UBJSON.
	stopExhausted
	// stopInvalid means the bytes contradict the format.
	stopInvalid
)

// uwalk defers structural errors to the walker so a single finding is emitted and
// the walk stops.
type uwalker struct {
	ctx  *artifact.Ctx
	sink *report.Sink
	l    limits.Limits

	r    *bufio.Reader
	size int64
	off  int64

	elems    int64
	elemsHi  bool
	structHi bool

	// quiet suppresses every finding and every member dispatch. The sniffer
	// walks a head with quiet set: it asks whether the bytes look like UBJSON
	// rather than reporting on them.
	quiet bool
	// stop is how the walk ended. It is the sniffer's whole answer.
	stop stopKind
}

// mark records a stop, keeping the strongest verdict: an invalid document stays
// invalid even if a later path is reached with the bytes exhausted.
func (w *uwalker) mark(k stopKind) {
	if k > w.stop {
		w.stop = k
	}
}

// looksLikeUBJ is the sniffer's verdict on a quiet head walk.
//
// A document that parsed to its end is UBJSON. So is one that ran out of bytes
// after making real progress, because that is what a large document looks like
// when only its first bytes are available. A structural failure is only evidence
// against the format when it happens in the ambiguous prefix — the first bytes,
// where `{` plus `#` is both a UBJSON object with a count and a Jinja comment
// opener, and the two only diverge when the bytes after the marker are read.
func (w *uwalker) looksLikeUBJ() bool {
	if w.stop == stopRunning {
		return true
	}
	return w.off >= ubjSniffProgress
}

// ubjSniffProgress is how far a quiet walk must get before a structural failure
// counts as a property of the document rather than of its ambiguous prefix.
const ubjSniffProgress = 16

// ubjSniffHead bounds how much of an artifact the sniffer walks.
const ubjSniffHead = 64 << 10

func (w *uwalker) run() {
	// XGBoost's UBJSON writer emits no magic prefix, but some producer of a
	// downloadable corpus writes the optional "UBJ" file-identifier. Accept both.
	if b, err := w.r.Peek(3); err == nil && bytes.Equal(b, []byte("UBJ")) {
		w.discard(3)
	}
	if err := w.value(0); err != nil {
		if errors.Is(err, errStop) {
			// A structural stop: fail() or failShort() recorded which.
			return
		}
		w.mark(stopExhausted)
		w.fail("truncated UBJSON value: " + err.Error())
		return
	}
	// The walk completed; stopRunning (the zero value) is the verdict.
	if w.off < w.size && !w.quiet {
		w.sink.EmitExtra(RuleTrailing, w.off,
			fmt.Sprintf("%d byte(s) follow the root UBJSON value; the XGBoost reader stops at the root and never sees them",
				w.size-w.off),
			map[string]string{"trailing_bytes": strconv.FormatInt(w.size-w.off, 10)})
	}
}

// count consumes one structural element of the configured budget.
func (w *uwalker) count() bool {
	w.elems++
	if cap := w.arrayCap(); w.elems > cap {
		if !w.elemsHi {
			w.elemsHi = true
			if !w.quiet {
				limits.Emit(w.sink, limits.RuleEntries, "MaxArrayElements", w.elems, cap, "ubjson elements")
			}
		}
		return false
	}
	return true
}

// arrayCap is the element budget for one UBJSON container. It is
// MaxArrayElements rather than MaxEntries: a UBJSON document is one array of
// model data, and the archive-member cap has nothing to say about it.
func (w *uwalker) arrayCap() int64 {
	if w.l.MaxArrayElements > 0 {
		return int64(w.l.MaxArrayElements)
	}
	return int64(limits.Default().MaxArrayElements)
}

// emitStruct emits the structural rule once per artifact.
func (w *uwalker) emitStruct(msg string) {
	if w.structHi || w.quiet {
		return
	}
	w.structHi = true
	w.sink.Emit(RuleStruct, w.off, msg)
}

// fail records a structural error — the bytes contradict UBJSON — emits the
// structural finding once, and stops the walk.
func (w *uwalker) fail(msg string) error {
	w.mark(stopInvalid)
	w.emitStruct(msg)
	return errStop
}

// failShort records an error that is indistinguishable from the document simply
// continuing past the bytes available. The parser reports it exactly as fail
// does; only the sniffer's verdict differs.
func (w *uwalker) failShort(msg string) error {
	w.mark(stopExhausted)
	w.emitStruct(msg)
	return errStop
}

func (w *uwalker) readByte() (byte, error) {
	b, err := w.r.ReadByte()
	if err != nil {
		return 0, err
	}
	w.off++
	return b, nil
}

func (w *uwalker) peek() (byte, error) {
	b, err := w.r.Peek(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (w *uwalker) discard(n int64) {
	if n <= 0 {
		return
	}
	skipped, _ := io.CopyN(io.Discard, w.r, n)
	w.off += skipped
}

// readN reads exactly n bytes. n MUST already have been validated against the
// bytes remaining and against MaxStringBlob.
func (w *uwalker) readN(n int64) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("negative length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(w.r, buf); err != nil {
		return nil, err
	}
	w.off += n
	return buf, nil
}

// remaining is the number of bytes not yet consumed by the walk.
func (w *uwalker) remaining() int64 {
	if w.off >= w.size {
		return 0
	}
	return w.size - w.off
}

// value parses one tagged UBJSON value.
func (w *uwalker) value(depth int) error {
	if depth > maxUBJDepth {
		return w.fail("UBJSON container nesting exceeds the walk cap")
	}
	if !w.count() {
		return errStop
	}
	marker, err := w.readByte()
	if err != nil {
		return io.ErrUnexpectedEOF
	}
	switch marker {
	case mNull, mTrue, mFalse, mNoop:
		return nil
	case mInt8, mUint8, mChar:
		return w.skipFixedBytes(1)
	case mInt16:
		return w.skipFixedBytes(2)
	case mInt32, mFloat32:
		return w.skipFixedBytes(4)
	case mInt64, mFloat64:
		return w.skipFixedBytes(8)
	case mString, mHigh:
		return w.stringValue()
	case mArray:
		return w.array(depth)
	case mObject:
		return w.object(depth)
	default:
		return w.fail(fmt.Sprintf("unknown UBJSON marker 0x%02x", marker))
	}
}

func (w *uwalker) skipFixedBytes(n int64) error {
	if n > w.remaining() {
		return io.ErrUnexpectedEOF
	}
	w.discard(n)
	return nil
}

// readLength reads an integer-valued UBJSON numeric as a length/count. Negative
// values are rejected by the callers.
func (w *uwalker) readLength() (int64, error) {
	marker, err := w.readByte()
	if err != nil {
		return 0, io.ErrUnexpectedEOF
	}
	switch marker {
	case mInt8:
		v, err := w.readByte()
		if err != nil {
			return 0, io.ErrUnexpectedEOF
		}
		return int64(int8(v)), nil
	case mUint8:
		v, err := w.readByte()
		if err != nil {
			return 0, io.ErrUnexpectedEOF
		}
		return int64(v), nil
	case mInt16:
		b, err := w.readN(2)
		if err != nil {
			return 0, err
		}
		return int64(int16(binary.BigEndian.Uint16(b))), nil
	case mInt32:
		b, err := w.readN(4)
		if err != nil {
			return 0, err
		}
		return int64(int32(binary.BigEndian.Uint32(b))), nil
	case mInt64:
		b, err := w.readN(8)
		if err != nil {
			return 0, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	default:
		return 0, fmt.Errorf("UBJSON length is not an integer marker (0x%02x)", marker)
	}
}

// stringValue parses `S` (or `H`) plus a length and payload.
func (w *uwalker) stringValue() error {
	n, err := w.readLength()
	if err != nil {
		return w.fail("UBJSON string: " + err.Error())
	}
	if n < 0 {
		return w.fail("UBJSON string declares a negative length")
	}
	if n > w.remaining() {
		return w.failShort("UBJSON string length exceeds the bytes remaining")
	}
	if n > w.l.MaxStringBlob {
		if !w.quiet {
			limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", n, w.l.MaxStringBlob, "ubjson string")
		}
		w.discard(n)
		return nil
	}
	off := w.off
	buf, err := w.readN(n)
	if err != nil {
		return w.fail("UBJSON string truncated")
	}
	w.scanString(off, buf)
	return nil
}

// key parses an object key, which UBJSON writes as a length-prefixed string
// *without* the `S` marker. Some writers emit the marker anyway, so both forms
// are accepted.
func (w *uwalker) key() error {
	pb, err := w.peek()
	if err != nil {
		return io.ErrUnexpectedEOF
	}
	if pb == mString {
		w.discard(1)
		return w.stringValue()
	}
	n, err := w.readLength()
	if err != nil {
		return w.fail("UBJSON object key: " + err.Error())
	}
	if n < 0 {
		return w.fail("UBJSON object key length is negative")
	}
	if n > w.remaining() {
		return w.failShort("UBJSON object key length exceeds the bytes remaining")
	}
	if n > w.l.MaxStringBlob {
		if !w.quiet {
			limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", n, w.l.MaxStringBlob, "ubjson key")
		}
		w.discard(n)
		return nil
	}
	off := w.off
	buf, err := w.readN(n)
	if err != nil {
		return w.fail("UBJSON object key truncated")
	}
	w.scanString(off, buf)
	return nil
}

// scanString runs the shared indicator engine over a string/blob value and, when
// the value begins with native-executable magic or a pickle protocol header,
// re-dispatches it so the polyglot and pickle engines can classify it.
func (w *uwalker) scanString(off int64, buf []byte) {
	if w.quiet {
		// The sniffer walks a head to classify it, not to report on it: no
		// finding and no member dispatch comes out of a sniff.
		return
	}
	stringscan.EmitString(w.sink, off, string(buf))
	if len(buf) >= 8 && bytescan.MagicAt(buf) != bytescan.NativeNone {
		artifact.ScanMemberBytes(w.ctx, "ubjson-string", buf)
		return
	}
	if len(buf) >= 2 && buf[0] == 0x80 && buf[1] >= 1 && buf[1] <= 5 {
		artifact.ScanMemberBytes(w.ctx, "ubjson-string", buf)
	}
}

func (w *uwalker) array(depth int) error {
	pb, err := w.peek()
	if err != nil {
		return w.failShort("unterminated UBJSON array")
	}
	if pb == mType {
		w.discard(1)
		t, err := w.readByte()
		if err != nil {
			return w.fail("typed UBJSON array without an element type")
		}
		if n, err := w.expectCount(); err != nil {
			return err
		} else {
			return w.typedValues(t, n, depth)
		}
	}
	if pb == mCount {
		w.discard(1)
		n, err := w.readLength()
		if err != nil {
			return w.fail("UBJSON array count: " + err.Error())
		}
		if n < 0 {
			return w.fail("UBJSON array declares a negative count")
		}
		for range n {
			if err := w.value(depth + 1); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		pb, err := w.peek()
		if err != nil {
			return w.failShort("unterminated UBJSON array")
		}
		if pb == mEndArr {
			w.discard(1)
			return nil
		}
		if err := w.value(depth + 1); err != nil {
			return err
		}
	}
}

func (w *uwalker) object(depth int) error {
	pb, err := w.peek()
	if err != nil {
		return w.failShort("unterminated UBJSON object")
	}
	if pb == mType {
		w.discard(1)
		t, err := w.readByte()
		if err != nil {
			return w.fail("typed UBJSON object without a value type")
		}
		if n, err := w.expectCount(); err != nil {
			return err
		} else {
			for range n {
				if err := w.key(); err != nil {
					return err
				}
				if err := w.typedValue(t, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if pb == mCount {
		w.discard(1)
		n, err := w.readLength()
		if err != nil {
			return w.fail("UBJSON object count: " + err.Error())
		}
		if n < 0 {
			return w.fail("UBJSON object declares a negative count")
		}
		for range n {
			if err := w.key(); err != nil {
				return err
			}
			if err := w.value(depth + 1); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		pb, err := w.peek()
		if err != nil {
			return w.failShort("unterminated UBJSON object")
		}
		if pb == mEndObj {
			w.discard(1)
			return nil
		}
		if err := w.key(); err != nil {
			return err
		}
		if err := w.value(depth + 1); err != nil {
			return err
		}
	}
}

// expectCount reads a mandatory `#`-prefixed count.
func (w *uwalker) expectCount() (int64, error) {
	pb, err := w.peek()
	if err != nil || pb != mCount {
		return 0, w.fail("typed UBJSON container without a count")
	}
	w.discard(1)
	n, err := w.readLength()
	if err != nil {
		return 0, w.fail("UBJSON container count: " + err.Error())
	}
	if n < 0 {
		return 0, w.fail("UBJSON container declares a negative count")
	}
	return n, nil
}

// typedValues parses a strongly typed container body (element markers omitted).
func (w *uwalker) typedValues(t byte, n int64, depth int) error {
	if depth > maxUBJDepth {
		return w.fail("UBJSON container nesting exceeds the walk cap")
	}
	switch t {
	case mInt8, mUint8, mChar:
		return w.skipFixed(n, 1)
	case mInt16:
		return w.skipFixed(n, 2)
	case mInt32, mFloat32:
		return w.skipFixed(n, 4)
	case mInt64, mFloat64:
		return w.skipFixed(n, 8)
	case mNull, mNoop, mTrue, mFalse:
		// A strongly typed container of payload-less values has an empty body.
		return nil
	case mString, mHigh:
		if cap := w.arrayCap(); n > cap {
			if !w.quiet {
				limits.Emit(w.sink, limits.RuleEntries, "MaxArrayElements", n, cap, "ubjson typed string array")
			}
			return errStop
		}
		for range n {
			if err := w.stringValue(); err != nil {
				return err
			}
		}
		return nil
	default:
		return w.fail(fmt.Sprintf("unsupported typed UBJSON element type 0x%02x", t))
	}
}

// typedValue parses one element of a typed *object* (the element type marker is
// carried by the object header).
func (w *uwalker) typedValue(t byte, depth int) error {
	if depth > maxUBJDepth {
		return w.fail("UBJSON container nesting exceeds the walk cap")
	}
	switch t {
	case mNull, mNoop, mTrue, mFalse:
		return nil
	case mInt8, mUint8, mChar:
		return w.skipFixedBytes(1)
	case mInt16:
		return w.skipFixedBytes(2)
	case mInt32, mFloat32:
		return w.skipFixedBytes(4)
	case mInt64, mFloat64:
		return w.skipFixedBytes(8)
	case mString, mHigh:
		return w.stringValue()
	default:
		return w.fail(fmt.Sprintf("unsupported typed UBJSON object value type 0x%02x", t))
	}
}

// skipFixed validates and skips n elements of a fixed-size type without reading
// them, which is how a multi-megabyte numeric array costs no allocation.
func (w *uwalker) skipFixed(n, size int64) error {
	remaining := w.remaining()
	if size <= 0 || n > remaining/size {
		// A declared extent that runs past the bytes available is a structural
		// error for the parser and, to the sniffer, indistinguishable from a real
		// document whose array data continues past the head it was given.
		return w.failShort("typed UBJSON array extent exceeds the bytes remaining")
	}
	w.discard(n * size)
	return nil
}

// sniff recognises UBJSON by content. The two-byte shape check is only a cheap
// gate; the document is then claimed only if a bounded, quiet walk of its head is
// consistent with UBJSON. The shape check alone is not enough: `{` followed by
// `#` is both a UBJSON object carrying a count and a Jinja comment opener, and
// `#` is UBJSON's count marker, so every `{# ... #}` chat template in the wild
// used to be claimed here, scanned as a broken UBJSON document, and never
// analysed as a template.
//
// The invariant this restores: a sniffer MUST NOT accept a document that its own
// parser reports as structurally invalid.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 3 {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, minInt64(size, ubjSniffHead))
	if err != nil && len(head) < 3 {
		return artifact.FormatUnknown, false
	}
	if bytes.HasPrefix(head, []byte("UBJ")) {
		return artifact.FormatXGBoostUBJ, true
	}
	if len(head) < 2 {
		return artifact.FormatUnknown, false
	}
	var shaped bool
	switch head[0] {
	case mObject:
		shaped = isObjectStart(head[1])
	case mArray:
		shaped = isArrayStart(head[1])
	}
	if !shaped {
		return artifact.FormatUnknown, false
	}
	if !ubjHeadIsConsistent(head, l) {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatXGBoostUBJ, true
}

// ubjHeadIsConsistent walks head as UBJSON with every finding suppressed and
// reports whether the bytes are consistent with the format.
func ubjHeadIsConsistent(head []byte, l limits.Limits) bool {
	w := &uwalker{
		sink:  report.NewCollector(0).For("sniff"),
		l:     l,
		size:  int64(len(head)),
		r:     bufio.NewReaderSize(bytes.NewReader(head), ubjWindowSize),
		quiet: true,
	}
	w.run()
	return w.looksLikeUBJ()
}

func isObjectStart(b byte) bool {
	switch b {
	case mInt8, mUint8, mInt16, mInt32, mInt64, mType, mCount:
		return true
	default:
		return false
	}
}

func isArrayStart(b byte) bool {
	switch b {
	case mType, mCount, mNull, mNoop, mTrue, mFalse, mString, mHigh, mChar,
		mInt8, mUint8, mInt16, mInt32, mInt64, mFloat32, mFloat64:
		return true
	default:
		// Deliberately excludes '[', '{', '"', '-', digits, 't', 'f', 'n' and ']'
		// so a JSON document is never claimed as UBJSON.
		return false
	}
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
