package numpy

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// joblibWrapperStream builds an object pickle whose first object is a
// NumpyArrayWrapper REDUCE. shape is the literal opcode bytes for the shape
// tuple; tail is appended after the STOP as the array payload.
func joblibWrapperStream(dtype string, shape []byte, tail []byte) []byte {
	out := []byte{0x80, 0x04} // PROTO 4
	out = append(out, 0x63)   // GLOBAL
	out = append(out, []byte("joblib.numpy_pickle\nNumpyArrayWrapper\n")...)
	out = append(out, 0x28)                   // MARK (args tuple)
	out = append(out, 0x8c, byte(len(dtype))) // SHORT_BINUNICODE dtype
	out = append(out, []byte(dtype)...)
	out = append(out, 0x28)            // MARK (shape tuple)
	out = append(out, shape...)        // dims
	out = append(out, 0x74)            // TUPLE (shape)
	out = append(out, 0x8c, 0x01, 'C') // order
	out = append(out, 0x89)            // NEWFALSE
	out = append(out, 0x4e)            // NONE (subclass)
	out = append(out, 0x74)            // TUPLE (args)
	out = append(out, 0x52)            // REDUCE
	out = append(out, 0x4e)            // NONE (state)
	out = append(out, 0x62)            // BUILD
	out = append(out, 0x2e)            // STOP
	return append(out, tail...)
}

func parseJoblib(t *testing.T, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	lim := limits.Default()
	sess := artifact.NewSession(c, "", lim)
	ctx := &artifact.Ctx{Session: sess, Sink: c.For("a.joblib"), Limits: lim, Format: artifact.FormatJoblib}
	src := source.Mem("a.joblib", data)
	defer src.Close()
	if err := (joblibParser{}).Parse(ctx, src); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c.Findings()
}

func TestJoblibWrapperPayloadMatches(t *testing.T) {
	// shape (2, 3) f8 = 48 bytes; padding byte 0 then exactly 48 bytes.
	tail := append([]byte{0x00}, make([]byte, 48)...)
	fs := parseJoblib(t, joblibWrapperStream("<f8", []byte{0x4b, 2, 0x4b, 3}, tail))
	want(t, fs, nil, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

func TestJoblibWrapperPaddingMatches(t *testing.T) {
	tail := append([]byte{0x03, 0xff, 0xff, 0xff}, make([]byte, 48)...)
	fs := parseJoblib(t, joblibWrapperStream("<f8", []byte{0x4b, 2, 0x4b, 3}, tail))
	want(t, fs, nil, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

func TestJoblibWrapperMismatch(t *testing.T) {
	// Declares 48 bytes but carries 47.
	tail := append([]byte{0x00}, make([]byte, 47)...)
	fs := parseJoblib(t, joblibWrapperStream("<f8", []byte{0x4b, 2, 0x4b, 3}, tail))
	want(t, fs, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"}, nil)
}

func TestJoblibFrameBroken(t *testing.T) {
	// Padding byte claims 5 bytes of 0xff but the next bytes are not 0xff.
	tail := []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00}
	fs := parseJoblib(t, joblibWrapperStream("<f8", []byte{0x4b, 2, 0x4b, 3}, tail))
	want(t, fs, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"}, nil)
}

func TestJoblibObjectArrayNestedPickle(t *testing.T) {
	gadget := []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85,
		0x52,
		0x2e,
	}
	tail := append([]byte{0x00}, gadget...)
	fs := parseJoblib(t, joblibWrapperStream("|O", []byte{0x4b, 2}, tail))
	want(t, fs, []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"}, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

func TestJoblibSniff(t *testing.T) {
	stream := joblibWrapperStream("<f8", []byte{0x4b, 1}, []byte{0x00})
	src := source.Mem("a.joblib", stream)
	defer src.Close()
	if f, ok := sniffJoblib(src, limits.Default()); !ok || f != artifact.FormatJoblib {
		t.Fatalf("sniffJoblib = %v,%v; want joblib,true", f, ok)
	}
	plain := source.Mem("b.bin", []byte("just some ordinary bytes here"))
	defer plain.Close()
	if _, ok := sniffJoblib(plain, limits.Default()); ok {
		t.Fatal("sniffJoblib claimed a non-joblib stream")
	}
}

// joblibInlineStream builds the layout joblib 1.6 writes: a protocol-5 pickle
// whose only object is a NumpyArrayWrapper created by NEWOBJ + BUILD, with the
// array payload written immediately after the wrapper and before STOP. The byte
// sequence reproduces `joblib.dump(np.zeros(4))` (joblib 1.6, numpy 2.3) with
// dtype, shape and body parameterised; the BINGET(6) memo slot follows from the
// fixed order of the MEMOIZE opcodes.
func joblibInlineStream(dtype string, dims []byte, body []byte) []byte {
	var b []byte
	str := func(s string) {
		b = append(b, 0x8c, byte(len(s)))
		b = append(b, s...)
	}
	b = append(b, 0x80, 0x05) // PROTO 5
	b = append(b, 0x95)       // FRAME
	frameLenAt := len(b)
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	str("joblib.numpy_pickle")
	b = append(b, 0x94)
	str("NumpyArrayWrapper")
	b = append(b, 0x94, 0x93, 0x94, 0x29, 0x81, 0x94, 0x7d, 0x94, 0x28)
	str("subclass")
	b = append(b, 0x94)
	str("numpy")
	b = append(b, 0x94)
	str("ndarray")
	b = append(b, 0x94, 0x93, 0x94)
	str("shape")
	b = append(b, 0x94)
	b = append(b, dims...)
	b = append(b, 0x85, 0x94) // TUPLE1, MEMOIZE
	str("order")
	b = append(b, 0x94)
	str("C")
	b = append(b, 0x94)
	str("dtype")
	b = append(b, 0x94, 0x68, 0x06) // BINGET 6 = "numpy"
	str("dtype")
	b = append(b, 0x94, 0x93, 0x94)
	str(dtype)
	b = append(b, 0x94, 0x89, 0x88, 0x87, 0x94, 0x52, 0x94) // (dtype, False, True), REDUCE
	b = append(b, 0x28, 0x4b, 0x03)
	str("<")
	b = append(b, 0x94, 0x4e, 0x4e, 0x4e)
	b = append(b, 0x4a, 0xff, 0xff, 0xff, 0xff, 0x4a, 0xff, 0xff, 0xff, 0xff, 0x4b, 0x00)
	b = append(b, 0x74, 0x94, 0x62) // TUPLE, MEMOIZE, BUILD (numpy.dtype)
	str("allow_mmap")
	b = append(b, 0x94, 0x88)
	str("numpy_array_alignment_bytes")
	b = append(b, 0x94, 0x4b, 0x10)
	b = append(b, 0x75, 0x62) // SETITEMS, BUILD (wrapper)
	payloadStart := len(b)
	// joblib writes the padding frame only for numeric arrays; an object-dtype
	// payload is the nested pickle dumped straight after the wrapper.
	if !strings.Contains(dtype, "O") {
		pad := 16 - (payloadStart+1)%16
		if pad == 0 {
			pad = 16
		}
		b = append(b, byte(pad))
		for i := 0; i < pad; i++ {
			b = append(b, 0xff)
		}
	}
	b = append(b, body...)
	b = append(b, 0x2e) // STOP
	flen := payloadStart - 11
	for i := 0; i < 8; i++ {
		b[frameLenAt+i] = byte(flen >> (8 * i))
	}
	return b
}

// gadget4 is a protocol-4 pickle whose only object is os.system("id"), used as
// array bytes to prove the payload is actually scanned.
func gadget4() []byte {
	return []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85,
		0x52,
		0x2e,
	}
}

func joblibEvidence(fs []report.Finding, substr string) bool {
	for _, f := range fs {
		if strings.Contains(f.Evidence, substr) {
			return true
		}
	}
	return false
}

// TestJoblibInlinePayloadNotReadAsOpcodes is the regression for the layout
// defect: joblib writes the array bytes before STOP, so an unwarned walk read
// them as opcodes and reported unknown-opcode/INCOMPLETE noise.
func TestJoblibInlinePayloadNotReadAsOpcodes(t *testing.T) {
	body := make([]byte, 32) // np.zeros(4): 4 x f8
	st := joblibInlineStream("f8", []byte{0x4b, 0x04}, body)

	ws := walkWrappers(st)
	if len(ws) != 1 || !ws[0].inline || ws[0].payloadEnd != int64(len(st)-1) {
		t.Fatalf("walkers = %+v (len %d)", ws, len(st))
	}

	fs := parseJoblib(t, st)
	if joblibEvidence(fs, "is not an opcode") {
		t.Errorf("payload bytes were read as opcodes: %v", fs)
	}
	want(t, fs, nil, []string{"SC4N-PICKLE-INCOMPLETE", "SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

// TestJoblibInlinePayloadDispatched proves the numeric payload is handed to the
// engine rather than ignored: a pickle gadget in the array bytes is reported.
func TestJoblibInlinePayloadDispatched(t *testing.T) {
	body := make([]byte, 32) // 4 x f8
	copy(body, gadget4())
	st := joblibInlineStream("f8", []byte{0x4b, 0x04}, body)
	fs := parseJoblib(t, st)
	want(t, fs, []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"}, []string{"SC4N-PICKLE-INCOMPLETE"})
}

// TestJoblibObjectInlinePayloadDispatched covers the object-dtype branch, whose
// payload is a nested pickle located at the wrapper's own position.
func TestJoblibObjectInlinePayloadDispatched(t *testing.T) {
	st := joblibInlineStream("O8", []byte{0x4b, 0x01}, gadget4())
	ws := walkWrappers(st)
	if len(ws) != 1 || !ws[0].object || !ws[0].inline {
		t.Fatalf("walkers = %+v", ws)
	}
	fs := parseJoblib(t, st)
	want(t, fs, []string{"SC4N-PICKLE-GLOBAL-CRITICAL"}, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

// TestJoblibInlineFramingMismatch covers a payload that belongs inline but does
// not carry the [padding][0xff x padding][data] framing its declared size
// describes.
func TestJoblibInlineFramingMismatch(t *testing.T) {
	st := joblibInlineStream("f8", []byte{0x4b, 0x04}, make([]byte, 32))
	ws := walkWrappers(st)
	if len(ws) != 1 || !ws[0].inline {
		t.Fatalf("walkers = %+v", ws)
	}
	st[ws[0].payloadStart+1] = 0x00 // break the 0xff padding run
	fs := parseJoblib(t, st)
	want(t, fs, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"}, nil)
}

// TestJoblibUnsizeableDtypeNoFalseMismatch covers a wrapper whose element size
// is not a single number (a structured dtype writes dtype.descr as a list, which
// this build cannot express; a zero-length void has the same property). The
// payload cannot be bounded, so no framing violation is claimed.
func TestJoblibUnsizeableDtypeNoFalseMismatch(t *testing.T) {
	st := joblibInlineStream("V0", []byte{0x4b, 0x01}, make([]byte, 8))
	fs := parseJoblib(t, st)
	want(t, fs, nil, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

// joblibMemoStream builds a REDUCE-layout wrapper whose dtype is written once
// and read back through the given memo opcodes, so a wrong argument width
// desynchronises the walk and the wrapper is not decoded.
func joblibMemoStream(putOp, getOp byte) []byte {
	idx := []byte{0x00}
	if putOp == 0x72 || getOp == 0x6a {
		idx = []byte{0, 0, 0, 0}
	}
	out := []byte{0x80, 0x02} // PROTO 2
	out = append(out, 0x8c, 0x03)
	out = append(out, "<f8"...)
	out = append(out, putOp)
	out = append(out, idx...)
	out = append(out, 0x63)
	out = append(out, []byte("joblib.numpy_pickle\nNumpyArrayWrapper\n")...)
	out = append(out, 0x28) // MARK (args)
	out = append(out, getOp)
	out = append(out, idx...)
	out = append(out, 0x28, 0x4b, 0x02, 0x74) // shape (2,)
	out = append(out, 0x8c, 0x01, 'C', 0x89, 0x4e, 0x74)
	out = append(out, 0x52)       // REDUCE
	out = append(out, 0x4e, 0x62) // NONE, BUILD
	out = append(out, 0x2e)       // STOP
	return append(out, append([]byte{0x00}, make([]byte, 16)...)...)
}

// TestJoblibMemoArgumentWidths is the regression for the one-byte BINPUT/BINGET
// index: treating them as four bytes desynchronised every protocol <= 3 stream.
func TestJoblibMemoArgumentWidths(t *testing.T) {
	cases := map[string][]byte{
		"BINPUT/BINGET (1 byte)":      joblibMemoStream(0x71, 0x68),
		"LONG_BINPUT/LONG_BINGET (4)": joblibMemoStream(0x72, 0x6a),
	}
	for name, st := range cases {
		ws := walkWrappers(st)
		if len(ws) != 1 {
			t.Fatalf("%s: wrappers = %+v", name, ws)
		}
		w := ws[0]
		if w.dtype != "<f8" || len(w.shape) != 1 || w.shape[0] != 2 {
			t.Fatalf("%s: decoded %q %v, want <f8 [2]", name, w.dtype, w.shape)
		}
	}
}

// joblibP2Stream builds a protocol-2 joblib wrapper whose own opcodes are all in
// the weights-only set, so nothing the stream contains forces the unsafe loader.
// inline places the array payload at the wrapper's own position — joblib's real
// layout — with the [padding][0xff x padding][data] frame; otherwise the payload
// follows the stream's STOP, which is the committed benign fixture's layout.
func joblibP2Stream(dtype string, shape, body []byte, inline bool) []byte {
	binUni := func(s string) []byte {
		return append([]byte{0x58, byte(len(s)), 0, 0, 0}, s...)
	}
	out := []byte{0x80, 0x02} // PROTO 2
	out = append(out, 0x63)   // GLOBAL
	out = append(out, []byte("joblib.numpy_pickle\nNumpyArrayWrapper\n")...)
	out = append(out, 0x28) // MARK (args)
	out = append(out, binUni(dtype)...)
	out = append(out, 0x28)     // MARK (shape)
	out = append(out, shape...) // dims
	out = append(out, 0x74)     // TUPLE (shape)
	out = append(out, binUni("C")...)
	out = append(out, 0x89) // NEWFALSE
	out = append(out, 0x4e) // NONE (subclass)
	out = append(out, 0x74) // TUPLE (args)
	out = append(out, 0x52) // REDUCE
	out = append(out, 0x4e) // NONE (state)
	out = append(out, 0x62) // BUILD
	if !inline {
		out = append(out, 0x2e, 0x00) // STOP, then the payload's zero padding
		return append(out, body...)
	}
	payloadStart := len(out)
	pad := 16 - (payloadStart+1)%16
	if pad == 0 {
		pad = 16
	}
	out = append(out, byte(pad))
	for range pad {
		out = append(out, 0xff)
	}
	out = append(out, body...)
	return append(out, 0x2e) // STOP
}

// TestJoblibInlineMaskStaysWeightsOnly is the regression for the mask writing POP
// (0x30), which is outside the weights-only opcode set. Masking an inline payload
// therefore made the scanner's own injection set RequiresUnsafeLoader, so a
// joblib file whose opcodes are all accepted was reported as
// SC4N-PICKLE-REQUIRES-UNSAFE-LOADER with evidence claiming torch.load
// (weights_only=True) cannot read it — on joblib's normal layout, and naming a
// torch loader for a file torch never reads.
func TestJoblibInlineMaskStaysWeightsOnly(t *testing.T) {
	body := make([]byte, 48) // 2x3 f8
	shape := []byte{0x4b, 2, 0x4b, 3}

	after := joblibP2Stream("<f8", shape, body, false)
	fs := parseJoblib(t, after)
	want(t, fs, nil, []string{"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER", "SC4N-JOBLIB-WRAPPER-MISMATCH"})

	inline := joblibP2Stream("<f8", shape, body, true)
	fs = parseJoblib(t, inline)
	want(t, fs, nil, []string{"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER", "SC4N-JOBLIB-WRAPPER-MISMATCH"})

	// A payload large enough that a mask growing the operand stack would trip
	// MaxStackDepth: 1 MiB is 131072 f8 elements.
	big := joblibP2Stream("<f8", []byte{0x4a, 0x00, 0x00, 0x02, 0x00}, make([]byte, 1<<20), true)
	fs = parseJoblib(t, big)
	want(t, fs, nil, []string{"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER", "SC4N-PICKLE-STACK", "SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

// TestJoblibInlineMaskDoesNotHideRealUnsafeOpcodes guards the other half: a stream
// that really does use an opcode outside the weights-only set must still say so
// after masking, so the mask cannot be used to silence the finding.
func TestJoblibInlineMaskDoesNotHideRealUnsafeOpcodes(t *testing.T) {
	body := make([]byte, 48)
	st := joblibP2Stream("<f8", []byte{0x4b, 2, 0x4b, 3}, body, true)
	// A POP_MARK (0x31) the stream itself contains, outside the accepted set.
	st = append(st[:len(st)-1], 0x31, 0x2e)
	fs := parseJoblib(t, st)
	want(t, fs, []string{"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER"}, nil)
}
