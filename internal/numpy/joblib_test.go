package numpy

import (
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
