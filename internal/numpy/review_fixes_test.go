package numpy

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestNPYStringEscapesDecodeObjectDtype(t *testing.T) {
	gadget := gadget4()
	for _, descr := range []string{
		`|\x4f`,
		`|\u004f`,
		`|\U0000004f`,
		`|\117`,
	} {
		hdr := "{'descr': '" + descr + "', 'fortran_order': False, 'shape': (1,)}"
		fs := parse(t, npyV1(hdr, gadget))
		want(t, fs, []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL"}, nil)
	}
}

func TestNPYDescrTrailingCommaTupleDtypeAndFallbackStruct(t *testing.T) {
	gadget := gadget4()
	for _, descr := range []string{
		"[('a', '|O',)]",
		"[('a', ('|O', (1,)))]",
		"[('a', ('|O', (1,),),)]",
		"[('a', ([('x', '|O')], (2,)))]",
	} {
		hdr := "{'descr': " + descr + ", 'fortran_order': False, 'shape': (1,)}"
		fs := parse(t, npyV1(hdr, gadget))
		want(t, fs, []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL"}, nil)
	}

	// When descrFieldsAt fails and p.list() fallback runs, parseNPY must emit
	// SC4N-NUMPY-STRUCT instead of silently returning nil.
	unmodeled := npyV1("{'descr': [[1, 2]], 'fortran_order': False, 'shape': (1,)}", make([]byte, 8))
	fs := parse(t, unmodeled)
	want(t, fs, []string{"SC4N-NUMPY-STRUCT"}, nil)
}

func TestNPYPython2LongSuffixInShape(t *testing.T) {
	hdr := "{'descr': '<f8', 'fortran_order': False, 'shape': (2L, 3L)}"
	fs := parse(t, npyV1(hdr, make([]byte, 48)))
	want(t, fs, nil, []string{"SC4N-NUMPY-STRUCT", "SC4N-NUMPY-TRAILING"})
}

func TestJoblibInlineDictAndLargePayloadNoStackCorruption(t *testing.T) {
	// A dict containing an inline joblib array: previously maskPayload wrote
	// MARK TUPLE pairs (+1 stack item per 2 bytes) causing SC4N-PICKLE-SETITEM-TARGET
	// on benign dicts and SC4N-PICKLE-STACK on >2 MiB arrays.
	var b []byte
	str := func(s string) {
		b = append(b, 0x8c, byte(len(s)))
		b = append(b, s...)
	}
	b = append(b, 0x80, 0x04) // PROTO 4
	b = append(b, 0x7d, 0x28) // EMPTY_DICT, MARK
	str("weights")
	b = append(b, 0x63)
	b = append(b, []byte("joblib.numpy_pickle\nNumpyArrayWrapper\n")...)
	b = append(b, 0x28)
	str("<f8")
	// shape = (393216,) -> 3 MiB payload (exceeds the old 2 MiB stack-abort limit).
	b = append(b, 0x28, 0x4a, 0x00, 0x00, 0x06, 0x00, 0x74)
	str("C")
	b = append(b, 0x89, 0x4e, 0x74, 0x52, 0x4e, 0x62) // TUPLE, REDUCE, NONE, BUILD
	pad := 16 - (len(b)+1)%16
	b = append(b, byte(pad))
	b = append(b, bytes.Repeat([]byte{0xff}, pad)...)
	b = append(b, make([]byte, 3<<20)...)
	str("tag")
	str("ok")
	b = append(b, 0x75, 0x2e) // SETITEMS, STOP

	fs := parseJoblib(t, b)
	want(t, fs, nil, []string{"SC4N-PICKLE-SETITEM-TARGET", "SC4N-PICKLE-STACK", "SC4N-PICKLE-INCOMPLETE", "SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

func TestJoblibWalkerExtendedOpcodesAndProtocolZeroNestedPickle(t *testing.T) {
	// Verify jwalk handles protocol-0/4/5 opcodes before a wrapper and locates a
	// protocol-0 nested pickle inside an object-dtype inline joblib array.
	var b []byte
	// Exercise EMPTY_SET, MARK, INT, LONG, FLOAT, STRING, UNICODE, ADDITEMS,
	// FROZENSET, PERSID, BINPERSID, EXT1, BYTEARRAY8, NEXT_BUFFER, READONLY_BUFFER,
	// then POP them before the wrapper.
	b = append(b, 0x8f, 0x28)                              // EMPTY_SET, MARK
	b = append(b, 'I', '4', '2', '\n')                     // INT 42
	b = append(b, 'L', '1', '2', '3', 'L', '\n')           // LONG 123L
	b = append(b, 'F', '1', '.', '5', '\n')                // FLOAT 1.5
	b = append(b, 'S', '\'', 'a', '\'', '\n')              // STRING 'a'
	b = append(b, 'V', 'b', '\n')                          // UNICODE b
	b = append(b, 0x90, 0x30)                              // ADDITEMS, POP
	b = append(b, 0x28, 0x91, 0x30)                        // MARK, FROZENSET, POP
	b = append(b, 'P', 'x', '\n', 0x30)                    // PERSID x, POP
	b = append(b, 0x4e, 0x51, 0x30)                        // NONE, BINPERSID, POP
	b = append(b, 0x82, 0x01, 0x30)                        // EXT1 1, POP
	b = append(b, 0x96, 1, 0, 0, 0, 0, 0, 0, 0, 'z', 0x30) // BYTEARRAY8, POP
	b = append(b, 0x97, 0x98, 0x30)                        // NEXT_BUFFER, READONLY_BUFFER, POP

	// Object-dtype NumpyArrayWrapper followed inline by a protocol-0 gadget pickle.
	b = append(b, 0x63)
	b = append(b, []byte("joblib.numpy_pickle\nNumpyArrayWrapper\n")...)
	b = append(b, 0x28)
	b = append(b, []byte("S'|O'\n")...)
	b = append(b, 0x28, 'I', '1', '\n', 0x74)
	b = append(b, []byte("S'C'\n")...)
	b = append(b, 0x89, 0x4e, 0x74, 0x52, 0x4e, 0x62) // TUPLE, REDUCE, NONE, BUILD
	b = append(b, []byte("cos\nsystem\n(S'id'\ntR.")...)
	b = append(b, 0x2e) // outer STOP

	ws := walkWrappers(b)
	if len(ws) != 1 || !ws[0].object || !ws[0].inline {
		t.Fatalf("wrappers = %+v, want 1 inline object wrapper", ws)
	}
	fs := parseJoblib(t, b)
	want(t, fs, []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"}, []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"})
}

func TestNPZSymlinkMemberWithPayloadIsScanned(t *testing.T) {
	obj := npyV1("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", gadget4())
	// Build a zip whose obj.npy entry has symlink mode bits (0o120777) AND payload bytes.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{Name: "obj.npy", Method: zip.Store}
	fh.ExternalAttrs = 0o120777 << 16
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(obj); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	fs := parseNPZ(t, buf.Bytes())
	want(t, fs, []string{"SC4N-ARCHIVE-LINK", "SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL"}, nil)
}

func TestNPZSpillErrorNonTooLargeDoesNotExhaustSpillBudget(t *testing.T) {
	// Member 1: stored > MaxStringBlob with a bad CRC (fails Spill with errCRC,
	// NOT SpillTooLargeError). Member 2: valid > MaxStringBlob object-array .npy.
	// Charging cap+1 on member 1's CRC error would exhaust MaxSpillBytes and
	// prevent member 2 from spilling cleanly.
	badBody := make([]byte, 2048)
	goodObj := npyV1("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", append(gadget4(), make([]byte, 2048)...))

	// Build raw zip with bad CRC on member 1 and valid CRC on member 2.
	var buf bytes.Buffer
	writeEntry := func(name string, body []byte, crc uint32) (off uint32) {
		off = uint32(buf.Len())
		var lh [30]byte
		binary.LittleEndian.PutUint32(lh[0:], 0x04034b50)
		binary.LittleEndian.PutUint16(lh[4:], 20)
		binary.LittleEndian.PutUint32(lh[14:], crc)
		binary.LittleEndian.PutUint32(lh[18:], uint32(len(body)))
		binary.LittleEndian.PutUint32(lh[22:], uint32(len(body)))
		binary.LittleEndian.PutUint16(lh[26:], uint16(len(name)))
		buf.Write(lh[:])
		buf.WriteString(name)
		buf.Write(body)
		return off
	}
	off1 := writeEntry("bad.npy", badBody, 0xdeadbeef)
	crc2 := crc32.ChecksumIEEE(goodObj)
	off2 := writeEntry("good.npy", goodObj, crc2)
	cdOff := uint32(buf.Len())
	writeCD := func(name string, body []byte, crc, off uint32) {
		var cd [46]byte
		binary.LittleEndian.PutUint32(cd[0:], 0x02014b50)
		binary.LittleEndian.PutUint16(cd[4:], 20)
		binary.LittleEndian.PutUint16(cd[6:], 20)
		binary.LittleEndian.PutUint32(cd[16:], crc)
		binary.LittleEndian.PutUint32(cd[20:], uint32(len(body)))
		binary.LittleEndian.PutUint32(cd[24:], uint32(len(body)))
		binary.LittleEndian.PutUint16(cd[28:], uint16(len(name)))
		binary.LittleEndian.PutUint32(cd[42:], off)
		buf.Write(cd[:])
		buf.WriteString(name)
	}
	writeCD("bad.npy", badBody, 0xdeadbeef, off1)
	writeCD("good.npy", goodObj, crc2, off2)
	cdSize := uint32(buf.Len()) - cdOff
	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:], 2)
	binary.LittleEndian.PutUint16(eocd[10:], 2)
	binary.LittleEndian.PutUint32(eocd[12:], cdSize)
	binary.LittleEndian.PutUint32(eocd[16:], cdOff)
	buf.Write(eocd[:])

	c := report.NewCollector(0)
	lim := limits.Default()
	lim.MaxStringBlob = 512
	lim.MaxSpillBytes = 4096
	sess := artifact.NewSession(c, "", lim)
	ctx := &artifact.Ctx{Session: sess, Sink: c.For("a.npz"), Limits: lim, Format: artifact.FormatNPZ}
	src := source.Mem("a.npz", buf.Bytes())
	defer src.Close()
	if err := (npzParser{}).Parse(ctx, src); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want(t, c.Findings(), []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL"}, []string{"SC4N-LIMIT-SPILL"})
}
