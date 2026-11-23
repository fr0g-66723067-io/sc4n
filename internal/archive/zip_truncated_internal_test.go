package archive

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// localHeader builds one zip local file header (with no extra field).
func localHeader(name string, method, flags uint16, comp, uncomp uint32) []byte {
	var b [30]byte
	binary.LittleEndian.PutUint32(b[0:], sigLocal)
	binary.LittleEndian.PutUint16(b[4:], 20)
	binary.LittleEndian.PutUint16(b[6:], flags)
	binary.LittleEndian.PutUint16(b[8:], method)
	binary.LittleEndian.PutUint32(b[18:], comp)
	binary.LittleEndian.PutUint32(b[22:], uncomp)
	binary.LittleEndian.PutUint16(b[26:], uint16(len(name)))
	return append(b[:], name...)
}

func TestRecoverLocalMembersDeclaredSizeIsTheSpan(t *testing.T) {
	first := localHeader("a.txt", 0, 0, 5, 5)
	second := localHeader("dir/b.pkl", 0, 0, 3, 3)
	data := append([]byte{}, first...)
	data = append(data, "hello"...)
	data = append(data, second...)
	data = append(data, "xyz"...)

	ms, capped, _ := recoverLocalMembers(source.Mem("t.zip", data), limits.Default())
	if capped {
		t.Fatal("cap reported with three members")
	}
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2", len(ms))
	}
	if ms[0].name != "a.txt" || ms[0].dataOff != int64(len(first)) || ms[0].dataEnd != int64(len(first)+5) {
		t.Fatalf("first member = %+v", ms[0])
	}
	wantOff := int64(len(first) + 5 + len(second))
	if ms[1].name != "dir/b.pkl" || ms[1].dataOff != wantOff || ms[1].dataEnd != wantOff+3 {
		t.Fatalf("second member = %+v", ms[1])
	}
}

func TestRecoverLocalMembersDataDescriptorBoundedByNextHeader(t *testing.T) {
	// Torch writes flags bit 3 with a zero compressed size: the size lives in a
	// data descriptor after the payload, which a slice never contains.
	first := localHeader("archive/data.pkl", 0, 0x8, 0, 0)
	second := localHeader("archive/byteorder", 0, 0, 6, 6)
	payload := []byte("\x80\x04gadget")
	data := append([]byte{}, first...)
	data = append(data, payload...)
	data = append(data, second...)
	data = append(data, "little"...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2", len(ms))
	}
	if want := int64(len(first) + len(payload)); ms[0].dataEnd != want {
		t.Fatalf("first member end = %d, want %d", ms[0].dataEnd, want)
	}
	if ms[0].dataEnd-ms[0].dataOff != int64(len(payload)) {
		t.Fatalf("first member span = %d, want %d", ms[0].dataEnd-ms[0].dataOff, len(payload))
	}
	if ms[1].name != "archive/byteorder" {
		t.Fatalf("second member name = %q", ms[1].name)
	}
}

func TestRecoverLocalMembersStopsAtNonHeader(t *testing.T) {
	data := []byte("this is not a local header at all, only text")
	if ms, capped, _ := recoverLocalMembers(source.Mem("t.bin", data), limits.Default()); ms != nil || capped {
		t.Fatalf("recovered %v (capped %v) from a non-zip prefix", ms, capped)
	}
}

func TestRecoverLocalMembersCap(t *testing.T) {
	var data []byte
	for range 3 {
		data = append(data, localHeader("m", 0, 0, 1, 1)...)
		data = append(data, 'x')
	}
	l := limits.Default()
	l.MaxEntries = 1
	ms, capped, _ := recoverLocalMembers(source.Mem("t.zip", data), l)
	if !capped {
		t.Fatal("cap not reported")
	}
	if len(ms) != 1 {
		t.Fatalf("members = %d, want 1", len(ms))
	}
}

func TestNextZipSigFindsHeaderPastScanWindow(t *testing.T) {
	// A member larger than one search window: the signature search must tile the
	// source rather than give up after the first window.
	pad := make([]byte, sigScanWindow+1024)
	for i := range pad {
		pad[i] = 0
	}
	first := localHeader("big.bin", 0, 0x8, 0, 0)
	second := localHeader("after.bin", 0, 0, 1, 1)
	data := append([]byte{}, first...)
	data = append(data, pad...)
	want := int64(len(data))
	data = append(data, second...)
	data = append(data, 'y')
	got := nextZipSig(source.Mem("t.zip", data), int64(len(first)), int64(len(data)))
	if got != want {
		t.Fatalf("nextZipSig = %d, want %d", got, want)
	}
}

// descr16 is the 16-byte data descriptor torch writes after a member payload:
// signature, CRC-32, compressed size, uncompressed size.
func descr16(crc uint32, size uint32) []byte {
	var b [16]byte
	binary.LittleEndian.PutUint32(b[0:], sigDataDescr)
	binary.LittleEndian.PutUint32(b[4:], crc)
	binary.LittleEndian.PutUint32(b[8:], size)
	binary.LittleEndian.PutUint32(b[12:], size)
	return b[:]
}

func TestRecoverLocalMembersTrimsDataDescriptor16(t *testing.T) {
	first := localHeader("archive/data.pkl", 0, 0x8, 0, 0)
	second := localHeader("archive/byteorder", 0, 0x8, 0, 0)
	payload := []byte("\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00}")
	data := append([]byte{}, first...)
	data = append(data, payload...)
	data = append(data, descr16(0xdeadbeef, uint32(len(payload)))...)
	data = append(data, second...)
	data = append(data, "little"...)
	data = append(data, descr16(0x12345678, 6)...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2", len(ms))
	}
	if got := ms[0].dataEnd - ms[0].dataOff; got != int64(len(payload)) {
		t.Fatalf("first span = %d, want %d (the descriptor was trimmed)", got, len(payload))
	}
	if got := ms[1].dataEnd - ms[1].dataOff; got != 6 {
		t.Fatalf("second span = %d, want 6", got)
	}
	if ms[1].name != "archive/byteorder" {
		t.Fatalf("second member name = %q (the walk did not advance past the descriptor)", ms[1].name)
	}
	// The payload bytes themselves must be untouched by the trim.
	body, err := source.Mem("t.pt", data).Bytes(ms[0].dataOff, ms[0].dataEnd-ms[0].dataOff)
	if err != nil || string(body) != string(payload) {
		t.Fatalf("first member body = %q, err %v", body, err)
	}
}

func TestRecoverLocalMembersTrimsDataDescriptor12(t *testing.T) {
	// The signature-less form: CRC-32, compressed size, uncompressed size.
	first := localHeader("data.pkl", 0, 0x8, 0, 0)
	second := localHeader("byteorder", 0, 0x8, 0, 0)
	payload := []byte("\x80\x04}\x94.")
	var d12 [12]byte
	binary.LittleEndian.PutUint32(d12[0:], 0x0badf00d)
	binary.LittleEndian.PutUint32(d12[4:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(d12[8:], uint32(len(payload)))
	data := append([]byte{}, first...)
	data = append(data, payload...)
	data = append(data, d12[:]...)
	data = append(data, second...)
	data = append(data, "l"...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2", len(ms))
	}
	if got := ms[0].dataEnd - ms[0].dataOff; got != int64(len(payload)) {
		t.Fatalf("first span = %d, want %d", got, len(payload))
	}
}

func TestRecoverLocalMembersTrimsDataDescriptor64(t *testing.T) {
	// Zip64 descriptor: signature, CRC-32, 8-byte compressed and uncompressed
	// sizes, so 24 bytes.
	first := localHeader("data.pkl", 0, 0x8, 0, 0)
	second := localHeader("byteorder", 0, 0x8, 0, 0)
	payload := []byte("\x80\x04N.")
	var d24 [24]byte
	binary.LittleEndian.PutUint32(d24[0:], sigDataDescr)
	binary.LittleEndian.PutUint32(d24[4:], 0xcafebabe)
	binary.LittleEndian.PutUint64(d24[8:], uint64(len(payload)))
	binary.LittleEndian.PutUint64(d24[16:], uint64(len(payload)))
	data := append([]byte{}, first...)
	data = append(data, payload...)
	data = append(data, d24[:]...)
	data = append(data, second...)
	data = append(data, "l"...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2", len(ms))
	}
	if got := ms[0].dataEnd - ms[0].dataOff; got != int64(len(payload)) {
		t.Fatalf("first span = %d, want %d", got, len(payload))
	}
}

func TestRecoverLocalMembersKeepsBytesThatOnlyLookLikeADescriptor(t *testing.T) {
	// Sixteen payload bytes that begin with the descriptor signature but whose
	// size fields do not describe the span: a member's data must not be trimmed
	// on a coincidence.
	first := localHeader("data.bin", 0, 0x8, 0, 0)
	second := localHeader("next.bin", 0, 0x8, 0, 0)
	payload := append([]byte("\x80\x04N."), descr16(0x11111111, 0x9999)...)
	data := append([]byte{}, first...)
	data = append(data, payload...)
	data = append(data, second...)
	data = append(data, "l"...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
	if len(ms) != 2 {
		t.Fatalf("members = %d, want 2", len(ms))
	}
	if got := ms[0].dataEnd - ms[0].dataOff; got != int64(len(payload)) {
		t.Fatalf("first span = %d, want %d (bytes were trimmed on a false match)", got, len(payload))
	}
}

func TestRecoverLocalMembersDescriptorAtEOF(t *testing.T) {
	first := localHeader("data.pkl", 0, 0x8, 0, 0)
	payload := []byte("\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00.")
	data := append([]byte{}, first...)
	data = append(data, payload...)
	data = append(data, descr16(0x0, uint32(len(payload)))...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
	if len(ms) != 1 {
		t.Fatalf("members = %d, want 1", len(ms))
	}
	if got := ms[0].dataEnd - ms[0].dataOff; got != int64(len(payload)) {
		t.Fatalf("span = %d, want %d", got, len(payload))
	}
}

func TestRecoverLocalMembersIgnoredWithoutBit3(t *testing.T) {
	// Without general-purpose bit 3 the sizes are in the header and no descriptor
	// follows, so descriptor-shaped trailing payload bytes stay part of the member.
	payload := append([]byte("hello"), descr16(0x0, 5)...)
	first := localHeader("a.bin", 0, 0, uint32(len(payload)), uint32(len(payload)))
	data := append([]byte{}, first...)
	data = append(data, payload...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.zip", data), limits.Default())
	if len(ms) != 1 {
		t.Fatalf("members = %d, want 1", len(ms))
	}
	if got := ms[0].dataEnd - ms[0].dataOff; got != int64(len(payload)) {
		t.Fatalf("span = %d, want %d", got, len(payload))
	}
}

// TestRecoverLocalMembersWrappedZip64SizeKeepsLaterMembers pins the size check
// that was performed after a uint64→int64 conversion: a compressed size of
// 2^64-1 converted to -1, so `dataOff+int64(c) <= size` held and the framing
// guard accepted a local signature planted one byte before the member's data.
// The walk then skipped the member as zero-length and continued inside its own
// header, and every later member was never scanned.
func TestRecoverLocalMembersWrappedZip64SizeKeepsLaterMembers(t *testing.T) {
	first := localHeader("a.txt", 0, 0, 5, 5)
	data := append([]byte{}, first...)
	data = append(data, "hello"...)

	// Only the compressed size is saturated, so the zip64 extra holds it alone:
	// id 1, length 8, comp = 2^64-1. A trailing extra record ends in 'P', so the
	// planted "PK\x03\x04" starts one byte before the payload.
	extra := []byte{1, 0, 8, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	extra = append(extra, 0x99, 0x99, 1, 0, 'P')
	data = append(data, hdrWithExtra("bad.pkl", 0, 0xFFFFFFFF, 0, extra)...)
	data = append(data, "K\x03\x04"...)

	later := localHeader("later.pkl", 0, 0, 3, 3)
	data = append(data, later...)
	data = append(data, "xyz"...)

	ms, _, _ := recoverLocalMembers(source.Mem("t.zip", data), limits.Default())
	for _, m := range ms {
		if m.name == "later.pkl" {
			return
		}
	}
	t.Fatalf("the member after a wrapped zip64 size was not recovered: %+v", ms)
}

// TestRecoveredZipMembersShareTheDecompressionBudget pins the budget on the
// no-EOCD path: each recovered deflate member was opened with the *configured*
// MaxDecompressedBytes instead of what the scan has left, so a truncated archive
// decompressed a fresh budget per member. Here the scan has 1 KiB left of an
// 8 GiB configuration; the first member must be cut at the 1 KiB and the second
// must not be entered at all.
func TestRecoveredZipMembersShareTheDecompressionBudget(t *testing.T) {
	body := bytes.Repeat([]byte("A"), 1<<16)
	var c1, c2 bytes.Buffer
	for _, w := range []*bytes.Buffer{&c1, &c2} {
		fw, err := flate.NewWriter(w, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(body)
		_ = fw.Close()
	}
	data := append(localHeader("a", 8, 0, uint32(c1.Len()), uint32(len(body))), c1.Bytes()...)
	data = append(data, localHeader("b", 8, 0, uint32(c2.Len()), uint32(len(body)))...)
	data = append(data, c2.Bytes()...)

	l := limits.Default()
	src := source.Mem("t.zip", data)
	ms, _, _ := recoverLocalMembers(src, l)
	if len(ms) != 2 {
		t.Fatalf("recovered %d members, want 2", len(ms))
	}
	ctx, col := testCtx(t, "t.zip", l)
	const left = 1024
	ctx.ChargeDecompressed(l.MaxDecompressedBytes - left)
	if got := ctx.RemainingDecompressed(); got != left {
		t.Fatalf("remaining budget = %d, want %d", got, left)
	}
	scanned, n := scanRecovered(ctx, src, ms)
	if n > left {
		t.Fatalf("read %d bytes against a %d byte remainder (the configured cap was used)", n, left)
	}
	if scanned != 1 {
		t.Fatalf("scanned %d members, want 1 before the budget was spent", scanned)
	}
found := false
	for _, f := range col.Findings() {
		if f.RuleID == "SC4N-LIMIT-DECOMPRESSED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the shared budget was silent; findings=%v", col.Findings())
	}
}
