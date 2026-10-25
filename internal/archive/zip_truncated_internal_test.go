package archive

import (
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

	ms, capped := recoverLocalMembers(source.Mem("t.zip", data), limits.Default())
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

	ms, _ := recoverLocalMembers(source.Mem("t.pt", data), limits.Default())
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
	if ms, capped := recoverLocalMembers(source.Mem("t.bin", data), limits.Default()); ms != nil || capped {
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
	ms, capped := recoverLocalMembers(source.Mem("t.zip", data), l)
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
