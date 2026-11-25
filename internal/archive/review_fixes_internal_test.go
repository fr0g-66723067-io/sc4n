package archive

import (
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestRecoverLocalMembersZip64BothSentinelsReadsCompressedSecond(t *testing.T) {
	// When BOTH compressed and uncompressed sizes are 0xFFFFFFFF in the local
	// header, APPNOTE 4.5.3 places uncompressed size first (bytes 0..7) and
	// compressed size second (bytes 8..15). Passing wantUncomp=false used to
	// mistake uncompressed size (1000) for compressed size (5).
	payload := []byte("hello")
	var ex [20]byte
	binary.LittleEndian.PutUint16(ex[0:], 0x0001)
	binary.LittleEndian.PutUint16(ex[2:], 16)
	binary.LittleEndian.PutUint64(ex[4:], 1000)                  // uncompressed
	binary.LittleEndian.PutUint64(ex[12:], uint64(len(payload))) // compressed

	data := hdrWithExtra("a.bin", 0, 0xFFFFFFFF, 0xFFFFFFFF, ex[:])
	data = append(data, payload...)
	data = append(data, hdrWithExtra("b.bin", 0, 3, 3, nil)...)
	data = append(data, "xyz"...)

	ms, _, _ := recoverLocalMembers(source.Mem("z64.zip", data), limits.Default())
	if len(ms) != 2 {
		t.Fatalf("recovered %d members, want 2: %+v", len(ms), ms)
	}
	if ms[0].sizeInvalid || ms[0].dataEnd-ms[0].dataOff != int64(len(payload)) {
		t.Fatalf("first member = %+v, want valid span %d", ms[0], len(payload))
	}
	if ms[1].name != "b.bin" {
		t.Fatalf("second member = %q, want b.bin", ms[1].name)
	}
}
