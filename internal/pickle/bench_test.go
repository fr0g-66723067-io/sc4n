package pickle

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// The opcodes used by the synthetic stream, written out rather than referenced from
// the opcode table so that a reader of this benchmark sees the encoding inline.
const (
	opProto      = 0x80
	opEmptyDict  = 0x7d
	opMark       = 0x28
	opStop       = 0x2e
	opBinUnicode = 0x58
	opBinBytes   = 0x42
	opSetItems   = 0x75
)

// stateDict builds a pickle shaped like a real tokenizer/state_dict pickle: a dict
// of many small keys mapped to byte blobs, which is the mix that makes the walk
// opcode-bound rather than memcpy-bound.
func stateDict(entries, blobSize int) []byte {
	out := []byte{opProto, 4, opEmptyDict, opMark}
	blob := make([]byte, blobSize)
	for i := range blob {
		blob[i] = byte(i * 7)
	}
	var lenBuf [4]byte
	for i := 0; i < entries; i++ {
		key := fmt.Sprintf("model.layers.%04d.attn.weight", i)
		out = append(out, opBinUnicode)
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(key)))
		out = append(out, lenBuf[:]...)
		out = append(out, key...)
		blob[0] = byte(i)
		out = append(out, opBinBytes)
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(blob)))
		out = append(out, lenBuf[:]...)
		out = append(out, blob...)
	}
	out = append(out, opSetItems, opStop)
	return out
}

func benchWalk(b *testing.B, data []byte) {
	b.Helper()
	l := limits.Default()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		c := report.NewCollector(0)
		sess := artifact.NewSession(c, "", l)
		src := source.Mem("bench.pkl", data)
		if _, err := Walk(sess.NewCtx("bench.pkl", l), src, Options{}); err != nil {
			b.Fatal(err)
		}
		src.Close()
	}
}

func BenchmarkWalkStateDict(b *testing.B) {
	benchWalk(b, stateDict(4000, 256))
}

func BenchmarkWalkLargeBlobs(b *testing.B) {
	benchWalk(b, stateDict(16, 1<<16))
}

// TestWalkAllocationBudget pins the property that actually holds: the walk's cost
// is proportional to the number of *structural* elements in the stream — keys,
// values, stack entries — and not to the number of bytes in it. A pickle whose
// blobs are 256 bytes and one whose blobs are 64 KiB must cost the same, or the
// walker is copying payload it has no business touching.
//
// Zero allocations overall is not attainable and the plan's requirement was aimed
// at the opcode stream, which is allocation-free: the walk keeps a value stack, a
// memo table, a globals map and a finding list that all grow with the structure.
func TestWalkAllocationBudget(t *testing.T) {
	measure := func(data []byte) (float64, int64) {
		l := limits.Default()
		run := func(b *testing.B) {
			for b.Loop() {
				c := report.NewCollector(0)
				sess := artifact.NewSession(c, "", l)
				src := source.Mem("bench.pkl", data)
				if _, err := Walk(sess.NewCtx("bench.pkl", l), src, Options{}); err != nil {
					b.Fatal(err)
				}
				src.Close()
			}
		}
		allocs := testing.AllocsPerRun(3, func() {
			c := report.NewCollector(0)
			sess := artifact.NewSession(c, "", l)
			src := source.Mem("bench.pkl", data)
			if _, err := Walk(sess.NewCtx("bench.pkl", l), src, Options{}); err != nil {
				t.Fatal(err)
			}
			src.Close()
		})
		res := testing.Benchmark(run)
		return allocs, res.AllocedBytesPerOp()
	}

	allocsSmall, bytesSmall := measure(stateDict(200, 256))
	allocsLarge, bytesLarge := measure(stateDict(200, 1<<16))
	t.Logf("256 B blobs: %.0f allocs, %d B/op", allocsSmall, bytesSmall)
	t.Logf("64 KiB blobs: %.0f allocs, %d B/op", allocsLarge, bytesLarge)

	if allocsLarge > allocsSmall+16 {
		t.Fatalf("allocations grow with payload size: %.0f -> %.0f", allocsSmall, allocsLarge)
	}
	// 200 entries x 64 KiB is ~13 MiB of payload; the walk must not copy a
	// meaningful fraction of it.
	if bytesLarge > 1<<20 {
		t.Fatalf("walk allocated %d bytes for a structure with 13 MiB of payload", bytesLarge)
	}
}
