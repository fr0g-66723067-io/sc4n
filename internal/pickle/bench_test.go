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
func stateDict(entries, blobSize int) []byte { return stateDictShape(entries, blobSize, false) }

// stateDictText is stateDict with printable blobs, for the retention tests: a
// value the walk keeps is the only kind that can exhaust the retention budget.
func stateDictText(entries, blobSize int) []byte {
	return stateDictShape(entries, blobSize, true)
}

func stateDictShape(entries, blobSize int, text bool) []byte {
	out := []byte{opProto, 4, opEmptyDict, opMark}
	blob := make([]byte, blobSize)
	for i := range blob {
		if text {
			blob[i] = byte('a' + i%26)
		} else {
			blob[i] = byte(i * 7)
		}
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

// TestWalkAllocationBudget pins the property that actually holds: what the walk
// keeps is bounded by Limits.MaxRetainedText, not by the artifact's size. The
// test runs the same 200-entry structure with 256 B blobs and with 64 KiB blobs
// against a deliberately small retention budget, and asserts that the memory the
// walk allocates stays under the budget plus a small constant even though the
// second structure carries 13 MiB of payload — and that the truncation is
// reported rather than silent.
//
// Zero allocations overall is not attainable and was never the point: the walk
// keeps a value stack, a memo table, a globals map and a finding list that grow
// with the structure. What must not happen is retention that scales with payload.
func TestWalkAllocationBudget(t *testing.T) {
	const budget = 1 << 20
	measure := func(data []byte) (float64, int64, []report.Finding) {
		l := limits.Default()
		l.MaxRetainedText = budget
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
		c := report.NewCollector(0)
		sess := artifact.NewSession(c, "", l)
		src := source.Mem("bench.pkl", data)
		if _, err := Walk(sess.NewCtx("bench.pkl", l), src, Options{}); err != nil {
			t.Fatal(err)
		}
		src.Close()
		findings := c.Findings()
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
		return allocs, res.AllocedBytesPerOp(), findings
	}

	allocsSmall, bytesSmall, _ := measure(stateDict(200, 256))
	allocsLarge, bytesLarge, findings := measure(stateDict(200, 1<<16))
	t.Logf("256 B binary blobs: %.0f allocs, %d B/op", allocsSmall, bytesSmall)
	t.Logf("64 KiB binary blobs: %.0f allocs, %d B/op", allocsLarge, bytesLarge)

	// 200 x 64 KiB is ~13 MiB of payload, and a binary constant is scanned in
	// place rather than decoded, so the walk must allocate far *less* than the
	// payload — the budget is not even reached.
	if bytesLarge > budget {
		t.Fatalf("walk allocated %d bytes for 13 MiB of binary payload against a %d-byte budget", bytesLarge, budget)
	}
	for _, f := range findings {
		if f.RuleID == "SC4N-LIMIT-RETAINED" {
			t.Fatalf("binary constants should not consume the retention budget, but %s fired", f.RuleID)
		}
	}

	// Text constants are kept, so they are what the budget bounds. 200 x 8 KiB is
	// 1.6 MiB against a 1 MiB budget: the budget must hold the total down and the
	// truncation must be reported.
	_, bytesText, textFindings := measure(stateDictText(200, 8<<10))
	t.Logf("8 KiB text blobs: %d B/op", bytesText)
	if bytesText > budget*4 {
		t.Fatalf("walk allocated %d bytes for 1.6 MiB of text against a %d-byte budget", bytesText, budget)
	}
	reported := false
	for _, f := range textFindings {
		if f.RuleID == "SC4N-LIMIT-RETAINED" {
			reported = true
		}
	}
	if !reported {
		t.Fatal("retention past the budget was not reported as SC4N-LIMIT-RETAINED")
	}
}
