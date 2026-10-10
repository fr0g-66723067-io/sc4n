package bytescan

import (
	"math/rand"
	"testing"
)

// benchBytes returns n bytes with the entropy of a real tensor body: essentially
// uniform, which is the worst case for a byte histogram (every counter is touched).
func benchBytes(n int) []byte {
	r := rand.New(rand.NewSource(1))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func BenchmarkEntropy(b *testing.B) {
	buf := benchBytes(1 << 20)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		sink = Entropy(buf)
	}
}

func BenchmarkFindNative(b *testing.B) {
	buf := benchBytes(1 << 20)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = FindNative(buf)
	}
}

var sink float64
