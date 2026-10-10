package stringscan

// The byte kernel.
//
// A SIMD replacement for this histogram (goexperiment.simd, simd/archsimd) was
// evaluated and not shipped: the pure-Go version already runs at 1.13 GB/s, and
// the string engine's real cost is the Aho-Corasick walk's dependent load chain,
// which a byte-class histogram does not touch. See docs/architecture.md for the
// measured numbers and the rule the decision followed (>= 1.5x on its own kernel
// or it does not land). The file therefore carries no build tag: there is exactly
// one implementation, so there is nothing for a tag to select between.

import "github.com/fr0g-66723067-io/sc4n/internal/bytescan"

// byteClass is the coarse class of a byte, used for the shape checks that need a
// histogram rather than a pattern.
type byteClass uint8

const (
	classOther byteClass = iota
	classDigit
	classLower
	classUpper
	classSpace
	classPunct
	classHigh
)

func classOf(c byte) byteClass {
	switch {
	case c >= '0' && c <= '9':
		return classDigit
	case c >= 'a' && c <= 'z':
		return classLower
	case c >= 'A' && c <= 'Z':
		return classUpper
	case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		return classSpace
	case c < 0x20 || c == 0x7f:
		return classOther
	case c < 0x80:
		return classPunct
	default:
		return classHigh
	}
}

// histogram fills counts with the byte-class frequencies of b.
func histogram(b []byte, counts *[7]int64) {
	for _, c := range b {
		counts[classOf(c)]++
	}
}

// entropyBits returns the Shannon entropy of b in bits per byte. It shares
// bytescan's implementation deliberately: a second entropy implementation would be
// a second answer to the same question, and the SIMD build may only change the
// histogram, not the definition.
func entropyBits(b []byte) float64 { return bytescan.Entropy(b) }
