//go:build !goexperiment.simd

package stringscan

// The pure-Go byte kernel. A GOEXPERIMENT=simd build replaces the histogram with
// internal/stringscan/kernel_simd.go; both files declare exactly the same
// functions, so the two implementations cannot drift in signature and a stock
// toolchain builds this one.

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
