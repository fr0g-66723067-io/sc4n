package safetensors

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Weight-statistics thresholds. Every one is a named constant with its
// rationale, because an unexplained magic number in an informational rule is
// indistinguishable from a bug. All of these are calibrations for a human
// reading a -deep-stats report; none of them affects the exit code.
const (
	// weightSampleBytes caps how much of one tensor is read for statistics.
	// Backdoor-relevant anomalies (a NaN storm, duplicated rows, a constant
	// block) are visible in a few megabytes, and reading a whole multi-gigabyte
	// tensor would defeat the memory budget for no extra signal.
	weightSampleBytes = 4 << 20

	// statsElementCap bounds the number of elements decoded from one sample, so
	// a tensor of 1-bit-ish exotic values cannot turn the pass into a large
	// allocation. 1 Mi elements covers a 4 MiB F32 sample exactly.
	statsElementCap = 1 << 20

	// minStatsElems is the smallest tensor worth reporting on. Below this a
	// "fraction" is dominated by a handful of values and produces noise.
	minStatsElems = 16

	// nanFractionWarn is the fraction of sampled float values that must be
	// NaN/Inf before the tensor is reported. A handful of NaNs does occur in
	// real checkpoints; a whole tensor of them does not.
	nanFractionWarn = 0.05

	// duplicateFractionWarn is the fraction of sampled elements that must repeat
	// an earlier value before the tensor is reported. Quantisation can raise
	// this, hence the deliberately high bar.
	duplicateFractionWarn = 0.5

	// outlierRatio is how many times the tensor's own mean magnitude an element
	// must exceed to count as an outlier, and outlierFractionWarn is the
	// fraction of elements that must be outliers. The pair is intentionally
	// loose: a magnitude spike is a hint, not a proof.
	outlierRatio        = 8.0
	outlierFractionWarn = 0.01

	// entropyLowWarn and entropyHighWarn bracket the expected byte entropy of
	// weight data. Below the low bound the tensor is a constant or zero region;
	// above the high bound it looks compressed or encrypted, which weights do
	// not.
	entropyLowWarn  = 1.0
	entropyHighWarn = 7.9
)

// weightStats is the result of one tensor's statistics pass.
type weightStats struct {
	elements   int64
	zeros      int64
	nonFinite  int64
	duplicates int64
	meanAbs    float64
	outliers   int64
	entropy    float64
}

// elementInfo describes how to decode one dtype for the statistics pass. ok is
// false for dtypes with sub-byte elements (F4, F6_*) and the F8 variants, whose
// decoding would add code for almost no signal; those tensors are skipped, not
// guessed.
type elementInfo struct {
	size    int
	numeric bool // a real number (NaN/Inf/outlier checks apply)
	complex bool
	// bf16 marks the brain-float encoding, which is 2 bytes like F16 but is not
	// IEEE binary16: it is the top 16 bits of a float32. Decoding a BF16 pattern
	// with the binary16 decoder turns a finite value into a NaN whenever the bits
	// land in binary16's all-ones exponent field, which is most of bf16's useful
	// range — a 0x7D00 element is ~1.15e36 in bf16 and NaN in binary16. Measured
	// before the fix: a tensor of 32 finite BF16 values reported "32/32 sampled
	// values are NaN or Inf". BF16 is the common weight format in modern
	// checkpoints, so the false positive landed on the tensors the pass exists for.
	bf16 bool
}

func elementInfoFor(dtype string) (elementInfo, bool) {
	switch dtype {
	case "F32":
		return elementInfo{size: 4, numeric: true}, true
	case "F64":
		return elementInfo{size: 8, numeric: true}, true
	case "F16":
		return elementInfo{size: 2, numeric: true}, true
	case "BF16":
		return elementInfo{size: 2, numeric: true, bf16: true}, true
	case "C64":
		return elementInfo{size: 8, numeric: true, complex: true}, true
	case "BOOL", "U8", "I8":
		return elementInfo{size: 1}, true
	case "U16", "I16":
		return elementInfo{size: 2}, true
	case "U32", "I32":
		return elementInfo{size: 4}, true
	case "U64", "I64":
		return elementInfo{size: 8}, true
	default:
		return elementInfo{}, false
	}
}

// runStats emits the informational weight statistics for the tensors of h. It
// is called only when the session opted into -deep-stats.
func runStats(ctx *artifact.Ctx, s source.Source, h *header, dataBase, bufferLen int64) {
	for i := range h.entries {
		e := &h.entries[i]
		if e.begin < 0 || e.end < e.begin || e.end > bufferLen {
			continue
		}
		ei, ok := elementInfoFor(e.dtype)
		if !ok {
			continue
		}
		span := e.end - e.begin
		readLen := span
		if readLen > weightSampleBytes {
			readLen = weightSampleBytes
		}
		readLen -= readLen % int64(ei.size)
		if readLen <= 0 || readLen/int64(ei.size) < minStatsElems {
			continue
		}
		b, err := s.Bytes(dataBase+e.begin, readLen)
		if err != nil && len(b) == 0 {
			continue
		}
		b = b[:len(b)-len(b)%ei.size]
		if len(b)/ei.size < minStatsElems {
			continue
		}
		st := computeStats(ei, b)
		emitWeightFindings(ctx, e, st)
	}
}

// computeStats decodes the sample and returns the statistics. The duplicate
// count is the number of elements that repeat a value already seen in the
// sample; it is exact for the sample, which is what a fraction over `elements`
// means.
func computeStats(ei elementInfo, b []byte) weightStats {
	st := weightStats{entropy: bytescan.Entropy(sampleForEntropy(b))}
	n := len(b) / ei.size
	if n > statsElementCap {
		n = statsElementCap
	}
	seen := make(map[uint64]struct{}, n)
	var sumAbs float64
	var finiteCount int64
	for i := range n {
		el := b[i*ei.size : (i+1)*ei.size]
		st.elements++
		if _, dup := seen[keyOf(el)]; dup {
			st.duplicates++
		} else {
			seen[keyOf(el)] = struct{}{}
		}
		v, zero, finite := decodeElement(ei, el)
		if zero {
			st.zeros++
		}
		if !finite {
			st.nonFinite++
		} else if ei.numeric {
			sumAbs += math.Abs(v)
			finiteCount++
		}
	}
	if finiteCount > 0 && ei.numeric {
		st.meanAbs = sumAbs / float64(finiteCount)
	}
	if ei.numeric && st.meanAbs > 0 {
		limit := outlierRatio * st.meanAbs
		for i := range n {
			el := b[i*ei.size : (i+1)*ei.size]
			v, _, finite := decodeElement(ei, el)
			if finite && math.Abs(v) > limit {
				st.outliers++
			}
		}
	}
	return st
}

// keyOf packs an element's raw bytes into a uint64 for exact-duplicate
// detection. Elements are at most 8 bytes.
func keyOf(el []byte) uint64 {
	var k uint64
	for i := len(el) - 1; i >= 0; i-- {
		k = k<<8 | uint64(el[i])
	}
	return k
}

// decodeElement decodes one element into (value, isZero, isFinite). For complex
// elements the value is the magnitude of the pair and finite means both parts
// are finite.
func decodeElement(ei elementInfo, el []byte) (float64, bool, bool) {
	switch ei.size {
	case 1:
		return float64(el[0]), el[0] == 0, true
	case 2:
		u := binary.LittleEndian.Uint16(el)
		if ei.numeric {
			if ei.bf16 {
				v := math.Float32frombits(uint32(u) << 16)
				return float64(v), u == 0, !isBad(float64(v))
			}
			v := halfToFloat(u)
			return float64(v), u == 0, !isBad(float64(v))
		}
		return float64(u), u == 0, true
	case 4:
		u := binary.LittleEndian.Uint32(el)
		if ei.numeric {
			v := math.Float32frombits(u)
			return float64(v), u == 0, !isBad(float64(v))
		}
		return float64(u), u == 0, true
	default: // 8
		if ei.complex {
			re := math.Float32frombits(binary.LittleEndian.Uint32(el[0:4]))
			im := math.Float32frombits(binary.LittleEndian.Uint32(el[4:8]))
			mag := math.Hypot(float64(re), float64(im))
			return mag, re == 0 && im == 0, !isBad(float64(re)) && !isBad(float64(im))
		}
		u := binary.LittleEndian.Uint64(el)
		if ei.numeric {
			v := math.Float64frombits(u)
			return v, u == 0, !isBad(v)
		}
		return float64(u), u == 0, true
	}
}

func isBad(v float64) bool { return math.IsNaN(v) || math.IsInf(v, 0) }

// halfToFloat converts an IEEE-754 binary16 bit pattern to float32.
func halfToFloat(h uint16) float32 {
	sign := uint32(h&0x8000) << 16
	exp := uint32(h>>10) & 0x1f
	mant := uint32(h & 0x3ff)
	switch exp {
	case 0:
		if mant == 0 {
			return math.Float32frombits(sign)
		}
		// subnormal
		for mant&0x400 == 0 {
			mant <<= 1
			exp--
		}
		exp++
		mant &= 0x3ff
		return math.Float32frombits(sign | (exp+112)<<23 | mant<<13)
	case 0x1f:
		return math.Float32frombits(sign | 0x7f800000 | mant<<13)
	default:
		return math.Float32frombits(sign | (exp+112)<<23 | mant<<13)
	}
}

// emitWeightFindings turns one tensor's statistics into informational findings.
func emitWeightFindings(ctx *artifact.Ctx, e *entry, st weightStats) {
	if st.elements == 0 {
		return
	}
	frac := func(n int64) float64 { return float64(n) / float64(st.elements) }
	base := int64(8) + e.off
	if st.nonFinite > 0 && frac(st.nonFinite) >= nanFractionWarn {
		ctx.Sink.EmitExtra(RuleWeightsNaN, base,
			fmt.Sprintf("tensor %q: %d/%d sampled values are NaN or Inf", e.name, st.nonFinite, st.elements),
			map[string]string{"fraction": fmt.Sprintf("%.4f", frac(st.nonFinite))})
	}
	if st.duplicates > 0 && frac(st.duplicates) >= duplicateFractionWarn {
		ctx.Sink.EmitExtra(RuleWeightsDuplicate, base,
			fmt.Sprintf("tensor %q: %d/%d sampled values repeat an earlier value", e.name, st.duplicates, st.elements),
			map[string]string{"fraction": fmt.Sprintf("%.4f", frac(st.duplicates))})
	}
	allZero := st.zeros == st.elements
	if allZero {
		ctx.Sink.Emit(RuleWeightsAllZero, base, fmt.Sprintf("tensor %q: all %d sampled values are zero", e.name, st.elements))
	}
	if st.outliers > 0 && frac(st.outliers) >= outlierFractionWarn && st.meanAbs > 0 {
		ctx.Sink.EmitExtra(RuleWeightsOutlier, base,
			fmt.Sprintf("tensor %q: %d/%d sampled values exceed %gx the mean magnitude %g",
				e.name, st.outliers, st.elements, outlierRatio, st.meanAbs),
			map[string]string{"fraction": fmt.Sprintf("%.4f", frac(st.outliers))})
	}
	// A zero tensor is always low-entropy; reporting both would be noise, so the
	// entropy finding is suppressed when the all-zero finding already fired.
	if !allZero && (st.entropy < entropyLowWarn || st.entropy > entropyHighWarn) {
		ctx.Sink.EmitExtra(RuleWeightsEntropy, base,
			fmt.Sprintf("tensor %q: sampled byte entropy %.2f bits/byte", e.name, st.entropy),
			map[string]string{"entropy": fmt.Sprintf("%.2f", st.entropy)})
	}
}
