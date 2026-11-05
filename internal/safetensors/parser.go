// Package safetensors parses HuggingFace safetensors files.
//
// Layout: an 8-byte little-endian uint64 header length n, then n bytes of JSON
// beginning with '{' (right-padded with 0x20), then the tensor byte buffer.
// Every tensor's data_offsets are relative to the start of the byte buffer, not
// the file.
//
// The parser validates the invariants the reference implementation enforces --
// header cap, UTF-8/JSON shape, __metadata__ typing, dtype/shape/offset typing,
// END >= BEGIN, contiguity (no overlap, no hole), the product(shape)*bitsize/8
// size equation and full coverage -- and reports each violation with its own
// evidence string. Every violation is also a finding, never a silent failure.
//
// Severity calibration is set by two facts: safetensors has no published
// security advisories, and its reference loader rejects trailing bytes and
// overlapping offsets before returning a tensor. A trailing/overlap finding is
// therefore "not what the reference loader accepts" -- the polyglot and
// steganography shape -- which is high, not critical.
package safetensors

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"sort"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// parser is the registered parser for a safetensors artifact.
type parser struct{}

// maxNativeScan bounds how many bytes of a region are searched for a native
// header. A well-formed file has an empty trailing region, so this only costs
// anything on a malformed or adversarial file, and 64 MiB is far more than any
// appended executable needs to be found.
const maxNativeScan = 64 << 20

// maxUnverifiedNative bounds how many bare-magic observations are reported per
// region, so a deliberate spray of native-looking bytes cannot bury the report.
const maxUnverifiedNative = 4

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatSafetensors,
		Magic:  "<uint64 LE header length n> then n bytes of JSON beginning with '{'",
		Depth:  artifact.DepthDeep,
		Notes: "the header is fully decoded and validated against the reference loader's invariants " +
			"(header cap, UTF-8/JSON shape, __metadata__ string map, dtype/shape/offset typing, contiguity, " +
			"coverage, product(shape)*bitsize size). Metadata values and tensor names go through the shared " +
			"string-indicator engine. With -deep-stats, per-tensor NaN/Inf, duplicate, all-zero, outlier and " +
			"entropy statistics are emitted as informational SC4N-WEIGHTS-* findings. Weight-level backdoor " +
			"proof (Neural Cleanse/ABS/STRIP) is deliberately out of band and never attempted here.",
	})
	artifact.RegisterSniffer("safetensors", 96, sniff)
	artifact.RegisterParser(artifact.FormatSafetensors, parser{})
}

// emitSlice reports a known header slice: the artifact is a prefix of a larger
// file, so what it declares runs past its end by design.
func emitSlice(sink *report.Sink, size, declared int64, what string) {
	sink.EmitExtra(artifact.RulePartialSlice, 0,
		fmt.Sprintf("the artifact is a %d-byte slice and %s runs to %d bytes, so the parse stopped at the slice boundary", size, what, declared),
		map[string]string{"bytes": strconv.FormatInt(size, 10), "declared": strconv.FormatInt(declared, 10)})
}

// Parse validates and analyses one safetensors artifact.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	// A header slice of a larger checkpoint is not a malformed file: the campaign
	// fetched a prefix under a per-file budget, so the declared extents run past
	// the bytes on purpose. Ask the session before claiming a violation (271 of
	// the 1038 artifacts in the benign corpus are slices; 120 of them were reported
	// SC4N-SAFETENSORS-TRUNCATED before this check).
	partial := ctx.Session != nil && ctx.Session.IsPartial(ctx.Sink.Artifact())
	if size < 8 {
		ctx.Sink.Emit(RuleStruct, 0, "file is shorter than the 8-byte header length")
		return nil
	}
	nb, err := s.Bytes(0, 8)
	if err != nil || len(nb) < 8 {
		ctx.Sink.Emit(RuleStruct, 0, "file is shorter than the 8-byte header length")
		return nil
	}
	n := int64(uint64(nb[0]) | uint64(nb[1])<<8 | uint64(nb[2])<<16 | uint64(nb[3])<<24 |
		uint64(nb[4])<<32 | uint64(nb[5])<<40 | uint64(nb[6])<<48 | uint64(nb[7])<<56)
	cap := headerCap(ctx.Limits)
	if n <= 0 {
		// The sniffer rejects a non-positive length; the guard stays because this
		// is the field every following read is sized from.
		ctx.Sink.Emit(RuleStruct, 0, "declared header length is zero")
		return nil
	}
	if n > cap {
		// The header cap has its own rule: reporting a MaxHeaderBytes breach under
		// the structural rule (or under MaxStringBlob) named a cap that did not
		// apply.
		limits.Emit(ctx.Sink, limits.RuleHeader, "MaxHeaderBytes", n, cap, "safetensors header length")
		return nil
	}

	raw, _ := s.Bytes(8, n)
	if int64(len(raw)) < n {
		if partial {
			emitSlice(ctx.Sink, size, 8+n, "the header and the tensor data")
			return nil
		}
		ctx.Sink.Emit(RuleTruncated, 8+int64(len(raw)),
			fmt.Sprintf("file is %d bytes but the header declares %d, so 8+%d=%d bytes are required", size, n, n, 8+n))
		// The available prefix may still decode far enough to be worth a look,
		// but a header this incomplete is not a model; stop here.
		return nil
	}

	h, viols := decodeHeader(raw)
	for _, v := range viols {
		ctx.Sink.Emit(RuleStruct, 8, v)
	}

	dataBase := 8 + n
	bufferLen := size - dataBase

	for i := range h.entries {
		validateEntry(ctx, &h.entries[i], bufferLen)
	}

	// Contiguity and coverage. The reference sorts the tensor list by
	// data_offsets before validating, so a header that lists a later tensor
	// first is accepted; validate a begin-ordered copy to match that, not the
	// document order. A tensor whose data_offsets are absent (both sentinels) is
	// skipped -- the missing-offsets violation was already reported -- and one
	// with a negative begin (reported separately by the decoder) can neither
	// open nor close a gap, because its begin is unusable. Its declared END still
	// contributes to the claimed extent so a malformed file is not reported with
	// trailing data for bytes a tensor actually claims.
	order := make([]int, len(h.entries))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return h.entries[order[a]].begin < h.entries[order[b]].begin })
	var expected, claimed int64
	for _, i := range order {
		e := &h.entries[i]
		if e.begin < 0 && e.end < 0 {
			continue
		}
		if e.begin >= 0 {
			switch {
			case e.begin > expected:
				ctx.Sink.Emit(RuleStruct, 8+e.off,
					fmt.Sprintf("tensor %q begins at %d, leaving a gap after %d", e.name, e.begin, expected))
			case e.begin < expected:
				ctx.Sink.Emit(RuleStruct, 8+e.off,
					fmt.Sprintf("tensor %q begins at %d, overlapping the previous tensor ending at %d", e.name, e.begin, expected))
			}
			if e.end > expected {
				expected = e.end
			}
		}
		if e.end > claimed {
			claimed = e.end
		}
	}
	switch {
	case claimed < bufferLen:
		extra := map[string]string{"trailing_bytes": fmt.Sprintf("%d", bufferLen-claimed)}
		if region, err := s.Bytes(dataBase+claimed, bufferLen-claimed); err == nil && len(region) > 0 {
			extra["entropy"] = fmt.Sprintf("%.2f", bytescan.Entropy(sampleForEntropy(region)))
			scanNativeRegion(ctx, dataBase+claimed, region)
		}
		ctx.Sink.EmitExtra(RuleTrailingData, dataBase+claimed,
			fmt.Sprintf("%d bytes follow the last declared tensor", bufferLen-claimed), extra)
	case claimed > bufferLen:
		if partial {
			emitSlice(ctx.Sink, size, dataBase+claimed, "the last declared tensor")
			return nil
		}
		ctx.Sink.Emit(RuleTruncated, dataBase+bufferLen,
			fmt.Sprintf("last tensor ends at %d but the byte buffer is only %d bytes", claimed, bufferLen))
	}

	// Content rules over the header strings.
	for i := range h.meta {
		m := &h.meta[i]
		scanHeaderString(ctx, 8+m.off, "metadata value "+m.key, m.value)
	}
	for i := range h.entries {
		e := &h.entries[i]
		scanHeaderString(ctx, 8+e.off, "tensor name", e.name)
	}

	// Native magic anywhere in the header, and in any trailing bytes.
	scanNativeRegion(ctx, 8, raw)

	if ctx.Session != nil && ctx.Session.DeepStats {
		runStats(ctx, s, h, dataBase, bufferLen)
	}
	return nil
}

// scanHeaderString runs the shared indicator engine over one header string. A
// value larger than MaxStringBlob, when the operator lowered it, is reported as
// a LIMIT finding and only its bounded prefix is scanned: the string was already
// materialised by the JSON decoder under the (much larger) MaxHeaderBytes cap,
// so there is nothing to save here except the indicator pass, but a cap that
// fires must never be silent.
func scanHeaderString(ctx *artifact.Ctx, base int64, what, s string) {
	if cap := ctx.Limits.MaxStringBlob; cap > 0 && int64(len(s)) > cap {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(s)), cap, what)
		s = s[:cap]
	}
	stringscan.EmitString(ctx.Sink, base, s)
}

// validateEntry checks the per-tensor invariants: END >= BEGIN, a known dtype,
// and the product(shape)*bitsize/8 size equation with its byte-alignment half.
func validateEntry(ctx *artifact.Ctx, e *entry, bufferLen int64) {
	if e.begin < 0 && e.end < 0 {
		return // data_offsets genuinely absent; the missing-offsets violation was already reported
	}
	if e.end < e.begin {
		ctx.Sink.Emit(RuleStruct, 8+e.off,
			fmt.Sprintf("tensor %q: data_offsets END %d is before BEGIN %d", e.name, e.end, e.begin))
		return
	}
	bitWidth, ok := dtypeBits[e.dtype]
	if !ok {
		ctx.Sink.Emit(RuleDtypeUnknown, 8+e.off, fmt.Sprintf("tensor %q: dtype %q is not a known dtype", e.name, e.dtype))
		return
	}
	prod, ok := productShape(e.shape)
	if !ok {
		ctx.Sink.Emit(RuleStruct, 8+e.off,
			fmt.Sprintf("tensor %q: shape product overflows uint64", e.name))
		return
	}
	totalBitsHi, totalBits := bits.Mul64(prod, uint64(bitWidth))
	if totalBitsHi != 0 {
		ctx.Sink.Emit(RuleStruct, 8+e.off, fmt.Sprintf("tensor %q: shape product times %d bits overflows uint64", e.name, bitWidth))
		return
	}
	if totalBits%8 != 0 {
		ctx.Sink.Emit(RuleStruct, 8+e.off,
			fmt.Sprintf("tensor %q: %d elements * %d bits is not byte-aligned", e.name, prod, bitWidth))
		return
	}
	want := int64(totalBits / 8)
	if got := e.end - e.begin; want != got {
		ctx.Sink.Emit(RuleStruct, 8+e.off,
			fmt.Sprintf("tensor %q: shape %d elements * %d bits = %d bytes but data_offsets span %d", e.name, prod, bitWidth, want, got))
	}
}

// scanNativeRegion reports validated native executables and bare native magics
// in a byte region.
func scanNativeRegion(ctx *artifact.Ctx, base int64, b []byte) {
	if len(b) == 0 {
		return
	}
	if int64(len(b)) > maxNativeScan {
		b = b[:maxNativeScan]
	}
	if kind, off, ok := bytescan.FindNative(b); ok {
		ctx.Sink.EmitExtra(RuleNativeMagic, base+int64(off), kind.String()+" header",
			map[string]string{"magic_offset": fmt.Sprintf("%d", off)})
	}
	found := 0
	for i := 0; i+4 <= len(b) && found < maxUnverifiedNative; i++ {
		if !nativeLead(b[i]) {
			continue
		}
		kind := bytescan.MagicAt(b[i:])
		if kind == bytescan.NativeNone {
			continue
		}
		if _, ok := bytescan.ValidNative(b[i:]); ok {
			continue
		}
		ctx.Sink.Emit(RuleNativeMagicUnverified, base+int64(i), kind.String()+" magic (header not validated)")
		found++
	}
}

// nativeLead is the same cheap first-byte gate bytescan.FindNative uses, kept in
// sync so both scans look at the same candidate positions.
func nativeLead(c byte) bool {
	switch c {
	case 0x7f, 'M', '\xfe', '\xce', '\xcf', '\xca', 0xd0, '!':
		return true
	}
	return false
}

// sampleForEntropy bounds the entropy sample so a multi-gigabyte trailing region
// does not turn an informational field into a full-file pass.
func sampleForEntropy(b []byte) []byte {
	const maxSample = 1 << 20
	if len(b) > maxSample {
		return b[:maxSample]
	}
	return b
}

// headerCap is the effective header cap: the reference implementation's own
// 100 MB cap, never above the operator's MaxHeaderBytes when that is smaller.
func headerCap(l limits.Limits) int64 {
	c := int64(referenceHeaderCap)
	if l.MaxHeaderBytes > 0 && l.MaxHeaderBytes < c {
		c = l.MaxHeaderBytes
	}
	return c
}

// sniff recognises the length+JSON shape. It accepts a header that runs past the
// end of the file (a truncated artifact) as long as the declared length is
// plausible and the available prefix begins a JSON object, so that the parser --
// not the sniffer -- is what reports the truncation. A scanner that skips the
// file silently would be indistinguishable from one that found it clean.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 9 || (l.MaxArtifactBytes > 0 && size > l.MaxArtifactBytes) {
		return artifact.FormatUnknown, false
	}
	nb, err := s.Bytes(0, 8)
	if err != nil || len(nb) < 8 {
		return artifact.FormatUnknown, false
	}
	n := int64(uint64(nb[0]) | uint64(nb[1])<<8 | uint64(nb[2])<<16 | uint64(nb[3])<<24 |
		uint64(nb[4])<<32 | uint64(nb[5])<<40 | uint64(nb[6])<<48 | uint64(nb[7])<<56)
	avail := size - 8
	cap := headerCap(l)
	if n <= 0 {
		return artifact.FormatUnknown, false
	}
	if n > cap {
		// Over the cap the shape alone is not evidence: 38 of 73 000 real files
		// under the reference corpus roots begin with 8 arbitrary bytes followed
		// by '{' (devicetree .overlay sources, a shell completion script). Claim
		// the file only when it actually carries the declared header, so the
		// parser can report SC4N-LIMIT-HEADER rather than the file falling
		// silently through to a text sniffer. The header itself is never read
		// here: the parser rejects it before its own read.
		if n > avail {
			return artifact.FormatUnknown, false
		}
		first, err := s.Bytes(8, 1)
		if err != nil || len(first) == 0 || first[0] != '{' {
			return artifact.FormatUnknown, false
		}
		return artifact.FormatSafetensors, true
	}
	got := n
	if avail < got {
		got = avail
	}
	head, err := s.Bytes(8, got)
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	if len(head) == 0 || head[0] != '{' {
		return artifact.FormatUnknown, false
	}
	if int64(len(head)) < n {
		// Truncated: the prefix begins an object, which is enough to route the
		// file to the parser for a TRUNCATED finding.
		return artifact.FormatSafetensors, true
	}
	// A complete header must parse as a single JSON object (trailing 0x20
	// padding is valid JSON whitespace, so json.Valid accepts it directly).
	if !json.Valid(head) {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatSafetensors, true
}
