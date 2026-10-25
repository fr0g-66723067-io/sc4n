// Package trt recognises TensorRT serialized engines (`.engine`, `.plan`,
// `.trt`).
//
// A TensorRT engine is the output of `trt.Builder.buildSerializedNetwork`: a
// `ftrt` magic, a serialization version, then an opaque section table that holds
// the layer graph, the kernel names and the weight blobs. The layout is versioned
// and *not published*: NVIDIA ships the serializer and deserializer, and a reader
// outside them cannot tell a well-formed section table from a corrupt one.
//
// That is why this package is honest about being shallow instead of pretending
// otherwise:
//
//   - the four-byte magic decides dispatch (the extensions are advisory only —
//     `.plan` is also used by other tools, and `.engine` by several), and the
//     magic is what the runtime itself checks first;
//   - the indicator engine runs over the first 4 MiB and the last 1 MiB, which is
//     where the serialization header, the section table, the layer and kernel
//     names, and the trailing metadata live;
//   - the weights between those two windows are NOT scanned, and no structural
//     rule is invented: there is no published specification whose violation could
//     honestly be called malformed. SC4N-TRT-UNVERIFIED states both facts, so a
//     shallow file is never reported as a clean one.
package trt

import (
	"fmt"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

const (
	// headWindow and tailWindow bound the indicator pass. A serialized engine's
	// names and section table live in the head; the tail carries the final
	// metadata and any appended trailer.
	headWindow = 4 << 20
	tailWindow = 1 << 20
	// minEngine is the magic plus the four serialization-version bytes.
	minEngine = 8
)

var magic = []byte("ftrt")

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatTRTEngine,
		Magic:  "\"ftrt\" at offset 0",
		Depth:  artifact.DepthShallow,
		Notes: "the four-byte `ftrt` magic is recognised and the buffer is run through the indicator " +
			"engine over its first 4 MiB and last 1 MiB, where the serialization header, the section " +
			"table and the layer/kernel names live. The section table is NOT interpreted (NVIDIA does " +
			"not publish a stable serialization format), and the weights between the two windows are " +
			"not scanned: a payload hidden there is out of scope, which SC4N-TRT-UNVERIFIED says.",
	})
	// Priority 94: the magic is unambiguous, so it goes above every
	// extension-heuristic sniffer and above the shallow text detectors.
	artifact.RegisterSniffer("trt-engine", 94, sniff)
	artifact.RegisterParser(artifact.FormatTRTEngine, parser{})
}

func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	if s.Size() < int64(len(magic)) {
		return artifact.FormatUnknown, false
	}
	b, err := s.Bytes(0, int64(len(magic)))
	if err != nil || len(b) < len(magic) {
		return artifact.FormatUnknown, false
	}
	for i := range magic {
		if b[i] != magic[i] {
			return artifact.FormatUnknown, false
		}
	}
	return artifact.FormatTRTEngine, true
}

type parser struct{}

func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	n := s.Size()
	if max := ctx.Limits.MaxArtifactBytes; max > 0 && n > max {
		n = max
	}
	b, err := s.Bytes(0, n)
	if err != nil {
		return err
	}
	headLen := minInt64(int64(len(b)), headWindow)
	head := b[:headLen]
	tailOff := maxInt64(0, int64(len(b))-tailWindow)
	tail := b[tailOff:]

	stringscan.Emit(ctx.Sink, 0, head)
	if tailOff > 0 {
		stringscan.Emit(ctx.Sink, tailOff, tail)
	}

	ctx.Sink.EmitExtra(RuleUnverified, 0, fmt.Sprintf(
		"%d-byte TensorRT serialized engine; the ftrt header is recognised, the section table is not "+
			"interpreted, and the indicator pass covered bytes [0,%d) and [%d,%d)",
		n, headLen, tailOff, n,
	),
		map[string]string{
			"size":       strconv.FormatInt(n, 10),
			"head_bytes": strconv.FormatInt(headLen, 10),
			"tail_bytes": strconv.FormatInt(int64(len(tail)), 10),
		})
	return nil
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
