// Package pte recognises ExecuTorch / PyTorch-Mobile program files (`.pte`, and
// the `.ptl` name the PyTorch Mobile lite flatbuffer also uses).
//
// A `.pte` is a *modified flatbuffer*: a 4-byte little-endian offset to the root
// table, then the flatbuffer file identifier `ET` plus two ASCII version digits at
// byte 4, an optional ExecuTorch extended header at byte 8 (`eh` plus two digits),
// the serialized program, and optional data segments. The format carries no
// pickle and no Python: the program is a flatbuffer graph whose operators live in
// native code on the device.
//
// Two things make it worth dispatching on content rather than extension:
//
//   - `.ptl` is ambiguous (TorchScript versus PyTorch Mobile flatbuffer), so the
//     extension cannot decide; and
//   - the segment region is opaque bytes that a loader maps and hands to the
//     runtime. An executable embedded there is not visible to a scanner that only
//     looks at the header.
//
// sc4n v1 does NOT decode the flatbuffer graph, and it says so out loud with
// SC4N-PTE-UNVERIFIED rather than reporting a shallow file as clean. What it does
// do is verify the header arithmetic, then scan the segment region for a validated
// native header (the embedded-executable shape) and run the indicator engine over
// the header strings.
package pte

import (
	"encoding/binary"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/polyglot"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// Header field offsets, from https://docs.pytorch.org/executorch/stable/pte-file-format.html.
const (
	offRootOffset = 0  // uint32: byte offset to the flatbuffer root table
	offFileMagic  = 4  // "ET" + two ASCII digits
	offExtMagic   = 8  // "eh" + two ASCII digits
	offExtSize    = 12 // uint32: extended header size including the magic
	offProgSize   = 16 // uint64: size of the flatbuffer-encoded program data
	offSegBase    = 24 // uint64: offset to the first segment
	offSegSize    = 32 // uint64: size of the segment data
	minExtHeader  = 40 // minimum extended-header size
)

// nativeWindow is the window the segment scan reads at a time.
const nativeWindow = 1 << 20

const (
	maxSegmentScanBytes = 16 << 20
	maxNativeCandidates = 64
)

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatPTE,
		Magic:  "root uint32 at 0, \"ET\" + two ASCII digits at offset 4",
		Depth:  artifact.DepthShallow,
		Notes: "the flatbuffer file magic, the root-table offset and the optional ExecuTorch extended " +
			"header are verified, the segment region is scanned for a validated native header, and the " +
			"header strings are run through the indicator engine. SHALLOW PATH, stated explicitly: the " +
			"flatbuffer program graph is NOT decoded in v1, and that is reported with SC4N-PTE-UNVERIFIED " +
			"rather than left implied. Dispatch is on content, never on the extension, because `.ptl` is " +
			"also used for the PyTorch Mobile lite flatbuffer.",
	})
	// Priority 72: above every extension-heuristic sniffer, below the
	// unambiguous magics. This is the only sniffer for FormatPTE -- the
	// generic offset-0 placeholder in internal/artifact is gone, because the
	// documented check is the file magic at offset 4, not offset 0, and two
	// sniffers for one format silently let dispatch order decide coverage.
	artifact.RegisterSniffer("pte-magic", 72, sniff)
	artifact.RegisterParser(artifact.FormatPTE, parser{})
}

type parser struct{}

func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	if size < 8 {
		ctx.Sink.Emit(RuleStruct, 0, "file is too short to hold a .pte header")
		return nil
	}
	head, err := s.Bytes(0, minInt64(size, 64))
	if err != nil && len(head) < 8 {
		ctx.Sink.Emit(RuleStruct, 0, "header could not be read")
		return nil
	}
	root := binary.LittleEndian.Uint32(head[offRootOffset:])
	if !isMagic(head[offFileMagic:]) {
		ctx.Sink.Emit(RuleStruct, 0, "file magic is not \"ET\" followed by two ASCII digits at offset 4")
		return nil
	}
	version := string(head[offFileMagic+2 : offFileMagic+4])
	if int64(root) >= size || root < 4 {
		ctx.Sink.EmitExtra(RuleStruct, 0,
			"flatbuffer root offset "+strconv.FormatUint(uint64(root), 10)+" is outside the file",
			map[string]string{"root_offset": strconv.FormatUint(uint64(root), 10), "size": strconv.FormatInt(size, 10)})
	}

	var (
		hasExt  bool
		segBase int64
		segSize int64
	)
	if len(head) >= 12 && isExtMagic(head[offExtMagic:]) {
		hasExt = true
		if len(head) < minExtHeader || size < minExtHeader {
			ctx.Sink.Emit(RuleStruct, 0, "extended header is truncated")
		} else {
			extSize := int64(binary.LittleEndian.Uint32(head[offExtSize:]))
			progSize := int64(binary.LittleEndian.Uint64(head[offProgSize:]))
			segBase = int64(binary.LittleEndian.Uint64(head[offSegBase:]))
			segSize = int64(binary.LittleEndian.Uint64(head[offSegSize:]))
			if extSize < minExtHeader || extSize > size {
				ctx.Sink.Emit(RuleStruct, 0, "extended header size "+strconv.FormatInt(extSize, 10)+" is out of range")
			}
			if progSize < 0 || progSize > size {
				ctx.Sink.Emit(RuleStruct, 0, "declared program data size exceeds the file")
			}
			if segBase < 0 || segSize < 0 || segBase > size || segSize > size-segBase {
				ctx.Sink.Emit(RuleStruct, 0, "declared segment region is outside the file")
				segSize = 0
			}
		}
	}

	// Header strings are a low-noise place for indicators (op names, debug info).
	// A flatbuffer segment is not prose: its strings are tensor names and operator
	// attributes. Only a reachable secret or endpoint is a finding here.
	stringscan.EmitKind(ctx.Sink, 0, head, stringscan.KindSecrets)

	if hasExt && segSize > 0 {
		scanNative(ctx, s, segBase, segSize)
	}

	extra := map[string]string{"version": version}
	if hasExt {
		extra["extended_header"] = "true"
		extra["segment_bytes"] = strconv.FormatInt(segSize, 10)
	} else {
		extra["extended_header"] = "false"
	}
	ctx.Sink.EmitExtra(RuleUnverified, 0,
		"ExecuTorch program file recognised (version "+version+"); the flatbuffer operator graph and its "+
			"possibly-appended segment bytes are not decoded by sc4n v1, so this file is only shallowly analysed",
		extra)
	return nil
}

// scanNative walks the segment region in windows and reports a validated native
// header. The universal polyglot layer only looks at the first and last MiB of an
// artifact, so a payload in the middle of a large segment region would otherwise
// never be seen at all.
func scanNative(ctx *artifact.Ctx, s source.Source, base, size int64) {
	if size > maxSegmentScanBytes {
		limits.Emit(ctx.Sink, limits.RuleEntries, "MaxSegmentScan", size, maxSegmentScanBytes,
			"ExecuTorch segment scan")
		size = maxSegmentScanBytes
	}
	attempts := 0
	for off := int64(0); off < size; off += nativeWindow {
		n := size - off
		if n > nativeWindow {
			n = nativeWindow
		}
		b, err := s.Bytes(base+off, n)
		if len(b) == 0 {
			if err != nil {
				return
			}
			continue
		}
		for i := 0; i < len(b); i++ {
			if bytescan.MagicAt(b[i:]) == bytescan.NativeNone {
				continue
			}
			attempts++
			if attempts > maxNativeCandidates {
				limits.Emit(ctx.Sink, limits.RuleEntries, "MaxNativeCandidates",
					int64(attempts), maxNativeCandidates, "ExecuTorch segment native candidates")
				return
			}
			abs := base + off + int64(i)
			kind, ok := polyglot.ValidateNativeHeader(s, s.Size(), abs)
			if !ok {
				continue
			}
			ctx.Sink.EmitExtra(RuleNative, abs,
				"a validated "+kind.String()+" header sits inside the ExecuTorch segment data, which the "+
					"runtime maps and hands to the device backend",
				map[string]string{"kind": kind.String(), "offset": strconv.FormatInt(abs, 10)})
		}
	}
}

// sniff implements the documented test: the file magic at byte offset 4, plus a
// plausible root offset at byte 0.
func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	if s.Size() < 8 {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, 8)
	if err != nil && len(head) < 8 {
		return artifact.FormatUnknown, false
	}
	if !isMagic(head[offFileMagic:]) {
		return artifact.FormatUnknown, false
	}
	root := binary.LittleEndian.Uint32(head[offRootOffset:])
	if root < 4 || int64(root) >= s.Size() {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatPTE, true
}

func isMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 'E' && b[1] == 'T' && isDigit(b[2]) && isDigit(b[3])
}

func isExtMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 'e' && b[1] == 'h' && isDigit(b[2]) && isDigit(b[3])
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
