package torch

import (
	"bytes"
	"fmt"
	"io"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/pickle"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// torchMagicLE is MAGIC_NUMBER = 0x1950A86A20F9469CFC6C in little-endian byte
// order. The value is 10 bytes, so it is not a qword; the plan's wording aside,
// torch never writes it raw either: _legacy_save calls
//
//	pickle_module.dump(MAGIC_NUMBER, f, protocol=pickle_protocol)
//
// so the file's first bytes are a *pickled* int (PROTO, LONG1, length 10, the
// ten bytes, STOP). detectLegacy accepts the pickled form (the real one) and the
// raw 8/10-byte forms (a documented-in-plan variant) so a future or third-party
// writer is not silently missed.
//
// Reference: torch/serialization.py `_legacy_save` / `_legacy_load` at the
// PyTorch main branch (MAGIC_NUMBER, PROTOCOL_VERSION = 1001).
var (
	torchMagicLE        = []byte{0x6C, 0xFC, 0x9C, 0x46, 0xF9, 0x20, 0x6A, 0xA8, 0x50, 0x19}
	torchMagicProto0L   = []byte("L119547037146038801333356L\n")
	torchMagicProto0NoL = []byte("L119547037146038801333356\n")
)

// opProto and opFrame are the pickle PROTO/FRAME opcodes needed to recognise
// the start of a leading pickle without importing internal/pickle's table.
const (
	opProto = 0x80
	opFrame = 0x95
)

// detectLegacy reports whether head begins the legacy torch magic, and how many
// bytes the magic occupies (its "after" offset). A pickled magic occupies 0
// bytes to skip: the first pickle to walk is the magic itself.
func detectLegacy(head []byte) (afterMagic int, ok bool) {
	switch {
	case len(head) >= 14 && head[0] == opProto && head[1] >= 2 && head[1] <= 5 &&
		head[2] == 0x8a && head[3] == byte(len(torchMagicLE)) && bytes.Equal(head[4:14], torchMagicLE):
		// Pickled magic (protocol 2..5 without FRAME): PROTO <proto> LONG1 <10> <ten LE bytes>.
		return 0, true
	case len(head) >= 23 && head[0] == opProto && (head[1] == 4 || head[1] == 5) &&
		head[2] == opFrame && head[11] == 0x8a && head[12] == byte(len(torchMagicLE)) &&
		bytes.Equal(head[13:23], torchMagicLE):
		// Pickled magic (protocol 4/5 with FRAME): PROTO <4|5> FRAME <8B> LONG1 <10> <ten LE bytes>.
		return 0, true
	case bytes.HasPrefix(head, torchMagicProto0L) || bytes.HasPrefix(head, torchMagicProto0NoL):
		// Pickled magic (protocol 0/1): L119547037146038801333356L\n.
		return 0, true
	case len(head) >= len(torchMagicLE) && bytes.Equal(head[:len(torchMagicLE)], torchMagicLE):
		return len(torchMagicLE), true
	case len(head) >= 8 && bytes.Equal(head[:8], torchMagicLE[:8]):
		// The low 64 bits of MAGIC_NUMBER, the form the plan calls a qword.
		return 8, true
	}
	return 0, false
}

// legacyParser handles both legacy layouts. The sniffer labels them
// FormatTorchLegacy; the tar variant is distinguished by the ustar magic.
type legacyParser struct{}

func (legacyParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	if isTarShape(s) {
		if ms, err := archive.Collect(s, ctx.Limits); err == nil && looksTorchTar(ms) {
			return parseLegacyTar(ctx, s, ms)
		}
	}
	return parseLegacyBinary(ctx, s)
}

// parseLegacyBinary walks the pickles _legacy_load unpickles, one at a time.
//
// The layout is a fixed sequence: MAGIC_NUMBER, PROTOCOL_VERSION, sys_info, the
// object, the storage keys, then raw storage. Each is handed to pickle.Walk as
// its own window with TrailingIsStorage set, so the walker stops at that pickle's
// STOP and treats whatever follows (the next pickle or the raw storage) as the
// container's payload. Walking the whole file as one window would either stop at
// the first (harmless) pickle or misreport the storage tail as an attack suffix.
func parseLegacyBinary(ctx *artifact.Ctx, s source.Source) error {
	head, _ := s.Bytes(0, 32)
	afterMagic, ok := detectLegacy(head)
	if !ok {
		ctx.Sink.Emit(ruleTorchStruct, 0, "legacy torch magic not present at offset 0")
		return nil
	}
	ctx.Sink.Emit(ruleTorchLegacy, 0,
		fmt.Sprintf("legacy torch checkpoint: magic at 0, %d leading pickle(s), then raw storage", legacyPickleCount(afterMagic)))

	size := s.Size()
	off := int64(afterMagic)
	// _legacy_load unpickles: magic (unless raw), protocol version, sys_info, the
	// object, and the storage-key list.
	n := 4
	if afterMagic == 0 {
		n = 5
	}
	for i := range n {
		if off >= size {
			break
		}
		if !pickleStartAt(s, off) {
			// The raw storage begins here (or the writer omitted storage_keys).
			// Before the object pickle this is a malformed container.
			if i < 3 {
				ctx.Sink.Emit(ruleTorchStruct, off, "a required leading pickle is missing before the raw storage")
			}
			break
		}
		sec, err := source.Section(s, off, size-off, s.Name())
		if err != nil {
			ctx.Sink.Emit(ruleTorchStruct, off, "legacy section unreadable: "+err.Error())
			break
		}
		st, werr := pickle.Walk(ctx, sec, pickle.Options{
			TrailingIsStorage:  true,
			StorageDescription: "legacy torch raw storage",
		})
		sec.Close()
		if werr != nil {
			ctx.Sink.Emit(ruleTorchStruct, off, "leading pickle walk failed: "+werr.Error())
			break
		}
		if st == nil || !st.SawStop || st.EndOffset <= 0 {
			ctx.Sink.Emit(ruleTorchStruct, off, "a leading pickle did not reach a STOP")
			break
		}
		off += st.EndOffset
	}
	return nil
}

// legacyPickleCount is the number of pickles before the raw storage, for evidence.
func legacyPickleCount(afterMagic int) int {
	if afterMagic == 0 {
		return 5
	}
	return 4
}

// pickleStartAt reports whether a pickle stream (protocol 0..5) begins at off.
func pickleStartAt(s source.Source, off int64) bool {
	b, err := s.Bytes(off, 2)
	return (err == nil || len(b) == 2) && pickle.OpensAsPickle(b)
}

// parseLegacyTar walks the three members of the old tar layout. `pickle` is the
// object graph; `storages` and `tensors` begin with metadata pickles and then
// carry raw storage, so they are walked with TrailingIsStorage. Every member is
// dispatched through a real member context so naming and depth stay central.
func parseLegacyTar(ctx *artifact.Ctx, s source.Source, ms archive.Members) error {
	ctx.Sink.Emit(ruleTorchLegacyTar, 0, "legacy torch tar: storages + tensors + pickle")
	ms.Check(ctx)
	for i := range ms.Members {
		m := ms.Members[i]
		if m.IsDir || m.LinkKind != "" {
			continue
		}
		allowPrefix := m.Name == "storages" || m.Name == "tensors"
		data, truncated, ok := readMemberBounded(ctx, s, m, allowPrefix)
		if !ok {
			continue
		}
		switch m.Name {
		case "pickle", "storages", "tensors":
			sub, ok := ctx.Member(m.Name, artifact.FormatPickle)
			if !ok {
				limits.Emit(ctx.Sink, limits.RuleDepth, "MaxDepth", int64(ctx.Depth+1), int64(ctx.Session.TopLimits.MaxDepth), "stopped at "+m.Name)
				continue
			}
			sec := source.Mem(m.Name, data)
			if m.Name == "pickle" {
				_, _ = pickle.Walk(sub, sec, pickle.Options{})
			} else {
				st, _ := pickle.Walk(sub, sec, pickle.Options{
					TrailingIsStorage:  true,
					StorageDescription: "legacy torch tar raw storage",
				})
				if truncated && (st == nil || !st.SawStop) {
					max := ctx.Limits.MaxStringBlob
					if max <= 0 {
						max = limits.Default().MaxStringBlob
					}
					limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", m.Size, max, "torch tar member "+m.Name)
				}
			}
			sec.Close()
		default:
			artifact.ScanMemberBytes(ctx, m.Name, data)
		}
	}
	return nil
}

// readMemberBounded reads a member into memory up to MaxStringBlob. When
// allowPrefix is true (for `storages` and `tensors`, which begin with a small
// metadata pickle followed by gigabytes of raw tensor bytes), a member larger
// than MaxStringBlob returns its leading MaxStringBlob bytes with truncated=true
// so the metadata pickle is still scanned. Otherwise a member above the cap is
// reported (never silently truncated) and skipped.
func readMemberBounded(ctx *artifact.Ctx, s source.Source, m archive.Member, allowPrefix bool) ([]byte, bool, bool) {
	max := ctx.Limits.MaxStringBlob
	if max <= 0 {
		max = limits.Default().MaxStringBlob
	}
	if !allowPrefix && m.Size > max {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", m.Size, max, "torch tar member "+m.Name)
		return nil, false, false
	}
	if ctx.RemainingDecompressed() == 0 {
		ctx.ReportDecompressedLimit(m.Size, ctx.Limits.MaxDecompressedBytes)
		return nil, false, false
	}
	l := ctx.Limits
	l.MaxDecompressedBytes = ctx.RemainingDecompressed()
	rc, err := archive.Open(s, l, m)
	if err != nil {
		// The generic archive walker reports exactly this condition; a legacy tar
		// member that cannot be opened must not be dropped in silence, or a .pth
		// truncated inside its pickle member is parsed as an empty structure with
		// no findings.
		archive.EmitOpenError(ctx, m.Name, err)
		return nil, false, false
	}
	defer rc.Close()
	if allowPrefix && m.Size > max {
		data, err := io.ReadAll(io.LimitReader(rc, max))
		if err != nil && len(data) == 0 {
			archive.EmitOpenError(ctx, m.Name, err)
			return nil, false, false
		}
		if err != nil {
			archive.EmitOpenError(ctx, m.Name, err)
		}
		ctx.ChargeDecompressed(int64(len(data)))
		return data, true, true
	}
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		archive.EmitOpenError(ctx, m.Name, err)
		return nil, false, false
	}
	if int64(len(data)) > max {
		if allowPrefix {
			ctx.ChargeDecompressed(max)
			return data[:max], true, true
		}
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(data)), max, "torch tar member "+m.Name)
		return nil, false, false
	}
	ctx.ChargeDecompressed(int64(len(data)))
	return data, false, true
}
