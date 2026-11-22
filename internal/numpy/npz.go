package numpy

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// npzParser is the registered parser for a .npz artifact.
type npzParser struct{}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatNPZ,
		Magic:     "PK\\x03\\x04 with a .npy member",
		Depth:     artifact.DepthDeep,
		Container: true,
		Notes: "a zip whose members are .npy files: the archive path/link/ratio rules run via " +
			"internal/archive, and every member is dispatched through artifact.ScanMember so its own " +
			"format decides the parser (a .npy member reaches the .npy parser, an appended executable " +
			"is caught by the universal polyglot layer). Members are never extracted to disk.",
	})
	// Priority 105 is deliberately above the built-in magic table's 100: a zip's
	// first bytes are always PK\x03\x04, so the magic sniffer would otherwise
	// claim every npz as a generic zip before the member names could be read.
	artifact.RegisterSniffer("numpy-npz", 105, sniffNPZ)
	artifact.RegisterParser(artifact.FormatNPZ, npzParser{})
}

// sniffNPZ claims a zip that holds at least one .npy member. It reads only the
// central directory (archive.ZipNames), so classifying a large generic zip is
// cheap, and it never claims a zip whose first 4 KiB of names name no .npy.
//
// A zip whose .npy member sits past the sampling window still gets its members
// scanned: it is dispatched as a generic zip and internal/archive hands each
// member to artifact.ScanMember, which reaches the .npy parser anyway. The
// sniffer only decides which container parser runs, not what is scanned.
func sniffNPZ(s source.Source, l limits.Limits) (artifact.Format, bool) {
	head, err := s.Bytes(0, 4)
	if len(head) < 4 {
		return artifact.FormatUnknown, false
	}
	if !bytes.Equal(head, []byte("PK\x03\x04")) && !bytes.Equal(head, []byte("PK\x05\x06")) {
		return artifact.FormatUnknown, false
	}
	names, err := archive.ZipNames(s, l, 4096)
	if err != nil {
		return artifact.FormatUnknown, false
	}
	for _, n := range names {
		if strings.HasSuffix(strings.ToLower(n), ".npy") {
			return artifact.FormatNPZ, true
		}
	}
	return artifact.FormatUnknown, false
}

// Parse walks the .npz container.
//
// It uses archive.Collect for the member directory and archive.Open per member,
// then hands each member to artifact.ScanMemberBytes. archive.Scan would do the
// same member loop but is bound to the *zip* format; the npz parser calls the
// exported Collect/Check/Open API directly so that the format is a first-class
// one in `sc4n formats` while the archive rules still run.
func (npzParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	ms, err := archive.Collect(s, ctx.Limits)
	if err != nil {
		ctx.Sink.Emit(RuleStruct, 0, "npz container is not a readable zip: "+err.Error())
		return err
	}
	ms.Check(ctx)

	max := ctx.Limits.MaxStringBlob
	if max <= 0 {
		max = limits.Default().MaxStringBlob
	}
	for i := range ms.Members {
		m := ms.Members[i]
		if m.IsDir || m.LinkKind != "" {
			// A directory or link member carries no content; Check already
			// reported the link.
			continue
		}
		if !dispatchMember(ctx, s, m, max) {
			return nil
		}
	}
	return nil
}

// dispatchMember reads one npz member (spilling it to a private file when it
// exceeds MaxStringBlob, so a multi-gigabyte member does not have to fit in
// memory) and dispatches it through artifact.ScanMember*. It returns false when
// the scan-wide decompression budget is spent and the caller must stop.
func dispatchMember(ctx *artifact.Ctx, s source.Source, m archive.Member, max int64) bool {
	if ctx.RemainingDecompressed() == 0 {
		reportNPZDecompressed(ctx)
		return false
	}
	l := ctx.Limits
	l.MaxDecompressedBytes = ctx.RemainingDecompressed()
	rc, err := archive.Open(s, l, m)
	if err != nil {
		archive.EmitOpenError(ctx, m.Name, err)
		return true
	}
	probe, rerr := io.ReadAll(io.LimitReader(rc, max+1))
	if rerr != nil && len(probe) == 0 {
		rc.Close()
		archive.EmitOpenError(ctx, m.Name, rerr)
		return true
	}
	if rerr != nil {
		// Some bytes arrived but the member did not read to its declared end — a
		// limit, or a checksum mismatch. The archive layer's limitReader returns a
		// *LimitError rather than emitting, so reporting is the caller's job; the
		// zip path does exactly this and then scans the prefix that arrived. Doing
		// it here too means a truncated member is never parsed as if complete.
		archive.EmitOpenError(ctx, m.Name, rerr)
	}
	if int64(len(probe)) > max {
		cap := ctx.Limits.MaxSpillBytes
		if cap <= 0 {
			cap = limits.Default().MaxSpillBytes
		}
		if remaining := ctx.RemainingSpill(); remaining < cap {
			cap = remaining
		}
		if cap <= 0 {
			ctx.ReportSpillLimit(ctx.ChargeSpill(1), ctx.Limits.MaxSpillBytes)
			rc.Close()
			artifact.ScanMemberBytes(ctx, m.Name, probe)
			ctx.ChargeDecompressed(int64(len(probe)))
			return ctx.RemainingDecompressed() > 0
		}
		src, serr := source.Spill(m.Name, io.MultiReader(bytes.NewReader(probe), rc), cap)
		rc.Close()
		if serr != nil {
			var st *source.SpillTooLargeError
			if errors.As(serr, &st) {
				limits.Emit(ctx.Sink, limits.RuleSpill, "MaxSpillBytes", m.Size, st.Limit, "npz member "+snippet(m.Name))
			} else {
				ctx.Sink.Emit(RuleStruct, 0, "npz member "+snippet(m.Name)+" cannot be materialised: "+serr.Error())
			}
			// The spill may have failed after writing a bounded prefix; scan what
			// was already read instead of dropping the payload it may contain.
			artifact.ScanMemberBytes(ctx, m.Name, probe)
			ctx.ChargeSpill(cap + 1)
			ctx.ChargeDecompressed(int64(len(probe)))
			return ctx.RemainingDecompressed() > 0
		}
		artifact.ScanMember(ctx, m.Name, src)
		n := src.Size()
		src.Close()
		ctx.ChargeSpill(n)
		ctx.ChargeDecompressed(n)
		return ctx.RemainingDecompressed() > 0
	}
	rc.Close()
	artifact.ScanMemberBytes(ctx, m.Name, probe)
	ctx.ChargeDecompressed(int64(len(probe)))
	return ctx.RemainingDecompressed() > 0
}

func reportNPZDecompressed(ctx *artifact.Ctx) {
	cap := ctx.Session.TopLimits.MaxDecompressedBytes
	if cap <= 0 {
		cap = limits.Default().MaxDecompressedBytes
	}
	ctx.ReportDecompressedLimit(ctx.ChargeDecompressed(0), cap)
}

// snippet bounds a member name for evidence text.
func snippet(name string) string {
	if len(name) <= 128 {
		return name
	}
	return name[:128] + "…"
}
