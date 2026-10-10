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
		dispatchMember(ctx, s, m, max)
	}
	return nil
}

// dispatchMember reads one npz member (spilling it to a private file when it
// exceeds MaxStringBlob, so a multi-gigabyte member does not have to fit in
// memory) and dispatches it through artifact.ScanMember*.
func dispatchMember(ctx *artifact.Ctx, s source.Source, m archive.Member, max int64) {
	rc, err := archive.Open(s, ctx.Limits, m)
	if err != nil {
		ctx.Sink.Emit(RuleStruct, 0, "npz member "+snippet(m.Name)+" cannot be read: "+err.Error())
		return
	}
	probe, rerr := io.ReadAll(io.LimitReader(rc, max+1))
	if rerr != nil && len(probe) == 0 {
		rc.Close()
		ctx.Sink.Emit(RuleStruct, 0, "npz member "+snippet(m.Name)+" cannot be read: "+rerr.Error())
		return
	}
	if int64(len(probe)) > max {
		cap := ctx.Limits.MaxSpillBytes
		if cap <= 0 {
			cap = limits.Default().MaxSpillBytes
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
			return
		}
		artifact.ScanMember(ctx, m.Name, src)
		src.Close()
		return
	}
	rc.Close()
	artifact.ScanMemberBytes(ctx, m.Name, probe)
}

// snippet bounds a member name for evidence text.
func snippet(name string) string {
	if len(name) <= 128 {
		return name
	}
	return name[:128] + "…"
}
