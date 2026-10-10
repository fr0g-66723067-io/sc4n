// Package torch parses the PyTorch checkpoint family: the new-format zip
// (torch.save since 1.6), TorchScript, the .pt2 export archive, the legacy binary
// layout and the legacy tar layout.
//
// Torch is the highest-value target sc4n covers, because every one of those
// shapes routes attacker-controlled bytes into `pickle.load`:
//
//   - new zip: `data.pkl`, plus `constants.pkl` / `*.debug_pkl` for TorchScript;
//   - `.pt2`: `data/sample_inputs/*.pt` are real torch.save pickles and
//     `data/constants/custom_obj_*` are TorchBind objects;
//   - legacy: a sequence of pickles (magic, protocol, sys_info, object,
//     storage_keys) followed by raw storage;
//   - legacy tar: the `pickle` member is the object graph.
//
// The package's own job is therefore *shape*: identify which container is in
// front of the scanner, emit the shape rule, and hand every member to the central
// dispatch (artifact.ScanMember through archive.Scan) so the pickle engine and the
// Python analyser see exactly the bytes they would see for a bare member. No
// member is ever extracted to disk and nothing is executed.
//
// The one dispatch subtlety: the built-in magic sniffer claims "PK\x03\x04" as a
// generic zip at priority 100, so a content sniffer that must distinguish
// torch/keras/npz/pt2 has to run *above* it. This package registers at 110 and
// returns a match only when the member names are unambiguously torch, so a
// non-torch zip is never swallowed (it falls through to the magic table).
package torch

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// sniffer priority. It must beat the built-in "magic" sniffer (100) for a
// non-prefixed zip, and it must beat the "tarkind" sniffer (90) for a legacy tar.
// It returns false cheaply for every other byte content (a 16-byte head read),
// so running first costs nothing on the common path.
const snifferPriority = 110

// maxSniffNames bounds how many zip member names the sniffer reads to classify a
// torch shape. Real torch archives have a handful of members; a crafted archive
// that pushes its markers past this cap is still scanned by the generic archive
// walker (so `data.pkl` still reaches the pickle engine) -- it only loses the
// torch-specific shape rule.
const maxSniffNames = 4096

// zipSig is the first local file header of a zip torch writes.
var zipSig = []byte("PK\x03\x04")

type zipParser struct{}

// Parse emits the shape rule and delegates the member walk to the archive layer,
// which dispatches every member through artifact.ScanMember. That is what puts
// data.pkl / constants.pkl / *.debug_pkl in front of pickle.Walk and
// code/**/*.py in front of the Python analyser without this package reimplementing
// either the naming or the depth accounting.
func (zipParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	switch ctx.Format {
	case artifact.FormatTorchNew:
		ctx.Sink.Emit(ruleTorchZip, 0, "new-format torch zip: data.pkl + data/<n> storages")
	case artifact.FormatTorchScript:
		ctx.Sink.Emit(ruleTorchScript, 0, "TorchScript archive: code/**/*.py is attacker-controlled Python stored as data")
	}
	return parseZipLike(ctx, s)
}

// parseZipLike reports the prefixed-archive shape and then runs the generic
// archive walk. It is shared by the new-format, TorchScript and .pt2 parsers.
func parseZipLike(ctx *artifact.Ctx, s source.Source) error {
	if !startsWithPK(s) {
		ctx.Sink.Emit(ruleTorchPrefixedArchive, 0,
			"the zip begins after a non-zip prefix; PyTorchStreamReader derives the archive base from the first record and still opens it")
	}
	return archive.Scan(ctx, s)
}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatTorchNew,
		Magic:     "PK\\x03\\x04 (first member data.pkl)",
		Depth:     artifact.DepthDeep,
		Container: true,
		Notes: "members are dispatched by content: data.pkl reaches the pickle engine, code/**/*.py reaches " +
			"the Python analyser, data/<n> storage blobs are scanned as opaque bytes. A zip whose local " +
			"header is preceded by a prefix is still unwrapped (SC4N-TORCH-PREFIXED-ARCHIVE).",
	})
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatTorchScript,
		Magic:     "PK\\x03\\x04 (constants.pkl and/or code/**/*.py)",
		Depth:     artifact.DepthDeep,
		Container: true,
		Notes: "code/*.py is valid Python stored as data and is analysed; data.pkl, constants.pkl and " +
			"*.debug_pkl are walked as pickles.",
	})
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatTorchLegacy,
		Magic:     "pickled MAGIC_NUMBER 0x1950A86A20F9469CFC6C, or a tar of storages/tensors/pickle",
		Depth:     artifact.DepthDeep,
		Container: true,
		Notes: "the legacy binary layout's leading pickles (protocol version, sys_info, the object and the " +
			"storage keys) are each walked with the appended raw storage treated as storage, so storage is " +
			"not misreported as an attack suffix; the legacy tar layout's storages/tensors/pickle members " +
			"are walked the same way.",
	})
	artifact.RegisterSniffer("torch-shape", snifferPriority, sniff)
	artifact.RegisterParser(artifact.FormatTorchNew, zipParser{})
	artifact.RegisterParser(artifact.FormatTorchScript, zipParser{})
	artifact.RegisterParser(artifact.FormatTorchLegacy, legacyParser{})
	artifact.RegisterUniversal("torch-7z", sevenZipUniversal)
}

// sniff recognises every torch shape by content.
//
// It is deliberately narrow: the legacy magic, a torch tar member list, or a zip
// whose member names identify a torch shape. Anything else returns false so the
// generic magic/tarkind/archive sniffers still own it.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	if s == nil || s.Size() < 8 {
		return artifact.FormatUnknown, false
	}
	head, _ := s.Bytes(0, 16)

	// Legacy binary: the magic is a pickled int, and the plan's raw little-endian
	// forms are accepted too (detectLegacy returns the byte width of the magic).
	if _, ok := detectLegacy(head); ok {
		return artifact.FormatTorchLegacy, true
	}

	// Legacy tar: a ustar archive whose members are storages/tensors/pickle.
	if isTarShape(s) {
		if ms, err := archive.Collect(s, l); err == nil && looksTorchTar(ms) {
			return artifact.FormatTorchLegacy, true
		}
	}

	// A zip is classified by its member names. The head check is the cheap path;
	// the extension-gated path is what catches a *prefixed* archive (whose first
	// bytes are not PK) without paying an EOCD scan on every non-zip file.
	if bytes.HasPrefix(head, zipSig) || isTorchExt(s.Name()) {
		if names, err := archive.ZipNames(s, l, maxSniffNames); err == nil {
			if f, ok := classifyZip(names); ok {
				return f, true
			}
		}
	}
	return artifact.FormatUnknown, false
}

// classifyZip maps a zip member-name list to a torch shape. The order matters:
// a TorchScript archive also contains data.pkl, so constants.pkl/code must be
// checked before the generic new-format shape.
func classifyZip(names []string) (artifact.Format, bool) {
	var hasData, hasConstants, hasArchiveFormat, hasCode bool
	for _, n := range names {
		switch {
		case n == "data.pkl":
			hasData = true
		case n == "constants.pkl":
			hasConstants = true
		case n == "archive_format":
			hasArchiveFormat = true
		case n == "code" || strings.HasPrefix(n, "code/"):
			hasCode = true
		}
	}
	switch {
	case hasArchiveFormat:
		return artifact.FormatPT2, true
	case hasData && (hasConstants || hasCode):
		return artifact.FormatTorchScript, true
	case hasData:
		return artifact.FormatTorchNew, true
	}
	return artifact.FormatUnknown, false
}

// looksTorchTar reports whether a tar's member list is the legacy torch layout.
func looksTorchTar(ms archive.Members) bool {
	if ms.Format != artifact.FormatTar {
		return false
	}
	var pickleMember, storages, tensors bool
	for _, m := range ms.Members {
		switch m.Name {
		case "pickle":
			pickleMember = true
		case "storages":
			storages = true
		case "tensors":
			tensors = true
		}
	}
	return pickleMember && (storages || tensors)
}

// isTarShape reports whether the source carries the ustar magic at offset 257,
// which every tar variant Go's archive/tar accepts does.
func isTarShape(s source.Source) bool {
	if s.Size() < 262 {
		return false
	}
	b, err := s.Bytes(257, 5)
	return (err == nil || len(b) >= 5) && len(b) >= 5 && string(b[:5]) == "ustar"
}

// startsWithPK reports whether the source begins with a zip local file header.
func startsWithPK(s source.Source) bool {
	b, err := s.Bytes(0, 4)
	return (err == nil || len(b) == 4) && len(b) == 4 && bytes.Equal(b, zipSig)
}

// torchExts are the extensions that denote a torch checkpoint. An extension is
// only ever a hint (dispatch is by content); it is used here solely to decide
// whether to probe for a *prefixed* zip, which the magic table cannot see.
var torchExts = map[string]bool{
	".pt": true, ".pth": true, ".ckpt": true, ".ptl": true, ".pt2": true,
}

// isTorchExt reports whether name's extension is a torch checkpoint extension.
// The name may be a container member ("model.pt:data/x"), so only the last
// segment is inspected.
func isTorchExt(name string) bool {
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		name = name[i+1:]
	}
	return torchExts[strings.ToLower(filepath.Ext(name))]
}
