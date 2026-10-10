package tfmodel

// keras.go parses the Keras 3 .keras archive and its Keras 2 .h5 sibling's config
// document.
//
// A .keras file is a zip holding config.json (the model topology), metadata.json
// and model.weights.h5. The attack surface is not the numpy weights: it is
// config.json. Keras rebuilds the model from class names, and a Lambda layer
// makes that reconstruction execute marshal-unmarshalled bytecode (VU#253266 /
// CVE-2024-3660), with the safe_mode guard bypassed repeatedly (CVE-2025-1550,
// CVE-2026-12481) and ignored entirely for H5 (GHSA-36rr-ww3j-vrjv).
//
// The parser therefore does two things: it reads config.json/metadata.json and
// applies the class allowlist, and it hands every member to the generic archive
// walk so a pickle, a nested h5 or an executable member is still scanned. The
// member walk is what makes "not a Lambda" a positive statement rather than an
// absence.

import (
	"io"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// kerasMembers are the file names inside a .keras archive whose JSON documents
// carry the class names and code strings this package analyses.
var kerasMembers = map[string]bool{"config.json": true, "metadata.json": true}

// kerasParser is the registered parser for a .keras artifact.
type kerasParser struct{}

// sniffKeras claims a zip whose member list is the .keras shape: config.json plus
// model.weights.h5. The member set is disjoint from torch (archive/data.pkl),
// .pt2 (models/*.json + data/) and .npz (*.npy), so the result cannot be
// swallowed by those formats or swallow them.
//
// The priority is above the generic magic sniffer: a file starting PK\x03\x04 is
// claimed as a bare zip at priority 100, so a discriminating container sniffer
// has to run before it.
func sniffKeras(s source.Source, l limits.Limits) (artifact.Format, bool) {
	if s.Size() < 4 {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, 4)
	if err != nil || len(head) < 4 || string(head) != "PK\x03\x04" {
		return artifact.FormatUnknown, false
	}
	names, err := archive.ZipNames(s, l, 4096)
	if err != nil {
		return artifact.FormatUnknown, false
	}
	hasConfig, hasWeights := false, false
	for _, n := range names {
		switch memberBase(n) {
		case "config.json":
			hasConfig = true
		case "model.weights.h5":
			hasWeights = true
		}
	}
	if hasConfig && hasWeights {
		return artifact.FormatKeras, true
	}
	return artifact.FormatUnknown, false
}

// Parse analyses one .keras artifact.
func (kerasParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	analyzeKerasContainer(ctx, s)
	// The generic archive walk dispatches every member: config.json and
	// metadata.json as JSON, model.weights.h5 through the HDF5 parser, and any
	// member that sniffs as a pickle or native binary through its own engine.
	// A corrupt container is reported rather than aborting, so the class analysis
	// above is never the only thing that ran.
	if err := archive.Scan(ctx, s); err != nil {
		ctx.Sink.Emit(ruleKerasStruct, 0, "not a readable zip container: "+err.Error())
	}
	return nil
}

// analyzeKerasContainer reads the config-bearing members and applies the class
// analysis. A member that cannot be opened is skipped here; the archive walk
// reports it.
func analyzeKerasContainer(ctx *artifact.Ctx, s source.Source) {
	ms, err := archive.Collect(s, ctx.Limits)
	if err != nil {
		return
	}
	for i := range ms.Members {
		m := &ms.Members[i]
		if m.IsDir || m.LinkKind != "" || m.Encrypted {
			continue
		}
		if !kerasMembers[memberBase(m.Name)] {
			continue
		}
		data, ok := readMemberCapped(ctx, s, *m)
		if !ok {
			continue
		}
		analyzeKerasDocument(ctx, 0, m.Name, data)
	}
}

// readMemberCapped decompresses one member into memory under the MaxStringBlob
// cap. A member larger than the cap is reported and its bounded prefix analysed,
// never silently skipped.
func readMemberCapped(ctx *artifact.Ctx, s source.Source, m archive.Member) ([]byte, bool) {
	rc, err := archive.Open(s, ctx.Limits, m)
	if err != nil {
		return nil, false
	}
	defer rc.Close()
	cap := ctx.Limits.MaxStringBlob
	if cap <= 0 {
		cap = limits.Default().MaxStringBlob
	}
	if m.Size > cap {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", m.Size, cap, "member "+m.Name)
	}
	data, err := io.ReadAll(io.LimitReader(rc, cap))
	if err != nil && len(data) == 0 {
		return nil, false
	}
	return data, true
}

// memberBase returns the final path element of an archive member name.
func memberBase(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name
}
