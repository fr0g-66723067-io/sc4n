package pickle

import (
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// parser is the registered parser for a bare pickle artifact.
type parser struct{}

// Parse walks the whole artifact as one or more pickles.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	_, err := Walk(ctx, s, Options{})
	return err
}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatPickle,
		Magic:  "\\x80 01..05 (PROTO) or a protocol-0/1 opener verified by a full opcode walk",
		Depth:  artifact.DepthDeep,
		Notes: "every opcode is decoded and every global is classified against the PyTorch weights-only " +
			"allowlist and the gadget tables; the walk is total, so a structural error is reported and " +
			"scanning resumes rather than aborting. Concatenated segments are each walked, and bytes before " +
			"the first opcode or after the last STOP are reported as their own findings.",
	})
	artifact.RegisterSniffer("pickle-walk", 95, sniff)
	artifact.RegisterParser(artifact.FormatPickle, parser{})
}

// sniff accepts a stream only after a bounded silent walk reaches a STOP without a
// structural error, or decodes at least eight opcodes cleanly in a protocol-bearing
// stream that is larger than the probe budget.
//
// A byte-pattern test is not enough here. A protocol-0/1 pickle opens with an
// ordinary letter ('c' for GLOBAL, '(' for MARK, ']' for EMPTY_LIST), and a Python
// source file opens with those letters too, so a pattern sniffer would classify
// source as a pickle and produce a page of structural findings for every .py file
// in a repository.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 2 || (l.MaxArtifactBytes > 0 && size > l.MaxArtifactBytes) {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, 2)
	if err != nil && len(head) < 2 {
		return artifact.FormatUnknown, false
	}
	if head[0] != opPROTO {
		info := opTable[head[0]]
		if info.name == "" || info.proto > 1 {
			return artifact.FormatUnknown, false
		}
	} else if head[1] < 1 || head[1] > highestProtocol {
		return artifact.FormatUnknown, false
	}

	data, err := s.Bytes(0, size)
	if err != nil && len(data) == 0 {
		return artifact.FormatUnknown, false
	}
	budget := len(data)
	if budget > maxProbeBytes {
		budget = maxProbeBytes
	}
	probe := &walker{
		silent:  true,
		lim:     l,
		data:    data,
		limit:   budget,
		mm:      newMemo(len(data)),
		globals: map[string]*Global{},
		structs: map[string]*structStat{},
		once:    map[string]bool{},
	}
	if probe.probePickle(0) {
		return artifact.FormatPickle, true
	}
	// A payload may precede the pickle stream — the nullifAI shape from the
	// February 2025 Hugging Face campaign — so a clean pickle that starts later in
	// the file still means the file is a pickle artifact. Without this the parser
	// would never run on exactly the files the shape was built to slip past.
	if _, ok := probe.locateStreamStart(); ok {
		return artifact.FormatPickle, true
	}
	return artifact.FormatUnknown, false
}
