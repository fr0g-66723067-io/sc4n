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
	n := min(size, int64(prefixProbe))
	head, err := s.Bytes(0, n)
	if err != nil && len(head) < 2 {
		return artifact.FormatUnknown, false
	}
	if !plausibleHead(head) {
		// The stream does not begin at offset 0 and no protocol byte appears in the
		// first prefixProbe bytes, so this is not a pickle artifact: a Python source
		// file opens with the same letters a protocol-0 pickle does, and claiming it
		// would produce a page of structural findings for every .py in a repository.
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

// prefixProbe bounds the search for a protocol byte when the artifact does not
// start with one. It is deliberately small: the shape it exists for is a few
// bytes of header in front of a stream (the nullifAI "MZ"/junk prefix), and a
// longer prefix would make every binary artifact pay for a scan it cannot use.
const prefixProbe = 64

// plausibleHead reports whether head either starts with a plausible pickle stream
// or carries a protocol byte inside the prefix.
//
// The second case is the fix for a real miss: a two-byte prefix that is not itself
// an opcode — "MZ", "\x7fELF", a NUL — made the file unclaimable, so a stream that
// pickle.load-adjacent tooling still reaches was dispatched "unknown" and reported
// nothing at all. Measured: "MZ" and "junk" prefixes already claimed the stream
// (their first bytes pass the opcode test) while "\x7fELF" and "\x00\x11" did not,
// which is the difference between a critical os.system finding and an empty list.
func plausibleHead(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	if head[0] == opPROTO {
		return len(head) > 1 && head[1] >= 1 && head[1] <= highestProtocol
	}
	if info := opTable[head[0]]; info.name != "" && info.proto <= 1 {
		return true
	}
	for i := 1; i+1 < len(head); i++ {
		if head[i] == opPROTO && head[i+1] >= 1 && head[i+1] <= highestProtocol {
			return true
		}
	}
	return false
}
