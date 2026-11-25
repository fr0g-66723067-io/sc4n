package pickle

import (
	"bytes"
	"compress/zlib"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestSniffRejectsOneLinePythonStartingWithCompileOrImport(t *testing.T) {
	// A one-line .py file starting with 'c' (GLOBAL) or 'i' (INST) hits short
	// EOF after reading its first newline. That is not a line-cap overflow and
	// must not trip LineOverflow to claim Python source as a pickle.
	for _, src := range []string{
		"compile('x', '', 'exec')\n",
		"import os\n",
		"import sys\n",
		"call_something()\n",
	} {
		s := source.Mem("one.py", []byte(src))
		got, ok := sniff(s, limits.Default())
		s.Close()
		if ok {
			t.Errorf("one-line python source %q was claimed as %s", src, got)
		}
	}
}

func TestSniffAcceptsProtocolZeroStartingWithZlibCollidingBytes(t *testing.T) {
	// "(S" = 0x28 0x53 satisfies (0x28<<8|0x53)%31 == 0 and CINFO=2 <= 7, so a
	// two-byte RFC 1950 check alone falsely rejected valid protocol-0 pickles.
	p0 := []byte("(S'id'\nios\nsystem\n.")
	s := source.Mem("p0.pkl", p0)
	got, ok := sniff(s, limits.Default())
	s.Close()
	if !ok || got != artifact.FormatPickle {
		t.Fatalf("protocol-0 starting with '(S' was not claimed: got %s, %v", got, ok)
	}

	// BINUNICODE (0x58) with length 9 (0x09) also satisfies 0x5809 % 31 == 0.
	p1 := []byte{opBINUNICODE, 9, 0, 0, 0, 'o', 's', '_', 'p', 'a', 'y', 'l', 'o', 'a', opSTOP}
	// Make a valid protocol-1 stream with a global so the sniffer accepts it cleanly.
	p1 = append([]byte{opBINUNICODE, 9, 0, 0, 0}, []byte("123456789")...)
	p1 = append(p1, []byte("cos\nsystem\n(S'id'\ntR.")...)
	s1 := source.Mem("p1.pkl", p1)
	got1, ok1 := sniff(s1, limits.Default())
	s1.Close()
	if !ok1 || got1 != artifact.FormatPickle {
		t.Fatalf("protocol-1 starting with BINUNICODE len=9 was not claimed: got %s, %v", got1, ok1)
	}

	// A genuine zlib stream must still be rejected by the pickle sniffer so the
	// archive zlib sniffer unwraps it instead of walking compressed bytes.
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	_, _ = zw.Write([]byte("cos\nsystem\n(S'id'\ntR."))
	_ = zw.Close()
	sz := source.Mem("real.zlib", zbuf.Bytes())
	if _, zok := sniff(sz, limits.Default()); zok {
		t.Fatal("real zlib stream was claimed by pickle sniffer")
	}
	sz.Close()
}

func TestProtocolZeroNotSkippedWhenConstantEmbedsProto4Pickle(t *testing.T) {
	// Protocol-0 stream at offset 0 whose os.system gadget runs BEFORE a string
	// constant embedding a benign protocol-4 pickle. walker.run must test offset
	// 0 before searching for a later PROTO.
	data := []byte("cos\nsystem\n(S'id'\ntR0(S'\x80\x04N.'\nt.")
	_, fs := walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE")
	mustNotHave(t, fs, "SC4N-PICKLE-PREFIX")
}

func TestUnicodeOpcodeDecodesRawUnicodeEscapes(t *testing.T) {
	// Protocol-0 UNICODE ('V') decodes Python raw-unicode-escape (\uXXXX and
	// \UXXXXXXXX) before STACK_GLOBAL assembles "os.system".
	stream := []byte("V\\u006f\\u0073\nV\\U00000073\\u0079stem\n\x93(S'id'\ntR.")
	_, fs := walk(t, stream)
	mustHave(t, fs, "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE")

	// Even backslashes before \u must remain literal per Python raw-unicode-escape.
	got, err := unescapeRawUnicode([]byte(`\\u006f`))
	if err != nil || got != `\\u006f` {
		t.Fatalf("even backslashes: got %q, %v; want %q, nil", got, err, `\\u006f`)
	}
	got3, err := unescapeRawUnicode([]byte(`\\\u006f`))
	if err != nil || got3 != `\\o` {
		t.Fatalf("three backslashes: got %q, %v; want %q, nil", got3, err, `\\o`)
	}
}

func TestClassifyGadgetDeterministicAndNewEntries(t *testing.T) {
	// Overlapping libraryGadgets prefixes (pathlib.Path vs pathlib.Path.open)
	// must always resolve deterministically to the longest prefix.
	for range 200 {
		g := classifyGadget("pathlib", "Path.open.wrapper")
		if g.Class != GadgetLibrary || g.Entry != "pathlib.Path.open.*" {
			t.Fatalf("classifyGadget(pathlib, Path.open.wrapper) = %+v; want pathlib.Path.open.*", g)
		}
	}

	// STACK_GLOBAL "torch" "hub.load" must match directModules["torch.hub"].
	g := classifyGadget("torch", "hub.load")
	if g.Class != GadgetDirect || g.Entry != "torch.hub.*" {
		t.Fatalf("classifyGadget(torch, hub.load) = %+v; want GadgetDirect torch.hub.*", g)
	}

	// Newly added gadgets and cPickle remapping.
	if got := classifyGadget("_pickle", "Unpickler"); got.Class != GadgetDirect {
		t.Fatalf("_pickle.Unpickler = %+v; want GadgetDirect", got)
	}
	for _, name := range []string{"attrgetter", "methodcaller"} {
		if got := classifyGadget("operator", name); got.Class != GadgetLibrary {
			t.Fatalf("operator.%s = %+v; want GadgetLibrary", name, got)
		}
	}
	mod, fn, remapped := resolveGlobal("cPickle", "loads")
	if !remapped || mod != "pickle" || fn != "loads" {
		t.Fatalf("resolveGlobal(cPickle, loads) = %q, %q, %v; want pickle, loads, true", mod, fn, remapped)
	}
}

func TestOnceMapIsBoundedByMaxOnceKeys(t *testing.T) {
	c := report.NewCollector(0)
	w := &walker{sink: c.For("x"), once: map[string]bool{}}
	for i := 0; i < maxOnceKeys+10; i++ {
		w.emitOnce("global:m.f"+strconvItoa(i), ruleGlobalCritical, int64(i), "x")
	}
	if len(w.once) != maxOnceKeys {
		t.Fatalf("once map len = %d, want %d", len(w.once), maxOnceKeys)
	}
	if !hasRule(c.Findings(), "SC4N-LIMIT-ENTRIES") {
		t.Fatal("once-map cap did not emit SC4N-LIMIT-ENTRIES")
	}
}

func TestMissingStopReportedForTruncatedStream(t *testing.T) {
	// Valid opcodes with no STOP must reach the missing-STOP structural finding.
	data := []byte{opPROTO, 4, opEMPTY_DICT}
	_, fs := walk(t, data)
	found := false
	for _, f := range fs {
		if f.RuleID == "SC4N-PICKLE-STRUCT" && bytes.Contains([]byte(f.Evidence), []byte("missing-STOP")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing-STOP not reported; findings=%v", fs)
	}
}

func TestInstAndObjInspectArgsForCodeStringsAndMalice(t *testing.T) {
	// INST calling os.system("id") must trigger malice-constructed.
	_, fs := walk(t, []byte("(S'id'\nios\nsystem\n."))
	mustHave(t, fs, "SC4N-PICKLE-INST", "SC4N-MALICE-CONSTRUCTED")

	// OBJ calling os.system("id") must trigger malice-constructed.
	_, fs = walk(t, []byte("(cos\nsystem\nS'id'\no."))
	mustHave(t, fs, "SC4N-PICKLE-OBJ", "SC4N-MALICE-CONSTRUCTED")

	// INST calling an allowlisted class with a code string must trigger CODE-STRING.
	_, fs = walk(t, []byte("(S'__import__(\"os\").system(\"id\")'\nicollections\nOrderedDict\n."))
	mustHave(t, fs, "SC4N-PICKLE-CODE-STRING")

	// OBJ calling an allowlisted class with a code string must trigger CODE-STRING.
	_, fs = walk(t, []byte("(ccollections\nOrderedDict\nS'__import__(\"os\").system(\"id\")'\no."))
	mustHave(t, fs, "SC4N-PICKLE-CODE-STRING")
}

func TestNewObjReportsWhenClassGlobalIsNil(t *testing.T) {
	// EXT1 pushes kUnknown (global == nil); NEWOBJ on it must still emit SC4N-PICKLE-NEWOBJ.
	data := []byte{opPROTO, 2, opEXT1, 1, opEMPTY_TUPLE, opNEWOBJ, opSTOP}
	_, fs := walk(t, data)
	mustHave(t, fs, "SC4N-PICKLE-NEWOBJ")
}

func TestProtocolZeroLongExceedingInt64(t *testing.T) {
	// PyTorch's legacy MAGIC_NUMBER in protocol 0 exceeds int64 and must decode
	// without triggering bad-decimal or corrupting the walk.
	data := []byte("L119547037146038801333356L\n.")
	st, fs := walk(t, data)
	if !st.SawStop || st.StructErrors != 0 {
		t.Fatalf("SawStop=%v StructErrors=%d findings=%v", st.SawStop, st.StructErrors, fs)
	}
	mustNotHave(t, fs, "SC4N-PICKLE-STRUCT")
}

func TestSkipRangesJumpsPayloadWithoutStackMutation(t *testing.T) {
	// Build a dict { "a": <wrapper>, "b": 1 } with arbitrary non-opcode binary
	// bytes spliced in between the wrapper and the next dict key, and pass that
	// exact span via SkipRanges. The stack must remain intact (no SETITEM-TARGET
	// false positive and no INCOMPLETE/unknown-opcode findings).
	var buf bytes.Buffer
	buf.Write([]byte{opPROTO, 4, opEMPTY_DICT, opMARK, opSHORT_BINUNICODE, 1, 'a', opNONE})
	skipStart := int64(buf.Len())
	buf.Write(bytes.Repeat([]byte{0xff, 0xfe, 0x00, 0x01, 0x02}, 1000))
	skipEnd := int64(buf.Len())
	buf.Write([]byte{opSHORT_BINUNICODE, 1, 'b', opBININT1, 1, opSETITEMS, opSTOP})

	st, fs := walkOpt(t, buf.Bytes(), Options{SkipRanges: [][2]int64{{skipStart, skipEnd}}}, limits.Default())
	if !st.SawStop || st.StructErrors != 0 {
		t.Fatalf("SawStop=%v StructErrors=%d findings=%v", st.SawStop, st.StructErrors, fs)
	}
	mustNotHave(t, fs, "SC4N-PICKLE-INCOMPLETE", "SC4N-PICKLE-SETITEM-TARGET", "SC4N-PICKLE-STACK", "SC4N-PICKLE-STRUCT")
}
