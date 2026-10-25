package main

import "encoding/base64"

// pickleFixtures writes the pickle-family fixtures.
//
// Each fixture reproduces a published attack or a field-observed scanner bug. The
// bytes are written by hand rather than produced by `pickle.dump` because the
// point of most of them is a property of the *byte stream* (an opcode at offset 0,
// a malformed opcode after a valid payload, a name assembled by STACK_GLOBAL) that
// a well-behaved serialiser would never emit.
func init() {
	register(contributor{
		name:     "pickle",
		fixtures: pickleFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return pickleExpectations(), pickleBenignExpectations()
		},
	})
}

func pickleFixtures(f *fixtureSet) {
	// --- direct gadget: os.system -------------------------------------------------
	// The canonical 2021-2025 pickle payload: STACK_GLOBAL so the name never
	// appears as "os.system" in the bytes, then REDUCE calls it.
	f.add("pickle_gadget_os_system.pkl", cat(
		proto(4),
		stackGlobal("os", "system"),
		shortBinUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// --- STACK_GLOBAL + code string ----------------------------------------------
	// builtins.eval called with a source string that itself imports and executes.
	f.add("pickle_stack_global.pkl", cat(
		proto(4),
		stackGlobal("builtins", "eval"),
		shortBinUnicode("__import__('os').system('id')"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// --- extension registry -------------------------------------------------------
	// EXT1 carries no name: the class is whatever the loading process registered,
	// so the artifact's behaviour depends on the host.
	f.add("pickle_ext_registry.pkl", cat(
		proto(2),
		[]byte{bEXT1, 0x01},
		stop(),
	))

	// --- memo rebinding (ShadowPickle overwritten-module shape) -------------------
	// Bind an allowlisted name to memo slot 0, then bind a different name to the
	// same slot. A scanner that collects names sees "collections.OrderedDict"; the
	// object the stream actually calls is posix.system. Reference: ShadowPickle,
	// arXiv 2607.17503.
	f.add("pickle_memo_overwrite.pkl", cat(
		proto(4),
		globalText("collections", "OrderedDict"),
		[]byte{bBINPUT, 0x00},
		stackGlobal("posix", "system"),
		[]byte{bBINPUT, 0x00},
		shortBinUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// --- allowlisted callable with a code-string argument ------------------------
	// The ShadowPickle motivating stream: `GLOBAL collections OrderedDict` + a code
	// string + REDUCE. Every name in it is allowlisted by
	// torch.load(weights_only=True), so no name-based policy can see it; the only
	// observable is the string argument. Protocol 2 and no protocol-4 opcode, so
	// this fixture trips exactly one rule.
	shadowPayload := "if not 'hypervisor' in open('/proc/cpuinfo').read(): import os; os.system('id')"
	f.add("pickle_code_string_allowlisted.pkl", cat(
		proto(2),
		globalText("collections", "OrderedDict"),
		[]byte{bMARK},
		binUnicode(shadowPayload),
		[]byte{bTUPLE},
		[]byte{bREDUCE},
		stop(),
	))

	// --- SETITEM into a non-dict -------------------------------------------------
	// CVE-2026-24747 / GHSA-63cw-57p8-fm3p: the reference unpickler assigns into
	// whatever is on the stack without a type check.
	f.add("pickle_setitem_target.pkl", cat(
		proto(2),
		[]byte{bEMPTY_LIST},
		binUnicode("k"),
		binUnicode("v"),
		[]byte{bSETITEM},
		stop(),
	))

	// --- valid payload followed by a malformed opcode ----------------------------
	// Exception-oriented programming (arXiv 2508.19774): a scanner that raises at
	// the first error never reaches the payload. Here the payload comes first and a
	// truncated BINUNICODE follows it, so a scanner that parses the whole stream
	// before reporting anything reports nothing.
	f.add("pickle_eop_truncated.pkl", cat(
		proto(4),
		stackGlobal("os", "system"),
		binUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		[]byte{bBINUNICODE}, u4(0xFFFFFFFF), // declared length with no payload
	))

	// --- two concatenated pickles, payload in the second -------------------------
	// STOP is not end-of-file. A reader that loops over load() executes every
	// segment, while a scanner that stops at the first STOP sees only the dict.
	f.add("pickle_stacked.pkl", cat(
		proto(2), []byte{bEMPTY_DICT}, stop(),
		proto(4), stackGlobal("os", "system"), binUnicode("id"), []byte{bTUPLE1}, []byte{bREDUCE}, stop(),
	))

	// --- executable opcode at stream offset 0 ------------------------------------
	// The classic protocol-0 gadget, and the field-observed scanner bug: an opcode
	// scan that starts at index 1 never sees the GLOBAL at byte 0.
	f.add("pickle_offset_zero.pkl", []byte("cos\nsystem\n(S'id'\ntR."))

	// --- base64-obfuscated payload ----------------------------------------------
	// builtins.exec called with a base64 literal. The step-9 obfuscation rule
	// reports the long literal; the step-2 rules report the global and the REDUCE.
	enc := base64.StdEncoding.EncodeToString([]byte("import os;os.system('id')"))
	f.add("pickle_b64_exec.pkl", cat(
		proto(2),
		globalText("builtins", "exec"),
		binUnicode(enc),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// --- payload ahead of the pickle stream --------------------------------------
	// The nullifAI shape from the February 2025 Hugging Face campaign: the payload
	// is at the start of the file and the pickle follows it, so a scanner that
	// starts at the first valid opcode reports the pickle and never mentions the
	// source text in front of it.
	f.add("pickle_leading_bytes.pkl", cat(
		[]byte("if not 'hypervisor' in open('/proc/cpuinfo').read(): import os; os.system('id')\n"),
		proto(4),
		stackGlobal("posix", "system"),
		binUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// --- memo-alias: two routes to one name ---------------------------------------
	// joblib's NumpyArrayWrapper emits its own STACK_GLOBAL numpy.dtype per array,
	// so a benign sklearn .joblib binds one name in several memo slots. That is not
	// the ShadowPickle signal: a name-keyed allowlist sees the same spelling every
	// time. The fixture is the shape that made
	// ptouch/phishing-distilbert-cyber207/log_reg_model.joblib report high.
	f.add("memo_routes/joblib_shape.pkl", cat(
		proto(2),
		stackGlobal("numpy", "dtype"),
		[]byte{bMEMOIZE},
		stackGlobal("numpy", "dtype"),
		[]byte{bMEMOIZE},
		[]byte{bBINGET, 0x00},
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// One name reached two ways: written literally by GLOBAL and assembled from
	// strings by STACK_GLOBAL. The spelling a name-keyed allowlist matches is not
	// the spelling the loader resolves, which is what the rule is for.
	f.add("memo_routes/two_routes.pkl", cat(
		proto(2),
		globalText("pickle", "loads"),
		[]byte{bBINPUT, 0x00},
		stackGlobal("pickle", "loads"),
		[]byte{bBINPUT, 0x01},
		[]byte{bNONE},
		stop(),
	))

	// --- numpy reconstruction: the critical is conditional on the dtype -----------
	// The gadget entry says "_reconstruct … with object dtype can hold arbitrary
	// objects", so the critical belongs to the object-dtype streams only. Before
	// this pair existed the critical fired for every numpy reconstruct, which made
	// 74 of the unsafe corpus's 274 criticals sklearn models that store numeric
	// arrays.
	f.add("pickle_numpy_float.pkl", cat(
		proto(2),
		stackGlobal("numpy.core.multiarray", "_reconstruct"),
		[]byte{bEMPTY_DICT},
		[]byte{bEMPTY_TUPLE},
		shortBinUnicode("f4"),
		[]byte{bTUPLE3},
		[]byte{bREDUCE},
		stop(),
	))
	f.add("pickle_numpy_object.pkl", cat(
		proto(2),
		stackGlobal("numpy.core.multiarray", "_reconstruct"),
		[]byte{bEMPTY_DICT},
		[]byte{bEMPTY_TUPLE},
		shortBinUnicode("O"),
		[]byte{bTUPLE3},
		[]byte{bREDUCE},
		stop(),
	))
	// The dtype as an instance, which is the shape joblib and torch write: the
	// spelling is inside a nested REDUCE, not a bare argument.
	f.add("pickle_numpy_dtype_object.pkl", cat(
		proto(2),
		stackGlobal("numpy.core.multiarray", "_reconstruct"),
		[]byte{bEMPTY_DICT},
		[]byte{bEMPTY_TUPLE},
		stackGlobal("numpy", "dtype"),
		shortBinUnicode("O"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		[]byte{bTUPLE3},
		[]byte{bREDUCE},
		stop(),
	))

	// --- benign: a real-structure torch state dict --------------------------------
	// The false-positive gate for the whole pickle engine. Every global is one the
	// weights-only unpickler accepts, the persistent id is the ("storage", …)
	// shape the loader permits, and every opcode is inside the accepted set, so the
	// correct output is no finding at all.
	f.add("benign/torch_state_dict.pkl", benignStateDict())

	// --- benign: a plain dict ------------------------------------------------------
	f.add("benign/plain_dict.pkl", cat(
		proto(2),
		[]byte{bEMPTY_DICT},
		[]byte{bMARK},
		binUnicode("model_type"),
		binUnicode("bert"),
		binUnicode("hidden_size"),
		binUnicode("768"),
		[]byte{bSETITEMS},
		stop(),
	))
}

// benignStateDict builds the pickle torch 2.x writes for a single F32 tensor.
//
// Structure, in order: a dict, then for the key "weight" the
// torch._utils._rebuild_tensor_v2 reduce with (storage_pid, storage_offset, size,
// stride, requires_grad, backward_hooks). The storage is a persistent id of the
// ("storage", dtype, key, location, numel) shape, which is exactly the one shape
// the loader's persistent_load accepts.
func benignStateDict() []byte {
	return cat(
		proto(2),
		[]byte{bEMPTY_DICT},
		[]byte{bBINPUT, 0x00},
		[]byte{bMARK},
		binUnicode("weight"),
		globalText("torch._utils", "_rebuild_tensor_v2"),
		[]byte{bMARK},
		// persistent id: ("storage", "FloatStorage", 0, "cpu", 512)
		[]byte{bMARK},
		binUnicode("storage"),
		binUnicode("FloatStorage"),
		[]byte{bBININT}, u4(0),
		binUnicode("cpu"),
		[]byte{bBININT}, u4(512),
		[]byte{bTUPLE},
		[]byte{bBINPERSID},
		// storage_offset 0, size (16, 32), stride (32, 1), requires_grad False, {}
		[]byte{bBININT}, u4(0),
		[]byte{bBININT1, 2},
		cat([]byte{bMARK}, []byte{bBININT1, 16}, []byte{bBININT1, 32}, []byte{bTUPLE}),
		cat([]byte{bMARK}, []byte{bBININT1, 32}, []byte{bBININT1, 1}, []byte{bTUPLE}),
		[]byte{bNEWFALSE},
		[]byte{bEMPTY_DICT},
		[]byte{bTUPLE},
		[]byte{bREDUCE},
		[]byte{bSETITEMS},
		stop(),
	)
}
