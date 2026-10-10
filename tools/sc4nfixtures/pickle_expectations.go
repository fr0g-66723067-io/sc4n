package main

// pickleExpectations and pickleBenignExpectations are the rule contracts for the
// pickle-family fixtures. The "forbid" half matters more than the "expect" half:
// anyone can assert that a scanner fires on a malicious file; the property that
// makes a scanner usable is that it does not over-attribute — for example that the
// allowlisted-callable ShadowPickle stream is reported for its code string and not
// for a gadget it does not contain.
func pickleExpectations() map[string]expectation {
	return map[string]expectation{
		"pickle_gadget_os_system.pkl": {
			Expect: []string{
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
				"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
			},
			Forbid: []string{"SC4N-PICKLE-BUILD-STATE"},
			Notes: "STACK_GLOBAL os.system + REDUCE. The name never appears as the " +
				"literal os.system in the bytes, so a scanner that greps for it finds " +
				"nothing.",
		},
		"pickle_stack_global.pkl": {
			Expect: []string{
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
				"SC4N-PICKLE-CODE-STRING",
			},
			Notes: "builtins.eval called with a source string that itself imports and " +
				"executes. Both the callable and the argument are reported.",
		},
		"pickle_ext_registry.pkl": {
			Expect: []string{
				"SC4N-PICKLE-EXT",
				"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
			},
			Forbid: []string{"SC4N-PICKLE-GLOBAL-CRITICAL"},
			Notes: "EXT1 carries no name: the class is whatever the loading process " +
				"registered for extension code 1, so the file's behaviour is a property " +
				"of the host, not of the artifact.",
		},
		"pickle_memo_overwrite.pkl": {
			Expect: []string{
				"SC4N-PICKLE-MEMO-ALIAS",
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
			},
			Notes: "ShadowPickle's overwritten-module shape (arXiv 2607.17503): an " +
				"allowlisted name is bound to memo slot 0 and then the same slot is " +
				"rebound to posix.system. Name-scanning scanners see one binding per " +
				"name and cannot observe the rebinding.",
		},
		"pickle_code_string_allowlisted.pkl": {
			Expect: []string{"SC4N-PICKLE-CODE-STRING"},
			// The whole point of the fixture: every name is allowlisted, so a
			// name-based policy reports nothing.
			Forbid: []string{
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-GLOBAL-HIGH",
				"SC4N-PICKLE-GLOBAL-UNKNOWN",
				"SC4N-PICKLE-REDUCE",
				"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
				"SC4N-PICKLE-MEMO-ALIAS",
			},
			Notes: "The ShadowPickle motivating stream: GLOBAL collections " +
				"OrderedDict + a code string + REDUCE. The callable is allowlisted by " +
				"torch.load(weights_only=True) and the payload is the REDUCE argument, " +
				"so SC4N-PICKLE-CODE-STRING is the only rule that can see it.",
		},
		"pickle_setitem_target.pkl": {
			Expect: []string{"SC4N-PICKLE-SETITEM-TARGET"},
			Notes: "SETITEM into a list. The reference unpickler assigns into whatever " +
				"is on the stack without a type check: CVE-2026-24747 / " +
				"GHSA-63cw-57p8-fm3p, fixed in torch 2.10.0.",
		},
		"pickle_eop_truncated.pkl": {
			Expect: []string{
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
				"SC4N-PICKLE-INCOMPLETE",
				"SC4N-PICKLE-STRUCT",
			},
			Notes: "Exception-oriented programming (arXiv 2508.19774): a valid payload " +
				"followed by a truncated argument. A scanner that aborts or returns at " +
				"the first error reports nothing about the payload; sc4n reports the " +
				"payload and the violation.",
		},
		"pickle_stacked.pkl": {
			Expect: []string{
				"SC4N-PICKLE-SEGMENT",
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
			},
			Notes: "Two concatenated pickles with the payload in the second. Any reader " +
				"that loops over load() executes both; a scanner that stops at the first " +
				"STOP sees only the dict.",
		},
		"pickle_offset_zero.pkl": {
			Expect: []string{
				"SC4N-PICKLE-OFFSET-ZERO",
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
			},
			Notes: "The protocol-0 gadget b\"cos\\nsystem\\n(S'id'\\ntR.\". A widely " +
				"deployed scanner starts its opcode scan at index 1 and therefore never " +
				"sees the GLOBAL at byte 0.",
		},
		"pickle_b64_exec.pkl": {
			Expect: []string{
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
			},
			Notes: "builtins.exec called with a base64 literal. The literal is " +
				"reconstructed as a stack value so the obfuscation rule and the " +
				"indicator engine can see through it.",
		},
		"pickle_leading_bytes.pkl": {
			Expect: []string{
				"SC4N-PICKLE-PREFIX",
				"SC4N-PICKLE-GLOBAL-CRITICAL",
				"SC4N-PICKLE-REDUCE",
			},
			Notes: "The nullifAI shape from the February 2025 Hugging Face campaign: " +
				"the payload is ahead of the pickle stream, so scanners that start at " +
				"the first valid opcode report the pickle and never mention the source " +
				"text in front of it.",
		},
		"memo_routes/joblib_shape.pkl": {
			Forbid: []string{"SC4N-PICKLE-MEMO-ALIAS"},
			Notes: "joblib's NumpyArrayWrapper shape: the same name assembled by STACK_GLOBAL twice, " +
				"each binding its own memo slot. One route, several slots — what every serializer " +
				"that rebuilds a global per object produces, and what made " +
				"ptouch/phishing-distilbert-cyber207/log_reg_model.joblib report high.",
		},
		"memo_routes/two_routes.pkl": {
			Expect: []string{"SC4N-PICKLE-MEMO-ALIAS"},
			Notes: "The same name written literally (GLOBAL pickle\\nloads\\n) and then assembled from " +
				"strings (STACK_GLOBAL \"pickle\",\"loads\"): two routes to one resolved name, so a " +
				"scanner keyed on the literal spelling and the loader disagree about the stream. " +
				"The evidence names both routes.",
		},
	}
}

func pickleBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/torch_state_dict.pkl": {
			Notes: "The pickle torch 2.x writes for one F32 tensor: " +
				"torch._utils._rebuild_tensor_v2 (allowlisted), a (\"storage\", …) " +
				"persistent id (the only shape the loader accepts), and opcodes that " +
				"are all inside the weights-only accepted set. The correct output is no " +
				"finding at all.",
		},
		"benign/plain_dict.pkl": {
			Notes: "A protocol-2 dict of strings with no global at all.",
		},
	}
}
