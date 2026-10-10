package main

import "bytes"

// round3Fixtures writes the regression fixtures for the round-3 review. Each one
// is the crafted input that reproduced a defect found in that review, kept so the
// fix cannot regress silently: a corpus fixture is the only form of "this exact
// byte sequence must keep behaving this way" that the gate enforces on every run.
//
// Every fixture here is a *shape*, not a live sample: the payloads are generated
// opcodes, the webhook is a placeholder and no real endpoint is contacted.
func init() {
	register(contributor{
		name:     "round3",
		fixtures: round3Fixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return round3Expectations(), nil
		},
	})
}

func round3Fixtures(f *fixtureSet) {
	gadget := cat(
		proto(4),
		stackGlobal("os", "system"),
		shortBinUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	)

	// A structured dtype whose single field is an object: descr is a list of
	// (name, format) pairs, so h.dtype stays empty and the object field has to be
	// recognised through h.structured. numpy.load(allow_pickle=True) executes the
	// data section for this form exactly as it does for descr '|O'.
	f.add("round3/npy_struct_object.npy", nfNPY(
		"{'descr': [('a', '|O')], 'fortran_order': False, 'shape': (1,)}", gadget))

	// A conformant zip written by Go's archive/zip: the local headers carry the
	// data-descriptor flag (bit 3) and zero crc/sizes, with the real values in the
	// descriptor after the data. The archive is valid; only the comparison between
	// local and central values has to know about the flag.
	f.add("round3/zip_data_descriptor.zip", nfZip(map[string][]byte{"m.pkl": gadget}))

	// An HDF5 whose model_config sits behind 4096 empty JSON objects. The shallow
	// reader recovers JSON objects by scanning for '{', and it used to stop at a
	// fixed cap and return the truncated set as complete, so decoys in front of a
	// Lambda hid a critical finding.
	lambda := `{"class_name":"Sequential","config":{"name":"h","layers":[` +
		`{"class_name":"Lambda","config":{"name":"l","function":{"class_name":"__lambda__",` +
		`"config":{"code":null,"defaults":null,"closure":null}}}}]}}`
	f.add("round3/h5_json_cap.h5", h5File(
		bytes.Repeat([]byte("{}"), 4096), []byte("model_config\x00"), []byte(lambda)))

	// joblib's real inline layout at protocol 2: the array bytes sit between the
	// wrapper's BUILD and the outer STOP. The mask that hides the payload from the
	// object-graph walk used to write POP, which is outside the weights-only opcode
	// set, so masking a well-formed file made sc4n report its own injection.
	f.add("round3/joblib_inline.joblib", round3JoblibInline(
		cat([]byte{bBININT1, 2}, []byte{bBININT1, 3}), nfPayload(make([]byte, 48))))

	// Two rebindings in one stream: slot 0 is rebound to a second name and slot 1
	// to a third, so no name is bound in two slots and the only signal is the
	// rebinding itself. It must produce exactly one finding, with the final count.
	f.add("round3/pickle_rebind.pkl", cat(
		proto(4),
		globalText("collections", "OrderedDict"),
		[]byte{bBINPUT, 0x00},
		globalText("posix", "system"),
		[]byte{bBINPUT, 0x00},
		globalText("os", "popen"),
		[]byte{bBINPUT, 0x01},
		globalText("os", "system"),
		[]byte{bBINPUT, 0x01},
		[]byte{bNONE},
		[]byte{bTUPLE},
		[]byte{bREDUCE},
		stop(),
	))

	// A metadata document holding two JSON values, the second carrying a webhook.
	// The name matters: config.json is routed to the card/metadata layer, which
	// decoded only the first value and never saw the second.
	f.add("round3/two_docs/config.json", []byte(
		`{"model_type":"bert"}`+"\n"+
			`{"note":"https://discord.com/api/webhooks/123456789012345678/`+
			`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}`+"\n"))

	// A Jinja template in a .txt file. .txt is the untyped text extension, so the
	// content decides: the leading "{{" must route it to the template analyser, and
	// the correct classification must not be reported as a name/content mismatch.
	f.add("round3/template_txt.txt", []byte("{{ ''.__class__.__mro__ }}\n"))

	// A .npy whose descr nests 200 levels around a valid field. The literal reader
	// recursed once per level with no bound, so a deep enough descr overflowed the
	// goroutine stack — a fatal error, not a panic, which scanGuarded cannot catch.
	// 200 levels is past the documented maxLitDepth (64) and, with a valid field at
	// the bottom, is the smallest shape whose verdict the bound changes: an
	// unbounded reader accepts it as a descriptor, the bounded one refuses it.
	deep := "{'descr': " + repeat("[", 200) + "('a', '<i4')" + repeat("]", 200) +
		", 'fortran_order': False, 'shape': (1,)}"
	f.add("round3/npy_deep_descr.npy", nfNPY(deep, make([]byte, 4)))

	// One statement of 4000 nested exec( calls. The call analysis scans from each
	// '(' to the end of the statement, so this is quadratic in the nesting and was
	// unbounded: the scan deadline is observed between artifacts, so -timeout could
	// not stop it either. It must trip the call-token budget and report it.
	nest := 4000
	f.add("round3/pysrc_nested_calls.py", []byte(
		"exec("+repeat("exec(", nest)+"1"+repeat(")", nest+1)+"\n"))

	// A map whose one blob is a run of NaN-shaped float pairs. The rule is emitted
	// for the blob, and its offset must be the blob's offset in the artifact, not
	// its index inside the blob.
	f.add("round3/msgpack_nan.msgpack", cat(
		[]byte{0x81, 0xa1, 'w', 0xc4, 0x0c},
		bytes.Repeat([]byte{0x7f, 0xf8}, 6),
	))
}

// repeat returns s repeated n times. strings.Repeat would do, but the fixture
// writer keeps its inputs to one import and no formatting.
func repeat(s string, n int) string {
	var b bytes.Buffer
	b.Grow(len(s) * n)
	for range n {
		b.WriteString(s)
	}
	return b.String()
}

// round3JoblibInline builds a protocol-2 joblib stream whose array payload sits
// between the wrapper's BUILD and the outer STOP, which is the layout joblib's own
// writer produces. The protocol matters: at 4 and 5 the stream is outside the
// weights-only opcode set for its protocol alone, which would mask the property
// this fixture exists to pin.
func round3JoblibInline(dims []byte, tail []byte) []byte {
	return cat(
		proto(2),
		globalText("joblib.numpy_pickle", "NumpyArrayWrapper"),
		[]byte{bMARK},
		binUnicode("<f8"),
		[]byte{bMARK},
		dims,
		[]byte{bTUPLE},
		binUnicode("C"),
		[]byte{bNEWFALSE},
		[]byte{bNONE},
		[]byte{bTUPLE},
		[]byte{bREDUCE},
		[]byte{bNONE},
		[]byte{bBUILD},
		tail,
		stop(),
	)
}

func round3Expectations() map[string]expectation {
	return map[string]expectation{
		"round3/npy_struct_object.npy": {
			Expect: []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-NUMPY-STRUCT"},
			Notes: "A structured dtype — descr as a list of (name, format) pairs — whose one field is " +
				"an object. Only the scalar descr form was recognised, so this shape reached neither " +
				"SC4N-NUMPY-OBJECT-ARRAY nor the pickle engine while numpy.load(allow_pickle=True) " +
				"executed it exactly as it does the scalar form.",
		},
		"round3/zip_data_descriptor.zip": {
			Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL"},
			Forbid: []string{"SC4N-ARCHIVE-NAME-MISMATCH", "SC4N-ARCHIVE-MEMBER-ERROR"},
			Notes: "A conformant zip from Go's archive/zip: bit 3 is set and the local crc/sizes are " +
				"zero, with the real values in the data descriptor after the data. Comparing the local " +
				"header against the central directory without honouring the flag reported every such " +
				"archive as a name mismatch, including committed benign fixtures.",
		},
		"round3/h5_json_cap.h5": {
			Expect: []string{"SC4N-KERAS-LAMBDA"},
			Forbid: []string{"SC4N-HDF5-STRUCT"},
			Notes: "model_config behind 4096 empty JSON objects. The shallow JSON recovery stopped at a " +
				"fixed object cap and returned the truncated set as complete, so decoys in front of a " +
				"Lambda hid a critical finding (Keras ignores safe_mode for H5, GHSA-36rr-ww3j-vrjv).",
		},
		"round3/joblib_inline.joblib": {
			Forbid: []string{
				"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
				"SC4N-JOBLIB-WRAPPER-MISMATCH",
			},
			Notes: "A protocol-2 joblib stream in joblib's own inline layout: the array bytes sit between " +
				"the wrapper's BUILD and the outer STOP. The payload mask used POP, which is outside the " +
				"weights-only opcode set, so masking a file whose own opcodes were all accepted made sc4n " +
				"report SC4N-PICKLE-REQUIRES-UNSAFE-LOADER against its own mask. The same bytes with the " +
				"payload after the STOP were clean, which is why the defect was layout-dependent.",
		},
		"round3/pickle_rebind.pkl": {
			Expect: []string{"SC4N-PICKLE-MEMO-ALIAS"},
			Notes: "Two memo rebindings (slot 0 and slot 1), no name bound in two slots. The finding is " +
				"emitted once per stream from flush, so the evidence carries the final rebinding count; " +
				"the emit key used to embed the count, which made it unique per rebinding and let a 400 KB " +
				"stream produce 100000 findings and grow the dedup map without bound. " +
				"TestRound3FixtureCounts asserts the count is exactly one.",
		},
		"round3/two_docs/config.json": {
			Expect: []string{"SC4N-STRING-C2"},
			Notes: "config.json holding two JSON values, the second with a webhook. The metadata layer " +
				"decoded one value and ignored the rest, so the second document was neither decoded nor " +
				"scanned — while the same bytes in a plain .json produced SC4N-STRING-C2.",
		},
		"round3/template_txt.txt": {
			Expect: []string{"SC4N-JINJA-PY-OBJECT"},
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A Jinja template saved as .txt. The JSON guess accepted the leading '{' of '{{', so " +
				"the file was claimed as JSON, never reached the template analyser, and the " +
				"misclassification was reported as a name/content mismatch. .txt lists Jinja in the " +
				"extension table, so the correct classification is not a contradiction.",
		},
		"round3/npy_deep_descr.npy": {
			Expect: []string{"SC4N-NUMPY-STRUCT"},
			Forbid: []string{"SC4N-NUMPY-OBJECT-ARRAY"},
			Notes: "A .npy whose descr nests 200 levels around a valid field. The literal reader recursed " +
				"once per level with no bound, so a deep enough descr produced an uncatchable fatal stack " +
				"overflow (exit 2, no report) rather than a structural finding. 200 levels is past the " +
				"documented maxLitDepth of 64: an unbounded reader accepts this descriptor, the bounded " +
				"one refuses it as not a dtype, which is the deliberate trade the bound makes.",
		},
		"round3/pysrc_nested_calls.py": {
			Expect: []string{"SC4N-LIMIT-ENTRIES"},
			Notes: "One statement of 4000 nested exec( calls. The call analysis scans from each '(' to " +
				"the end of the statement, so the cost is quadratic in the nesting; the call-token budget " +
				"bounds it and the truncation is reported as SC4N-LIMIT-ENTRIES/MaxCallTokens. 60000 " +
				"nested calls measured over 120 s before the bound.",
		},
		"round3/msgpack_nan.msgpack": {
			Expect: []string{"SC4N-MSGPACK-NAN-PAYLOAD"},
			Notes: "A one-entry map whose blob is six NaN-shaped float pairs. The finding's offset must " +
				"be the blob's offset in the artifact (5), not its index inside the blob (0), which is " +
				"what every other finding in the parser reports. " +
				"TestRound3FixtureCounts asserts the offset.",
		},
	}
}
