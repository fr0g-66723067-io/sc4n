package main

// dupOutputFixtures writes the fixtures for the two duplicate-output defects: a
// repeated fact becoming two findings.
//
// Both are one-artifact-one-fact violations rather than format properties. The
// safetensors header object is deserialised by the reference loader into a map,
// so a repeated top-level key is accepted and only its last value survives; the
// decoder's job is to report the duplicate once and then walk the file the loader
// would build. The ONNX custom-domain rule reports an operator the runtime must
// supply as native code, and an onnxruntime-optimised model repeats that domain on
// hundreds of nodes: the fact is "this artifact needs a native operator set", not
// one fact per node, so the finding is aggregated per (domain, kind) and carries
// the number of uses and the first offset.
func init() {
	register(contributor{
		name:     "dup-output",
		fixtures: dupOutputFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return dupOutputExpectations(), dupOutputBenignExpectations()
		},
	})
}

func dupOutputFixtures(f *fixtureSet) {
	// A repeated top-level tensor key. json.loads and serde_json both accept this
	// and keep the last value, so the file loads; the duplicate must be reported
	// once, and the surviving entry must be the one the loader sees rather than
	// both entries, which made the contiguity pass report the tensor as
	// overlapping its own shadow (two findings for one accepted file).
	f.add("safetensors_dup_top_key.safetensors", stBuild(
		`{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}`,
		make([]byte, 8),
	))

	// A model whose graph puts two nodes in one runtime-supplied domain, and
	// imports the same domain as an op set. Both uses are one fact each: the
	// domain needs a plugin, so the contract is one finding per (domain, kind),
	// not one per node (a real onnxruntime-optimised model has hundreds).
	f.add("onnx_dup_domain_aggregate.onnx", pbCat(
		pbVar(1, 8), // ir_version
		pbStr(2, "sc4n-fixture"),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(8, pbOpset("com.example", 1)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(1, pbNode("fuse1", "Fused", "com.example")),
			pbBytes(1, pbNode("fuse2", "Fused", "com.example")),
		)),
	))

	// Benign control: two distinct tensors, contiguous and non-overlapping. It is
	// the counterpart of the duplicate-key fixture -- it must stay clean, so the
	// de-duplication cannot be implemented by dropping tensors and the contiguity
	// pass cannot be silenced to hide the duplicate.
	f.add("benign/dup_output_distinct.safetensors", stBuild(
		`{"a":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"b":{"dtype":"F32","shape":[2],"data_offsets":[8,16]}}`,
		make([]byte, 16),
	))
}

func dupOutputExpectations() map[string]expectation {
	return map[string]expectation{
		"safetensors_dup_top_key.safetensors": {
			Expect: []string{"SC4N-SAFETENSORS-STRUCT"},
			Forbid: []string{"SC4N-SAFETENSORS-TRAILING-DATA", "SC4N-SAFETENSORS-TRUNCATED"},
			Notes:  "One accepted file whose header object repeats the tensor key \"a\": the reference loader deserialises the header into a map, so the last value wins and the file loads. The duplicate is a structural violation and must be reported exactly once; keeping both entries made the contiguity pass then report the surviving tensor as overlapping its own shadow.",
		},
		"onnx_dup_domain_aggregate.onnx": {
			Expect: []string{"SC4N-ONNX-CUSTOM-DOMAIN"},
			Forbid: []string{"SC4N-ONNX-STRUCT"},
			Notes:  "Two nodes and one opset import in the runtime-supplied domain com.example. All of it is one fact about the artifact -- the domain needs a native plugin -- so the rule reports one finding per distinct (domain, kind) pair carrying the use count and the first offset, not one per node.",
		},
	}
}

func dupOutputBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/dup_output_distinct.safetensors": {
			Expect: []string{},
			Notes:  "Two genuinely distinct tensors with contiguous, non-overlapping extents. It is the control for the duplicate-top-level-key fixture: a de-duplication implemented by dropping tensors, or by silencing the contiguity pass, has to fail somewhere, and it must not fail here.",
		},
	}
}
