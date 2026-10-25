package main

// trtFixtures writes the TensorRT serialized-engine fixtures.
//
// The format has one honest claim: `ftrt` at offset 0, the section table not
// interpreted, the indicator engine over the first 4 MiB and last 1 MiB. The
// malicious fixture puts an indicator in the head window; the benign one is a
// bare header, which must produce the depth note and nothing above info.
func init() {
	register(contributor{
		name:     "trt",
		fixtures: trtFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return trtExpectations(), trtBenignExpectations()
		},
	})
}

func trtFixtures(f *fixtureSet) {
	eng := make([]byte, 64<<10)
	copy(eng, "ftrt")
	copy(eng[4096:], "os.system")
	f.add("trt/engine_with_indicator.engine", eng)

	f.add("benign/tiny.engine", []byte("ftrt\x00\x00\x00\x00"))
}

func trtExpectations() map[string]expectation {
	return map[string]expectation{
		"trt/engine_with_indicator.engine": {
			Expect: []string{"SC4N-TRT-UNVERIFIED", "SC4N-METADATA-CODE"},
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A serialized engine whose section-table region names `os.system` at 4096. The " +
				"indicator engine covers the head window, so the call is reported inside an artifact " +
				"that no Python parser would ever open.",
		},
	}
}

func trtBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/tiny.engine": {
			Expect: nil,
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH", "SC4N-METADATA-CODE"},
			Notes:  "A bare `ftrt` header: recognised, shallow, and nothing above info.",
		},
	}
}
