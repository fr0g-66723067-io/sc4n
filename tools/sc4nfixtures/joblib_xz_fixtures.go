package main

// joblibXZFixtures commits the xz-stream fixture for the loader escalation.
//
// The stream is data rather than something the generator computes, because the
// standard library has no xz writer and a hand-rolled encoder would be a second
// implementation of the format under test. It was produced once, on the
// reference host, with exactly:
//
//	python3 -c '...write the 41-byte witness pickle...' > /tmp/w.pkl
//	xz -1 -T1 -c /tmp/w.pkl > /tmp/w.xz     # 100 bytes, `xz -t` accepts it
//	xxd -p /tmp/w.xz
//
// The payload is the same builtins.eval(42) pickle as zlib_level2_eval.pkl.zlib,
// so a reader can compare the two rows: zlib is unwrapped and the eval is
// reported at critical; xz is not unwrapped, and the escalation exists to say
// that joblib.load will still load it.
func init() {
	register(contributor{
		name:     "joblib-xz",
		fixtures: joblibXZFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"joblib_xz_pickle.joblib": {
					Expect: []string{
						"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION",
						"SC4N-JOBLIB-UNSCANNED-PAYLOAD",
					},
					Notes: "A valid xz stream (`xz -t` accepts it) named .joblib, holding the " +
						"builtins.eval(42) pickle from zlib_level2_eval.pkl.zlib. joblib.load's " +
						"_detect_compressor reads the xz magic and decompresses before unpickling, so this " +
						"file executes its payload on load while the scanner can only report that it did not " +
						"look inside. The medium names the algorithm and the offset; the critical states the " +
						"consequence for the loader.",
				},
			}, map[string]expectation{}
		},
	})
}

func joblibXZFixtures(f *fixtureSet) {
	f.add("joblib_xz_pickle.joblib", []byte{
		0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
		0x02, 0x00, 0x21, 0x01, 0x10, 0x00, 0x00, 0x00, 0xa8, 0x70, 0x8e, 0x86,
		0x01, 0x00, 0x28, 0x80, 0x04, 0x95, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x8c, 0x08, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x73,
		0x94, 0x8c, 0x04, 0x65, 0x76, 0x61, 0x6c, 0x94, 0x93, 0x94, 0x8c, 0x02,
		0x34, 0x32, 0x94, 0x85, 0x94, 0x52, 0x94, 0x2e, 0x00, 0x00, 0x00, 0x00,
		0x46, 0xc6, 0x57, 0x9c, 0x92, 0x88, 0x8f, 0xb4, 0x00, 0x01, 0x41, 0x29,
		0x03, 0x53, 0x56, 0x8b, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x59, 0x5a,
	})
}
