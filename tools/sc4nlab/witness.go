package main

// witnessPickle is the payload every container mutant wraps: a protocol-4 pickle
// of builtins.eval(42), the same 41 bytes as the uncompressed head of
// testdata/fixtures/zlib_level2_eval.pkl.zlib.
//
// It is a witness rather than a weapon on purpose. The lab's question is "does
// the scanner see the payload through this wrapper", and the smallest pickle the
// engine already calls critical answers that question without the artifact ever
// being opened by a loader outside a container that only validates structure.
func witnessPickle() []byte {
	return []byte{
		0x80, 0x04, 0x95, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x8c, 0x08, 'b', 'u', 'i', 'l', 't', 'i', 'n', 's', 0x94,
		0x8c, 0x04, 'e', 'v', 'a', 'l', 0x94, 0x93, 0x94,
		0x8c, 0x02, '4', '2', 0x94, 0x85, 0x94, 0x52, 0x94, 0x2e,
	}
}
