package main

// pickleBlobFixtures writes the negative control for the pickle sniffer's silent
// probe: a torch storage member that is not a pickle.
//
// The shape was found by the top-downloads campaign on Bingsu/adetailer's YOLO
// checkpoints. A `data/<n>` member is raw float32 values; two of them begin with
// the bytes 0x5d 0x2e, which are EMPTY_LIST and STOP — a complete two-opcode
// pickle. The sniffer accepted the member, the walker stopped at offset 2, and the
// parser reported a high SC4N-PICKLE-TRAILING about the other 126 bytes. Twice, on
// a repository of published ultralytics weights.
//
// The fix is an opcode floor on a handshake-free stream, so the fixture pins both
// halves: this blob must not be claimed, and the two-opcode stream itself must
// still be a pickle when the artifact is exactly that stream (the protocol byte is
// the handshake that exempts it).
func init() {
	register(contributor{
		name:     "pickle-blob",
		fixtures: pickleBlobFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{},
				map[string]expectation{
					"benign/pickle_storage_blob.bin": {
						Forbid: []string{
							"SC4N-PICKLE-TRAILING", "SC4N-PICKLE-SEGMENT", "SC4N-PICKLE-STRUCT",
							"SC4N-PICKLE-PREFIX", "SC4N-PICKLE-GLOBAL-CRITICAL",
						},
						Notes: "128 bytes of float32 storage whose first two bytes are EMPTY_LIST + STOP. " +
							"torch.save writes one of these per tensor, so a checkpoint carries hundreds; " +
							"claiming the format made every one of them a candidate for a high " +
							"SC4N-PICKLE-TRAILING about the rest of the blob.",
					},
				}
		},
	})
}

func pickleBlobFixtures(f *fixtureSet) {
	blob := make([]byte, 128)
	blob[0], blob[1] = 0x5d, 0x2e // EMPTY_LIST, STOP
	// The rest is float-ish: no opcode letter runs, no second STOP.
	for i := 2; i < len(blob); i++ {
		blob[i] = byte(0x2d + (i*7)%0x40)
	}
	f.add("benign/pickle_storage_blob.bin", blob)
}
