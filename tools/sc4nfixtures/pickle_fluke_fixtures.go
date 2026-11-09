package main

// The "pickle fluke" fixtures pin the boundary between a pickle that is inside
// another file's bytes (a real payload prefix, which must be reported) and a run
// of bytes that merely decodes as a pickle (a coincidence, which must not be).
//
// The measured case: a 196 KB WebP in a live repository carries PROTO 4,
// LONG1(9 bytes), STOP at offset 129551 inside its entropy-coded body. The pickle
// sniffer claimed the file (a PROTO byte sat inside its 64-byte prefix probe) and
// the walker accepted the 14-byte run as a complete stream, so an image produced
// SC4N-PICKLE-PREFIX and SC4N-PICKLE-TRAILING at high — two false positives on a
// benign asset. Two rules now decide against it: a file that opens with a media
// magic is not claimed by the pickle sniffer (artifact.LeadingContainerMagic), and
// a candidate found by the prefix scan must decode more than a scalar before STOP
// (walker.probePickle's needEvidence).
//
// The positive control is pickle_leading_bytes.pkl, which already pins the
// nullifAI shape: a junk prefix in front of a stream that names a global is still
// reported.

func init() {
	register(contributor{
		name:     "pickle_fluke",
		fixtures: pickleFlukeFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return pickleFlukeExpectations(), nil
		},
	})
}

// flukeStream is the exact 14 bytes the WebP's body decoded as: PROTO 4, LONG1
// carrying 9 bytes, STOP. Nothing in it is a name.
var flukeStream = []byte{0x80, 0x04, 0x8a, 0x09, 0x22, 0xe3, 0x3c, 0xd2, 0xb1, 0x82, 0x87, 0x5b, 0x8a, 0x2e}

// entropyBody returns n bytes with no NUL and no long opcode run, the shape an
// entropy-coded image body has.
func entropyBody(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(0x81 + (i*37)%0x60)
	}
	// Put a PROTO byte inside the first 64 bytes, which is what made the sniffer
	// claim the file before the magic guard existed.
	if n > 40 {
		out[40], out[41] = 0x80, 0x04
	}
	return out
}

func pickleFlukeFixtures(f *fixtureSet) {
	// A RIFF/WEBP container whose body decodes as a 14-byte pickle.
	webp := []byte("RIFF")
	webp = append(webp, 0x40, 0x2e, 0x0b, 0x00) // size, unused by the scanner
	webp = append(webp, []byte("WEBPVP8 ")...)
	webp = append(webp, entropyBody(1000)...)
	webp = append(webp, flukeStream...)
	webp = append(webp, entropyBody(400)...)
	f.add("pickle_fluke/webp_proto_fluke.webp", webp)

	// The same fluke deep inside a binary with no magic at all: the prefix scan
	// finds it at a random offset, which is the case the evidence rule decides.
	blob := append(entropyBody(600), flukeStream...)
	blob = append(blob, entropyBody(200)...)
	f.add("pickle_fluke/binary_deep_fluke.bin", blob)
}

func pickleFlukeExpectations() map[string]expectation {
	return map[string]expectation{
		"pickle_fluke/webp_proto_fluke.webp": {
			Forbid: []string{"SC4N-PICKLE-PREFIX", "SC4N-PICKLE-TRAILING", "SC4N-PICKLE-STRUCT"},
			Notes: "A WebP whose body decodes as PROTO+LONG1+STOP. The media magic keeps the pickle " +
				"sniffer from claiming it, so an image no longer carries two high pickle findings.",
		},
		"pickle_fluke/binary_deep_fluke.bin": {
			Forbid: []string{"SC4N-PICKLE-PREFIX", "SC4N-PICKLE-TRAILING", "SC4N-PICKLE-STRUCT"},
			Notes: "The same 14 bytes at offset 600 inside a binary with no recognised magic: a " +
				"candidate found by the prefix scan has to decode more than one scalar before STOP.",
		},
	}
}
