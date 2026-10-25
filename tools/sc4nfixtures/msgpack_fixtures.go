package main

import "bytes"

// msgpackFixtures writes the MessagePack fixtures.
//
// MessagePack is data-only, so the fixtures pin the three shapes that matter: a
// binary blob that is itself a pickle (Flax/JAX/MLX store arrays as blobs, so a
// blob is the one place a second format can hide), a truncated length, and a run
// of NaN-shaped bytes used as a payload carrier.
func init() {
	register(contributor{
		name:     "msgpack",
		fixtures: msgpackFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return msgpackExpectations(), msgpackBenignExpectations()
		},
	})
}

func msgpackFixtures(f *fixtureSet) {
	gadget := cat(
		proto(4),
		stackGlobal("os", "system"),
		shortBinUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	)

	// A parameter blob that is a pickle stream.
	f.add("msgpack_nested_pickle.msgpack", mfMap(mfStr("params"), mfBin(gadget)))

	// A blob that is a run of NaN-shaped float pairs, the classic way to carry a
	// payload through numeric code untouched.
	f.add("msgpack_nan/flax_model.msgpack", mfMap(mfStr("w"), mfBin(bytes.Repeat([]byte{0x7f, 0xf8}, 6))))

	// A document cut mid-value, in the shape a truncated fetch produces: an
	// array16 of 2001 values whose first 2000 decode, then a str32 that declares
	// 65535 bytes with three present, padded to 4 KiB. The sniffer claims a
	// truncated document only on a decoded prefix of an artifact at least 4 KiB
	// long, so a four-byte header pair no longer qualifies (and no longer
	// describes anything a reader could act on).
	truncated := []byte{0xdc, 0x07, 0xd1}
	for range 2000 {
		truncated = append(truncated, 0x01)
	}
	truncated = append(truncated, 0xdb, 0x00, 0x00, 0xff, 0xff, 'x', 'y', 'z')
	truncated = append(truncated, make([]byte, 4096-len(truncated))...)
	f.add("msgpack_truncated.msgpack", truncated)

	// Benign: a Flax-style parameter tree with no blob payloads.
	f.add("benign/flax_model.msgpack", mfMap(
		mfStr("model"), mfStr("flax"),
		mfStr("params"), mfMap(mfStr("dense"), mfStr("kernel")),
	))
}

func msgpackExpectations() map[string]expectation {
	return map[string]expectation{
		"msgpack_nested_pickle.msgpack": {
			Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-MSGPACK-STRUCT"},
			Notes:  "A binary blob whose bytes are a protocol-4 os.system pickle; the blob must be dispatched to the pickle engine.",
		},
		"msgpack_nan/flax_model.msgpack": {
			Expect: []string{"SC4N-MSGPACK-NAN-PAYLOAD"},
			Forbid: []string{"SC4N-MSGPACK-STRUCT"},
			Notes:  "A blob made of six NaN-shaped byte pairs: a payload carrier, reported at info because a run has benign explanations.",
		},
		"msgpack_truncated.msgpack": {
			Expect: []string{"SC4N-MSGPACK-STRUCT"},
			Notes: "A 4 KiB array16 whose 2000 decoded values are followed by a str32 that " +
				"declares 65535 bytes with three present: the bounded walker reports the " +
				"truncation rather than reading past the buffer, and the size floor keeps " +
				"four-byte header pairs from being claimed as documents.",
		},
	}
}

func msgpackBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/flax_model.msgpack": {
			Notes: "A Flax-style nested string map with no blob payloads; the correct output is no finding at all.",
		},
	}
}

func mfStr(s string) []byte { return cat([]byte{0xa0 | byte(len(s))}, []byte(s)) }

func mfBin(b []byte) []byte { return cat([]byte{0xc4, byte(len(b))}, b) }

// mfMap builds a fixmap from alternating key/value byte slices.
func mfMap(kv ...[]byte) []byte {
	out := []byte{0x80 | byte(len(kv)/2)}
	for _, p := range kv {
		out = append(out, p...)
	}
	return out
}
