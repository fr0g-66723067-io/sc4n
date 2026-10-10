package main

import "encoding/binary"

// xgbFixtures writes the XGBoost/UBJSON fixtures.
//
// The point of this family is the *routing* contract and the UBJSON frame:
//
//   - an XGBoost `.pkl` (a `Booster` snapshot) is a pickle, and the fixture proves
//     it reaches the pickle engine rather than this package;
//   - a UBJSON `.ubj` model is data, and the fixture proves the walk reaches the
//     root value and reports bytes appended after it (which the XGBoost reader
//     ignores).
func init() {
	register(contributor{
		name:     "xgb",
		fixtures: xgbFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return xgbExpectations(), xgbBenignExpectations()
		},
	})
}

func xgbFixtures(f *fixtureSet) {
	// A UBJSON object followed by a planted payload. The object is well-formed so
	// the walk reaches its end and the trailing region is what remains.
	root := append([]byte{xbObject}, xbKey("model")...)
	root = append(root, xbStr("boosted-tree")...)
	root = append(root, xbObjectEnd)
	root = append(root, []byte("PLANTED-UBJ-TRAILING-PAYLOAD")...)
	f.add("xgb_model.ubj", root)

	// A Booster snapshot: a pickle. XGBoost's own documentation says the in-memory
	// snapshot is not secure, and a REDUCE-bearing stream reaches whatever
	// callable it names.
	f.add("xgb_booster.pkl", cat(
		proto(4),
		stackGlobal("os", "system"),
		binUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	))

	// Benign: a well-formed UBJSON model with a typed int32 array and exact
	// framing.
	benign := append([]byte{xbObject}, xbKey("learner")...)
	benign = append(benign, xbObject)
	benign = append(benign, xbKey("weights")...)
	benign = append(benign, xbTypedI32Array([]int32{1, 2, 3})...)
	benign = append(benign, xbObjectEnd, xbObjectEnd)
	f.add("benign/xgb_model.ubj", benign)

	// Benign: the default since-2.1.0 JSON model (data only).
	f.addText("benign/xgb_model.json",
		`{"version":[2,1,0],"learner":{"gradient_booster":{"model":{"trees":[]}}}}`)
}

func xgbExpectations() map[string]expectation {
	return map[string]expectation{
		"xgb_model.ubj": {
			Expect: []string{"SC4N-XGB-UBJ-TRAILING"},
			Forbid: []string{"SC4N-XGB-UBJ-STRUCT", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A well-formed XGBoost UBJSON object with bytes appended after the root value. " +
				"XGBoost's reader decodes exactly one root value and never sees the tail, which is the " +
				"smuggling shape.",
		},
		"xgb_booster.pkl": {
			Expect: []string{"SC4N-PICKLE-REDUCE", "SC4N-PICKLE-GLOBAL-CRITICAL"},
			Forbid: []string{"SC4N-XGB-UBJ-STRUCT", "SC4N-XGB-UBJ-TRAILING"},
			Notes: "An XGBoost Booster snapshot is a pickle whose REDUCE reaches os.system. It must be " +
				"claimed by the pickle engine (sniffer priority 95), not by the UBJSON sniffer, proving " +
				"the legacy/pickle shapes are routed to the engine.",
		},
	}
}

func xgbBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/xgb_model.ubj": {
			Forbid: []string{"SC4N-XGB-UBJ-STRUCT", "SC4N-XGB-UBJ-TRAILING", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A well-formed UBJSON model with a typed int32 array and exact framing: the " +
				"false-positive gate for the UBJSON walker.",
		},
		"benign/xgb_model.json": {
			Forbid: []string{"SC4N-XGB-UBJ-STRUCT", "SC4N-XGB-UBJ-TRAILING", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "An XGBoost model in its default since-2.1.0 JSON form: data only, handled by the " +
				"JSON parser. It must not be misrouted to the UBJSON parser.",
		},
	}
}

// The UBJSON builder. XGBoost writes strings and object keys as `L` + int64
// big-endian length + bytes, integers with the smallest signed marker, and typed
// numeric arrays as `[` `$` <type> `#` `L` <count> <raw big-endian elements>.

const (
	xbObject    = '{'
	xbObjectEnd = '}'
	xbArray     = '['
	xbType      = '$'
	xbCount     = '#'
	xbInt64     = 'L'
	xbInt32     = 'l'
	xbString    = 'S'
)

// xbKey writes an object key: length-prefixed without the `S` marker.
func xbKey(k string) []byte {
	return append(xbLen(len(k)), k...)
}

// xbStr writes a string value: `S` + length + bytes.
func xbStr(s string) []byte {
	return append([]byte{xbString}, append(xbLen(len(s)), s...)...)
}

func xbLen(n int) []byte {
	b := []byte{xbInt64}
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(n))
	return append(b, v[:]...)
}

// xbTypedI32Array writes `[` `$` `l` `#` `L` <count> <count * int32 BE>.
func xbTypedI32Array(vals []int32) []byte {
	b := []byte{xbArray, xbType, xbInt32, xbCount}
	b = append(b, xbLen(len(vals))...)
	for _, v := range vals {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], uint32(v))
		b = append(b, raw[:]...)
	}
	return b
}
