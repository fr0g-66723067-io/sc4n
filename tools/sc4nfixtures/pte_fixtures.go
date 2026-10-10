package main

import "encoding/binary"

// pteFixtures writes the ExecuTorch / PyTorch-Mobile fixtures.
//
// The header layout is from https://docs.pytorch.org/executorch/stable/pte-file-format.html:
// a uint32 flatbuffer root offset at byte 0, the file magic `ET`+two ASCII digits
// at byte 4, and an optional extended header (`eh`+two digits) carrying the
// program size and the segment region. The malicious fixture embeds a validated
// ELF in the segment region so the segment scan has something to find.
func init() {
	register(contributor{
		name:     "pte",
		fixtures: pteFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return pteExpectations(), pteBenignExpectations()
		},
	})
}

func pteFixtures(f *fixtureSet) {
	f.add("pte_custom.pte", ptBuild("12", "12", 64, tinyELF()))

	// Benign: a valid header with no segment data.
	f.add("benign/tiny.pte", ptBuild("10", "10", 48, nil))
}

func pteExpectations() map[string]expectation {
	return map[string]expectation{
		"pte_custom.pte": {
			Expect: []string{"SC4N-PTE-UNVERIFIED", "SC4N-PTE-NATIVE"},
			Forbid: []string{"SC4N-PTE-STRUCT", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A valid `.pte` header whose segment region holds a validated ELF. sc4n does not " +
				"decode the flatbuffer graph (hence PTE-UNVERIFIED) but it does scan the opaque segment " +
				"region for an embedded executable, which the runtime maps and hands to the backend.",
		},
	}
}

func pteBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/tiny.pte": {
			Forbid: []string{
				"SC4N-PTE-STRUCT",
				"SC4N-PTE-NATIVE",
				"SC4N-POLYGLOT-NATIVE",
				"SC4N-FORMAT-EXTENSION-MISMATCH",
			},
			Notes: "A valid `.pte` header with no declared segment data: the false-positive gate for " +
				"the header verifier and the segment native scan.",
		},
	}
}

// ptBuild assembles a `.pte` header plus an optional segment region.
func ptBuild(version, extVersion string, progSize int64, segData []byte) []byte {
	const segBase = 64
	b := make([]byte, 40)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 32) // arbitrary in-range flatbuffer root offset
	copy(b[4:], "ET"+version)
	copy(b[8:], "eh"+extVersion)
	le.PutUint32(b[12:], 40)
	le.PutUint64(b[16:], uint64(progSize))
	if len(segData) == 0 {
		le.PutUint64(b[24:], 48)
		le.PutUint64(b[32:], 0)
		out := make([]byte, 48)
		copy(out, b)
		return out
	}
	le.PutUint64(b[24:], segBase)
	le.PutUint64(b[32:], uint64(len(segData)))
	out := make([]byte, segBase)
	copy(out, b)
	out = append(out, segData...)
	return out
}
