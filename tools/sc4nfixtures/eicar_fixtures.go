package main

// eicarFixtures writes the EICAR self-test marker fixtures.
//
// The marker is the industry's scanner self-test: a corpus that contains it
// contains an artifact every antivirus product quarantines, and a scanner that
// says nothing about it reports the file as clean. The benign fixture is prose
// that *names* the standard without reproducing the marker.
func init() {
	register(contributor{
		name:     "eicar",
		fixtures: eicarFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return eicarExpectations(), eicarBenignExpectations()
		},
	})
}

func eicarFixtures(f *fixtureSet) {
	f.addText("eicar/eicar_test_file", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n\n")
	f.addText("benign/eicar_prose.txt", "EICAR is the antivirus test-file standard.\n")
}

func eicarExpectations() map[string]expectation {
	return map[string]expectation{
		"eicar/eicar_test_file": {
			Expect: []string{"SC4N-CONTENT-EICAR"},
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "The 68-byte EICAR antivirus self-test, verbatim. Low severity: it is not malware, " +
				"but a scanner that stays silent reports the file as clean.",
		},
	}
}

func eicarBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/eicar_prose.txt": {
			Forbid: []string{"SC4N-CONTENT-EICAR"},
			Notes:  "Prose naming the standard without reproducing the marker.",
		},
	}
}
