package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/malice"
)

const digestA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestAddRunFoldsDuplicateDigests pins the producer half of the attestation
// contract. A malware corpus copies one payload into several repositories, so the
// same bytes arrive at several paths; the reader refuses a duplicate digest
// (an ambiguous attestation is a producer bug), which makes folding them here the
// producer's job.
//
// The failure this pins was found on the real corpus: 84 artifacts folded to 62
// digests, and before the fold `sc4n scan -attestation` refused the whole file.
func TestAddRunFoldsDuplicateDigests(t *testing.T) {
	var runs []malice.Run
	idx := map[string]int{}

	addRun(&runs, idx, malice.Run{
		SHA256: digestA, Path: "repo-a/model.bin",
		Exec: []string{"/bin/sh -c id"},
	})
	addRun(&runs, idx, malice.Run{
		SHA256: digestA, Path: "repo-b/model.bin",
		Connect: []string{"1.2.3.4:80"}, Loaded: true,
	})

	if len(runs) != 1 {
		t.Fatalf("got %d runs, want the two identical digests folded into 1", len(runs))
	}
	r := runs[0]
	if r.Path != "repo-a/model.bin" {
		t.Fatalf("path = %q, want the first path kept", r.Path)
	}
	if len(r.Exec) != 1 || len(r.Connect) != 1 {
		t.Fatalf("effects were not unioned: exec=%v connect=%v", r.Exec, r.Connect)
	}
	if !r.Loaded {
		t.Fatal("loaded = false, want the union to keep the successful load")
	}

	// A run with no digest cannot be folded: it identifies nothing.
	addRun(&runs, idx, malice.Run{Path: "dir-without-config"})
	addRun(&runs, idx, malice.Run{Path: "another-dir"})
	if len(runs) != 3 {
		t.Fatalf("got %d runs, want the two digest-less runs kept separately", len(runs))
	}
}

// TestAttestationRoundTrip is the contract with the scanner: what this tool
// writes must load under malice's strict reader (unknown fields refused, version
// checked, no duplicate digests).
func TestAttestationRoundTrip(t *testing.T) {
	var runs []malice.Run
	idx := map[string]int{}
	addRun(&runs, idx, malice.Run{
		SHA256: digestA, Path: "a", Loader: "torch.load",
		Exec: []string{"/bin/sh -c id", "/bin/sh -c hostname"},
	})
	addRun(&runs, idx, malice.Run{
		SHA256: digestA, Path: "b", Loader: "torch.load",
		Exec: []string{"/bin/sh -c id"},
	})

	b, err := json.Marshal(malice.Attestation{Version: malice.Version, Runs: runs})
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/att.json"
	if err := writeAttestation(path, malice.Attestation{Version: malice.Version, Runs: runs}); err != nil {
		t.Fatal(err)
	}
	ix, err := malice.Load(path)
	if err != nil {
		t.Fatalf("the scanner refused what this tool wrote: %v", err)
	}
	if got := ix.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
	r := ix.For("full", digestA)
	if r == nil {
		t.Fatal("For did not match the digest")
	}
	if strings.Join(r.Exec, "|") != "/bin/sh -c hostname|/bin/sh -c id" {
		t.Fatalf("exec list = %v, want the deduplicated union", r.Exec)
	}
	if len(b) == 0 {
		t.Fatal("empty attestation bytes")
	}
}
