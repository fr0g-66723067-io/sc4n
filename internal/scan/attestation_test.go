package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/malice"
)

// attestedPickle is PROTO 2, GLOBAL posix.system, a 31-byte command string,
// TUPLE1, REDUCE: the 63-byte artifact the unsafe corpus ships, which the walker
// grades constructed on its own.
var attestedPickle = []byte("\x80\x02cposix\nsystem\nq\x00X\x1f\x00\x00\x00nslookup pickle-rce-test.rce.lcq\x01\x85q\x02Rq\x03.")

func writeAttestation(t *testing.T, path, digest string, exec []string) {
	t.Helper()
	body := `{"version":"sc4nconfirm/1","runs":[{"sha256":"` + digest +
		`","loader":"torch.load","loaded":true,"exec":["` + exec[0] + `"]}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAttestationMerge pins the demonstrated grade's contract at the scan layer:
// it appears when the digest matches, it never appears without an attestation,
// and it never appears for an attestation about other bytes.
func TestAttestationMerge(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "pytorch_model.bin")
	if err := os.WriteFile(art, attestedPickle, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(attestedPickle)
	digest := hex.EncodeToString(sum[:])

	run := func(ix *malice.Index) map[string]int {
		t.Helper()
		res, err := Run(context.Background(), Config{Paths: []string{art}, Limits: limits.Default(), Attestations: ix})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		out := map[string]int{}
		for _, f := range res.Collector.Findings() {
			out[f.RuleID]++
		}
		return out
	}

	// No attestation: the static grades only.
	base := run(nil)
	if base["SC4N-MALICE-DEMONSTRATED"] != 0 {
		t.Fatalf("demonstrated grade without an attestation")
	}
	if base["SC4N-MALICE-CONSTRUCTED"] != 1 {
		t.Fatalf("constructed grade x%d, want 1", base["SC4N-MALICE-CONSTRUCTED"])
	}

	// The matching attestation adds exactly one demonstrated finding, attributed
	// to the artifact, and leaves the constructed grade in place.
	good := filepath.Join(dir, "good.json")
	writeAttestation(t, good, digest, []string{`/bin/sh -c nslookup x`})
	ix, err := malice.Load(good)
	if err != nil {
		t.Fatal(err)
	}
	got := run(ix)
	if got["SC4N-MALICE-DEMONSTRATED"] != 1 {
		t.Fatalf("demonstrated grade x%d, want 1", got["SC4N-MALICE-DEMONSTRATED"])
	}
	if got["SC4N-MALICE-CONSTRUCTED"] != 1 {
		t.Fatalf("constructed grade x%d, want 1", got["SC4N-MALICE-CONSTRUCTED"])
	}
	if ix.Matched() != 1 {
		t.Fatalf("Matched = %d, want 1", ix.Matched())
	}

	// An attestation about other bytes must not fabricate a finding for these.
	other := filepath.Join(dir, "other.json")
	writeAttestation(t, other, "ff"+digest[2:], []string{`/bin/sh -c id`})
	oix, err := malice.Load(other)
	if err != nil {
		t.Fatal(err)
	}
	if n := run(oix)["SC4N-MALICE-DEMONSTRATED"]; n != 0 {
		t.Fatalf("demonstrated grade x%d for an attestation about other bytes", n)
	}
	if oix.Matched() != 0 {
		t.Fatalf("Matched = %d for an attestation about other bytes", oix.Matched())
	}
}

// TestAttestationNeedsFullDigest pins the scope rule: a prefix digest identifies
// no file, so -max-hash (which downgrades the digest to a prefix) makes an
// attestation inapplicable rather than approximately applicable.
func TestAttestationNeedsFullDigest(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "pytorch_model.bin")
	if err := os.WriteFile(art, attestedPickle, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(attestedPickle)
	att := filepath.Join(dir, "att.json")
	writeAttestation(t, att, hex.EncodeToString(sum[:]), []string{"/bin/sh -c id"})
	ix, err := malice.Load(att)
	if err != nil {
		t.Fatal(err)
	}

	l := limits.Default()
	l.MaxHashBytes = 16
	res, err := Run(context.Background(), Config{Paths: []string{art}, Limits: l, Attestations: ix})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := res.Artifacts[0].SHA256Scope; got != "prefix:16" {
		t.Fatalf("sha256Scope = %q, want prefix:16", got)
	}
	for _, f := range res.Collector.Findings() {
		if f.RuleID == "SC4N-MALICE-DEMONSTRATED" {
			t.Fatal("a prefix digest matched an attestation")
		}
	}
}
