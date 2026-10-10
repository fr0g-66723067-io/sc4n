package hfcache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// buildRepo lays out one `models--org--repo` directory with a blob referenced
// from two snapshot commits, refs, and a `.no_exist` marker.
func buildRepo(t *testing.T) (dir, blobPath, commitA, commitB, sha string) {
	t.Helper()
	dir = t.TempDir()
	repo := filepath.Join(dir, "models--org--repo")
	blobs := filepath.Join(repo, "blobs")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	sha = strings.Repeat("a", 64)
	blobPath = filepath.Join(blobs, sha)
	if err := os.WriteFile(blobPath, []byte("blob-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitA = strings.Repeat("1", 40)
	commitB = strings.Repeat("2", 40)
	for _, c := range []string{commitA, commitB} {
		snap := filepath.Join(repo, "snapshots", c)
		if err := os.MkdirAll(snap, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(snap, "model.safetensors")
		if err := os.Symlink(filepath.Join("..", "..", "blobs", sha), link); err != nil {
			t.Fatal(err)
		}
	}
	refs := filepath.Join(repo, "refs")
	if err := os.MkdirAll(refs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refs, "main"), []byte(commitA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	noexist := filepath.Join(repo, ".no_exist", commitB)
	if err := os.MkdirAll(noexist, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(noexist, "absent.bin"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

func TestTwoRevisionsOneBlobScannedOnce(t *testing.T) {
	dir, blobPath, _, _, sha := buildRepo(t)
	entries, err := Expand(dir, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry for a blob reachable from 2 revisions, got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Path != blobPath {
		t.Errorf("entry path = %q, want %q", e.Path, blobPath)
	}
	if e.Digest != sha {
		t.Errorf("entry digest = %q, want %q", e.Digest, sha)
	}
	if e.Revision != "main" {
		t.Errorf("entry revision = %q, want main", e.Revision)
	}
	if !strings.Contains(e.Display, "snapshots") {
		t.Errorf("entry display = %q, want a snapshot path", e.Display)
	}
	// The `.no_exist` marker must not contribute an entry.
	for _, e := range entries {
		if strings.Contains(e.Display, ".no_exist") {
			t.Errorf("unexpected .no_exist entry: %q", e.Display)
		}
	}
}

func TestEscapingSymlinkIsReportedNotScanned(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--org--repo")
	snap := filepath.Join(repo, "snapshots", strings.Repeat("3", 40))
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(snap, "leak")); err != nil {
		t.Fatal(err)
	}
	c := report.NewCollector(0)
	if _, err := Expand(dir, c); err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !hasRule(c.Findings(), RuleSymlinkEscape.ID) {
		t.Fatalf("expected %s, got %v", RuleSymlinkEscape.ID, ids(c.Findings()))
	}
}

func TestMissingBlobAndMalformedRef(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--org--repo")
	snap := filepath.Join(repo, "snapshots", strings.Repeat("4", 40))
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "blobs", "deadbeef"), filepath.Join(snap, "gone")); err != nil {
		t.Fatal(err)
	}
	refs := filepath.Join(repo, "refs")
	if err := os.MkdirAll(refs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refs, "bad"), []byte("not-a-commit"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := report.NewCollector(0)
	if _, err := Expand(dir, c); err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !hasRule(c.Findings(), RuleBlobMissing.ID) {
		t.Errorf("expected %s, got %v", RuleBlobMissing.ID, ids(c.Findings()))
	}
	if !hasRule(c.Findings(), RuleRefMalformed.ID) {
		t.Errorf("expected %s, got %v", RuleRefMalformed.ID, ids(c.Findings()))
	}
}

func TestExpandRejectsNonDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Expand(f, nil); err == nil {
		t.Fatal("expected an error for a non-directory")
	}
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func ids(fs []report.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

// TestCopiedCacheWithoutSymlinksKeepsEveryRepo: a hub cache copied or extracted
// without symlinks has a regular file under each snapshots/<commit>/ directory.
// De-duplicating on the file's basename collapsed every repository's config.json
// into one entry, so every repository after the first was never scanned and its
// findings never appeared.
func TestCopiedCacheWithoutSymlinksKeepsEveryRepo(t *testing.T) {
	dir := t.TempDir()
	commits := []string{strings.Repeat("1", 40), strings.Repeat("2", 40)}
	repos := []string{"models--org--one", "models--org--two"}
	for i, repo := range repos {
		snap := filepath.Join(dir, repo, "snapshots", commits[i])
		if err := os.MkdirAll(snap, 0o755); err != nil {
			t.Fatal(err)
		}
		body := `{"index": ` + string(rune('0'+i)) + `}`
		if err := os.WriteFile(filepath.Join(snap, "config.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := Expand(dir, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected one entry per repository, got %d: %+v", len(entries), entries)
	}
	// Both entries name a distinct file, and their content keys differ.
	if entries[0].Path == entries[1].Path {
		t.Fatalf("both entries point at %q", entries[0].Path)
	}
	if entries[0].Digest == entries[1].Digest {
		t.Fatalf("both entries share the content key %q", entries[0].Digest)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Path, "config.json") {
			t.Errorf("entry path = %q, want a config.json", e.Path)
		}
	}
}
