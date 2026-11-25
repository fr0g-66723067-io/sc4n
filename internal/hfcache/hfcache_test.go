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

func TestDirectorySymlinkIsReportedNotSilent(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--org--repo")
	snap := filepath.Join(repo, "snapshots", strings.Repeat("5", 40))
	blobDir := filepath.Join(repo, "blobs", "dirblob")
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "blobs", "dirblob"), filepath.Join(snap, "folder")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	c := report.NewCollector(0)
	if _, err := Expand(dir, c); err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !hasRule(c.Findings(), RuleNotScanned.ID) {
		t.Fatalf("directory link was silent; findings=%v", ids(c.Findings()))
	}
}

// TestSnapshotDotNoExistIsScanned pins that a directory literally named
// `.no_exist` inside snapshots/ is walked and its files are yielded: the real
// HF cache puts `.no_exist/` as a sibling of `snapshots/`, so skipping it inside
// `snapshots/` let malicious repos hide files there.
func TestSnapshotDotNoExistIsScanned(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--org--repo")
	commit := strings.Repeat("a", 40)
	hidden := filepath.Join(repo, "snapshots", commit, ".no_exist")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(hidden, "evil.pkl")
	if err := os.WriteFile(evil, []byte("\x80\x04N."), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := Expand(dir, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Display, ".no_exist/evil.pkl") {
		t.Fatalf("entries = %+v, want hidden .no_exist/evil.pkl to be scanned", entries)
	}
}

// TestTwoHopSymlinkEscapeReportsSymlinkEscape pins that a 2-hop escape (snapshot
// symlink -> blobs/<sha> -> /etc/passwd, or blobs/ -> /etc) emits HIGH
// RuleSymlinkEscape rather than Medium RuleBlobMissing.
func TestTwoHopSymlinkEscapeReportsSymlinkEscape(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("blob symlink escapes", func(t *testing.T) {
		dir := t.TempDir()
		repo := filepath.Join(dir, "models--org--repo")
		snap := filepath.Join(repo, "snapshots", strings.Repeat("1", 40))
		blobs := filepath.Join(repo, "blobs")
		if err := os.MkdirAll(snap, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(blobs, 0o755); err != nil {
			t.Fatal(err)
		}
		sha := strings.Repeat("b", 64)
		if err := os.Symlink(outside, filepath.Join(blobs, sha)); err != nil {
			t.Skipf("symlink: %v", err)
		}
		if err := os.Symlink(filepath.Join("..", "..", "blobs", sha), filepath.Join(snap, "leak.bin")); err != nil {
			t.Fatal(err)
		}
		c := report.NewCollector(0)
		entries, err := Expand(dir, c)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("escaping 2-hop blob yielded entries: %+v", entries)
		}
		if !hasRule(c.Findings(), RuleSymlinkEscape.ID) {
			t.Fatalf("expected %s, got %v", RuleSymlinkEscape.ID, ids(c.Findings()))
		}
		if hasRule(c.Findings(), RuleBlobMissing.ID) {
			t.Fatalf("2-hop escape was misclassified as %s: %v", RuleBlobMissing.ID, ids(c.Findings()))
		}
	})

	t.Run("blobs dir symlink escapes", func(t *testing.T) {
		dir := t.TempDir()
		repo := filepath.Join(dir, "models--org--repo")
		snap := filepath.Join(repo, "snapshots", strings.Repeat("2", 40))
		if err := os.MkdirAll(snap, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(outside), filepath.Join(repo, "blobs")); err != nil {
			t.Skipf("symlink: %v", err)
		}
		if err := os.Symlink(filepath.Join("..", "..", "blobs", "secret.txt"), filepath.Join(snap, "leak.bin")); err != nil {
			t.Fatal(err)
		}
		c := report.NewCollector(0)
		entries, err := Expand(dir, c)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("escaping blobs dir yielded entries: %+v", entries)
		}
		if !hasRule(c.Findings(), RuleSymlinkEscape.ID) {
			t.Fatalf("expected %s, got %v", RuleSymlinkEscape.ID, ids(c.Findings()))
		}
	})
}

// TestDeduplicatedBlobPreservesLaterRevisionAndCaseInsensitiveRefs pins that
// when two revisions share one blob and the lexicographically earlier commit has
// no ref (or a different ref), the later revision's ref label is merged onto the
// surviving entry rather than dropped, and uppercase commit hex in refs/ matches.
func TestDeduplicatedBlobPreservesLaterRevisionAndCaseInsensitiveRefs(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--org--repo")
	blobs := filepath.Join(repo, "blobs")
	refs := filepath.Join(repo, "refs")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(refs, 0o755); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("c", 64)
	if err := os.WriteFile(filepath.Join(blobs, sha), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitA := strings.Repeat("0", 40) // walked first, has no ref
	commitB := strings.Repeat("f", 40) // walked second, pointed to by refs/main (uppercase in file)
	for _, c := range []string{commitA, commitB} {
		snap := filepath.Join(repo, "snapshots", c)
		if err := os.MkdirAll(snap, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", "..", "blobs", sha), filepath.Join(snap, "model.bin")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(refs, "main"), []byte(strings.ToUpper(commitB)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := Expand(dir, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Revision != "main" {
		t.Fatalf("Revision = %q, want %q", entries[0].Revision, "main")
	}
}

func TestMissingRefsDirIsQuietAndOversizedRefIsMalformed(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--org--norefs")
	snap := filepath.Join(repo, "snapshots", strings.Repeat("1", 40))
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap, "a.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := report.NewCollector(0)
	entries, err := Expand(dir, c)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if len(c.Findings()) != 0 {
		t.Fatalf("missing refs/ emitted findings: %v", ids(c.Findings()))
	}

	// An oversized ref file is capped at 4 KiB and reported as malformed.
	refsDir := filepath.Join(repo, "refs")
	if err := os.MkdirAll(refsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refsDir, "huge"), []byte(strings.Repeat("a", 8192)), 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := report.NewCollector(0)
	if _, err := Expand(dir, c2); err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !hasRule(c2.Findings(), RuleRefMalformed.ID) {
		t.Fatalf("oversized ref did not emit %s: %v", RuleRefMalformed.ID, ids(c2.Findings()))
	}
}
