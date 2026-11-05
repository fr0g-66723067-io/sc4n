//go:build unix

package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

// TestNamedPipeIsReportedNotOpened pins the one outcome a scanner must never
// produce: no outcome at all. os.Open on a FIFO with no writer blocks inside the
// open(2) syscall, so the worker never returns, the wait group never completes and
// neither -timeout nor context cancellation can interrupt it — a single pipe in a
// scanned tree hung the whole run with no finding, no summary and no exit code.
//
// The scan now records such an entry instead of opening it, which is a reported
// path (exit 3) rather than a silent skip.
func TestNamedPipeIsReportedNotOpened(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// A regular file beside the pipe proves the walk continues past it.
	card := filepath.Join(dir, "README.md")
	if err := os.WriteFile(card, []byte("# card\nordinary documentation\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		res *scan.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := scan.Run(context.Background(), scan.Config{Paths: []string{dir}, Limits: limits.Default()})
		done <- outcome{res, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("scan: %v", got.err)
		}
		if got.res.Unreadable != 1 {
			t.Fatalf("unreadable paths = %d, want 1 (the pipe)", got.res.Unreadable)
		}
		var found bool
		for _, a := range got.res.Artifacts {
			if a.Path == pipe {
				found = true
				if !strings.Contains(a.Error, "named pipe") {
					t.Fatalf("pipe summary error = %q, want it to name the kind", a.Error)
				}
			}
			if a.Path == card && a.Error != "" {
				t.Fatalf("the regular file beside the pipe was not scanned: %q", a.Error)
			}
		}
		if !found {
			t.Fatalf("the pipe was not reported at all: %+v", got.res.Artifacts)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the scan did not return: opening a named pipe blocks until a writer appears")
	}
}

// TestSymlinkToPipeIsReportedNotOpened is the same defect one indirection away: the
// walk sees a symlink (which it follows, for the hf-cache layout), and the target is
// a pipe.
func TestSymlinkToPipeIsReportedNotOpened(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "real-pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	link := filepath.Join(dir, "weights.bin")
	if err := os.Symlink(pipe, link); err != nil {
		t.Skipf("symlink: %v", err)
	}

	done := make(chan *scan.Result, 1)
	go func() {
		res, _ := scan.Run(context.Background(), scan.Config{Paths: []string{link}, Limits: limits.Default()})
		done <- res
	}()
	select {
	case res := <-done:
		if res.Unreadable != 1 {
			t.Fatalf("unreadable paths = %d, want 1 (the link to a pipe)", res.Unreadable)
		}
		if len(res.Artifacts) != 1 || !strings.Contains(res.Artifacts[0].Error, "named pipe") {
			t.Fatalf("summaries = %+v, want one naming the pipe", res.Artifacts)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the scan did not return: the link's target is a pipe")
	}
}

// TestSymlinkedDirectoryIsNotUnreadable pins the exit-code contract at its boundary.
// The contract is "a path the user named could not be opened", and a directory
// symlink inside the tree is not one: filepath.WalkDir does not follow it, so the
// link itself is not an artifact and the directory's contents are scanned through
// their real path. Reporting the link made a completely readable tree exit 3 on a
// benign `models/current -> models/v3`.
func TestSymlinkedDirectoryIsNotUnreadable(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "models", "v3")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "f.bin"), []byte("plain text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The link is a sibling of its target, as a `current -> v3` pointer is.
	if err := os.Symlink("v3", filepath.Join(dir, "models", "current")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	res, err := scan.Run(context.Background(), scan.Config{Paths: []string{dir}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("unreadable paths = %d, want 0: a symlinked directory is not an artifact", res.Unreadable)
	}
	for _, a := range res.Artifacts {
		if a.Path == filepath.Join(dir, "models", "current") {
			t.Fatalf("the directory link was reported as an artifact: %+v", a)
		}
	}
}

// TestSymlinkOutOfRootIsNotOpened is the containment contract. The walk used to
// hand every non-directory symlink to the reader with no check, so
// `ln -s /etc/shadow repo/leak.txt && sc4n scan repo` read the outside file,
// reported a clean scan and exited 0. Nothing in the tree said the scan had left
// it.
func TestSymlinkOutOfRootIsNotOpened(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(outside, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "leak.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	res, err := scan.Run(context.Background(), scan.Config{Paths: []string{repo}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Unreadable != 1 {
		t.Fatalf("unreadable paths = %d, want 1: the escaping link was not recorded", res.Unreadable)
	}
	if len(res.Collector.Findings()) != 0 {
		t.Fatalf("findings = %d, want 0: the target outside the root must not be read", len(res.Collector.Findings()))
	}
	var named bool
	for _, a := range res.Artifacts {
		if strings.Contains(a.Error, "out of the scan root") {
			named = true
		}
	}
	if !named {
		t.Fatalf("no artifact error named the escape: %+v", res.Artifacts)
	}
}

// TestSymlinkOutOfRootFollowedWithFlag is the opt-out: -symlinks follow restores
// reading a file link wherever it resolves, and the artifact is scanned.
func TestSymlinkOutOfRootFollowedWithFlag(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(outside, []byte("AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "leak.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	res, err := scan.Run(context.Background(), scan.Config{
		Paths:    []string{repo},
		Limits:   limits.Default(),
		Symlinks: scan.SymlinkFollow,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("unreadable paths = %d, want 0 under -symlinks follow", res.Unreadable)
	}
	if len(res.Collector.Findings()) == 0 {
		t.Fatal("the followed target was not scanned")
	}
}

// TestSymlinkOutOfRootDirectoryIsNamed: the walk does not descend a directory link
// (filepath.WalkDir does not follow links), and before this a link leaving the tree
// was dropped with no trace — an entire subtree outside the root would be unscanned
// and unreported.
func TestSymlinkOutOfRootDirectoryIsNamed(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "w.bin"), []byte("weights\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(repo, "weights")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	res, err := scan.Run(context.Background(), scan.Config{Paths: []string{repo}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Unreadable != 1 {
		t.Fatalf("unreadable paths = %d, want 1 for the escaping directory link", res.Unreadable)
	}
	var named bool
	for _, a := range res.Artifacts {
		if strings.Contains(a.Error, "out of the scan root") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the directory link was dropped with no trace: %+v", res.Artifacts)
	}
}

// TestSymlinkInsideRootStillFollowed is the regression guard for the ordinary
// layouts: a sibling file link and a `current -> v3` directory link inside the
// tree must scan without an error.
func TestSymlinkInsideRootStillFollowed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.bin"), []byte("plain text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.bin", filepath.Join(dir, "alias.bin")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "v3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("v3", filepath.Join(dir, "current")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	res, err := scan.Run(context.Background(), scan.Config{Paths: []string{dir}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("unreadable paths = %d, want 0: every link resolves inside the root", res.Unreadable)
	}
	var scanned bool
	for _, a := range res.Artifacts {
		if strings.HasSuffix(a.Path, "alias.bin") && a.Error == "" {
			scanned = true
		}
	}
	if !scanned {
		t.Fatalf("the in-root file link was not scanned: %+v", res.Artifacts)
	}
}
