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
