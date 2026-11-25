package main

import (
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/tools/internal/boundary"
)

// TestScanPathStillDoesNotExec is the boundary this tool exists on the far side
// of: it runs a container, so the scanner must keep running nothing.
func TestScanPathStillDoesNotExec(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		offenders, err := boundary.NoExecUnder(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, f := range offenders {
			t.Errorf("%s/%s imports os/exec: executing artifacts is this tool's job, not the scanner's", dir, f)
		}
	}
}

// TestScannerDoesNotImportTheHarness is the other direction: a scanner that
// imported sc4nconfirm could load an artifact in-process, which is the one thing
// the confirmation path must never make possible by accident.
func TestScannerDoesNotImportTheHarness(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		offenders, err := boundary.ImportsUnder(filepath.Join(root, dir), "tools/")
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, f := range offenders {
			t.Errorf("%s/%s imports a tools/ package", dir, f)
		}
	}
}

// TestScanPathStaysOffline enforces AGENTS.md Invariant #2: the only non-test
// package under internal/ or cmd/ that may import net/http is internal/hubapi.
func TestScanPathStaysOffline(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, tc := range []struct {
		dir   string
		allow []string
	}{
		{"internal", []string{"hubapi"}},
		{"cmd", nil},
	} {
		offenders, err := boundary.NoNetOutside(filepath.Join(root, tc.dir), tc.allow...)
		if err != nil {
			t.Fatalf("%s: %v", tc.dir, err)
		}
		for _, f := range offenders {
			t.Errorf("%s/%s imports net/http: only internal/hubapi may dial", tc.dir, f)
		}
	}
}
