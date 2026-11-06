package main

import (
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/tools/internal/boundary"
)

// TestScanPathDoesNotExec fails if any file under internal/ or cmd/ imports
// os/exec.
//
// The lab may shell out — generation and validation are not the scanner — and
// sc4n must not, because a scanner that can run a program has to be trusted not
// to run the artifact it is inspecting. The property was true by accident
// before this test: it is the cheapest possible guarantee that adding a mutant
// generator cannot quietly turn into "and now the scanner shells out to xz".
func TestScanPathDoesNotExec(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		offenders, err := boundary.NoExecUnder(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, f := range offenders {
			t.Errorf("%s/%s imports os/exec: the scan path must not execute anything", dir, f)
		}
	}
}
