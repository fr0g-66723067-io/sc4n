package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
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
		base := filepath.Join(root, dir)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				if imp.Path.Value == `"os/exec"` {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s imports os/exec: the scan path must not execute anything", rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
	}
}
