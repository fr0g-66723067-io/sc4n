// Package boundary holds the shared, test-time assertion that the scanner never
// executes anything.
//
// It is a package rather than a copy of the same walk in every tool's tests
// because the property has to hold for all of them at once: sc4nlab shells out to
// archive tools and sc4nconfirm runs a container, and both are allowed to do that
// precisely because internal/ and cmd/ are not.
package boundary

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
)

// NoExecUnder walks dir and returns the Go files that import os/exec, relative to
// dir. An empty result is the property the scanner must keep: a scanner that can
// run a program has to be trusted not to run the artifact it is inspecting.
func NoExecUnder(dir string) ([]string, error) {
	var offenders []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
				rel, rerr := filepath.Rel(dir, path)
				if rerr != nil {
					rel = path
				}
				offenders = append(offenders, rel)
				break
			}
		}
		return nil
	})
	return offenders, err
}

// ImportsUnder walks dir and returns the Go files that import a package whose
// path contains want. It is the other direction of the same boundary: the scanner
// must not import a tool, because a tool is where execution is allowed.
func ImportsUnder(dir, want string) ([]string, error) {
	var offenders []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
			if strings.Contains(imp.Path.Value, want) {
				rel, rerr := filepath.Rel(dir, path)
				if rerr != nil {
					rel = path
				}
				offenders = append(offenders, rel)
				break
			}
		}
		return nil
	})
	return offenders, err
}
