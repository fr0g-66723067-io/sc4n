// Package boundary holds the shared, test-time assertion that the scanner never
// executes anything.
//
// It is a package rather than a copy of the same walk in every tool's tests
// because the property has to hold for all of them at once: sc4nlab shells out to
// archive tools and sc4nconfirm runs a container, and both are allowed to do that
// precisely because internal/ and cmd/ are not.
package boundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// NoExecUnder walks dir and returns the Go files that import os/exec or plugin,
// or reference syscall.Exec, syscall.ForkExec, syscall.StartProcess, or
// os.StartProcess, relative to dir. An empty result is the property the scanner
// must keep: a scanner that can run a program or load native code has to be
// trusted not to execute the artifact it is inspecting.
func NoExecUnder(dir string) ([]string, error) {
	var offenders []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		if fileUsesExec(f) {
			rel, rerr := filepath.Rel(dir, path)
			if rerr != nil {
				rel = path
			}
			offenders = append(offenders, rel)
		}
		return nil
	})
	return offenders, err
}

func fileUsesExec(f *ast.File) bool {
	syscallNames := map[string]bool{}
	osNames := map[string]bool{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		switch p {
		case "os/exec", "plugin":
			return true
		case "syscall":
			name := "syscall"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name != "_" && name != "." {
				syscallNames[name] = true
			}
		case "os":
			name := "os"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name != "_" && name != "." {
				osNames[name] = true
			}
		}
	}
	if len(syscallNames) == 0 && len(osNames) == 0 {
		return false
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if syscallNames[id.Name] {
			switch sel.Sel.Name {
			case "Exec", "ForkExec", "StartProcess":
				found = true
				return false
			}
		}
		if osNames[id.Name] && sel.Sel.Name == "StartProcess" {
			found = true
			return false
		}
		return true
	})
	return found
}

// NoNetOutside walks dir and returns the non-test Go files that import net/http
// (or any net/http/* subpackage) outside the allowed relative subdirectories.
// This enforces AGENTS.md Invariant #2: only internal/hubapi may dial.
func NoNetOutside(dir string, allowed ...string) ([]string, error) {
	normAllowed := make([]string, 0, len(allowed))
	for _, a := range allowed {
		a = strings.Trim(filepath.ToSlash(filepath.Clean(a)), "/")
		if a != "" && a != "." {
			normAllowed = append(normAllowed, a)
		}
	}
	var offenders []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			rel = path
		}
		relSlash := filepath.ToSlash(rel)
		for _, a := range normAllowed {
			if relSlash == a || strings.HasPrefix(relSlash, a+"/") {
				return nil
			}
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if p == "net/http" || strings.HasPrefix(p, "net/http/") {
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
