package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// containerOps is the containers profile: wrap the witness pickle in every
// container the scanner recognises, so the row measures whether the payload is
// still reachable through that wrapper.
//
// Each build is either the standard library (gzip, zip) or the host tool that
// also validates the result — the lab never hand-writes a container format it
// cannot validate, because an invalid container proves nothing.
func containerOps() []op {
	return []op{
		{
			Name:     "wrap-7z-pt",
			Needs:    "7z",
			Build:    build7z("wrap-7z-pt", "model.pt"),
			Oracle:   newHostValid("7z", "7z", "t", "-bd", "-y"),
			Expected: []string{"SC4N-TORCH-7Z"},
		},
		{
			Name:     "wrap-7z-bin",
			Needs:    "7z",
			Build:    build7z("wrap-7z-bin", "model.bin"),
			Oracle:   newHostValid("7z", "7z", "t", "-bd", "-y"),
			Expected: []string{"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION"},
		},
		{
			Name:     "wrap-xz-joblib",
			Needs:    "xz",
			Build:    buildXZ("model.joblib", "-1", "-T1"),
			Oracle:   newHostValid("xz", "xz", "-t"),
			Expected: []string{"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION", "SC4N-JOBLIB-UNSCANNED-PAYLOAD"},
		},
		{
			Name:     "wrap-lzma-joblib",
			Needs:    "xz",
			Build:    buildXZ("model.joblib", "--format=lzma", "-1"),
			Oracle:   newHostValid("xz", "xz", "-t"),
			Expected: []string{"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION", "SC4N-JOBLIB-UNSCANNED-PAYLOAD"},
		},
		{
			Name:   "wrap-zstd-joblib",
			Needs:  "zstd",
			Build:  buildZstd("model.joblib"),
			Oracle: newHostValid("zstd", "zstd", "-t", "-q"),
			// zstd is deliberately NOT escalated: joblib 1.4.2 ships no zstd coder, so
			// joblib.load cannot read this file and SC4N-JOBLIB-WRAPPER-MISMATCH
			// already says the name lies.
			Expected: []string{"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION"},
		},
		{
			// The control: a wrapper the scanner does decompress must still reach
			// the payload. If this row reports no critical, the zlib/gzip path is
			// broken and every other container row is uninterpretable.
			Name:   "wrap-gzip-pkl",
			Build:  buildGzip("model.pkl"),
			Oracle: newHostValid("gzip", "gzip", "-t"),
			// The control declares the two findings a pickle of builtins.eval(42)
			// earns: the gadget and the REDUCE that calls it. Anything else high is
			// news and fails the row.
			Expected: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
		},
		{
			Name:     "nested-7z-gzip",
			Needs:    "7z",
			Build:    buildNested7zGzip("model.pt"),
			Oracle:   newHostValid("7z", "7z", "t", "-bd", "-y"),
			Expected: []string{"SC4N-TORCH-7Z"},
		},
		{
			// Declared with its dependency and no fallback: a mutant no validator
			// accepts proves nothing, so without lz4 the row is unavailable.
			Name:     "wrap-lz4-joblib",
			Needs:    "lz4",
			Build:    buildLZ4("model.joblib"),
			Oracle:   newHostValid("lz4", "lz4", "-t"),
			Expected: []string{"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION", "SC4N-JOBLIB-UNSCANNED-PAYLOAD"},
		},
	}
}

// mutantPath makes the row directory and returns (file path, path relative to
// out).
func mutantPath(out, opName, name string) (string, string, error) {
	dir := filepath.Join(out, "mutants", opName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, name), filepath.ToSlash(filepath.Join("mutants", opName, name)), nil
}

// buildGzip is the standard-library control: the compressed payload the scanner
// is expected to decompress and walk.
func buildGzip(name string) func(out string, seed int64) (string, error) {
	return func(out string, seed int64) (string, error) {
		full, rel, err := mutantPath(out, "wrap-gzip-pkl", name)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			return "", err
		}
		if _, err := zw.Write(witnessPickle()); err != nil {
			return "", err
		}
		if err := zw.Close(); err != nil {
			return "", err
		}
		return rel, os.WriteFile(full, buf.Bytes(), 0o644)
	}
}

// build7z wraps the witness in a 7z archive under a name that does or does not
// claim to be a torch checkpoint; the two rows differ only in the extension, so
// a difference between their findings is the extension-based rule and nothing
// else.
func build7z(opName, name string) func(out string, seed int64) (string, error) {
	return func(out string, seed int64) (string, error) {
		full, rel, err := mutantPath(out, opName, name)
		if err != nil {
			return "", err
		}
		src, err := tempWitness()
		if err != nil {
			return "", err
		}
		defer os.Remove(src)
		if err := runTool("7z", "a", "-t7z", "-mx=1", "-bd", "-y", full, src); err != nil {
			return "", err
		}
		return rel, nil
	}
}

// buildNested7zGzip is gzip(witness) inside a 7z archive: the depth the nesting
// cap is about, in the one order a real artifact uses (a .pt that is a 7z of a
// gzip of a pickle).
func buildNested7zGzip(name string) func(out string, seed int64) (string, error) {
	return func(out string, seed int64) (string, error) {
		full, rel, err := mutantPath(out, "nested-7z-gzip", name)
		if err != nil {
			return "", err
		}
		src, err := tempWitness()
		if err != nil {
			return "", err
		}
		defer os.Remove(src)
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(witnessPickle()); err != nil {
			return "", err
		}
		if err := zw.Close(); err != nil {
			return "", err
		}
		inner := src + ".gz"
		if err := os.WriteFile(inner, buf.Bytes(), 0o644); err != nil {
			return "", err
		}
		defer os.Remove(inner)
		if err := runTool("7z", "a", "-t7z", "-mx=1", "-bd", "-y", full, inner); err != nil {
			return "", err
		}
		return rel, nil
	}
}

// buildXZ pipes the witness through xz; the flags are the caller's so the same
// builder makes the xz row and the (single-coder) lzma row.
func buildXZ(name string, flags ...string) func(out string, seed int64) (string, error) {
	opName := "wrap-xz-joblib"
	for _, f := range flags {
		if f == "--format=lzma" {
			opName = "wrap-lzma-joblib"
		}
	}
	return func(out string, seed int64) (string, error) {
		full, rel, err := mutantPath(out, opName, name)
		if err != nil {
			return "", err
		}
		src, err := tempWitness()
		if err != nil {
			return "", err
		}
		defer os.Remove(src)
		if err := runShell("xz", append(append([]string{}, flags...), "-c", src), full); err != nil {
			return "", err
		}
		return rel, nil
	}
}

func buildZstd(name string) func(out string, seed int64) (string, error) {
	return func(out string, seed int64) (string, error) {
		full, rel, err := mutantPath(out, "wrap-zstd-joblib", name)
		if err != nil {
			return "", err
		}
		src, err := tempWitness()
		if err != nil {
			return "", err
		}
		defer os.Remove(src)
		if err := runShell("zstd", []string{"-1", "-q", "-c", src}, full); err != nil {
			return "", err
		}
		return rel, nil
	}
}

// buildLZ4 exists so the row can be declared and reported unavailable on a host
// without the binary; it is never reachable with an oracle that accepts the
// output, so it is deliberately not implemented beyond writing the raw frame.
func buildLZ4(name string) func(out string, seed int64) (string, error) {
	return func(out string, seed int64) (string, error) {
		_, rel, err := mutantPath(out, "wrap-lz4-joblib", name)
		if err != nil {
			return "", err
		}
		return rel, fmt.Errorf("lz4: no writer and no validator on this host")
	}
}

// tempWitness writes the witness bytes to a temp file for a host tool to read.
func tempWitness() (string, error) {
	f, err := os.CreateTemp("", "sc4nlab-witness-*.pkl")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(witnessPickle()); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// runShell runs a tool that writes to stdout and captures it into path: the xz
// and zstd rows are pipes, and writing them through a file descriptor is what
// keeps the exact bytes on disk.
func runShell(bin string, args []string, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.Command(bin, args...) // #nosec G204 -- lab-owned generator
	cmd.Stdout = f
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", bin, err, firstLine(errb.String()))
	}
	return nil
}

// runTool executes a tool that writes its own output file.
func runTool(bin string, args ...string) error {
	cmd := exec.Command(bin, args...) // #nosec G204 -- lab-owned generator
	var errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Stdout = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", bin, err, firstLine(errb.String()))
	}
	return nil
}

// zipStore writes a zip with one member, uncompressed: a content sniffer reads
// the member's declared bytes, and a compressed member would exercise the
// decompressor instead of the member dispatch the row is about.
func zipStore(path, member string, data []byte) error {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: member, Method: zip.Store})
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
