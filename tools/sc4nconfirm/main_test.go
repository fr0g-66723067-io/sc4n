package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerOutputIsBounded(t *testing.T) {
	b := newCappedBuffer(16)
	n, err := b.Write([]byte("0123456789abcdefghij"))
	if err != nil || n != 20 {
		t.Fatalf("Write = %d, %v; want 20, nil", n, err)
	}
	if got := b.String(); got != "0123456789abcdef" {
		t.Fatalf("buffer = %q, want the first 16 bytes", got)
	}
}

func TestReadTraceIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace")
	if err := os.WriteFile(path, []byte("0123456789abcdefghij"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTail(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "cdefghij") || !strings.Contains(got, "trace truncated") {
		t.Fatalf("readTail = %q, want the last 8 bytes and a truncation marker", got)
	}
	if strings.Contains(got, "0123456789") {
		t.Fatalf("readTail kept the head: %q", got)
	}
}

func TestReadResultRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, make([]byte, maxResultBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readResult(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readResult error = %v, want an oversize refusal", err)
	}
}
