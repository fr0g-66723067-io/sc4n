package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/malice"
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

// TestApplyTraceFileStreamsFromStartBounded proves that streaming from byte 0
// preserves early payload effects even when the tail floods past maxBytes.
func TestApplyTraceFileStreamsFromStartBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace")
	var b strings.Builder
	b.WriteString(`1 execve("/usr/local/bin/python3", ["python3", "/opt/sc4nconfirm/load.py", "/w/a.pkl", "/tmp/result.json"], 0x0) = 0` + "\n")
	b.WriteString(`2 execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x0) = 0` + "\n")
	for range 200 {
		b.WriteString(`1 openat(AT_FDCWD, "/usr/lib/quiet.py", O_RDONLY) = 3` + "\n")
	}
	b.WriteString(`3 execve("/bin/sh", ["/bin/sh", "-c", "after-cap"], 0x0) = 0` + "\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &malice.Run{}
	if err := applyTraceFile(r, path, 512); err != nil {
		t.Fatal(err)
	}
	if len(r.Exec) != 1 || r.Exec[0] != "/bin/sh -c id" {
		t.Fatalf("Exec = %v, want early payload preserved and tail beyond cap ignored", r.Exec)
	}
}

func TestConfirmOneRejectsDirWithoutConfigJSON(t *testing.T) {
	dir := t.TempDir()
	var errb bytes.Buffer
	_, err := confirmOne(options{}, dir, 0, &errb)
	if err == nil || !strings.Contains(err.Error(), "config.json") {
		t.Fatalf("confirmOne(dir without config.json) = %v, want error naming config.json", err)
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
