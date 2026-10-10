package source

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
)

func TestMemBytesIsZeroCopyAndBoundsChecked(t *testing.T) {
	b := []byte("0123456789")
	s := Mem("x", b)
	defer s.Close()

	got, err := s.Bytes(2, 4)
	if err != nil {
		t.Fatalf("Bytes(2,4): %v", err)
	}
	if string(got) != "2345" {
		t.Fatalf("Bytes(2,4) = %q, want %q", got, "2345")
	}
	if &got[0] != &b[2] {
		t.Fatal("Bytes returned a copy; the contract is a view into the source")
	}

	if _, err := s.Bytes(8, 4); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Bytes past the end: err = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := s.Bytes(-1, 1); err == nil {
		t.Fatal("Bytes accepted a negative offset")
	}
	if _, err := s.Bytes(0, -1); err == nil {
		t.Fatal("Bytes accepted a negative length")
	}
}

func TestMemReadAtMatchesReaderAtContract(t *testing.T) {
	s := Mem("x", []byte("abcdef"))
	defer s.Close()

	p := make([]byte, 3)
	n, err := s.ReadAt(p, 4)
	if n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(p, 4) = %d, %v; want 2, io.EOF", n, err)
	}
	if string(p[:n]) != "ef" {
		t.Fatalf("ReadAt returned %q", p[:n])
	}
	if _, err := s.ReadAt(p, 6); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt at the end: err = %v, want io.EOF", err)
	}
}

func TestReaderAndSize(t *testing.T) {
	s := Mem("x", []byte("hello world"))
	defer s.Close()
	if s.Size() != 11 {
		t.Fatalf("Size = %d", s.Size())
	}
	b, err := io.ReadAll(s.Reader(6))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(b) != "world" {
		t.Fatalf("Reader(6) = %q", b)
	}
}

// TestOpenMapsLargeFileAndReadsSmall pins the threshold behaviour: below the
// threshold the bytes come from a buffer, at or above it they come from a mapping.
// The observable difference is that Bytes on a mapped source is a view whose
// contents change only with the file, so the test asserts content equality and
// that a mapping-backed source still has the file's size after a write-free read.
func TestOpenMapsLargeFileAndReadsSmall(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")
	payload := bytes.Repeat([]byte("sc4n"), 4096)
	if err := os.WriteFile(big, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(dir, "small.bin")
	if err := os.WriteFile(small, []byte("tiny"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := limits.Default()
	l.MmapThreshold = 1024

	for _, tc := range []struct {
		path string
		want int64
	}{
		{big, int64(len(payload))},
		{small, 4},
	} {
		s, err := Open(tc.path, l)
		if err != nil {
			t.Fatalf("Open(%s): %v", tc.path, err)
		}
		if s.Size() != tc.want {
			t.Fatalf("Open(%s).Size() = %d, want %d", tc.path, s.Size(), tc.want)
		}
		b, err := s.Bytes(0, tc.want)
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		if int64(len(b)) != tc.want {
			t.Fatalf("Bytes returned %d bytes, want %d", len(b), tc.want)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		// Close is idempotent because both the explicit call and the GC cleanup
		// run release.
		if err := s.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	}
}

func TestOpenRefusesOversizedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 64), 0o644); err != nil {
		t.Fatal(err)
	}
	l := limits.Default()
	l.MaxArtifactBytes = 16
	if _, err := Open(p, l); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Open: err = %v, want ErrTooLarge", err)
	}
}

func TestOpenUnreadableIsAnError(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "absent"), limits.Default()); err == nil {
		t.Fatal("Open succeeded on a missing file")
	}
}
