// Package source is the only place bytes enter the scanner.
//
// Every parser in sc4n reads through a Source, so the two properties that matter
// for correctness on multi-gigabyte, attacker-controlled artifacts are
// established exactly once:
//
//   - one mapping per file, reused by every parser that runs over it, so a
//     100 GB file never costs 100 GB of RSS; and
//   - a hard byte cap applied at open, so a "file" that is really a named pipe
//     or a 4 TB sparse image cannot make the scanner read unbounded bytes.
//
// Nothing in this package executes, extracts or writes anything.
package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
)

// ErrTooLarge is returned by Open when a file exceeds Limits.MaxArtifactBytes.
var ErrTooLarge = errors.New("source: artifact exceeds MaxArtifactBytes")

// errNoMmap is returned by mmapSource on platforms without a mapping syscall.
var errNoMmap = errors.New("source: memory mapping unsupported on this platform")

// Source is a random-access, read-only byte range with a name.
//
// Bytes may return a slice that aliases a memory mapping. That slice stays valid
// until Close, and callers MUST NOT retain it past Close: the mapping is unmapped
// (and, on the memory-based implementation, the backing slice released) at that
// point. Callers that need bytes to outlive the Source copy them.
type Source interface {
	// Name is the path or synthetic name ("<stdin>", "evil.whl:member.pkl")
	// used in findings.
	Name() string

	// Size is the total byte length of the range.
	Size() int64

	// ReadAt implements io.ReaderAt over the range. Implementations MUST NOT
	// panic on a range past the end; they return io.EOF, as io.ReaderAt
	// requires.
	ReadAt(p []byte, off int64) (int, error)

	// Bytes returns the bytes at [off, off+n) where available. Unlike ReadAt it
	// returns a slice directly into the underlying storage where the whole range
	// is mapped, so it performs no copy for mapped sources. It returns
	// io.ErrUnexpectedEOF (with a short slice) when the range runs past the end,
	// and an error when the range exceeds the implementation's copy budget.
	Bytes(off, n int64) ([]byte, error)

	// Reader returns a sequential reader over [off, size).
	Reader(off int64) io.Reader

	// Close releases the mapping or buffer. Close is idempotent.
	Close() error
}

// Open opens path read-only.
//
// On unix, a regular file of at least l.MmapThreshold bytes is memory-mapped;
// smaller files and character devices are read into memory (capped at
// l.MaxArtifactBytes) with os.ReadFile so that a pipe or /dev/* path still
// works. On other platforms the file is read into memory. The returned Source
// owns its bytes and MUST be closed by the caller.
func Open(path string, l limits.Limits) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if l.MaxArtifactBytes > 0 && fi.Mode().IsRegular() && fi.Size() > l.MaxArtifactBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, cap %d", ErrTooLarge, path, fi.Size(), l.MaxArtifactBytes)
	}

	if mmapSupported && fi.Mode().IsRegular() && fi.Size() >= l.MmapThreshold {
		// Mapping can legitimately fail (a 32-bit address space, a filesystem
		// that refuses MAP_SHARED with PROT_READ, a /proc-like file reporting a
		// bogus st_size), so a failure falls through to reading rather than
		// failing the scan.
		if src, err := mmapSource(path, f, fi.Size()); err == nil {
			return src, nil
		}
	}

	b, err := readCapped(f, path, l.MaxArtifactBytes)
	if err != nil {
		return nil, err
	}
	return Mem(path, b), nil
}

// readCapped reads all of r into memory, refusing to exceed max.
func readCapped(r io.Reader, name string, max int64) ([]byte, error) {
	if max <= 0 {
		b, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	// io.ReadAll-style growth with one extra byte so that "exactly max" is
	// accepted and "max+1" is rejected, without trusting any size header.
	var buf []byte
	tmp := make([]byte, 1<<20)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			if int64(len(buf))+int64(n) > max {
				return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, name, max)
			}
			buf = append(buf, tmp[:n]...)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// memSource is the in-memory implementation, used for small files, archive
// members, decompressed streams and stdin. It is also the fallback on platforms
// without mmap.
type memSource struct {
	name string
	b    []byte
	once sync.Once
}

// Mem returns a Source over b. The caller MUST NOT mutate b until the Source is
// closed.
func Mem(name string, b []byte) Source { return &memSource{name: name, b: b} }

func (s *memSource) Name() string { return s.name }
func (s *memSource) Size() int64  { return int64(len(s.b)) }

func (s *memSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("source: negative offset")
	}
	if off >= int64(len(s.b)) {
		return 0, io.EOF
	}
	n := copy(p, s.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *memSource) Bytes(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 {
		return nil, errors.New("source: negative range")
	}
	if off > int64(len(s.b)) || off+n > int64(len(s.b)) {
		end := int64(len(s.b))
		if off > end {
			off = end
		}
		return s.b[off:end], io.ErrUnexpectedEOF
	}
	return s.b[off : off+n], nil
}

func (s *memSource) Reader(off int64) io.Reader {
	if off < 0 || off > int64(len(s.b)) {
		return io.NewSectionReader(bytesReaderAt(s.b), 0, 0)
	}
	return io.NewSectionReader(bytesReaderAt(s.b), off, int64(len(s.b))-off)
}

func (s *memSource) Close() error {
	s.once.Do(func() {
		// Release the reference so the backing array becomes collectable; a
		// Source handed to Mem from a caller (e.g. a decompression buffer from a
		// sync.Pool) is not ours to free, so this is all that is safe to do.
		s.b = nil
	})
	return nil
}

// bytesReaderAt adapts a []byte to io.ReaderAt without the io package's
// io.ReaderAt assertion dance.
type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("source: negative offset")
	}
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
