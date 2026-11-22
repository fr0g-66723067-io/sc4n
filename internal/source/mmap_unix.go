//go:build unix

package source

import (
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
)

// mmapSupported reports whether Open may memory-map. It is a constant rather than
// a runtime check so that Open's read fallback is not dead code to the compiler.
const mmapSupported = true

// mmapHandle owns one mapping and the descriptor that produced it. Release is
// idempotent, which matters because the mapping is given up in two independent
// ways: the caller's Close, and the GC cleanup installed by mmapSource. Without
// the once-guard a cleanup that ran after Close would munmap an address range
// that may since have been handed to an unrelated mapping.
type mmapHandle struct {
	b    []byte
	f    *os.File
	done atomic.Bool
}

func (h *mmapHandle) release() error {
	if h.done.Swap(true) {
		return nil
	}
	b := h.b
	h.b = nil
	err := syscall.Munmap(b)
	_ = h.f.Close()
	return err
}

// mmapSource maps size bytes of f read-only and returns a Source over it.
//
// Bytes returns sub-slices of the mapping, so the mapping MUST outlive every
// slice it handed out; a caller that retains one past Close has a bug, which is
// why the contract is stated on the Source interface.
func mmapSource(name string, f *os.File, size int64) (Source, error) {
	if size <= 0 {
		_ = f.Close()
		return nil, errors.New("source: refusing to map empty range")
	}
	if int64(int(size)) != size {
		_ = f.Close()
		return nil, errors.New("source: file too large to map on this platform")
	}
	b, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		// The caller keeps ownership when this returns an error, but every
		// current caller closes on error too; closing here as well makes the
		// function safe for a caller that does not.
		_ = f.Close()
		return nil, err
	}
	if int64(len(b)) < size {
		// A file truncated between Stat and Mmap yields a shorter mapping than
		// requested. Report the mapping's own length rather than the stale one.
		size = int64(len(b))
	}
	h := &mmapHandle{b: b, f: f}
	s := &mmapSource_{name: name, h: h, size: size}
	runtime.AddCleanup(s, func(h *mmapHandle) { _ = h.release() }, h)
	return s, nil
}

type mmapSource_ struct {
	name string
	h    *mmapHandle
	size int64
	once sync.Once
}

func (s *mmapSource_) Name() string { return s.name }
func (s *mmapSource_) Size() int64  { return s.size }

func (s *mmapSource_) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("source: negative offset")
	}
	if off >= s.size {
		return 0, io.EOF
	}
	n := copy(p, s.h.b[off:s.size])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *mmapSource_) Bytes(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 {
		return nil, errors.New("source: negative range")
	}
	b := s.h.b
	// n > size-off rather than off+n > size: off+n wraps for a large n and the
	// guard would pass, leaving b[off : off+n] to panic on a negative high bound.
	if off > s.size || n > s.size-off {
		end := s.size
		if off > end {
			off = end
		}
		return b[off:end], io.ErrUnexpectedEOF
	}
	return b[off : off+n], nil
}

// Reader reads through the mapping rather than the descriptor, so it is immune to
// a concurrent Seek on the file and to a caller closing the descriptor.
func (s *mmapSource_) Reader(off int64) io.Reader {
	b := s.h.b[:s.size]
	if off < 0 || off > s.size {
		return io.NewSectionReader(bytesReaderAt(nil), 0, 0)
	}
	return io.NewSectionReader(bytesReaderAt(b), off, s.size-off)
}

func (s *mmapSource_) Close() error {
	var err error
	s.once.Do(func() { err = s.h.release() })
	return err
}
