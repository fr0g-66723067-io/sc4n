//go:build unix

package source

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// Spill decompresses or otherwise materialises r into a private temporary file and
// returns a mapped Source over it, so that a member far larger than memory can be
// parsed by the same random-access parsers that read a top-level file.
//
// The file is unlinked before it is mapped, so it cannot be observed by another
// process, cannot be left behind by a crash, and needs no cleanup path: the
// descriptor and the mapping are both released by Source.Close (or by the GC
// cleanup if a caller forgets). It is created in TMPDIR.
//
// max bounds the bytes copied; exceeding it is an error rather than a truncation,
// because a parser handed a truncated member would report findings about bytes
// that are not there.
func Spill(name string, r io.Reader, max int64) (Source, error) {
	if max <= 0 {
		return nil, errors.New("source: refusing to spill with no byte cap")
	}
	dir := os.TempDir()
	f, err := os.CreateTemp(dir, "sc4n-spill-*.bin")
	if err != nil {
		return nil, err
	}
	// Unlink first: from here on the only handle is the descriptor.
	path := f.Name()
	if err := os.Remove(path); err != nil {
		f.Close()
		return nil, err
	}
	n, err := io.Copy(f, io.LimitReader(r, max+1))
	if err != nil {
		f.Close()
		return nil, err
	}
	if n > max {
		f.Close()
		return nil, &SpillTooLargeError{Name: name, Limit: max, Path: filepath.Base(path)}
	}
	if n == 0 {
		f.Close()
		return nil, errors.New("source: member is empty")
	}
	// The mapping must see the bytes that were just written.
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return mmapSource(name, f, n)
}

// SpillTooLargeError reports that a member exceeded the spill cap. It is a typed
// error so that a container parser can turn it into the SC4N-LIMIT-SPILL finding
// instead of an artifact-level failure.
type SpillTooLargeError struct {
	Name  string
	Limit int64
	Path  string
}

func (e *SpillTooLargeError) Error() string {
	return "source: " + e.Name + " exceeds the spill cap of " + strconv.FormatInt(e.Limit, 10) + " bytes"
}

// Section returns a Source over [off, off+size) of parent without copying it.
//
// The view is only valid while parent is open — it aliases the parent's mapping —
// which is the same lifetime rule the Source interface states for Bytes. Container
// parsers use it to hand a *stored* (uncompressed) member to the normal parser
// machinery without a copy and without a temporary file, which is the common shape
// for the big storage members of a torch archive.
func Section(parent Source, off, size int64, name string) (Source, error) {
	if off < 0 || size < 0 {
		return nil, errors.New("source: negative range")
	}
	b, err := parent.Bytes(off, size)
	if err != nil && len(b) < int(size) {
		return nil, err
	}
	return Mem(name, b[:size]), nil
}
