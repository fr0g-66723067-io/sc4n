//go:build !unix

package source

import (
	"errors"
	"io"
	"strconv"
)

// Spill materialises r in memory on platforms without a mapping syscall. The cap
// still applies; the difference is that the member then costs its size in RSS,
// which is why the unix implementation prefers a private temporary file.
func Spill(name string, r io.Reader, max int64) (Source, error) {
	if max <= 0 {
		return nil, errors.New("source: refusing to spill with no byte cap")
	}
	b, err := readCapped(r, name, max)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, &SpillTooLargeError{Name: name, Limit: max}
		}
		return nil, err
	}
	return Mem(name, b), nil
}

// SpillTooLargeError reports that a member exceeded the spill cap.
type SpillTooLargeError struct {
	Name  string
	Limit int64
	Path  string
}

func (e *SpillTooLargeError) Error() string {
	return "source: " + e.Name + " exceeds the spill cap of " + strconv.FormatInt(e.Limit, 10) + " bytes"
}

// Section returns a Source over a range of parent without copying it.
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
