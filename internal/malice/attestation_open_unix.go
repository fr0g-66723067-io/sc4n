//go:build unix

package malice

import (
	"os"
	"syscall"
)

// openAttestation opens without blocking on a FIFO. The caller checks the mode
// from the open descriptor and refuses anything but a regular file, so a pipe or
// device named as an attestation cannot hang the scan before that check.
func openAttestation(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
