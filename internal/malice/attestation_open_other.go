//go:build !unix

package malice

import (
	"fmt"
	"os"
)

func openAttestation(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; refusing to open it", path)
	}
	return os.Open(path)
}
