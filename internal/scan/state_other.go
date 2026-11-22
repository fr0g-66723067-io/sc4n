//go:build !linux && !darwin

package scan

import "os"

// sameFileState is the portable subset: size and mtime. The ctime field has a
// different name on every Unix, so only the two CI targets compare it.
func sameFileState(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
