//go:build !unix

package scan

import "os"

func sameFileState(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
