//go:build !unix

package source

import "os"

// mmapSupported is false on platforms without the unix syscall package's Mmap,
// so Open always reads the file into memory there. Windows could use
// CreateFileMapping, but sc4n's reference scan host is Linux, and a half-tested
// second mapping implementation is worse than a documented read path.
const mmapSupported = false

// mmapSource never succeeds on this platform. It exists so that Open compiles
// with a single body for every platform.
func mmapSource(name string, f *os.File, size int64) (Source, error) {
	return nil, errNoMmap
}
