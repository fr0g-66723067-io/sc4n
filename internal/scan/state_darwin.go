//go:build darwin

package scan

import (
	"os"
	"syscall"
)

// sameFileState compares the identity fields a rewrite changes. Ctimespec is
// Darwin's ctime, which cannot be set from user space.
func sameFileState(a, b os.FileInfo) bool {
	if a == nil || b == nil || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	as, aok := a.Sys().(*syscall.Stat_t)
	bs, bok := b.Sys().(*syscall.Stat_t)
	if aok && bok {
		return as.Ctimespec.Sec == bs.Ctimespec.Sec && as.Ctimespec.Nsec == bs.Ctimespec.Nsec
	}
	return true
}
