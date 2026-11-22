//go:build linux

package scan

import (
	"os"
	"syscall"
)

// sameFileState compares the identity fields a rewrite changes. Ctim catches a
// same-size rewrite whose mtime an attacker restored, which ctime cannot be set
// from user space on Linux.
func sameFileState(a, b os.FileInfo) bool {
	if a == nil || b == nil || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	as, aok := a.Sys().(*syscall.Stat_t)
	bs, bok := b.Sys().(*syscall.Stat_t)
	if aok && bok {
		return as.Ctim.Sec == bs.Ctim.Sec && as.Ctim.Nsec == bs.Ctim.Nsec
	}
	return true
}
