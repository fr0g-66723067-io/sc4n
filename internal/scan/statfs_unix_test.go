//go:build bigfixtures && unix

package scan_test

import "syscall"

type syscallStatfs = syscall.Statfs_t

func statfs(dir string, st *syscallStatfs) error { return syscall.Statfs(dir, st) }
