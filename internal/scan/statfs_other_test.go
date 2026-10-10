//go:build bigfixtures && !unix

package scan_test

import "errors"

type syscallStatfs struct {
	Bavail uint64
	Bsize  uint64
}

func statfs(dir string, st *syscallStatfs) error { return errors.New("unsupported platform") }
