package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// runHash prints a file's digests. It exists so that a scan finding can be tied to
// a blob without a second tool: the report's artifact summary carries SHA-256, and
// this command is how a human reproduces it for a single file (including a
// symlinked hf-cache blob).
func runHash(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "sc4n hash needs exactly one path")
		return exitUsage
	}
	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", err)
		return exitUnreadable
	}
	defer f.Close()

	s256 := sha256.New()
	s1 := sha1.New()
	if _, err := io.Copy(io.MultiWriter(s256, s1), f); err != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", err)
		return exitUnreadable
	}
	fmt.Fprintf(stdout, "sha256  %s\nsha1    %s\n", hex.EncodeToString(s256.Sum(nil)), hex.EncodeToString(s1.Sum(nil)))
	return exitClean
}
