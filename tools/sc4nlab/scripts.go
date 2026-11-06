package main

import (
	"embed"
	"os"
	"path/filepath"
)

// oracleScripts is the container's Python, embedded so the lab runs the scripts
// that are in the repository rather than whatever an image was built with.
//
// Two reasons, both learned the hard way while writing this: a script change
// needed a full image rebuild to be visible (and silently ran the old code
// otherwise), and the image is pinned for its *dependencies* — carrying a stale
// copy of the generator inside it makes "which mutate.py validated this mutant"
// unanswerable from the matrix.
//
//go:embed py/check.py py/mutate.py
var oracleScripts embed.FS

// stageScripts writes the embedded scripts under dir and returns that directory,
// which is mounted at /opt/sc4nlab in the oracle container.
func stageScripts(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for _, name := range []string{"check.py", "mutate.py"} {
		b, err := oracleScripts.ReadFile("py/" + name)
		if err != nil {
			return "", err
		}
		if err := writeFile(filepath.Join(dir, name), b); err != nil {
			return "", err
		}
	}
	return dir, nil
}
