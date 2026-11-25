//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEntrypointPassesTheLoaderResultPathOnce pins the argv contract between the
// image entrypoint and load.py: the caller passes TARGET RESULT, and the loader
// must see those two arguments once each. The previous entrypoint appended its
// own result path, so load.py saw three arguments, exited on its usage check and
// every confirmation reported zero effects without opening the artifact.
func TestEntrypointPassesTheLoaderResultPathOnce(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	for _, sub := range []string{".cache/huggingface", ".ssh", "DOCUMENTS", ".aws"} {
		if err := os.MkdirAll(filepath.Join(home, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "strace.argv")
	bin := filepath.Join(dir, "bin")
	for name, body := range map[string]string{
		"strace": "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$STUB_LOG\"\n",
		"mkdir":  "#!/bin/sh\nexit 0\n",
		"chown":  "#!/bin/sh\nexit 0\n",
		"cp":     "#!/bin/sh\nexit 0\n",
	} {
		path := filepath.Join(bin, name)
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("sh", "image/entrypoint.sh", "/w/model.pkl", "/tmp/result.json")
	cmd.Env = append(
		os.Environ(),
		"HOME="+home,
		"PATH="+bin+":"+os.Getenv("PATH"),
		"STUB_LOG="+logPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("entrypoint: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("strace was not invoked: %v", err)
	}
	argv := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if got := strings.Count(string(raw), "/tmp/result.json"); got != 1 {
		t.Fatalf("load.py result path appears %d times in strace argv, want once:\n%s", got, raw)
	}
	if len(argv) < 2 || argv[len(argv)-2] != "/w/model.pkl" || argv[len(argv)-1] != "/tmp/result.json" {
		t.Fatalf("load.py argv tail = %q, want target and result once", argv)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-o /out/trace") {
		t.Fatalf("strace must write directly to /out/trace; got %q", joined)
	}
	for _, sc := range []string{"sendto", "sendmsg", "sendmmsg", "creat", "unlinkat", "renameat2", "memfd_create"} {
		if !strings.Contains(joined, sc) {
			t.Errorf("strace trace filter missing %s: %q", sc, joined)
		}
	}
}
