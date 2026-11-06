package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/malice"
)

const sampleTrace = `12345 execve("/bin/sh", ["/bin/sh", "-c", "nslookup pickle-rce-test.rce.lc"], 0x7ffd /* 12 vars */) = 0
12345 openat(AT_FDCWD, "/home/worker/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3
12345 openat(AT_FDCWD, "/usr/lib/python3.12/json/__init__.py", O_RDONLY|O_CLOEXEC) = 5
12345 openat(AT_FDCWD, "/w/model.bin", O_RDONLY) = 3
12345 openat(AT_FDCWD, "/home/worker/stolen.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
12345 openat(AT_FDCWD, "/home/worker/.cache/huggingface/token", O_RDONLY) = 6
12345 openat(AT_FDCWD, "/home/worker/.cache/huggingface/hub", O_RDONLY|O_DIRECTORY) = -1 ENOENT (No such file or directory)
12345 connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("187.7.7.7")}, 16) = -1 ENETUNREACH (Network is unreachable)
12345 connect(4, {sa_family=AF_UNIX, sun_path="/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
12345 openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 7
12345 futex(0x7f00, FUTEX_WAKE_PRIVATE, 1) = 0
12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 8
12346 <... execve resumed>) = 0
12346 execve("/usr/bin/id", ["id"], 0x7ffd /* 10 vars */ <unfinished ...>
`

func TestApplyTrace(t *testing.T) {
	r := &malice.Run{Loaded: true}
	applyTrace(r, sampleTrace)

	if got := r.Exec; len(got) != 1 || got[0] != "/bin/sh -c nslookup pickle-rce-test.rce.lc" {
		t.Fatalf("Exec = %v", got)
	}
	if len(r.Connect) != 2 {
		t.Fatalf("Connect = %v, want the inet and the unix dials", r.Connect)
	}
	if r.Connect[0] != "187.7.7.7:53" {
		t.Fatalf("Connect[0] = %q", r.Connect[0])
	}
	if r.Connect[1] != "unix:/run/nscd/socket" {
		t.Fatalf("Connect[1] = %q", r.Connect[1])
	}
	if len(r.Wrote) != 1 || r.Wrote[0] != "/home/worker/stolen.txt" {
		t.Fatalf("Wrote = %v", r.Wrote)
	}
	// The canary read is the effect that matters, and loader plumbing is not.
	var outside []string
	outside = append(outside, r.OpenedOutside...)
	if !contains(outside, "/home/worker/.cache/huggingface/token") {
		t.Fatalf("the canary read is missing from OpenedOutside: %v", outside)
	}
	for _, p := range outside {
		switch {
		case strings.HasPrefix(p, "/usr/"), strings.HasPrefix(p, "/w/"),
			strings.HasPrefix(p, "/proc/"), strings.HasPrefix(p, "/etc/"),
			strings.Contains(p, "/.cache/huggingface/hub"):
			t.Errorf("quiet path %q reported as an effect", p)
		}
	}
	if r.Effects() != 1+2+1+len(outside) {
		t.Fatalf("Effects() = %d, lists = %d %d %d %d", r.Effects(),
			len(r.Exec), len(r.Connect), len(r.OpenedOutside), len(r.Wrote))
	}
}

// TestApplyTraceOldPidForm covers the `[pid N]` prefix an older strace writes,
// so a run on a different host does not silently report no effects.
func TestApplyTraceOldPidForm(t *testing.T) {
	r := &malice.Run{}
	applyTrace(r, `[pid 99] execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x0 /* 1 var */) = 0`)
	if len(r.Exec) != 1 || r.Exec[0] != "/bin/sh -c id" {
		t.Fatalf("Exec = %v", r.Exec)
	}
}

// TestApplyTraceUnterminated keeps the truncated part: strace cuts a long argv at
// -s, and dropping the whole call would hide the program that ran.
func TestApplyTraceUnterminated(t *testing.T) {
	r := &malice.Run{}
	applyTrace(r, `7 execve("/bin/sh", ["/bin/sh", "-c", "curl http://x") = 0`)
	if len(r.Exec) != 1 || !strings.Contains(r.Exec[0], "/bin/sh -c curl http://x") {
		t.Fatalf("Exec = %v", r.Exec)
	}
}

// TestApplyTraceDedupesAndBounds pins the size contract: a payload that opens the
// same file a thousand times produces one entry, and one that opens thousands of
// distinct files is bounded.
func TestApplyTraceDedupesAndBounds(t *testing.T) {
	var b strings.Builder
	for range 1000 {
		b.WriteString(`1 openat(AT_FDCWD, "/home/worker/f.txt", O_RDONLY) = 3` + "\n")
	}
	r := &malice.Run{}
	applyTrace(r, b.String())
	if len(r.OpenedOutside) != 1 {
		t.Fatalf("OpenedOutside = %d entries, want 1 deduped", len(r.OpenedOutside))
	}

	b.Reset()
	for i := range 500 {
		b.WriteString(`1 openat(AT_FDCWD, "/home/worker/f` + itoa(i) + `.txt", O_RDONLY) = 3` + "\n")
	}
	r = &malice.Run{}
	applyTrace(r, b.String())
	if len(r.OpenedOutside) != maxEffectEntries {
		t.Fatalf("OpenedOutside = %d entries, want the bound %d", len(r.OpenedOutside), maxEffectEntries)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }
