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
	applyTrace(r, sampleTrace, "")

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
	applyTrace(r, `[pid 99] execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x0 /* 1 var */) = 0`, "")
	if len(r.Exec) != 1 || r.Exec[0] != "/bin/sh -c id" {
		t.Fatalf("Exec = %v", r.Exec)
	}
}

// TestApplyTraceUnterminated keeps the truncated part: strace cuts a long argv at
// -s, and dropping the whole call would hide the program that ran.
func TestApplyTraceUnterminated(t *testing.T) {
	r := &malice.Run{}
	applyTrace(r, `7 execve("/bin/sh", ["/bin/sh", "-c", "curl http://x") = 0`, "")
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
	applyTrace(r, b.String(), "")
	if len(r.OpenedOutside) != 1 {
		t.Fatalf("OpenedOutside = %d entries, want 1 deduped", len(r.OpenedOutside))
	}

	b.Reset()
	for i := range 500 {
		b.WriteString(`1 openat(AT_FDCWD, "/home/worker/f` + itoa(i) + `.txt", O_RDONLY) = 3` + "\n")
	}
	r = &malice.Run{}
	applyTrace(r, b.String(), "")
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

func TestQuietPathIsBoundaryAware(t *testing.T) {
	cases := []struct {
		path    string
		writing bool
		want    bool
	}{
		{"/tmp/stage", true, false}, // a write is the effect
		{"/out/trace", true, false}, // the payload cannot write it; if it does, report
		{"/work", true, false},      // not a harness prefix
		{"/usr/lib/x.py", false, true},
		{"/usrlib/x.py", false, false}, // bare HasPrefix would hide this
		{canaryPaths[0], false, false},
		{canaryPaths[0] + "/child", false, false},
	}
	for _, c := range cases {
		if got := quietPath(c.path, c.writing); got != c.want {
			t.Errorf("quietPath(%q, %v) = %v, want %v", c.path, c.writing, got, c.want)
		}
	}
}

func TestHarnessExecMatchIsExact(t *testing.T) {
	if !harnessExec([]string{"/usr/local/bin/python3", "python3", "/opt/sc4nconfirm/load.py"}) {
		t.Fatal("the loader exec was not recognised")
	}
	for _, parts := range [][]string{
		{"/bin/sh", "sh", "-c", "/opt/sc4nconfirm/load.py"},
		{"/usr/bin/python3", "python3"},
		{"/usr/bin/python3", "python3", "/tmp/load.py"},
	} {
		if harnessExec(parts) {
			t.Errorf("harnessExec(%q) = true, want false", parts)
		}
	}
}

func TestApplyTraceDropsOnlyTheFirstHarnessExec(t *testing.T) {
	r := &malice.Run{}
	applyTrace(r, `1 execve("/usr/local/bin/python3", ["python3", "/opt/sc4nconfirm/load.py", "/w/a.pkl", "/tmp/result.json"], 0x0) = 0
2 execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x0) = 0
3 execve("/bin/sh", ["/bin/sh", "-c", "/opt/sc4nconfirm/load.py"], 0x0) = 0
`, "")
	if len(r.Exec) != 2 {
		t.Fatalf("Exec = %v, want the shell and the later loader-named shell", r.Exec)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestHarnessExecIsDroppedByPIDNotPosition pins the truncated-tail case: only the
// last 8 MiB of a trace are parsed, so a payload that floods quiet reads and then
// execs the loader's exact command line is the first exec of the parsed text. When
// the drop was keyed on position, that exec was discarded as the harness and the
// payload's own exec left no effect at all.
func TestHarnessExecIsDroppedByPIDNotPosition(t *testing.T) {
	harness := "1"
	tail := `77 execve("/usr/local/bin/python3", ["python3", "/opt/sc4nconfirm/load.py"], 0x0) = 0
78 execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x0) = 0
`
	r := &malice.Run{}
	applyTrace(r, tail, harness)
	if len(r.Exec) != 2 {
		t.Fatalf("Exec = %v, want the payload's loader-shaped exec kept", r.Exec)
	}

	// The harness's own exec, at its pid, is still dropped.
	r = &malice.Run{}
	applyTrace(r, `1 execve("/usr/local/bin/python3", ["python3", "/opt/sc4nconfirm/load.py"], 0x0) = 0
2 execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x0) = 0
`, harness)
	if len(r.Exec) != 1 || r.Exec[0] != "/bin/sh -c id" {
		t.Fatalf("Exec = %v, want only the shell", r.Exec)
	}
}
