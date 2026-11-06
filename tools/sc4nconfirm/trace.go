package main

// strace parsing.
//
// The trace is the evidence, so the parser's job is to be boring and total: it
// reads the syscalls the entrypoint asked for (execve, execveat, openat,
// connect) and turns each into one line of an effect list. It never fails a run
// on a line it does not understand - a payload can emit arbitrary text through
// the file it writes, and a parser that gave up would turn "unparseable" into
// "no effects".

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/malice"
)

// maxEffectEntries bounds each list. A payload that opens ten thousand files
// should not produce a hundred-kilobyte attestation; the finding quotes the
// first few and the count is in the extra fields.
const maxEffectEntries = 64

// directories the loader legitimately reads, so an open inside them is not an
// effect. /home/worker is deliberately not here: it holds the canaries.
var traceQuietPrefixes = []string{
	"/w", "/usr", "/lib", "/lib64", "/opt/sc4nconfirm", "/proc", "/sys", "/dev",
	"/tmp", "/etc", "/run", "/var/cache", "/root/.cache/huggingface",
	// /out holds the harness's own result file and trace: a write there is the
	// harness talking to itself, not a payload effect.
	"/out",
}

// the canaries the entrypoint plants. A read of one of these is the strongest
// signal the harness can produce: the payload went looking for credentials.
var canaryPaths = []string{
	"/home/worker/.cache/huggingface/token",
	"/home/worker/.ssh/id_rsa",
	"/home/worker/.ssh/id_ed25519",
	"/home/worker/DOCUMENTS/id.txt",
	"/home/worker/.aws/credentials",
	"/home/worker/.netrc",
}

// framework cache probing under the worker home is noise: transformers asks for
// $HOME/.cache/huggingface on every load.
var homeNoisePrefixes = []string{
	"/home/worker/.cache/huggingface/hub",
	"/home/worker/.cache/huggingface/transformers",
}

// applyTrace fills the effect lists from a strace log.
func applyTrace(r *malice.Run, trace string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(trace, "\n") {
		call, rest := splitCall(line)
		if call == "" {
			continue
		}
		switch call {
		case "execve", "execveat":
			if argv := execArgv(rest); argv != "" && !harnessExec(argv) {
				addEffect(&r.Exec, seen, argv)
			}
		case "open", "openat", "openat2":
			path, writing := openTarget(rest)
			if path == "" {
				continue
			}
			switch {
			case writing && !quietPath(path):
				addEffect(&r.Wrote, seen, path)
			case !quietPath(path):
				addEffect(&r.OpenedOutside, seen, path)
			}
		case "connect":
			if addr := connectAddr(rest); addr != "" {
				addEffect(&r.Connect, seen, addr)
			}
		}
	}
}

// splitCall returns the syscall name and its argument text for one strace line,
// or "" for a line that is not a completed syscall. Both `1234  execve(...)` and
// the older `[pid 1234] execve(...)` forms are handled, and an unfinished or
// resumed line is skipped: half a call is not evidence.
func splitCall(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "<") || strings.Contains(line, "<unfinished ...>") {
		return "", ""
	}
	if strings.HasPrefix(line, "[pid ") {
		if i := strings.Index(line, "] "); i >= 0 {
			line = line[i+2:]
		}
	}
	// Skip the pid column.
	if i := strings.IndexAny(line, " \t"); i > 0 && isDigits(line[:i]) {
		line = strings.TrimLeft(line[i:], " \t")
	}
	open := strings.IndexByte(line, '(')
	if open <= 0 {
		return "", ""
	}
	call := line[:open]
	for _, c := range call {
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", ""
		}
	}
	body := line[open+1:]
	if i := strings.LastIndex(body, ") = "); i >= 0 {
		body = body[:i]
	}
	return call, body
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// quotedStrings returns the double-quoted strings in s, honouring the escapes
// strace emits (\\, \", \n, and \NNN octal for non-printables). A string cut short
// by strace's -s limit is returned with a trailing marker rather than dropped.
func quotedStrings(s string) []string {
	var out []string
	// The index is advanced by the scan itself, so the classic form stays.
	for i := 0; i < len(s); {
		q := strings.IndexByte(s[i:], '"')
		if q < 0 {
			break
		}
		var b strings.Builder
		j := i + q + 1
		closed := false
		for j < len(s) {
			c := s[j]
			if c == '\\' && j+1 < len(s) {
				b.WriteByte(s[j+1])
				j += 2
				continue
			}
			if c == '"' {
				closed = true
				j++
				break
			}
			b.WriteByte(c)
			j++
		}
		switch {
		case closed:
			out = append(out, b.String())
		case b.Len() > 0:
			out = append(out, b.String()+"...")
		}
		i = j
	}
	return out
}

// execArgv renders the program and its arguments as one line.
func execArgv(body string) string {
	parts := quotedStrings(body)
	if len(parts) == 0 {
		return ""
	}
	// execve(path, [argv...]) and execveat(dirfd, path, [argv...], ...) put the
	// path first and the argv array after it. argv[0] repeats the program under
	// another spelling (`/bin/sh` vs `sh`), so it is dropped rather than printed
	// twice, and the arguments are capped: four name what ran.
	prog := parts[0]
	rest := parts[1:]
	if len(rest) > 0 && (rest[0] == prog || filepath.Base(prog) == rest[0]) {
		rest = rest[1:]
	}
	if len(rest) > 4 {
		rest = append(rest[:4], "...")
	}
	if len(rest) == 0 {
		return prog
	}
	return prog + " " + strings.Join(rest, " ")
}

// harnessExec reports whether an exec is the harness loading the artifact rather
// than something the artifact started. The container's own python3 is the first
// execve in every trace.
func harnessExec(argv string) bool {
	return strings.Contains(argv, "/opt/sc4nconfirm/load.py")
}

// openTarget returns the path an open/openat call names and whether the flags
// ask for a write.
func openTarget(body string) (string, bool) {
	parts := quotedStrings(body)
	if len(parts) == 0 {
		return "", false
	}
	writing := strings.Contains(body, "O_WRONLY") || strings.Contains(body, "O_RDWR") ||
		strings.Contains(body, "O_CREAT") || strings.Contains(body, "O_TRUNC")
	return parts[0], writing
}

// connectAddr renders the dialled address as ip:port, or unix:path.
func connectAddr(body string) string {
	if i := strings.Index(body, "sun_path="); i >= 0 {
		if parts := quotedStrings(body[i:]); len(parts) > 0 {
			return "unix:" + parts[0]
		}
	}
	host := ""
	for _, key := range []string{`inet_addr("`, `inet_pton(AF_INET6, "`} {
		if i := strings.Index(body, key); i >= 0 {
			rest := body[i+len(key):]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				host = rest[:j]
			}
		}
	}
	port := ""
	if i := strings.Index(body, "htons("); i >= 0 {
		rest := body[i+len("htons("):]
		if j := strings.IndexByte(rest, ')'); j > 0 {
			if n, err := strconv.Atoi(rest[:j]); err == nil {
				port = strconv.Itoa(n)
			}
		}
	}
	switch {
	case host != "" && port != "":
		return host + ":" + port
	case host != "":
		return host
	case port != "":
		return "port " + port
	}
	return ""
}

// quietPath reports whether an opened path is loader plumbing rather than an
// effect. Canaries are never quiet, even when they live under a quiet tree.
func quietPath(p string) bool {
	if p == "" {
		return true
	}
	for _, c := range canaryPaths {
		if p == c || strings.HasPrefix(p, c) {
			return false
		}
	}
	for _, n := range homeNoisePrefixes {
		if strings.HasPrefix(p, n) {
			return true
		}
	}
	for _, q := range traceQuietPrefixes {
		if p == q || strings.HasPrefix(p, q+"/") || strings.HasPrefix(p, q) {
			return true
		}
	}
	return false
}

func addEffect(list *[]string, seen map[string]bool, v string) {
	if seen[v] || len(*list) >= maxEffectEntries {
		return
	}
	seen[v] = true
	*list = append(*list, v)
}
