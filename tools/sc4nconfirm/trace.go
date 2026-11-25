package main

// strace parsing.
//
// The trace is the evidence, so the parser's job is to be boring and total: it
// reads the syscalls the entrypoint asked for (execve, execveat, open/openat,
// creat, unlinkat, renameat2, memfd_create, connect, sendto/sendmsg/sendmmsg)
// and turns each into one line of an effect list. It never fails a run on a
// line it does not understand - a payload can emit arbitrary text through the
// file it writes, and a parser that gave up would turn "unparseable" into "no
// effects".

import (
	"bufio"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/malice"
)

// maxEffectEntries bounds each list. A payload that opens ten thousand files
// should not produce a hundred-kilobyte attestation; the finding quotes the
// first few and the count is in the extra fields.
const maxEffectEntries = 64

// maxPendingPIDs bounds the in-flight <unfinished ...> table so an attacker
// that forks continuously cannot exhaust host memory while parsing.
const maxPendingPIDs = 4096

// directories the loader legitimately reads, so an open inside them is not an
// effect. /home/worker is deliberately not here: it holds the canaries.
var traceQuietPrefixes = []string{
	"/w", "/usr", "/lib", "/lib64", "/opt/sc4nconfirm", "/proc", "/sys", "/dev",
	"/etc", "/run", "/var/cache", "/root/.cache/huggingface",
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

// applyTraceFile streams tracePath from the start up to maxBytes and fills r's
// effect lists. Streaming from byte 0 ensures a payload that floods quiet calls
// at the tail cannot push earlier effects out of view.
func applyTraceFile(r *malice.Run, tracePath string, maxBytes int64) error {
	f, err := os.Open(tracePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return applyTraceReader(r, f, "", maxBytes)
}

// applyTrace fills the effect lists from an in-memory strace log. harnessPID is
// the optional pid of the harness exec, or "" to identify it as the first exec.
func applyTrace(r *malice.Run, trace, harnessPID string) {
	_ = applyTraceReader(r, strings.NewReader(trace), harnessPID, 0)
}

// applyTraceReader stream-parses strace output line-by-line up to maxBytes
// (unlimited when maxBytes <= 0), reassembling per-PID <unfinished ...> /
// <... resumed> pairs so multi-threaded workloads do not lose syscalls.
func applyTraceReader(r *malice.Run, rd io.Reader, harnessPID string, maxBytes int64) error {
	if maxBytes > 0 {
		rd = io.LimitReader(rd, maxBytes)
	}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64<<10), 4<<20)

	seen := map[string]bool{}
	pending := map[string]string{}
	firstExec := true

	for sc.Scan() {
		pid, content := stripPID(sc.Text())
		if content == "" {
			continue
		}
		if idx := strings.Index(content, "<unfinished ...>"); idx >= 0 {
			if len(pending) < maxPendingPIDs || pending[pid] != "" {
				pending[pid] = strings.TrimRight(content[:idx], " \t")
			}
			continue
		}
		if strings.HasPrefix(content, "<... ") {
			resumedIdx := strings.Index(content, " resumed>")
			if resumedIdx < 0 {
				continue
			}
			resumedCall := strings.TrimSpace(content[len("<... "):resumedIdx])
			prefix, ok := pending[pid]
			if !ok {
				continue
			}
			delete(pending, pid)
			if !strings.HasPrefix(prefix, resumedCall+"(") {
				continue
			}
			content = prefix + content[resumedIdx+len(" resumed>"):]
		}

		call, rest := parseCall(content)
		if call == "" {
			continue
		}
		switch call {
		case "execve", "execveat":
			parts := quotedStrings(rest)
			drop := false
			if firstExec && harnessExec(parts) {
				// Only the very first execve can be the harness's own start of
				// load.py; a later in-place execve by the same PID is payload.
				if harnessPID != "" {
					drop = pid == harnessPID
				} else {
					drop = true
				}
			}
			if !drop {
				if argv := execArgv(call, rest); argv != "" {
					addEffect(&r.Exec, seen, argv)
				}
			}
			firstExec = false
		case "open", "openat", "openat2":
			p, writing := openTarget(rest)
			if p == "" {
				continue
			}
			if writing {
				addEffect(&r.Wrote, seen, p)
			} else if !quietPath(p, false) {
				addEffect(&r.OpenedOutside, seen, p)
			}
		case "creat", "unlinkat":
			if p, _, ok := firstQuotedString(rest); ok && p != "" {
				addEffect(&r.Wrote, seen, p)
			}
		case "renameat2":
			parts := quotedStrings(rest)
			for i := 0; i < len(parts) && i < 2; i++ {
				if parts[i] != "" {
					addEffect(&r.Wrote, seen, parts[i])
				}
			}
		case "memfd_create":
			if p, _, ok := firstQuotedString(rest); ok {
				addEffect(&r.Wrote, seen, "memfd:"+p)
			}
		case "connect", "sendto", "sendmsg", "sendmmsg":
			if addr := connectAddr(rest); addr != "" {
				addEffect(&r.Connect, seen, addr)
			}
		}
	}
	return sc.Err()
}

// stripPID splits the leading pid column from one strace line. Both
// `1234  execve(...)` and the older `[pid 1234] execve(...)` forms are handled.
func stripPID(line string) (pid, content string) {
	t := strings.TrimSpace(line)
	if t == "" {
		return "", ""
	}
	if strings.HasPrefix(t, "[pid ") {
		rest := t[len("[pid "):]
		if i := strings.IndexByte(rest, ']'); i > 0 {
			return strings.TrimSpace(rest[:i]), strings.TrimLeft(rest[i+1:], " \t")
		}
		return "", ""
	}
	if i := strings.IndexAny(t, " \t"); i > 0 && isDigits(t[:i]) {
		return t[:i], strings.TrimLeft(t[i:], " \t")
	}
	return "", t
}

// parseCall extracts the syscall name and argument body from a PID-stripped
// strace line, or "" when the line is not a completed syscall.
func parseCall(content string) (string, string) {
	if content == "" || strings.HasPrefix(content, "<") {
		return "", ""
	}
	open := strings.IndexByte(content, '(')
	if open <= 0 {
		return "", ""
	}
	call := content[:open]
	for _, c := range call {
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", ""
		}
	}
	body := content[open+1:]
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

// firstQuotedString returns the first double-quoted string in s and the
// remainder of s immediately after its closing quote, honouring backslash
// escapes so callers can inspect syscall flags strictly after the path.
func firstQuotedString(s string) (val, after string, ok bool) {
	q := strings.IndexByte(s, '"')
	if q < 0 {
		return "", "", false
	}
	var b strings.Builder
	j := q + 1
	for j < len(s) {
		c := s[j]
		if c == '\\' && j+1 < len(s) {
			b.WriteByte(s[j+1])
			j += 2
			continue
		}
		if c == '"' {
			return b.String(), s[j+1:], true
		}
		b.WriteByte(c)
		j++
	}
	if b.Len() > 0 {
		return b.String() + "...", "", true
	}
	return "", "", false
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
func execArgv(call, body string) string {
	parts := quotedStrings(body)
	if len(parts) == 0 {
		return ""
	}
	// execve(path, [argv...]) and execveat(dirfd, path, [argv...], ...) put the
	// path first and the argv array after it. When execveat is called with
	// AT_EMPTY_PATH (fileless memfd execution), path is "" and dirfd identifies
	// the executable descriptor.
	prog := parts[0]
	rest := parts[1:]
	if call == "execveat" && prog == "" && strings.Contains(body, "AT_EMPTY_PATH") {
		fd := "unknown"
		if comma := strings.IndexByte(body, ','); comma > 0 {
			if f := strings.TrimSpace(body[:comma]); f != "" {
				fd = f
			}
		}
		prog = "fd:" + fd
	} else if len(rest) > 0 && (rest[0] == prog || filepath.Base(prog) == rest[0]) {
		// argv[0] repeats the program under another spelling (`/bin/sh` vs `sh`),
		// so it is dropped rather than printed twice.
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

// harnessExec reports whether the first exec is the harness loading the
// artifact rather than something the artifact started. Match the executable,
// the argv[0] and the loader path exactly: `/bin/sh -c "/opt/sc4nconfirm/load.py"`
// is a payload spawning a shell that mentions the loader, not the harness.
func harnessExec(parts []string) bool {
	if len(parts) < 3 {
		return false
	}
	return filepath.Base(parts[0]) == "python3" &&
		parts[2] == "/opt/sc4nconfirm/load.py"
}

// openTarget returns the path an open/openat call names and whether the flags
// after the path ask for a write.
func openTarget(body string) (string, bool) {
	p, after, ok := firstQuotedString(body)
	if !ok {
		return "", false
	}
	writing := strings.Contains(after, "O_WRONLY") || strings.Contains(after, "O_RDWR") ||
		strings.Contains(after, "O_CREAT") || strings.Contains(after, "O_TRUNC")
	return p, writing
}

// connectAddr renders the dialled address as ip:port (or [ipv6]:port), or unix:path.
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
		if strings.Contains(host, ":") {
			return "[" + host + "]:" + port
		}
		return host + ":" + port
	case host != "":
		return host
	case port != "":
		return "port " + port
	}
	return ""
}

// quietPath reports whether an open is harness plumbing rather than an effect.
// A write is never quiet: the payload writing its own scratch file is the
// observation. Paths are cleaned first so traversal segments such as
// `/dev/../home/worker/.aws/credentials` cannot hide canary reads behind a
// quiet prefix.
func quietPath(p string, writing bool) bool {
	if p == "" {
		return true
	}
	p = path.Clean(p)
	if writing {
		return false
	}
	for _, c := range canaryPaths {
		if p == c || strings.HasPrefix(p, c+"/") {
			return false
		}
	}
	for _, n := range homeNoisePrefixes {
		if p == n || strings.HasPrefix(p, n+"/") {
			return true
		}
	}
	for _, q := range traceQuietPrefixes {
		if p == q || strings.HasPrefix(p, q+"/") {
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
