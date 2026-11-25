package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const defaultOracleTimeout = 2 * time.Minute

// Oracle is the independent validator the lab trusts. It is never sc4n: the
// whole point of the instrument is that the "is this artifact loadable" answer
// comes from a tool whose defects are uncorrelated with the scanner's.
type Oracle interface {
	// Name is the tool, for matrix.json.
	Name() string
	// Available returns why the oracle cannot run, or nil.
	Available() error
	// Validate reports whether the file is an artifact this tool accepts, plus
	// a one-line note (the tool's own words on failure, "ok" on success).
	Validate(path string) (bool, string)
}

// hostValid runs an external tool that validates its last argument and exits
// non-zero on a file it rejects. Every host oracle in this plan is that shape:
// `7z t`, `xz -t`, `zstd -t`, `gzip -t`, `readelf -h`.
type hostValid struct {
	name string
	bin  string
	args []string
}

func newHostValid(name string, args ...string) *hostValid {
	return &hostValid{name: name, bin: args[0], args: args[1:]}
}

func (h *hostValid) Name() string { return h.name }

func (h *hostValid) Available() error {
	if _, err := exec.LookPath(h.bin); err != nil {
		return fmt.Errorf("%s: %w", h.name, err)
	}
	return nil
}

func (h *hostValid) Validate(path string) (bool, string) {
	args := append(append([]string{}, h.args...), path)
	out, err := exec.Command(h.bin, args...).CombinedOutput() // #nosec G204 -- the lab's own generator, not scanner input
	note := strings.TrimSpace(string(out))
	if err != nil {
		if note == "" {
			return false, err.Error()
		}
		return false, firstLine(note)
	}
	return true, "ok"
}

// firstLine keeps the matrix readable: tools like 7z print several lines of
// banner before the useful message.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// dockerOracle validates a mutant inside the pinned image: python3 check.py
// reads /w/check.json and exits non-zero when onnx.checker (or, in "session"
// mode, onnxruntime) rejects the model.
type dockerOracle struct {
	name    string
	image   string
	dir     string // host directory mounted at /w
	file    string // base name inside that directory
	mode    string
	timeout time.Duration
}

func (d *dockerOracle) Name() string { return d.name }

func (d *dockerOracle) Available() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	// `docker image inspect` is the cheapest proof the image exists; a pull here
	// would make a run depend on the network, which the oracle must not.
	out, err := exec.Command("docker", "image", "inspect", d.image, "--format", "{{.Id}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker: image %s not present (%s)", d.image, firstLine(strings.TrimSpace(string(out))))
	}
	return nil
}

type oracleCheckReq struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

func dockerOracleArgs(dir, py, image string) []string {
	return []string{
		"run", "--rm", "--network=none",
		"--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", "1g", "--pids-limit", "64",
		"-v", dir + ":/w:ro", "-v", py + ":/opt/sc4nlab:ro", image,
		"python3", "/opt/sc4nlab/check.py", "/w/check.json",
	}
}

func (d *dockerOracle) Validate(path string) (bool, string) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	// The argument file is what check.py reads, so one invocation serves both
	// validity modes and the model itself is never re-encoded.
	cf, err := json.Marshal(oracleCheckReq{Path: base, Mode: d.mode})
	if err != nil {
		return false, err.Error()
	}
	if err := writeFile(filepath.Join(dir, "check.json"), cf); err != nil {
		return false, err.Error()
	}
	py, err := stageScripts(filepath.Join(d.dir, "oracle"))
	if err != nil {
		return false, err.Error()
	}
	timeout := d.timeout
	if timeout <= 0 {
		timeout = defaultOracleTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", dockerOracleArgs(dir, py, d.image)...) // #nosec G204 -- fixed image, lab-owned directory
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if ctx.Err() != nil {
		return false, "timed out after " + timeout.String()
	}
	note := strings.TrimSpace(out.String())
	if err != nil {
		if note == "" {
			return false, err.Error()
		}
		return false, lastLine(note)
	}
	if note == "" {
		return true, "ok"
	}
	return true, lastLine(note)
}

// lastLine is what a Python traceback ends with, and it is the sentence worth
// putting in a matrix cell.
func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
