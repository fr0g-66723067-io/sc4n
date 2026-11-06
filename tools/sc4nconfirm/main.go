// Command sc4nconfirm records what an artifact does when a loader loads it.
//
// SC4N-MALICE-CONSTRUCTED says the loader's load path runs code the artifact
// supplies. This tool answers the next question, the only one left: does it, in
// fact, run - and what did it touch? It loads the artifact in a disposable
// container with no network interface and a read-only root, under strace, and
// writes an attestation the scanner merges with -attestation into
// SC4N-MALICE-DEMONSTRATED.
//
// Executing untrusted artifacts is a *tool's* job and never the scanner's.
// internal/ and cmd/ keep zero os/exec (TestScanPathDoesNotExec), the scanner
// links no third-party code, and this binary never touches an artifact outside
// the container it started.
//
// The container is the boundary:
//
//	--network=none          nothing leaves, so a connect is an attempt, not a
//	                        call home - and the attempt is the evidence
//	--read-only             the image cannot be modified by the payload
//	--tmpfs /tmp,/home/worker  writable scratch, so writes are observable and
//	                        canaries can exist
//	--cap-add SYS_PTRACE    the one capability granted, because ptrace is the
//	                        only effect source a payload cannot bypass: an
//	                        audit hook can be blinded from native code, and a
//	                        filesystem diff sees writes but not exec or connect
//	--pids-limit, --memory, --cpus  a payload that forks or allocates is cut off
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/malice"
)

const (
	exitOK     = 0
	exitFailed = 1 // at least one artifact could not be confirmed
	exitUsage  = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// options is the decoded command line.
type options struct {
	artifacts []string
	out       string
	image     string
	timeout   time.Duration
	keep      bool
}

func run(args []string, stdout, stderr io.Writer) int {
	var o options
	fs := flag.NewFlagSet("sc4nconfirm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Func("artifact", "artifact to load (file or model directory); repeatable", func(v string) error {
		if v == "" {
			return errors.New("empty artifact path")
		}
		o.artifacts = append(o.artifacts, v)
		return nil
	})
	fs.StringVar(&o.out, "out", "", "write the attestation to FILE")
	fs.StringVar(&o.image, "image", "sc4nconfirm:1", "container image that provides strace and the loaders")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Minute, "wall-clock bound for one load")
	fs.BoolVar(&o.keep, "keep", false, "keep the scratch directory (trace and loader output)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "sc4nconfirm: unexpected argument %q\n", fs.Args()[0])
		return exitUsage
	}
	if len(o.artifacts) == 0 || o.out == "" {
		fmt.Fprintln(stderr, "sc4nconfirm: -artifact and -out are required")
		return exitUsage
	}
	if err := dockerAvailable(); err != nil {
		fmt.Fprintf(stderr, "sc4nconfirm: %v\n", err)
		return exitFailed
	}

	doc := malice.Attestation{Version: malice.Version}
	byDigest := map[string]int{}
	failed := 0
	for i, a := range o.artifacts {
		r, err := confirmOne(o, a, i, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "sc4nconfirm: %s: %v\n", a, err)
			failed++
			continue
		}
		addRun(&doc.Runs, byDigest, *r)
	}
	sortRuns(doc.Runs)
	if err := writeAttestation(o.out, doc); err != nil {
		fmt.Fprintf(stderr, "sc4nconfirm: %v\n", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "sc4nconfirm: %d artifact(s), %d with effects, wrote %s\n",
		len(doc.Runs), withEffects(doc.Runs), o.out)
	if failed > 0 {
		fmt.Fprintf(stderr, "sc4nconfirm: %d artifact(s) could not be confirmed\n", failed)
		return exitFailed
	}
	return exitOK
}

// confirmOne loads one artifact in the sandbox and turns what happened into a
// Run.
func confirmOne(o options, artifact string, index int, stderr io.Writer) (*malice.Run, error) {
	abs, err := filepath.Abs(artifact)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	// A model directory is attested through the config.json that names its
	// code: that file is the artifact a scan reports SC4N-CONFIG-AUTO-MAP on, and
	// the digest key is what lets the demonstration land on it. A directory
	// without a config.json has no digest of its own, so its run informs a human
	// and can never be merged - leaving SHA256 empty keeps that visible instead
	// of colliding with another artifact.
	var digest string
	switch {
	case fi.Mode().IsRegular():
		digest, err = fileDigest(abs)
		if err != nil {
			return nil, err
		}
	case fi.IsDir():
		if cfg := filepath.Join(abs, "config.json"); isRegularFile(cfg) {
			digest, err = fileDigest(cfg)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("%s is neither a regular file nor a directory", artifact)
	}

	scratch, err := os.MkdirTemp("", "sc4nconfirm-")
	if err != nil {
		return nil, err
	}
	if o.keep {
		fmt.Fprintf(stderr, "sc4nconfirm: scratch %s\n", scratch)
	} else {
		defer os.RemoveAll(scratch)
	}
	outDir := filepath.Join(scratch, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	// The artifact is bind-mounted read-only at the path the loader is told to
	// open: a file is mounted as itself so its siblings are invisible, a model
	// directory as the directory the loader must import from.
	target := "/w/" + filepath.Base(abs)
	mount := abs + ":" + target + ":ro"
	if fi.IsDir() {
		target = "/w"
		mount = abs + ":/w:ro"
	}

	name := fmt.Sprintf("sc4nconfirm-%d-%d", os.Getpid(), index)
	runArgs := []string{
		"run", "--rm", "--name", name,
		"--network=none", "--read-only",
		"--tmpfs", "/tmp:rw,size=64m",
		"--tmpfs", "/home/worker:rw,size=64m",
		"--memory", "2g", "--pids-limit", "128", "--cpus", "2",
		"--cap-add", "SYS_PTRACE", "--security-opt", "no-new-privileges",
		"-v", mount, "-v", outDir + ":/out",
		o.image, target, "/out/result.json",
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", runArgs...) // #nosec G204 -- fixed image, operator-supplied artifact
	var tail bytes.Buffer
	cmd.Stdout = &tail
	cmd.Stderr = &tail
	runErr := cmd.Run()
	if ctx.Err() != nil {
		// The client was killed; the container it started may not have been.
		rm := exec.CommandContext(context.Background(), "docker", "rm", "-f", name) // #nosec G204 -- fixed name
		_ = rm.Run()
	}

	r := &malice.Run{
		SHA256: digest,
		Path:   abs,
	}
	res, resErr := readResult(filepath.Join(outDir, "result.json"))
	switch {
	case resErr != nil:
		r.Loaded = false
		r.Error = resErr.Error()
		if runErr != nil {
			r.Error = firstLine(tail.String())
			if r.Error == "" {
				r.Error = runErr.Error()
			}
		}
	case ctx.Err() != nil:
		r.Loaded = false
		r.Error = "timed out after " + o.timeout.String()
	default:
		r.Loader = res.Loader
		r.Loaded = res.Loaded
		r.Error = res.Error
		r.MissingModules = res.MissingModules
	}
	if trace, terr := os.ReadFile(filepath.Join(outDir, "trace")); terr == nil {
		applyTrace(r, string(trace))
	}
	if r.Error == "" && r.Loaded {
		r.Error = ""
	}
	return r, nil
}

// addRun appends a run, or folds it into the run already recorded for the same
// digest.
//
// One digest can legitimately appear at several paths - a malware corpus is full
// of the same payload pasted into a dozen repositories - and the attestation is
// keyed by digest, so a second entry for the same bytes is not new evidence. The
// reader refuses duplicates (an ambiguous attestation is a producer bug), which
// makes folding them here the producer's job: the effects are unioned and the
// first path is kept.
func addRun(runs *[]malice.Run, byDigest map[string]int, r malice.Run) {
	if r.SHA256 != "" {
		if idx, seen := byDigest[r.SHA256]; seen {
			mergeRun(&(*runs)[idx], &r)
			return
		}
		byDigest[r.SHA256] = len(*runs)
	}
	*runs = append(*runs, r)
}

// mergeRun unions b's effects into a. The loads are of identical bytes, so the
// union is the honest record; the first path is kept because it is where the
// operator pointed the harness.
func mergeRun(a, b *malice.Run) {
	a.Loaded = a.Loaded || b.Loaded
	a.Exec = union(a.Exec, b.Exec)
	a.Connect = union(a.Connect, b.Connect)
	a.OpenedOutside = union(a.OpenedOutside, b.OpenedOutside)
	a.Wrote = union(a.Wrote, b.Wrote)
	a.MissingModules = union(a.MissingModules, b.MissingModules)
	if a.Error == "" {
		a.Error = b.Error
	}
}

func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// loaderResult is what image/load.py wrote for this run.
type loaderResult struct {
	Loader         string   `json:"loader"`
	Loaded         bool     `json:"loaded"`
	Error          string   `json:"error"`
	MissingModules []string `json:"missingModules"`
}

func readResult(path string) (*loaderResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the container wrote no loader result: %w", err)
	}
	var r loaderResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("loader result: %w", err)
	}
	return &r, nil
}

func isRegularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// fileDigest is the full SHA-256 of an artifact, the key the scanner merges on.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeAttestation(path string, doc malice.Attestation) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func dockerAvailable() error {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker is required (it is the sandbox this tool needs): %v: %s", err, firstLine(errb.String()))
	}
	return nil
}

// sortRuns makes the document deterministic: runs by digest, effects sorted, so
// two runs over the same corpus produce byte-identical attestations.
func sortRuns(runs []malice.Run) {
	sort.SliceStable(runs, func(i, j int) bool {
		if runs[i].SHA256 != runs[j].SHA256 {
			return runs[i].SHA256 < runs[j].SHA256
		}
		return runs[i].Path < runs[j].Path
	})
	for i := range runs {
		sort.Strings(runs[i].Exec)
		sort.Strings(runs[i].Connect)
		sort.Strings(runs[i].OpenedOutside)
		sort.Strings(runs[i].Wrote)
		sort.Strings(runs[i].MissingModules)
	}
}

func withEffects(runs []malice.Run) int {
	n := 0
	for i := range runs {
		if runs[i].Effects() > 0 {
			n++
		}
	}
	return n
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
