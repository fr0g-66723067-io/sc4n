package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/hfcache"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/malice"
	"github.com/fr0g-66723067-io/sc4n/internal/policy"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

type scanFlags struct {
	format      string
	out         string
	failOn      string
	jobs        int
	memBudget   string
	maxArtifact string
	maxDepth    int
	maxDecomp   string
	maxRatio    int64
	maxFindings int
	timeout     time.Duration
	root        string
	stdin       bool
	name        string
	baseline    string
	attestation string
	hfCache     bool
	hfCacheDir  string
	symlinks    string
	deepStats   bool
	partial     []string
	timings     bool
	quiet       bool
	color       bool
}

func runScan(args []string, stdout, stderr io.Writer) int {
	var f scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.format, "format", "text", "output format: text, json, sarif or cyclonedx")
	fs.StringVar(&f.out, "out", "", "write output to FILE instead of stdout")
	fs.StringVar(&f.failOn, "fail-on", "high", "lowest severity that makes the run exit 1")
	fs.IntVar(&f.jobs, "j", 0, "worker count (0 = number of CPUs)")
	fs.StringVar(&f.memBudget, "mem-budget", "1GiB", "total artifact bytes mapped at once")
	fs.StringVar(&f.maxArtifact, "max-artifact", "64GiB", "largest single file to open")
	fs.IntVar(&f.maxDepth, "max-depth", 4, "container nesting cap")
	fs.StringVar(&f.maxDecomp, "max-decompress", "8GiB", "cumulative decompression cap per archive")
	fs.Int64Var(&f.maxRatio, "max-ratio", 200, "decompression ratio cap")
	fs.IntVar(&f.maxFindings, "max-findings", 100000, "finding cap, applied after -baseline suppression; the most severe findings are kept, so a dropped finding is never more severe than a kept one")
	fs.DurationVar(&f.timeout, "timeout", 0, "bound the whole scan (e.g. 10m; 0 = unbounded)")
	fs.StringVar(&f.root, "root", "", "containment root for path-shaped values")
	fs.StringVar(&f.symlinks, "symlinks", "root", "symlink targets: root (must resolve inside the scanned tree) or follow")
	fs.StringVar(&f.baseline, "baseline", "", "suppress findings already present in a previous JSON report")
	fs.StringVar(&f.attestation, "attestation", "",
		"merge a tools/sc4nconfirm attestation: artifacts whose digest appears in it get SC4N-MALICE-DEMONSTRATED")
	fs.BoolVar(&f.hfCache, "hf-cache", false, "scan a Hugging Face download cache instead of paths")
	fs.StringVar(&f.hfCacheDir, "hf-cache-dir", "", "cache root for -hf-cache (default $HF_HOME/hub or ~/.cache/huggingface/hub)")
	fs.BoolVar(&f.stdin, "stdin", false, "scan one artifact from stdin")
	fs.StringVar(&f.name, "name", "", "artifact name to use with -stdin")
	fs.BoolVar(&f.deepStats, "deep-stats", false, "enable informational weight-statistics findings")
	fs.Func("partial", "PATH whose bytes are a truncated copy of a larger file (repeatable); a rule that compares a declared extent against the file reports it as unverifiable instead of a violation", func(v string) error {
		f.partial = append(f.partial, v)
		return nil
	})
	fs.BoolVar(&f.timings, "timings", false, "include per-phase timings in the JSON output")
	fs.BoolVar(&f.quiet, "quiet", false, "print only rule counts and the summary line (text only)")
	fs.BoolVar(&f.color, "color", false, "force ANSI colour (text only; default: only on a terminal)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	paths := fs.Args()

	switch {
	case f.stdin:
		if f.name == "" {
			fmt.Fprintln(stderr, "sc4n: -stdin requires -name")
			return exitUsage
		}
		if f.hfCache {
			fmt.Fprintln(stderr, "sc4n: -stdin and -hf-cache are mutually exclusive")
			return exitUsage
		}
	case f.hfCache:
		// -hf-cache names its own scope; a path argument as well would make the
		// report's scope ambiguous, which is the one thing a scanner must not be.
		if len(paths) > 0 {
			fmt.Fprintln(stderr, "sc4n: -hf-cache takes no path arguments (use -hf-cache-dir to point it at a cache)")
			return exitUsage
		}
	case len(paths) == 0:
		fmt.Fprintln(stderr, "sc4n: scan needs at least one path (or -stdin -name NAME, or -hf-cache)")
		return exitUsage
	}
	// The format is validated before anything else touches the filesystem: an
	// invalid -format used to be caught by render() *after* os.Create had already
	// truncated the previous report to zero bytes.
	if !validFormat(f.format) {
		fmt.Fprintf(stderr, "sc4n: unknown -format %q (want text, json, sarif or cyclonedx)\n", f.format)
		return exitUsage
	}
	if _, err := report.ParseSeverity(f.failOn); err != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", err)
		return exitUsage
	}
	sev, _ := report.ParseSeverity(f.failOn)
	warnInertFlags(f, stderr)

	l, err := buildLimits(f)
	if err != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", err)
		return exitUsage
	}
	budget, err := parseSize(f.memBudget)
	if err != nil {
		fmt.Fprintf(stderr, "sc4n: -mem-budget: %v\n", err)
		return exitUsage
	}

	// The baseline is loaded before the scan because it changes how the finding
	// cap is applied: with a baseline the scan runs uncapped and the cap applies
	// to what survives suppression.
	var baseline map[string]bool
	if f.baseline != "" {
		base, err := policy.LoadBaseline(f.baseline)
		if err != nil {
			fmt.Fprintf(stderr, "sc4n: -baseline: %v\n", err)
			return exitUsage
		}
		baseline = base
	}
	var attestations *malice.Index
	if f.attestation != "" {
		ix, err := malice.Load(f.attestation)
		if err != nil {
			fmt.Fprintf(stderr, "sc4n: -attestation: %v\n", err)
			return exitUsage
		}
		attestations = ix
	}
	var symlinkPolicy scan.SymlinkPolicy
	switch f.symlinks {
	case "root":
		symlinkPolicy = scan.SymlinkRoot
	case "follow":
		symlinkPolicy = scan.SymlinkFollow
	default:
		fmt.Fprintf(stderr, "sc4n: -symlinks must be root or follow\n")
		return exitUsage
	}
	cfg := scan.Config{
		Paths:        paths,
		Partial:      f.partial,
		Symlinks:     symlinkPolicy,
		Limits:       l,
		Jobs:         f.jobs,
		MemBudget:    budget,
		Root:         f.root,
		DeepStats:    f.deepStats,
		Timeout:      f.timeout,
		MaxFindings:  f.maxFindings,
		Baseline:     baseline,
		Attestations: attestations,
	}
	switch {
	case f.stdin:
		cfg.StdinName = f.name
		cfg.Stdin = os.Stdin
		cfg.Paths = nil
	case f.hfCache:
		dir := f.hfCacheDir
		if dir == "" {
			dir = hfcache.DefaultDir()
		}
		// The expander runs before the walk and reports its own structural
		// findings (an escaping symlink, a missing blob), so it needs the
		// collector the report will be built from.
		collector := report.NewCollector(collectorLimit(f.maxFindings, l.MaxFindings, baseline))
		entries, err := hfcache.Expand(dir, collector)
		if err != nil {
			fmt.Fprintf(stderr, "sc4n: -hf-cache: %v\n", err)
			return exitUnreadable
		}
		if len(entries) == 0 {
			// The expander's structural findings — a malformed ref, a dangling blob
			// — are already in the collector, which is exactly why it is created
			// before Expand runs. Returning here without a report made a cache whose
			// refs are broken indistinguishable from a cache that is simply empty,
			// and -out was never created.
			fmt.Fprintf(stderr, "sc4n: -hf-cache: %s holds no blobs\n", dir)
			rep := report.Build(report.Tool{Name: "sc4n", Version: version}, f.root, nil, collector,
				reportLimits(l), nil, 0)
			if werr := writeReport(rep, f, stdout); werr != nil {
				fmt.Fprintf(stderr, "sc4n: %v\n", werr)
			}
			return exitUnreadable
		}
		cfg.Paths = nil
		cfg.Collector = collector
		cfg.Entries = make([]scan.Entry, 0, len(entries))
		for _, e := range entries {
			cfg.Entries = append(cfg.Entries, scan.Entry{
				Path: e.Path, Display: e.Display, Digest: e.Digest, Revision: e.Revision, RootDir: e.RootDir, Rel: e.Rel,
			})
		}
	}

	res, runErr := scan.Run(context.Background(), cfg)
	if res == nil {
		// scan.Run only returns a nil result when it refused the configuration
		// before looking at any file, which is a usage error.
		fmt.Fprintf(stderr, "sc4n: %v\n", runErr)
		return exitUsage
	}

	var timings map[string]int64
	if f.timings {
		timings = res.Timings
	}
	rep := report.Build(report.Tool{Name: "sc4n", Version: version}, f.root, res.Artifacts, res.Collector, reportLimits(l), timings, res.Suppressed)
	rep.Unreadable = res.Unreadable
	rep.Cancelled = res.Cancelled

	if werr := writeReport(rep, f, stdout); werr != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", werr)
		return exitUsage
	}

	if res.Cancelled {
		fmt.Fprintln(stderr, "sc4n: scan deadline reached; results are partial")
	}
	if attestations != nil {
		// Report the match count, not just the findings: an attestation whose
		// digests match nothing scanned is otherwise indistinguishable from one
		// that found nothing, and the operator's next step is different.
		fmt.Fprintf(stderr, "sc4n: attestation %s: %d of %d run(s) matched a scanned artifact\n",
			f.attestation, attestations.Matched(), attestations.Len())
	}

	if runErr != nil {
		// A path the user named could not be expanded. Reported separately from
		// findings because it means part of the requested scope was not scanned.
		fmt.Fprintf(stderr, "sc4n: %v\n", runErr)
	}
	// A cancelled walk is not a clean run: the artifacts that were never visited
	// cannot have produced findings, so exiting 0 would be a false CLEAN for a CI
	// gate. It is reported the same way an unopenable path is, and the summary
	// carries summary.cancelled for a consumer that reads only the report.
	if res.Cancelled {
		fmt.Fprintln(stderr, "sc4n: the scan was cancelled before every artifact was visited, so the requested scope was not fully scanned")
		return exitUnreadable
	}
	v := policy.Decide(rep.Findings, sev, res.Unreadable)
	if v.Code == policy.CodeFindings || v.Code == policy.CodeUnreadable {
		fmt.Fprintf(stderr, "sc4n: %s\n", v.Reason)
	}
	return v.Code
}

// writeReport renders rep to -out (or stdout) and, for a non-text format written
// to a file, echoes the summary line to stdout. Both the normal path and the
// empty-hf-cache path use it, so no path can return without the report the run
// was asked for.
func writeReport(rep *report.Report, f scanFlags, stdout io.Writer) error {
	w := stdout
	var file *os.File
	if f.out != "" {
		var err error
		file, err = os.Create(f.out)
		if err != nil {
			return err
		}
		w = file
	}
	werr := render(rep, f, w)
	if file != nil {
		if cerr := file.Close(); cerr != nil && werr == nil {
			werr = cerr
		}
	}
	if werr != nil {
		return werr
	}
	if file != nil && f.format != "text" {
		fmt.Fprintln(stdout, rep.SummaryLine())
	}
	return nil
}

func buildLimits(f scanFlags) (limits.Limits, error) {
	l := limits.Default()
	art, err := parseSize(f.maxArtifact)
	if err != nil {
		return l, fmt.Errorf("-max-artifact: %w", err)
	}
	dec, err := parseSize(f.maxDecomp)
	if err != nil {
		return l, fmt.Errorf("-max-decompress: %w", err)
	}
	l.MaxArtifactBytes = art
	l.MaxDecompressedBytes = dec
	l.MaxDepth = f.maxDepth
	l.MaxRatio = f.maxRatio
	l.MaxFindings = f.maxFindings
	// Normalize here rather than letting scan.Run reject it, so that a negative
	// flag is a usage error before any file is opened.
	return l.Normalize()
}

func reportLimits(l limits.Limits) report.Limits { return l.ReportLimits() }

// render writes rep in the requested format.
// warnInertFlags prints one line for a flag that has no effect in this
// invocation, so a caller who sets it does not believe it did something. None of
// these is a usage error: -timings with -format sarif is a harmless mistake, and
// exiting non-zero would break a wrapper script that passes a fixed flag set.
func warnInertFlags(f scanFlags, w io.Writer) {
	// -timings is JSON-only. The text encoder's summary line is the text-mode
	// equivalent, and SARIF and CycloneDX have no place for it, so the flag was
	// silently dropped for text.
	if f.timings && f.format != "json" {
		fmt.Fprintf(w, "sc4n: -timings has no effect with -format %s (the timings block is part of json only)\n", f.format)
	}
	// -color and -quiet are text-encoder options: they reach the encoder only in
	// the "text" branch of render.
	if f.format != "text" {
		if f.color {
			fmt.Fprintf(w, "sc4n: -color has no effect with -format %s (it colours the text report only)\n", f.format)
		}
		if f.quiet {
			fmt.Fprintf(w, "sc4n: -quiet has no effect with -format %s (it shortens the text report only)\n", f.format)
		}
	}
	// -stdin scans exactly one artifact, on the calling goroutine, so the worker
	// count is never consulted.
	if f.stdin && f.jobs > 0 {
		fmt.Fprintln(w, "sc4n: -j has no effect with -stdin (a single stream is scanned in the calling goroutine)")
	}
	if f.hfCacheDir != "" && !f.hfCache {
		fmt.Fprintln(w, "sc4n: -hf-cache-dir has no effect without -hf-cache")
	}
	if f.name != "" && !f.stdin {
		fmt.Fprintln(w, "sc4n: -name has no effect without -stdin")
	}
}

// collectorLimit is the finding cap the collector is created with. With a baseline
// it is unlimited, because suppression has to run before the cap.
func collectorLimit(maxFindings, limitsDefault int, baseline map[string]bool) int {
	if len(baseline) > 0 {
		return 0
	}
	if maxFindings > 0 {
		return maxFindings
	}
	return limitsDefault
}

// validFormat reports whether a -format value names an encoder.
func validFormat(format string) bool {
	switch format {
	case "text", "json", "sarif", "cyclonedx":
		return true
	}
	return false
}

func render(rep *report.Report, f scanFlags, w io.Writer) error {
	switch f.format {
	case "text":
		return rep.WriteText(w, report.TextOptions{
			Color: f.color || (f.out == "" && isTerminal(os.Stdout)),
			Quiet: f.quiet,
		})
	case "json":
		return rep.WriteJSON(w)
	case "sarif":
		return rep.WriteSARIF(w)
	case "cyclonedx":
		return rep.WriteCycloneDX(w)
	default:
		return fmt.Errorf("unknown -format %q (want text, json, sarif or cyclonedx)", f.format)
	}
}

func isTerminal(fh *os.File) bool {
	fi, err := fh.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// parseSize accepts a plain byte count or a suffixed size (KiB/MiB/GiB/TiB,
// case-insensitive, also K/M/G/T and their binary-exact KB/MB forms, which are
// treated as binary because every other size in sc4n is). A bare "0" means
// unlimited for the flags that document it.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	upper := strings.ToUpper(s)
	for _, suf := range []struct {
		s string
		m int64
	}{
		{"TIB", 1 << 40}, {"TB", 1 << 40}, {"T", 1 << 40},
		{"GIB", 1 << 30}, {"GB", 1 << 30}, {"G", 1 << 30},
		{"MIB", 1 << 20}, {"MB", 1 << 20}, {"M", 1 << 20},
		{"KIB", 1 << 10}, {"KB", 1 << 10}, {"K", 1 << 10},
		{"B", 1},
	} {
		if strings.HasSuffix(upper, suf.s) {
			mult = suf.m
			upper = strings.TrimSpace(strings.TrimSuffix(upper, suf.s))
			break
		}
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a size: %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size: %q", s)
	}
	if mult > 1 && n > (1<<62)/mult {
		return 0, fmt.Errorf("size overflows int64: %q", s)
	}
	return n * mult, nil
}
