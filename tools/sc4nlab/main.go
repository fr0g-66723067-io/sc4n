// Command sc4nlab measures the scanner's recall where no external label exists.
//
// It generates mutants of real artifacts, keeps only the ones an *independent*
// validator accepts (7z t, xz -t, zstd -t, readelf -h on the host; onnx.checker
// and onnxruntime in a pinned container), scans each valid mutant with the real
// engine in-process, and compares the answer against a pre-registered
// expectation table. A mutant the validator rejects is discarded, which is what
// makes the comparison an oracle: an artifact no loader accepts proves nothing
// about a scanner.
//
// This tool shells out and runs Python inside a container, because generation
// and validation are not the scanner. internal/ and cmd/ keep zero os/exec and
// zero third-party imports, and TestScanPathDoesNotExec fails the build if that
// changes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"

	// The lab runs the real scanner, so the format and model registry has to be
	// linked in. Without it only artifact's built-in sniffers are registered and
	// every mutant is dispatched as text — the same trap that makes a non-CLI
	// scan.Run caller report a clean corpus.
	_ "github.com/fr0g-66723067-io/sc4n/internal/formats"
)

// Exit codes. exitGaps is a distinct code because "a real loader accepts an
// artifact sc4n does not report" is a scanner defect, not a usage error, and a
// caller that only checks for non-zero cannot tell the two apart.
const (
	exitClean = 0 // every row is expected, unavailable or invalid
	exitGaps  = 1 // at least one row is gap or extra
	exitUsage = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// options is the decoded command line.
type options struct {
	profile     string
	seeds       string
	out         string
	seed        int64
	n           int
	jobs        int
	oracleImage string
	keepInvalid bool
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sc4nlab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.profile, "profile", "containers", "containers, native or graphs")
	fs.StringVar(&o.seeds, "seeds", "$CORPUS/top25-downloads/repos", "directories searched for .onnx graph seeds")
	fs.StringVar(&o.out, "out", "", "output root (required)")
	fs.Int64Var(&o.seed, "seed", 1, "deterministic generation seed")
	fs.IntVar(&o.n, "n", 2, "seeds used per profile")
	fs.IntVar(&o.jobs, "jobs", 0, "scan workers, 0 = NumCPU")
	fs.StringVar(&o.oracleImage, "oracle-image", "sc4n-oracle:1", "image for the graphs profile")
	fs.BoolVar(&o.keepInvalid, "keep-invalid", false, "keep oracle-rejected mutants for inspection")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "sc4nlab: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if o.out == "" {
		fmt.Fprintln(stderr, "sc4nlab: -out is required")
		return exitUsage
	}
	if o.jobs <= 0 {
		o.jobs = runtime.NumCPU()
	}
	out, err := filepath.Abs(o.out)
	if err != nil {
		fmt.Fprintf(stderr, "sc4nlab: %v\n", err)
		return exitUsage
	}
	if err := os.MkdirAll(filepath.Join(out, "mutants"), 0o755); err != nil {
		fmt.Fprintf(stderr, "sc4nlab: %v\n", err)
		return exitUsage
	}

	rows, oracleName, unavailable := rows(context.Background(), o, out, stderr)

	// Scanning happens after every mutant exists, one artifact per row, so a
	// row's findings are exactly the findings of its own file.
	for i := range rows {
		if rows[i].Verdict == verdictUnavailable || rows[i].Verdict == verdictInvalid {
			continue
		}
		rows[i].scanOutcome(scanOne(o, out, rows[i].Mutant))
		rows[i].classify()
	}

	sum := summarise(rows)
	doc := matrix{
		Tool:    "sc4nlab",
		Profile: o.profile,
		Seed:    o.seed,
		Oracle:  oracle{Name: oracleName, Available: !unavailable, Note: unavailableNote(rows)},
		Rows:    rows,
		Summary: sum,
	}
	if err := writeMatrix(out, doc); err != nil {
		fmt.Fprintf(stderr, "sc4nlab: %v\n", err)
		return exitUsage
	}
	for _, r := range rows {
		fmt.Fprintf(stdout, "%-22s %-9s %-8s %s\n", r.Operator, validWord(r.Valid), r.Sc4n.MaxSeverity, r.Verdict)
	}
	fmt.Fprintf(stdout, "rows=%d valid=%d expected=%d gap=%d extra=%d invalid=%d unavailable=%d\n",
		sum.Rows, sum.Valid, sum.Expected, sum.Gap, sum.Extra, sum.Invalid, sum.Unavailable)
	if sum.Gap+sum.Extra > 0 {
		fmt.Fprintf(stderr, "sc4nlab: %d gap(s), %d unexpected finding set(s); see %s\n",
			sum.Gap, sum.Extra, filepath.Join(out, "matrix.md"))
		return exitGaps
	}
	return exitClean
}

func unavailableNote(rows []Row) string {
	for _, r := range rows {
		if r.Verdict == verdictUnavailable && r.OracleNote != "" {
			return r.OracleNote
		}
	}
	return ""
}

// scanOne runs the real engine over one artifact and returns its findings and
// the artifact summary the engine wrote for it.
func scanOne(o options, root, rel string) ([]report.Finding, report.ArtifactSummary) {
	path := filepath.Join(root, rel)
	res, err := scan.Run(context.Background(), scan.Config{
		Paths:  []string{path},
		Limits: limits.Default(),
		Jobs:   o.jobs,
		Root:   root,
	})
	if err != nil || res == nil {
		return nil, report.ArtifactSummary{Path: rel, Error: errText(err)}
	}
	findings := res.Collector.Findings()
	if len(res.Artifacts) == 0 {
		return findings, report.ArtifactSummary{Path: rel}
	}
	return findings, res.Artifacts[0]
}

func errText(err error) string {
	if err == nil {
		return "scan returned no result"
	}
	return err.Error()
}

// rows builds the profile's mutants and validates them. It never returns an
// error: a missing external tool is a row verdict, not a failure of the run.
func rows(ctx context.Context, o options, out string, stderr io.Writer) ([]Row, string, bool) {
	switch o.profile {
	case "containers":
		return runOps(ctx, containerOps(), o, out, "7z")
	case "native":
		return runNative(ctx, o, out)
	case "graphs":
		return runGraphs(ctx, o, out)
	default:
		fmt.Fprintf(stderr, "sc4nlab: unknown profile %q\n", o.profile)
		return nil, "", true
	}
}

// runOps builds every operator's mutant, validates it with the operator's own
// oracle, and records the row. The oracle name reported in matrix.json is the
// first operator's, which is what the containers profile has meant since it was
// written: one host tool per row, named in the row's note when it differs.
func runOps(ctx context.Context, ops []op, o options, out, oracleName string) ([]Row, string, bool) {
	var rows []Row
	allUnavailable := len(ops) > 0
	for _, opd := range ops {
		r := Row{Operator: opd.Name, Expected: opd.Expected, Forbidden: opd.Forbid}
		mut, err := opd.Build(out, o.seed)
		if err != nil {
			r.Verdict = verdictUnavailable
			r.OracleNote = err.Error()
			rows = append(rows, r)
			continue
		}
		r.Mutant = mut
		if opd.Oracle == nil {
			r.Verdict = verdictUnavailable
			r.OracleNote = "no oracle declared"
			rows = append(rows, r)
			continue
		}
		if err := opd.Oracle.Available(); err != nil {
			r.Verdict = verdictUnavailable
			r.OracleNote = err.Error()
			rows = append(rows, r)
			continue
		}
		allUnavailable = false
		valid, note := opd.Oracle.Validate(filepath.Join(out, mut))
		r.Valid = valid
		r.OracleNote = note
		if !valid {
			r.Verdict = verdictInvalid
			if !o.keepInvalid {
				_ = os.RemoveAll(filepath.Dir(filepath.Join(out, mut)))
			}
		}
		rows = append(rows, r)
	}
	return rows, oracleName, allUnavailable
}

func validWord(v bool) string {
	if v {
		return "valid"
	}
	return "-"
}

var errNoSeeds = errors.New("no seeds")
