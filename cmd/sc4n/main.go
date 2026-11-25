// Command sc4n statically scans ML model artifacts and the code around them.
//
// It never executes the artifact, never extracts an archive member to disk and
// never calls an external parser or decompressor: every verdict comes from
// decoding bytes in memory. Exit codes are the CI contract:
//
//	0  clean: no finding at or above -fail-on
//	1  findings at or above -fail-on
//	2  usage error
//	3  a path the user named could not be opened, or the scan was cancelled by
//	   -timeout (never a finding)
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	// Blank-imported so every format parser registers itself with
	// internal/artifact; see internal/formats for why this is explicit.
	_ "github.com/fr0g-66723067-io/sc4n/internal/formats"
)

// version is stamped by the build when set with -ldflags, and is otherwise the
// development value. It is embedded in every output format's tool record, which
// is what makes a SARIF upload attributable to a scanner revision.
var version = "dev"

const (
	exitClean      = 0
	exitFindings   = 1
	exitUsage      = 2
	exitUnreadable = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return runScan(rest, stdout, stderr)
	case "rules":
		return runRules(rest, stdout, stderr)
	case "formats":
		return runFormats(rest, stdout, stderr)
	case "hub":
		return runHub(rest, stdout, stderr)
	case "hash":
		return runHash(rest, stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "sc4n %s\n", version)
		return exitClean
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return exitClean
	default:
		fmt.Fprintf(stderr, "sc4n: unknown command %q\n", cmd)
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, strings.TrimLeft(`
sc4n — static scanner for ML model artifacts and the code around them.

usage:
  sc4n scan [flags] <path...>   scan files and directories
  sc4n rules  [-format md|json] print the rule catalogue
  sc4n formats                  print the format capability matrix
  sc4n hub    [flags]           run a Hugging Face campaign: enumerate repos the
                                Hub scans at a level, fetch, scan and join
  sc4n hash   <path>            print sha256 and sha1 of a file
  sc4n version                  print the version

scan flags:
  -format text|json|sarif|cyclonedx  output format (default text)
  -out FILE                    write output to FILE instead of stdout
  -fail-on info|low|medium|high|critical
                               lowest severity that makes the run exit 1 (default high)
  -j N                         worker count (default: number of CPUs)
  -mem-budget BYTES            total artifact bytes mapped at once (default 1GiB)
  -max-artifact BYTES          largest single file to open (default 64GiB)
  -max-depth N                 container nesting cap (default 4; 0 disables recursion)
  -max-decompress BYTES        cumulative decompression cap per archive (default 8GiB)
  -max-ratio N                 decompression ratio cap (default 200)
  -max-hash BYTES              prefix byte cap for artifact sha256 (default 256MiB; 0 = full)
  -max-findings N              finding cap (keeps the most severe findings), applied after
                               -baseline suppression
                               (default 100000)
  -timeout DURATION            bound the whole scan (e.g. 10m)
  -root DIR                    containment root for path-shaped values
  -baseline FILE               suppress findings already present in a JSON report
  -stdin                       scan one artifact from stdin (-name required)
  -name NAME                   artifact name to use with -stdin
  -hf-cache                    scan a Hugging Face download cache instead of paths
  -hf-cache-dir DIR            cache root for -hf-cache (default ~/.cache/huggingface/hub)
  -deep-stats                  enable informational weight-statistics findings
  -timings                     include per-phase timings in the JSON output (json only)
  -quiet                       print only rule counts and the summary line (text only)
  -color                       force ANSI colour (text only; default: only on a terminal)

hub flags:
  -out DIR                     campaign directory (required; the only path written)
  -stage all|candidates|verdicts|fetch|scan|report
                               run one stage to resume a campaign (default all)
  -search/-tag/-author TERM    selectors (repeatable); -search-file reads a list
  -defaults                    include the built-in universe (default true)
  -level unsafe|suspicious|caution|error
                               Hub verdict level that selects a repo (default unsafe)
  -full-limit/-flagged-limit/-slice/-repo-budget/-total-budget SIZE
                               what to fetch whole, slice, or refuse (32MiB/1GiB/2MiB/1GiB/9GiB)
                               a whole fetch that does not fit falls back to a header slice
  -api URL                     Hub base URL (default https://huggingface.co)
  -token-file FILE             token (default $HF_TOKEN, then $HF_HOME/token)
  -refresh                     recompute a stage that already wrote its file
  -fail-on LEVEL|none          exit 1 when a campaign finding is at or above (default none)
  -json                        also print campaign.json to stdout

sc4n scan never touches the network. Only "sc4n hub" does, and it writes only
under -out: the fetched bytes, the stage files and the reports all live there.

exit codes: 0 clean, 1 findings at or above -fail-on, 2 usage error,
            3 a named path could not be opened, or the scan was cancelled by
            -timeout (the report then carries "cancelled": true). A failed hub
            stage (network unreachable, IO error, missing stage input) also
            exits 3.

sc4n never executes, extracts or rewrites anything it scans; -out is the only path
it writes permanently. A member too large to hold in memory is materialised in an
unlinked temporary file under TMPDIR and mapped, never extracted to a visible path.
`, "\n"))
}
