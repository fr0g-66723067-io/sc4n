package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
	"github.com/fr0g-66723067-io/sc4n/internal/hubcampaign"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// runHub is the `hub` command: the Hugging Face campaign.
//
// The design invariant, stated in the usage text too: `sc4n scan` never touches
// the network. Only this command does, and it writes only under -out — the
// fetched bytes, the stage files and the reports all live in that one directory.
func runHub(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		out        = fs.String("out", "", "campaign directory (required)")
		stage      = fs.String("stage", "all", "all|candidates|verdicts|fetch|scan|report")
		searchFile = fs.String("search-file", "", "file of search terms, one per line ('#' comments)")
		defaults   = fs.Bool("defaults", true, fmt.Sprintf("include the built-in universe (%d terms, %d tags, %d authors)",
			len(hubcampaign.DefaultTerms), len(hubcampaign.DefaultTags), len(hubcampaign.DefaultAuthors)))
		limit      = fs.Int("limit", 100, "results per query (1..1000)")
		level      = fs.String("level", "unsafe", "Hub verdict level that selects a repo: unsafe|suspicious|caution|error")
		jobs       = fs.Int("jobs", 8, "concurrent Hub requests")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request timeout")
		api        = fs.String("api", "https://huggingface.co", "Hub base URL (https; http only for loopback)")
		tokenFile  = fs.String("token-file", "", "token file (default $HF_HOME/token)")
		fullLimit  = fs.String("full-limit", "32MiB", "fetch a file whole at or below this size")
		flagLimit  = fs.String("flagged-limit", "1GiB", "fetch a flagged file whole up to this size (a header slice is used above it)")
		sliceSize  = fs.String("slice", "2MiB", "header slice for a larger file")
		repoBudget = fs.String("repo-budget", "1GiB", "per-repo byte cap")
		totBudget  = fs.String("total-budget", "9GiB", "campaign byte cap")
		scanJobs   = fs.Int("scan-jobs", 0, "scan worker count (default: number of CPUs)")
		refresh    = fs.Bool("refresh", false, "recompute a stage that already wrote its file")
		failOn     = fs.String("fail-on", "none", "exit 1 when a campaign finding is at or above this level")
		jsonOut    = fs.Bool("json", false, "also print campaign.json to stdout")
	)
	var search, tag, author stringList
	fs.Var(&search, "search", "model-id search term (repeatable)")
	fs.Var(&tag, "tag", "Hub tag filter (repeatable)")
	fs.Var(&author, "author", "author/account name (repeatable)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "sc4n hub: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *out == "" {
		fmt.Fprintln(stderr, "sc4n hub: -out DIR is required")
		return exitUsage
	}
	validStage := map[string]bool{
		"all": true, "candidates": true, "verdicts": true, "fetch": true, "scan": true, "report": true,
	}
	if !validStage[*stage] {
		fmt.Fprintf(stderr, "sc4n hub: -stage %q is not all, candidates, verdicts, fetch, scan or report\n", *stage)
		return exitUsage
	}
	switch *level {
	case "unsafe", "suspicious", "caution", "error":
	default:
		fmt.Fprintf(stderr, "sc4n hub: -level %q is not unsafe, suspicious, caution or error\n", *level)
		return exitUsage
	}
	var gate *report.Severity
	if *failOn != "none" {
		sev, err := report.ParseSeverity(*failOn)
		if err != nil {
			fmt.Fprintf(stderr, "sc4n hub: -fail-on %q is not none or a severity\n", *failOn)
			return exitUsage
		}
		gate = &sev
	}
	sizes := map[string]int64{}
	for name, raw := range map[string]string{
		"full-limit": *fullLimit, "flagged-limit": *flagLimit, "slice": *sliceSize,
		"repo-budget": *repoBudget, "total-budget": *totBudget,
	} {
		n, err := parseSize(raw)
		if err != nil {
			fmt.Fprintf(stderr, "sc4n hub: -%s %q: %v\n", name, raw, err)
			return exitUsage
		}
		sizes[name] = n
	}

	queries := make([]hubcampaign.Sel, 0, len(search)+len(tag)+len(author))
	for _, v := range search {
		queries = append(queries, hubcampaign.Sel{Kind: "search", Value: v})
	}
	for _, v := range tag {
		queries = append(queries, hubcampaign.Sel{Kind: "tag", Value: v})
	}
	for _, v := range author {
		queries = append(queries, hubcampaign.Sel{Kind: "author", Value: v})
	}
	if *searchFile != "" {
		terms, err := readLines(*searchFile)
		if err != nil {
			fmt.Fprintf(stderr, "sc4n hub: -search-file: %v\n", err)
			return exitUsage
		}
		for _, t := range terms {
			queries = append(queries, hubcampaign.Sel{Kind: "search", Value: t})
		}
	}

	token, err := hubapi.Token(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "sc4n hub: %v\n", err)
		return exitUsage
	}
	client, err := hubapi.New(hubapi.Config{
		BaseURL:   *api,
		Token:     token,
		UserAgent: "sc4n/" + version,
		Jobs:      *jobs,
		Timeout:   *timeout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "sc4n hub: %v\n", err)
		return exitUsage
	}

	o := hubcampaign.Options{
		Dir:          *out,
		Tool:         report.Tool{Name: "sc4n", Version: version},
		Client:       client,
		Queries:      queries,
		UseDefaults:  *defaults,
		Limit:        *limit,
		Level:        *level,
		Jobs:         *jobs,
		Refresh:      *refresh,
		FullLimit:    sizes["full-limit"],
		FlaggedLimit: sizes["flagged-limit"],
		SliceSize:    sizes["slice"],
		RepoBudget:   sizes["repo-budget"],
		TotalBudget:  sizes["total-budget"],
		ScanJobs:     *scanJobs,
		Limits:       limits.Default(),
		Stderr:       stderr,
	}
	if err := o.Validate(); err != nil {
		fmt.Fprintf(stderr, "sc4n hub: %v\n", err)
		return exitUsage
	}
	if token == "" {
		fmt.Fprintln(stderr, "sc4n hub: no Hub token found; the campaign runs anonymously and gated repos are reported as gated")
	}

	ctx := context.Background()
	switch *stage {
	case "all":
		err = hubcampaign.Run(ctx, o)
	case "candidates":
		_, err = hubcampaign.Candidates(ctx, o)
	case "verdicts":
		_, err = hubcampaign.Verdicts(ctx, o)
	case "fetch":
		_, err = hubcampaign.Fetch(ctx, o)
	case "scan":
		_, err = hubcampaign.ScanTree(ctx, o)
	case "report":
		var rep *hubcampaign.CampaignReport
		if rep, err = hubcampaign.Join(o); err == nil {
			err = hubcampaign.Report(o, rep)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "sc4n hub: %v\n", err)
		return exitUnreadable
	}

	rep, err := hubcampaign.Load(o)
	if err != nil {
		// A single early stage has not produced campaign.json yet; the stage's own
		// progress line is the result, so this is not an error.
		return exitClean
	}
	printCampaign(stdout, rep, *jsonOut)
	if gate != nil {
		worst := report.SeverityInfo
		clean := rep.Totals.Findings.Max == "none"
		if !clean {
			worst, err = report.ParseSeverity(rep.Totals.Findings.Max)
			if err != nil {
				fmt.Fprintf(stderr, "sc4n hub: %v\n", err)
				return exitUnreadable
			}
		}
		if !clean && worst >= *gate {
			fmt.Fprintf(stderr, "sc4n hub: campaign findings are at or above %s (worst: %s)\n",
				gate.String(), worst.String())
			return exitFindings
		}
	}
	return exitClean
}

// printCampaign writes the summary line and, with -json, the whole report.
func printCampaign(w io.Writer, rep *hubcampaign.CampaignReport, asJSON bool) {
	t := rep.Totals
	fmt.Fprintf(w, "sc4n hub: %d repos, %d flagged files (%d full, %d partial, %d none), %d findings [%d critical, %d high], max %s\n",
		t.Repos, t.Files, t.CoveredFull, t.CoveredPartial, t.NotCovered,
		t.Findings.Critical+t.Findings.High+t.Findings.Medium+t.Findings.Low+t.Findings.Info,
		t.Findings.Critical, t.Findings.High, t.Findings.Max)
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	}
}

// readLines reads one term per non-empty, non-'#' line.
func readLines(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
