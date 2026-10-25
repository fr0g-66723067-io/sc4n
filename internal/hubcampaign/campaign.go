// Package hubcampaign runs the Hugging Face "unsafe" campaign: enumerate the
// repos the Hub's own scanner marks at a level, fetch the flagged files, scan
// them with sc4n, and join the two verdicts into one report.
//
// It exists because the round that produced the 2026-10-24 unsafe list was five
// Python scripts and a hand-written join: the join was the part a reader had to
// trust, and the fetch stage's budget math was the part that could silently drop
// files. Here every stage is a pure file -> file transform over one directory, so
// a campaign can be interrupted, inspected and resumed:
//
//	candidates.json  which repos are candidates, and the query that found each
//	verdicts.json    each candidate's per-file Hub verdict
//	fetch.json       what was fetched, how much of it, and what was refused
//	repos/           the fetched bytes, laid out as repos/<owner>/<name>/<path>
//	scan.json        the standard sc4n report over repos/
//	campaign.json    the join: Hub verdict per flagged file, sc4n verdict, coverage
//	campaign.md      the same, readable, with the no-finding files listed
//
// Two invariants decide most of the code: nothing is dropped silently (a budget
// refusal, a gated file and an unsafe path all become a status with a reason, and
// the report counts them), and a re-run over the same inputs is byte-identical
// (no timestamps, every slice sorted, no map iteration order in the output).
package hubcampaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Version is the schema version of every file this package writes.
const Version = 1

// DefaultLevel is the Hub verdict level that selects a repo when -level is unset.
const DefaultLevel = "unsafe"

// Stage file names, relative to Options.Dir.
const (
	fileCandidates = "candidates.json"
	fileVerdicts   = "verdicts.json"
	fileFetch      = "fetch.json"
	fileScan       = "scan.json"
	fileCampaign   = "campaign.json"
	fileCampaignMD = "campaign.md"
	dirRepos       = "repos"
)

// Budget defaults. They are the values the Python round used.
const (
	defaultLimit     = 100
	defaultJobs      = 8
	defaultFullLimit = 32 << 20
	// defaultFlaggedLimit is 1 GiB because a slice is not a substitute for the
	// whole file when the format needs its end. Measured on the 2026-10-24 round:
	// a 2 MiB slice of a 474 MiB torch checkpoint yields only SC4N-PARSE-FAILED
	// (medium) because the member lives behind the central directory, while the
	// whole file yields SC4N-PICKLE-GLOBAL-CRITICAL. With a 32 MiB limit 15 flagged
	// files dropped from critical to medium for 5 GiB of saved transfer.
	defaultFlaggedLimit = 1 << 30
	// defaultRepoBudget covers every repo of that round once the per-file cap
	// applies (largest demands: 822 MiB, 667 MiB, then 487 MiB per file).
	defaultRepoBudget = 1 << 30
	// defaultTotalBudget is the round's demand plus headroom: 9.63 GiB of flagged
	// files in total, 8.30 GiB with the per-file cap. A 6 GiB cap left 7 flagged
	// files fetched only as slices, and one 2.4 GiB file stays a slice whatever the
	// cap. An operator scanning a bigger universe lowers it.
	defaultTotalBudget = 9 << 30
	defaultSliceSize    = 2 << 20

)

// Sel is one candidate query. Kind is "search", "tag" or "author".
type Sel struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Options configures a stage. Every zero value has a working default.
type Options struct {
	// Dir is the campaign directory; created when absent.
	Dir string
	// Tool names the scanner in the embedded scan report.
	Tool report.Tool
	// Client is the Hub client. It is required.
	Client *hubapi.Client
	// Queries are explicit selectors, in flag order.
	Queries []Sel
	// UseDefaults adds DefaultTerms/DefaultTags/DefaultAuthors before Queries.
	UseDefaults bool
	// Limit caps each query's result count (1..1000).
	Limit int
	// Level is the Hub verdict level that selects a repo.
	Level string
	// Jobs is the concurrency for Hub requests.
	Jobs int
	// Refresh recomputes a stage whose output file already exists.
	Refresh bool

	// FullLimit fetches a file whole when it is at or below this size.
	FullLimit int64
	// FlaggedLimit fetches a *flagged* file whole up to this size.
	FlaggedLimit int64
	// SliceSize is the Range size for a file that is fetched as a header slice.
	SliceSize int64
	// RepoBudget and TotalBudget cap the bytes one repo / the campaign fetches.
	RepoBudget, TotalBudget int64

	// ScanJobs is the scan worker count; zero means one per CPU.
	ScanJobs int
	// Limits is threaded into the scan stage.
	Limits limits.Limits
	// Stderr receives one progress line per stage.
	Stderr io.Writer
}

// withDefaults fills every zero field.
func (o Options) withDefaults() Options {
	if o.Level == "" {
		o.Level = DefaultLevel
	}
	if o.Limit <= 0 {
		o.Limit = defaultLimit
	}
	if o.Jobs <= 0 {
		o.Jobs = defaultJobs
	}
	if o.Jobs > 32 {
		o.Jobs = 32
	}
	if o.FullLimit <= 0 {
		o.FullLimit = defaultFullLimit
	}
	if o.FlaggedLimit <= 0 {
		o.FlaggedLimit = defaultFlaggedLimit
	}
	if o.SliceSize <= 0 {
		o.SliceSize = defaultSliceSize
	}
	if o.RepoBudget <= 0 {
		o.RepoBudget = defaultRepoBudget
	}
	if o.TotalBudget <= 0 {
		o.TotalBudget = defaultTotalBudget
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if n, err := o.Limits.Normalize(); err == nil {
		o.Limits = n
	}
	return o
}

func (o Options) path(name string) string { return filepath.Join(o.Dir, name) }

func (o Options) reposDir() string { return filepath.Join(o.Dir, dirRepos) }

func progress(o Options, format string, args ...any) {
	fmt.Fprintf(o.Stderr, format+"\n", args...)
}

// levelValid reports whether s is one of the four Hub verdict levels.
func levelValid(s string) bool {
	switch s {
	case "unsafe", "suspicious", "caution", "error":
		return true
	}
	return false
}

// Validate rejects an option set a stage cannot run with. It is exported so the
// CLI can turn a bad flag into a usage error before touching the filesystem.
func (o Options) Validate() error {
	if o.Dir == "" {
		return errors.New("hubcampaign: -out is required")
	}
	if !levelValid(o.Level) {
		return fmt.Errorf("hubcampaign: level %q is not unsafe, suspicious, caution or error", o.Level)
	}
	if o.Client == nil {
		return errors.New("hubcampaign: no Hub client")
	}
	if o.Limit < 0 || o.Limit > 1000 {
		return fmt.Errorf("hubcampaign: limit %d is outside 1..1000", o.Limit)
	}
	for _, q := range o.Queries {
		switch q.Kind {
		case "search", "tag", "author":
		default:
			return fmt.Errorf("hubcampaign: query kind %q is not search, tag or author", q.Kind)
		}
		if strings.TrimSpace(q.Value) == "" {
			return errors.New("hubcampaign: query value is empty")
		}
	}
	return nil
}

// Run executes every stage in order: candidates, verdicts, fetch, scan, join,
// report. It is the -stage all path; a resumed campaign runs one stage at a time.
func Run(ctx context.Context, o Options) error {
	o = o.withDefaults()
	if err := o.Validate(); err != nil {
		return err
	}
	if _, err := Candidates(ctx, o); err != nil {
		return err
	}
	if _, err := Verdicts(ctx, o); err != nil {
		return err
	}
	if _, err := Fetch(ctx, o); err != nil {
		return err
	}
	if _, err := ScanTree(ctx, o); err != nil {
		return err
	}
	rep, err := Join(o)
	if err != nil {
		return err
	}
	return Report(o, rep)
}

// Load reads campaign.json, which is what the CLI prints and gates on.
func Load(o Options) (*CampaignReport, error) {
	var rep CampaignReport
	if err := readJSON(o.path(fileCampaign), &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// readJSON decodes one stage file, distinguishing "not there yet" from "broken".
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("hubcampaign: %s: %w", path, err)
	}
	return nil
}

// writeJSON writes one stage file atomically: a marshal error leaves nothing
// behind, and a reader never sees a half-written stage.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("hubcampaign: %w", err)
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("hubcampaign: %w", err)
	}
	return nil
}

// missing is the error for a stage whose input is absent: it names the stage to
// run, because the stages are the campaign's resume points.
func missing(name, prev string) error {
	return fmt.Errorf("hubcampaign: %s is missing; run -stage %s first", name, prev)
}

// safeRepoID splits and validates a repo id. A repo id is exactly two path
// components, which is what makes repos/<owner>/<name> unambiguous.
func safeRepoID(id string) (owner, name string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	if !localName(parts[0]) || !localName(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// safeFilePath splits a repo-relative file path into components, rejecting
// anything that could escape the campaign directory.
//
// It is checked, not assumed: the 2026-10-24 round met `sub/../test8.txt`,
// `sub/..%00/test7.txt` and `%2e%2e/%2e%2e/etc/traversal.txt` as real sibling
// names, so a path is rejected when a component is empty, `.`, `..`, carries a
// NUL or a separator, or *decodes* to one of those (a percent-encoded traversal is
// a traversal once the Hub resolves it).
func safeFilePath(p string) ([]string, bool) {
	if p == "" || strings.ContainsRune(p, 0) || strings.HasPrefix(p, "/") {
		return nil, false
	}
	parts := strings.Split(p, "/")
	for _, seg := range parts {
		if !localName(seg) {
			return nil, false
		}
		if d, err := url.PathUnescape(seg); err == nil && d != seg && !localName(d) {
			return nil, false
		}
	}
	return parts, true
}

// localName validates one path component.
func localName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.ContainsAny(s, "\x00/\\") {
		return false
	}
	return filepath.IsLocal(s)
}

// forEach runs fn for every index with Jobs workers, stopping the launch loop at
// the first error but letting running work finish. It returns the first error in
// index order, so a failure is reported deterministically.
func forEach(ctx context.Context, jobs, n int, fn func(i int) error) error {
	if jobs < 1 {
		jobs = 1
	}
	errs := make([]error, n)
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = fn(i)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// sortedKeys returns a map's keys in order, for anything that reaches output.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
