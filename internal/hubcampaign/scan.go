package hubcampaign

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	// The campaign runs the real scanner, so it needs the format/model registry
	// that cmd/sc4n links in. Without this import the scan sees only the
	// artifact package's built-in sniffers: every pickle, GGUF and safetensors
	// file is classified as text and the campaign reports a clean corpus.
	_ "github.com/fr0g-66723067-io/sc4n/internal/formats"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

// ScanResult is what ScanTree returns; scan.json holds the same report the
// standalone `sc4n scan` writes.
type ScanResult struct {
	Findings   []report.Finding
	Artifacts  []report.ArtifactSummary
	BySeverity [5]int
	Unreadable int
	Cancelled  bool
}

// ScanTree scans <Dir>/repos and writes scan.json.
//
// The scan itself is the ordinary engine — same limits, same rules, same report
// schema — because the campaign's value is the join, not a second scanner. The
// report root is the repos directory so the artifact paths in scan.json are
// repo-relative, which is what Join attributes findings with.
func ScanTree(ctx context.Context, o Options) (*ScanResult, error) {
	o = o.withDefaults()
	repos := o.reposDir()
	if st, err := os.Stat(repos); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("hubcampaign: %s is missing; run -stage fetch first", dirRepos)
	}
	if !o.Refresh {
		if r, err := loadScan(o); err == nil {
			progress(o, "scan: %d artifacts, %d findings (cached, -refresh to rescan)",
				len(r.Artifacts), len(r.Findings)+sum(r.BySeverity[:]))
			return r, nil
		}
	}

	cfg := scan.Config{
		Paths:       []string{repos},
		Limits:      o.Limits,
		Jobs:        o.ScanJobs,
		Root:        repos,
		MaxFindings: 0,
	}
	res, err := scan.Run(ctx, cfg)
	if res == nil {
		if err == nil {
			err = errors.New("scan refused the configuration")
		}
		return nil, fmt.Errorf("hubcampaign: %w", err)
	}
	rep := report.Build(o.Tool, repos, res.Artifacts, res.Collector, o.Limits.ReportLimits(), nil, res.Suppressed)
	rep.Unreadable = res.Unreadable
	rep.Cancelled = res.Cancelled
	relativise(repos, rep)
	if werr := writeReportJSON(o.path(fileScan), rep); werr != nil {
		return nil, werr
	}
	out := &ScanResult{
		Findings:   rep.Findings,
		Artifacts:  rep.Artifacts,
		BySeverity: res.Collector.CountBySeverity(),
		Unreadable: res.Unreadable,
		Cancelled:  res.Cancelled,
	}
	if res.Cancelled {
		return out, errors.New("hubcampaign: the scan deadline stopped the walk; scan.json is partial")
	}
	if err != nil {
		// An unreadable path inside repos/ is part of the scan's result, not a
		// stage failure: the report already counts it.
		progress(o, "scan: %v", err)
	}
	progress(o, "scan: %d artifacts, %d findings [%d critical, %d high]",
		len(out.Artifacts), len(out.Findings), out.BySeverity[report.SeverityCritical], out.BySeverity[report.SeverityHigh])
	return out, nil
}

// relativise strips the repos root from every path in the report.
//
// The scan engine names an artifact by the path it was given, and the campaign
// walks an absolute directory (it may be invoked from anywhere), so without this
// scan.json would carry absolute paths and the join — which attributes findings by
// repo-relative path — would match nothing. It also makes scan.json portable.
func relativise(root string, rep *report.Report) {
	prefix := strings.TrimRight(root, string(os.PathSeparator)) + string(os.PathSeparator)
	trim := func(p string) string {
		return strings.TrimPrefix(p, prefix)
	}
	for i := range rep.Artifacts {
		rep.Artifacts[i].Path = trim(rep.Artifacts[i].Path)
	}
	for i := range rep.Findings {
		rep.Findings[i].Artifact = trim(rep.Findings[i].Artifact)
	}
}

// writeReportJSON writes the scan report atomically.
func writeReportJSON(path string, rep *report.Report) error {
	tmp := path + ".tmp"
	fh, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := rep.WriteJSON(fh); err != nil {
		fh.Close()
		os.Remove(tmp)
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		os.Remove(tmp)
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := fh.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("hubcampaign: %w", err)
	}
	return nil
}

// scanDoc is the part of scan.json Join needs. It is a local decoder on purpose:
// the standalone -stage report path must not re-run the scan, and a struct with
// three fields is cheaper to keep honest than a dependency on the report's whole
// JSON shape (which carries timings, limits and the tool block).
type scanDoc struct {
	Findings []struct {
		Artifact string `json:"artifact"`
		RuleID   string `json:"ruleId"`
		Severity string `json:"severity"`
	} `json:"findings"`
	Artifacts []struct {
		Path   string `json:"path"`
		Format string `json:"format"`
	} `json:"artifacts"`
}

func sum(v []int) int {
	n := 0
	for _, x := range v {
		n += x
	}
	return n
}

func readScanDoc(o Options) (*scanDoc, error) {
	var doc scanDoc
	if err := readJSON(o.path(fileScan), &doc); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing(fileScan, "scan")
		}
		return nil, err
	}
	return &doc, nil
}

// loadScan rebuilds the ScanResult from scan.json. Findings stays nil: the
// three-field decoder in scanDoc cannot reconstruct a finding, and every caller
// that needs them reads scan.json itself (Join does).
func loadScan(o Options) (*ScanResult, error) {
	doc, err := readScanDoc(o)
	if err != nil {
		return nil, err
	}
	var bySev [5]int
	for _, f := range doc.Findings {
		sev, err := report.ParseSeverity(f.Severity)
		if err != nil {
			return nil, fmt.Errorf("hubcampaign: %s: %w", fileScan, err)
		}
		bySev[sev]++
	}
	arts := make([]report.ArtifactSummary, 0, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		arts = append(arts, report.ArtifactSummary{Path: a.Path, Format: a.Format})
	}
	return &ScanResult{Artifacts: arts, BySeverity: bySev}, nil
}
