package hubcampaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	// The campaign runs the real scanner, so it needs the format/model registry
	// that cmd/sc4n links in. Without this import the scan sees only the
	// artifact package's built-in sniffers: every pickle, GGUF and safetensors
	// file is classified as text and the campaign reports a clean corpus.
	_ "github.com/fr0g-66723067-io/sc4n/internal/formats"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

const fileScanMeta = ".scan-cache.json"

type scanCacheMeta struct {
	Version        int    `json:"version"`
	FetchSHA256    string `json:"fetchSha256,omitempty"`
	BaselineSHA256 string `json:"baselineSha256,omitempty"`
}

// partialFiles names the files this campaign fetched as a header slice. A rule
// that compares a declared extent against the file on disk needs that fact: on
// BAAI/bge-m3 the ONNX external-data check reported 389 high findings because a
// 2.2 GB data file was present as a 2 MiB slice, and every one of them said the
// model's lengths ran past the end of the file.
func partialFiles(o Options) []string {
	var fd FetchDoc
	if err := readJSON(o.path(fileFetch), &fd); err != nil {
		return nil
	}
	var out []string
	for _, r := range fd.Repos {
		for _, f := range r.Files {
			if f.Status == "slice" {
				out = append(out, r.ID+"/"+f.Path)
			}
		}
	}
	return out
}

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
		Paths:    []string{repos},
		Limits:   o.Limits,
		Jobs:     o.ScanJobs,
		Root:     repos,
		Partial:  partialFiles(o),
		Baseline: prefixBaseline(repos, o.Baseline),
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
	suppressed := res.Suppressed
	if len(o.Baseline) > 0 {
		// report.Fingerprint hashes the artifact path, so a baseline loaded from a
		// relativised scan.json cannot be path-prefixed before scan.Run. Apply it
		// here once findings carry their repo-relative paths.
		kept := rep.Findings[:0]
		for _, f := range rep.Findings {
			if o.Baseline[report.Fingerprint(f)] {
				suppressed++
				continue
			}
			kept = append(kept, f)
		}
		rep.Findings = kept
	}
	rep.Suppressed = suppressed
	if werr := writeReportJSON(o.path(fileScan), rep); werr != nil {
		return nil, werr
	}
	if !res.Cancelled {
		fetchHash, _ := fetchFingerprint(o)
		meta := scanCacheMeta{
			Version:        Version,
			FetchSHA256:    fetchHash,
			BaselineSHA256: baselineFingerprint(o.Baseline),
		}
		_ = writeJSON(o.path(fileScanMeta), meta)
	}
	bySev := res.Collector.CountBySeverity()
	if suppressed > 0 {
		// The collector counted what the walk produced; the campaign reports what
		// survived its baseline, so the severity totals must follow the report.
		bySev = [5]int{}
		for _, f := range rep.Findings {
			bySev[int(f.Severity)]++
		}
	}
	out := &ScanResult{
		Findings:   rep.Findings,
		Artifacts:  rep.Artifacts,
		BySeverity: bySev,
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

// prefixBaseline rewrites the artifact component of each baseline fingerprint to
// the absolute path the scan engine sees. The previous scan.json is repo-relative
// after relativise, while suppression runs while the engine still names the file by
// its absolute path.
func prefixBaseline(base string, fp map[string]bool) map[string]bool {
	if len(fp) == 0 {
		return nil
	}
	out := make(map[string]bool, len(fp))
	for k := range fp {
		parts := strings.SplitN(k, "\x00", 3)
		if len(parts) == 3 {
			parts[1] = prefixArtifact(base, parts[1])
			k = strings.Join(parts, "\x00")
		}
		out[k] = true
	}
	return out
}

// prefixArtifact prepends base to the filesystem portion of art without letting
// filepath.Join / filepath.Clean rewrite container member paths after ':'.
func prefixArtifact(base, art string) string {
	if !strings.ContainsRune(art, ':') {
		return filepath.Join(base, filepath.FromSlash(art))
	}
	// If the full name (containing ':') exists on disk, it is the file itself.
	full := filepath.Join(base, filepath.FromSlash(art))
	if _, err := os.Stat(full); err == nil {
		return full
	}
	// Otherwise scan ':' right-to-left to preserve colons in the file's own name
	// while keeping the member chain verbatim.
	for i := len(art) - 1; i >= 0; i-- {
		if art[i] != ':' {
			continue
		}
		cand := filepath.Join(base, filepath.FromSlash(art[:i]))
		if _, err := os.Stat(cand); err == nil {
			return cand + art[i:]
		}
	}
	idx := strings.IndexByte(art, ':')
	return filepath.Join(base, filepath.FromSlash(art[:idx])) + art[idx:]
}

// relativise strips the repos root from every path in the report and converts
// OS separators to forward slashes so scan.json is portable across platforms.
//
// The scan engine names an artifact by the path it was given, and the campaign
// walks an absolute directory (it may be invoked from anywhere), so without this
// scan.json would carry absolute paths and the join — which attributes findings by
// repo-relative path — would match nothing. It also makes scan.json portable.
func relativise(root string, rep *report.Report) {
	cleanRoot := filepath.Clean(root)
	prefix := strings.TrimRight(cleanRoot, string(os.PathSeparator)) + string(os.PathSeparator)
	slashPrefix := strings.TrimRight(filepath.ToSlash(cleanRoot), "/") + "/"
	trim := func(p string) string {
		if strings.HasPrefix(p, prefix) {
			p = strings.TrimPrefix(p, prefix)
		} else {
			p = strings.TrimPrefix(filepath.ToSlash(p), slashPrefix)
		}
		return filepath.ToSlash(p)
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
	// Suppressed is what -baseline removed from this scan, carried so the campaign
	// can say how many findings it chose not to report.
	Suppressed int `json:"suppressed,omitempty"`
	// Cancelled reports an interrupted scan, which must never be served as cache.
	Cancelled bool `json:"cancelled,omitempty"`
}

func fetchFingerprint(o Options) (string, bool) {
	b, err := os.ReadFile(o.path(fileFetch))
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), true
}

func baselineFingerprint(fp map[string]bool) string {
	if len(fp) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fp))
	for k, v := range fp {
		if v {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func scanCacheValid(o Options, doc *scanDoc) bool {
	if doc.Cancelled {
		return false
	}
	var meta scanCacheMeta
	if err := readJSON(o.path(fileScanMeta), &meta); err != nil || meta.Version != Version {
		return false
	}
	if meta.BaselineSHA256 != baselineFingerprint(o.Baseline) {
		return false
	}
	fetchHash, hasFetch := fetchFingerprint(o)
	if hasFetch {
		if meta.FetchSHA256 != fetchHash {
			return false
		}
		if fi, err := os.Stat(o.path(fileFetch)); err == nil {
			if si, serr := os.Stat(o.path(fileScan)); serr == nil && fi.ModTime().After(si.ModTime()) {
				return false
			}
		}
	} else if meta.FetchSHA256 != "" {
		return false
	}
	return true
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
	if !scanCacheValid(o, doc) {
		return nil, errors.New("hubcampaign: scan cache is stale")
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
