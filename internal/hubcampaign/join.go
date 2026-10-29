package hubcampaign

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// FileReport is one flagged file's joined verdict. Every field answers a question
// the Hub alone cannot: hf is the Hub's level, coverage is how much of the file
// sc4n actually saw, sc4n is what it found, and reason says why a covered file has
// no finding.
type FileReport struct {
	Path     string   `json:"path"`
	HF       string   `json:"hf"`
	Fetch    string   `json:"fetch"`
	Coverage string   `json:"coverage"`
	Format   string   `json:"format"`
	Sc4n     string   `json:"sc4n"`
	Reason   string   `json:"reason"`
	Rules    []string `json:"rules"`
	// Member is the artifact path of the worst finding when it differs from the
	// file itself (a container's member), so the verdict names where it came from.
	Member string `json:"member,omitempty"`
}

// ExtraReport is a file the Hub did *not* flag that sc4n found high or critical
// material in. It is the campaign's recall signal, so it is never omitted.
type ExtraReport struct {
	Path  string   `json:"path"`
	Sc4n  string   `json:"sc4n"`
	Rules []string `json:"rules"`
}

// RepoSc4n is the per-repo severity block.
type RepoSc4n struct {
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"bySeverity"`
}

// RepoReport is one repo row.
type RepoReport struct {
	ID     string        `json:"id"`
	Status string        `json:"status"`
	Files  []FileReport  `json:"files"`
	Extras []ExtraReport `json:"extras"`
	Sc4n   RepoSc4n      `json:"sc4n"`
}

// CampaignInfo is the campaign's own parameters and universe size.
type CampaignInfo struct {
	Level    string              `json:"level"`
	Limit    int                 `json:"limit"`
	Queries  map[string][]string `json:"queries"`
	Probed   int                 `json:"probed"`
	Selected int                 `json:"selected"`
	// Rank is the ranked listing the universe came from, when it came from one.
	// Sort is the Hub's own ordering name, so a reader can tell a 30-day download
	// count from the recent-window trending score without opening the tool.
	Rank *RankInfo `json:"rank,omitempty"`
}

// RankInfo is the ranked listing a campaign's universe was taken from.
type RankInfo struct {
	Sort  string `json:"sort"`
	Top   int    `json:"top"`
	Rows  int    `json:"rows"`
	First string `json:"first,omitempty"`
	Last  string `json:"last,omitempty"`
}

// FindingsTotals is the scan-wide finding count, plus the worst severity.
type FindingsTotals struct {
	Max      string `json:"max"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
}

// Totals is the campaign-level summary. covered_* count flagged files that sc4n
// saw (fully or as a slice) and found something in; not_covered counts flagged
// files with no coverage at all, which is the number that keeps a clean report
// honest.
type Totals struct {
	Repos          int            `json:"repos"`
	Files          int            `json:"files"`
	CoveredFull    int            `json:"covered_full"`
	CoveredPartial int            `json:"covered_partial"`
	NotCovered     int            `json:"not_covered"`
	BySc4n         map[string]int `json:"by_sc4n"`
	Findings       FindingsTotals `json:"findings"`
	// ByRule is the campaign's per-rule count, the table a reviewer triages
	// instead of reading 300 rows: the same numbers a hand-written summary of the
	// campaign used to compute.
	ByRule []RuleCount `json:"by_rule"`
	// Suppressed is the number of findings -baseline removed, so a differential
	// campaign says what it did not report.
	Suppressed int `json:"suppressed,omitempty"`
}

// RuleCount is one row of the per-rule summary.
type RuleCount struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// CampaignReport is campaign.json.
type CampaignReport struct {
	Version  int          `json:"version"`
	Tool     report.Tool  `json:"tool"`
	Campaign CampaignInfo `json:"campaign"`
	Totals   Totals       `json:"totals"`
	Repos    []RepoReport `json:"repos"`
}

// agg accumulates the findings of one artifact path or one repo.
type agg struct {
	has    bool
	worst  report.Severity
	count  int
	bySev  [5]int
	rules  map[string]report.Severity
	member string
}

func (a *agg) add(sev report.Severity, rule, artifact string) {
	if a.rules == nil {
		a.rules = map[string]report.Severity{}
	}
	a.count++
	a.bySev[sev]++
	if s, ok := a.rules[rule]; !ok || sev > s {
		a.rules[rule] = sev
	}
	if !a.has || sev > a.worst {
		a.has = true
		a.worst = sev
		a.member = artifact
	}
}

// topRules returns up to n rule ids, worst severity first, then alphabetically.
func (a *agg) topRules(n int) []string {
	ids := make([]string, 0, len(a.rules))
	for id := range a.rules {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		si, sj := a.rules[ids[i]], a.rules[ids[j]]
		if si != sj {
			return si > sj
		}
		return ids[i] < ids[j]
	})
	if len(ids) > n {
		ids = ids[:n]
	}
	return ids
}

// key is the join key: one repo's one file.
func key(repoID, rel string) string { return repoID + "\x00" + rel }

// topPath is the artifact path with any member chain and any fetch-slice suffix
// removed: `o/n/pytorch_model.bin:archive/data.pkl` and `o/n/big.bin.slice` both
// name a file on disk.
func topPath(artifact string) string {
	top, _, _ := strings.Cut(artifact, ":")
	return strings.TrimSuffix(top, ".slice")
}

// splitTop splits a repo-relative artifact path into repo id and file path.
func splitTop(top string) (repoID, rel string, ok bool) {
	parts := strings.Split(top, "/")
	if len(parts) < 3 {
		return "", "", false
	}
	return parts[0] + "/" + parts[1], strings.Join(parts[2:], "/"), true
}

// coverage maps a fetch status onto what sc4n saw.
func coverage(status string) string {
	switch status {
	case "full":
		return "full"
	case "slice":
		return "partial"
	}
	return "none"
}

// Join reads verdicts.json, fetch.json and scan.json and builds the campaign
// report without touching the network or the artifacts.
func Join(o Options) (*CampaignReport, error) {
	o = o.withDefaults()

	var vs VerdictsFile
	if err := readJSON(o.path(fileVerdicts), &vs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing(fileVerdicts, "verdicts")
		}
		return nil, err
	}
	var fd FetchDoc
	if err := readJSON(o.path(fileFetch), &fd); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing(fileFetch, "fetch")
		}
		return nil, err
	}
	doc, err := readScanDoc(o)
	if err != nil {
		return nil, err
	}

	// Artifact summaries carry the format, which is how a covered file with no
	// finding is distinguished from a file sc4n could not dispatch.
	formats := make(map[string]string, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		formats[a.Path] = a.Format
	}

	byFile := map[string]*agg{}
	byRepo := map[string]*agg{}
	filesOf := map[string][]string{}
	var totals FindingsTotals
	var sevCount [5]int
	worst := report.Severity(-1)
	ruleCount := map[string]*RuleCount{}
	for _, f := range doc.Findings {
		sev, err := report.ParseSeverity(f.Severity)
		if err != nil {
			return nil, fmt.Errorf("hubcampaign: %s: %w", fileScan, err)
		}
		sevCount[sev]++
		rc := ruleCount[f.RuleID]
		if rc == nil {
			rc = &RuleCount{Rule: f.RuleID, Severity: f.Severity}
			ruleCount[f.RuleID] = rc
		}
		rc.Count++
		if s, err := report.ParseSeverity(rc.Severity); err == nil && sev > s {
			rc.Severity = f.Severity
		}
		if sev > worst {
			worst = sev
		}
		top := topPath(f.Artifact)
		repoID, rel, ok := splitTop(top)
		if !ok {
			// A finding outside repos/<owner>/<name>/ is not attributable to a
			// repo (a stray file at the repos root). It still counts in the
			// scan-wide totals; it cannot appear in a repo row.
			continue
		}
		k := key(repoID, rel)
		a := byFile[k]
		if a == nil {
			a = &agg{}
			byFile[k] = a
			filesOf[repoID] = append(filesOf[repoID], rel)
		}
		a.add(sev, f.RuleID, f.Artifact)

		r := byRepo[repoID]
		if r == nil {
			r = &agg{}
			byRepo[repoID] = r
		}
		r.add(sev, f.RuleID, f.Artifact)
	}
	for id := range filesOf {
		sort.Strings(filesOf[id])
	}

	totals.Max = "none"
	if worst >= 0 {
		totals.Max = worst.String()
	}
	totals.Critical = sevCount[report.SeverityCritical]
	totals.High = sevCount[report.SeverityHigh]
	totals.Medium = sevCount[report.SeverityMedium]
	totals.Low = sevCount[report.SeverityLow]
	totals.Info = sevCount[report.SeverityInfo]

	// A verdict file that changed after the fetch (a -refresh, or a repo the Hub
	// flagged since) would leave repos selected but never fetched, and the report
	// would under-count coverage without saying so. The two stage files must agree.
	if err := checkStagesAgree(vs, fd, o.Level); err != nil {
		return nil, err
	}

	verdictByID := make(map[string]RepoVerdict, len(vs.Repos))
	for _, v := range vs.Repos {
		verdictByID[v.ID] = v
	}

	rep := &CampaignReport{
		Version: Version,
		Tool:    o.Tool,
		Campaign: CampaignInfo{
			Level:    o.Level,
			Limit:    o.Limit,
			Queries:  map[string][]string{"search": {}, "tag": {}, "author": {}},
			Probed:   len(vs.Repos),
			Selected: len(fd.Repos),
		},
		Totals: Totals{
			Repos:  len(fd.Repos),
			BySc4n: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "none": 0},
		},
	}
	var cands CandidatesFile
	if err := readJSON(o.path(fileCandidates), &cands); err == nil {
		for _, q := range cands.Queries {
			rep.Campaign.Queries[q.Kind] = append(rep.Campaign.Queries[q.Kind], q.Value)
		}
		if cands.Rank != nil {
			info := &RankInfo{Sort: cands.Rank.Sort, Rows: len(cands.Rank.Captured)}
			if o.Top > 0 {
				info.Top = o.Top
			} else {
				info.Top = len(cands.Rank.Captured)
			}
			if info.Rows > 0 {
				info.First = cands.Rank.Captured[0].ID
				info.Last = cands.Rank.Captured[info.Rows-1].ID
			}
			rep.Campaign.Rank = info
		}
	}
	rep.Totals.Findings = totals
	rep.Totals.ByRule = make([]RuleCount, 0, len(ruleCount))
	for _, rc := range ruleCount {
		rep.Totals.ByRule = append(rep.Totals.ByRule, *rc)
	}
	sort.Slice(rep.Totals.ByRule, func(i, j int) bool {
		a, b := rep.Totals.ByRule[i], rep.Totals.ByRule[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Severity != b.Severity {
			return sevRank(a.Severity) > sevRank(b.Severity)
		}
		return a.Rule < b.Rule
	})
	if doc.Suppressed > 0 {
		rep.Totals.Suppressed = doc.Suppressed
	}

	repos := make([]RepoReport, 0, len(fd.Repos))
	for _, rf := range fd.Repos {
		rr := RepoReport{ID: rf.ID, Status: rf.Status, Files: []FileReport{}, Extras: []ExtraReport{}}
		flagged := map[string]bool{}
		hubLevel := map[string]string{}
		if v, ok := verdictByID[rf.ID]; ok {
			for _, fi := range v.Files {
				if fi.Level == o.Level {
					flagged[fi.Path] = true
				}
				if prev, seen := hubLevel[fi.Path]; !seen || fi.Level < prev {
					hubLevel[fi.Path] = fi.Level
				}
			}
		}
		// A verdict-level campaign reviews the files the Hub flagged at that
		// level. A list campaign (LevelAny) reviews every file it fetched: the
		// question is about the repos, and the Hub's own level for a file is
		// carried into the row rather than deciding whether the row exists.
		for _, ff := range rf.Files {
			hub := o.Level
			if o.Level == LevelAny {
				hub = "none"
				if l, ok := hubLevel[ff.Path]; ok {
					hub = l
				}
			} else if !flagged[ff.Path] {
				continue
			}
			fr := FileReport{
				Path:     ff.Path,
				HF:       hub,
				Fetch:    ff.Status,
				Coverage: coverage(ff.Status),
				Format:   formats[rf.ID+"/"+ff.Path],
			}
			if a := byFile[key(rf.ID, ff.Path)]; a != nil {
				fr.Sc4n = a.worst.String()
				fr.Rules = a.topRules(8)
				if a.member != rf.ID+"/"+ff.Path {
					fr.Member = a.member
				}
			} else {
				fr.Sc4n = "none"
				fr.Rules = []string{}
			}
			fr.Reason = reasonFor(fr.Sc4n, fr.Coverage, ff.Status, fr.Format)
			rr.Files = append(rr.Files, fr)

			rep.Totals.Files++
			rep.Totals.BySc4n[fr.Sc4n]++
			// Coverage is how much of the file the scan read, which is a fact about
			// the bytes and not about the verdict: a clean file that was read whole is
			// fully covered. Counting only files with findings made the header
			// disagree with its own table — 59 "fully covered" beside a table whose
			// rows summed to 167 — and left the three numbers short of Files.
			switch fr.Coverage {
			case "none":
				rep.Totals.NotCovered++
			case "full":
				rep.Totals.CoveredFull++
			default:
				rep.Totals.CoveredPartial++
			}
		}
		sort.Slice(rr.Files, func(i, j int) bool { return rr.Files[i].Path < rr.Files[j].Path })

		for _, rel := range filesOf[rf.ID] {
			if flagged[rel] {
				continue
			}
			a := byFile[key(rf.ID, rel)]
			if !a.has || a.worst < report.SeverityHigh {
				continue
			}
			rr.Extras = append(rr.Extras, ExtraReport{
				Path:  rel,
				Sc4n:  a.worst.String(),
				Rules: a.topRules(4),
			})
		}
		sort.Slice(rr.Extras, func(i, j int) bool { return rr.Extras[i].Path < rr.Extras[j].Path })

		if a := byRepo[rf.ID]; a != nil {
			rr.Sc4n = RepoSc4n{
				Findings: a.count,
				BySeverity: map[string]int{
					"critical": a.bySev[report.SeverityCritical],
					"high":     a.bySev[report.SeverityHigh],
					"medium":   a.bySev[report.SeverityMedium],
					"low":      a.bySev[report.SeverityLow],
					"info":     a.bySev[report.SeverityInfo],
				},
			}
		} else {
			rr.Sc4n = RepoSc4n{BySeverity: map[string]int{
				"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
			}}
		}
		repos = append(repos, rr)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })
	rep.Repos = repos
	return rep, nil
}

// checkStagesAgree refuses a verdict/fetch pair that names different repo sets.
//
// Fetch writes exactly the repos selected from the verdict file it read, so any
// difference means one of the two files was recomputed alone: the fetch is stale
// (a repo the Hub flagged since is missing) or the verdicts are (a repo that is no
// longer flagged is still fetched). Either way the join would silently drop or
// add rows, which is the failure mode the stage split is meant to prevent.
func checkStagesAgree(vs VerdictsFile, fd FetchDoc, level string) error {
	selected := make(map[string]bool)
	for _, r := range selectedRepos(vs.Repos, level) {
		selected[r.ID] = true
	}
	fetched := make(map[string]bool)
	for _, r := range fd.Repos {
		fetched[r.ID] = true
	}
	var missing, stale []string
	for id := range selected {
		if !fetched[id] {
			missing = append(missing, id)
		}
	}
	for id := range fetched {
		if !selected[id] {
			stale = append(stale, id)
		}
	}
	if len(missing) == 0 && len(stale) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(stale)
	msg := fmt.Sprintf("hubcampaign: %s and %s disagree at level %s", fileVerdicts, fileFetch, level)
	if len(missing) > 0 {
		msg += fmt.Sprintf(": %d selected repo(s) not fetched, e.g. %s", len(missing), missing[0])
	}
	if len(stale) > 0 {
		msg += fmt.Sprintf(": %d fetched repo(s) no longer selected, e.g. %s", len(stale), stale[0])
	}
	return fmt.Errorf("%s; re-run -stage fetch", msg)
}

// reasonFor explains a file with no sc4n finding. A covered file with no finding
// and a recognised format is the campaign's honest miss; everything else is a
// statement about coverage or dispatch.
func reasonFor(sc4n, cov, fetchStatus, format string) string {
	if sc4n != "none" {
		return ""
	}
	switch cov {
	case "none":
		return fetchStatus
	case "partial":
		return "partial-only"
	}
	switch format {
	case "":
		return "not-scanned"
	case "unknown":
		return "unsupported-format"
	}
	return "no-findings"
}
