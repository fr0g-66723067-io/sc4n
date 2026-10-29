package hubcampaign

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Report writes campaign.json and campaign.md.
//
// Neither carries a timestamp: two runs over the same stage files must produce
// byte-identical output, which is what makes a campaign reproducible and what the
// determinism test asserts.
func Report(o Options, rep *CampaignReport) error {
	o = o.withDefaults()
	if err := writeJSON(o.path(fileCampaign), rep); err != nil {
		return err
	}
	md := campaignMarkdown(rep)
	tmp := o.path(fileCampaignMD) + ".tmp"
	if err := os.WriteFile(tmp, []byte(md), 0o644); err != nil {
		return fmt.Errorf("hubcampaign: %w", err)
	}
	if err := os.Rename(tmp, o.path(fileCampaignMD)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("hubcampaign: %w", err)
	}
	progress(o, "report: %d repos, %d flagged files, %d findings, max %s",
		rep.Totals.Repos, rep.Totals.Files, severityCount(rep.Totals.Findings), rep.Totals.Findings.Max)
	return nil
}

func severityCount(t FindingsTotals) int {
	return t.Critical + t.High + t.Medium + t.Low + t.Info
}

// campaignMarkdown renders the report as one header, one repo table and the list
// of files that were fully covered and produced no finding.
func campaignMarkdown(rep *CampaignReport) string {
	var b strings.Builder
	t := rep.Totals

	fmt.Fprintf(&b, "# sc4n Hugging Face campaign: level %s\n\n", rep.Campaign.Level)
	fmt.Fprintf(&b, "- tool: %s %s\n", rep.Tool.Name, rep.Tool.Version)
	fmt.Fprintf(&b, "- universe: %d repos probed, %d selected at level %s\n",
		rep.Campaign.Probed, rep.Campaign.Selected, rep.Campaign.Level)
	fmt.Fprintf(&b, "- queries: %d search, %d tag, %d author, %d list\n",
		len(rep.Campaign.Queries["search"]), len(rep.Campaign.Queries["tag"]),
		len(rep.Campaign.Queries["author"]), len(rep.Campaign.Queries["list"]))
	fmt.Fprintf(&b, "- flagged files: %d — %d fully covered, %d partially, %d not covered\n",
		t.Files, t.CoveredFull, t.CoveredPartial, t.NotCovered)
	fmt.Fprintf(&b, "- sc4n verdict per flagged file: critical %d, high %d, medium %d, low %d, info %d, none %d\n",
		t.BySc4n["critical"], t.BySc4n["high"], t.BySc4n["medium"], t.BySc4n["low"], t.BySc4n["info"], t.BySc4n["none"])
	fmt.Fprintf(&b, "- all findings under repos/: %d (critical %d, high %d, medium %d, low %d, info %d), worst %s\n\n",
		severityCount(t.Findings), t.Findings.Critical, t.Findings.High, t.Findings.Medium,
		t.Findings.Low, t.Findings.Info, t.Findings.Max)

	b.WriteString("| repo | status | flagged | coverage | sc4n | findings (crit/high/med) |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range rep.Repos {
		cov := map[string]int{}
		for _, f := range r.Files {
			cov[f.Coverage]++
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %d full, %d partial, %d none | %s | %d/%d/%d |\n",
			r.ID, r.Status, len(r.Files), cov["full"], cov["partial"], cov["none"],
			worstOf(r.Files),
			r.Sc4n.BySeverity["critical"], r.Sc4n.BySeverity["high"], r.Sc4n.BySeverity["medium"])
	}

	// The misses are the visible artifact, not a footnote: a fully covered file
	// with a recognised format and no finding is what "sc4n saw nothing" means.
	var misses []struct{ repo, file, format string }
	for _, r := range rep.Repos {
		for _, f := range r.Files {
			if f.Reason == "no-findings" {
				misses = append(misses, struct{ repo, file, format string }{r.ID, f.Path, f.Format})
			}
		}
	}
	b.WriteString("\n## Fully covered, no sc4n finding\n\n")
	if len(misses) == 0 {
		b.WriteString("None.\n")
	} else {
		b.WriteString("| repo | file | format |\n|---|---|---|\n")
		sort.Slice(misses, func(i, j int) bool {
			if misses[i].repo != misses[j].repo {
				return misses[i].repo < misses[j].repo
			}
			return misses[i].file < misses[j].file
		})
		for _, m := range misses {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", m.repo, m.file, m.format)
		}
	}

	var extras []struct {
		repo string
		e    ExtraReport
	}
	for _, r := range rep.Repos {
		for _, e := range r.Extras {
			extras = append(extras, struct {
				repo string
				e    ExtraReport
			}{r.ID, e})
		}
	}
	if len(extras) > 0 {
		if rep.Campaign.Level == LevelAny {
			// Every file in a list campaign is "not flagged": the heading has to
			// say what the table actually is.
			b.WriteString("\n## Files with high or critical findings\n\n")
		} else {
			b.WriteString("\n## Not flagged by the Hub, found by sc4n\n\n")
		}
		b.WriteString("| repo | file | sc4n | rules |\n|---|---|---|---|\n")
		sort.Slice(extras, func(i, j int) bool {
			if extras[i].repo != extras[j].repo {
				return extras[i].repo < extras[j].repo
			}
			return extras[i].e.Path < extras[j].e.Path
		})
		for _, x := range extras {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", x.repo, x.e.Path, x.e.Sc4n, strings.Join(x.e.Rules, ", "))
		}
	}
	return b.String()
}

// worstOf is the worst sc4n verdict among the listed files, or "-".
func worstOf(files []FileReport) string {
	worst := ""
	for _, f := range files {
		if f.Sc4n == "none" {
			continue
		}
		if worst == "" || sevRank(f.Sc4n) > sevRank(worst) {
			worst = f.Sc4n
		}
	}
	if worst == "" {
		return "none"
	}
	return worst
}

// sevRank orders severity names for the markdown summary. It is local because
// the names here come from JSON, and an unknown name must not panic a report.
func sevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
