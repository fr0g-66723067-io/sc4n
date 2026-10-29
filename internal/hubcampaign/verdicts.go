package hubcampaign

import (
	"context"
	"errors"
	"os"
	"sort"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
)

// RepoVerdict is one candidate's per-file Hub verdict. Files lists every issue at
// every level; selection by Options.Level happens in Fetch, so one probe pass
// serves any level.
type RepoVerdict struct {
	ID        string             `json:"id"`
	Status    string             `json:"status"`
	ScansDone bool               `json:"scansDone"`
	Files     []hubapi.FileIssue `json:"files"`
	Detail    string             `json:"detail,omitempty"`
}

// VerdictsFile is verdicts.json.
type VerdictsFile struct {
	Version int           `json:"version"`
	Level   string        `json:"level"`
	Repos   []RepoVerdict `json:"repos"`
}

// Verdicts probes every candidate and writes verdicts.json.
func Verdicts(ctx context.Context, o Options) ([]RepoVerdict, error) {
	o = o.withDefaults()
	if err := o.Validate(); err != nil {
		return nil, err
	}
	var cands CandidatesFile
	if err := readJSON(o.path(fileCandidates), &cands); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing(fileCandidates, "candidates")
		}
		return nil, err
	}
	if !o.Refresh {
		var cached VerdictsFile
		err := readJSON(o.path(fileVerdicts), &cached)
		if err == nil && cached.Version == Version && cached.Level == o.Level {
			progress(o, "verdicts: %d at level %s (cached, -refresh to re-probe)",
				countLevel(cached.Repos, o.Level), o.Level)
			return cached.Repos, nil
		}
		if err == nil && cached.Level != o.Level {
			// The probe records every level, so a re-probe is only needed because
			// the *file* is stamped with the level it was probed for, and Fetch
			// refuses a mismatch. Re-probe rather than leaving a dead end.
			progress(o, "verdicts: re-probing for level %s (file is stamped %s)", o.Level, cached.Level)
		}
	}

	repos := make([]RepoVerdict, len(cands.Repos))
	err := forEach(ctx, o.Jobs, len(cands.Repos), func(i int) error {
		repos[i] = probe(ctx, o.Client, cands.Repos[i].ID)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })

	out := VerdictsFile{Version: Version, Level: o.Level, Repos: repos}
	if err := writeJSON(o.path(fileVerdicts), out); err != nil {
		return nil, err
	}
	progress(o, "verdicts: %d at level %s of %d probed", countLevel(repos, o.Level), o.Level, len(repos))
	return repos, nil
}

// probe asks the Hub for one repo's verdict and classifies the failure, so a
// campaign never mistakes "could not probe" for "clean".
func probe(ctx context.Context, c *hubapi.Client, id string) RepoVerdict {
	v := RepoVerdict{ID: id}
	verdict, err := c.Scan(ctx, id)
	switch {
	case err == nil:
	case errors.Is(err, hubapi.ErrGated), errors.Is(err, hubapi.ErrAuth):
		v.Status = "gated"
		return v
	case errors.Is(err, hubapi.ErrNotFound):
		v.Status = "notfound"
		return v
	default:
		v.Status = "error"
		v.Detail = err.Error()
		return v
	}
	v.ScansDone = verdict.ScansDone
	v.Files = append(v.Files, verdict.Files...)
	sort.Slice(v.Files, func(i, j int) bool {
		if v.Files[i].Path != v.Files[j].Path {
			return v.Files[i].Path < v.Files[j].Path
		}
		return v.Files[i].Level < v.Files[j].Level
	})
	if !verdict.ScansDone {
		v.Status = "unscanned"
		return v
	}
	v.Status = "ok"
	return v
}

func countLevel(repos []RepoVerdict, level string) int {
	n := 0
	for _, r := range repos {
		if hasLevel(r, level) {
			n++
		}
	}
	return n
}

// hasLevel reports whether any file of r carries the level. LevelAny selects
// every probed repo: the campaign's question is about the whole list, not about
// what the Hub already flagged.
func hasLevel(r RepoVerdict, level string) bool {
	if level == LevelAny {
		return true
	}
	for _, f := range r.Files {
		if f.Level == level {
			return true
		}
	}
	return false
}

// selectedRepos returns the repos with at least one file at the level, in id
// order.
func selectedRepos(repos []RepoVerdict, level string) []RepoVerdict {
	out := make([]RepoVerdict, 0, len(repos))
	for _, r := range repos {
		if hasLevel(r, level) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
