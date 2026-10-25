package hubcampaign

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
)

// Candidate is one repo the universe query set produced, with the queries that
// found it. `why` is what makes the universe auditable after the fact.
type Candidate struct {
	ID  string   `json:"id"`
	Why []string `json:"why"`
}

// CandidatesFile is candidates.json.
type CandidatesFile struct {
	Version int         `json:"version"`
	Queries []Sel       `json:"queries"`
	Repos   []Candidate `json:"repos"`
}

// Candidates enumerates the universe and writes candidates.json.
//
// A query that fails aborts the stage with the query named: a universe that
// silently shrank is a campaign that under-reports its own coverage.
func Candidates(ctx context.Context, o Options) ([]Candidate, error) {
	o = o.withDefaults()
	if err := o.Validate(); err != nil {
		return nil, err
	}
	queries, err := o.queries()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("hubcampaign: %w", err)
	}
	if !o.Refresh {
		var cached CandidatesFile
		if err := readJSON(o.path(fileCandidates), &cached); err == nil && cached.Version == Version {
			progress(o, "candidates: %d repos (cached, -refresh to recompute)", len(cached.Repos))
			return cached.Repos, nil
		}
	}

	results := make([][]string, len(queries))
	err = forEach(ctx, o.Jobs, len(queries), func(i int) error {
		ids, err := o.Client.Models(ctx, query(queries[i], o.Limit))
		if err != nil {
			return fmt.Errorf("hubcampaign: query %s:%s: %w", queries[i].Kind, queries[i].Value, err)
		}
		results[i] = ids
		return nil
	})
	if err != nil {
		return nil, err
	}

	why := map[string]map[string]bool{}
	for i, q := range queries {
		for _, id := range results[i] {
			if id == "" {
				continue
			}
			if why[id] == nil {
				why[id] = map[string]bool{}
			}
			why[id][q.Kind+":"+q.Value] = true
		}
	}
	repos := make([]Candidate, 0, len(why))
	for _, id := range sortedKeys(why) {
		c := Candidate{ID: id}
		for _, w := range sortedKeys(why[id]) {
			c.Why = append(c.Why, w)
		}
		repos = append(repos, c)
	}

	out := CandidatesFile{Version: Version, Queries: queries, Repos: repos}
	if err := writeJSON(o.path(fileCandidates), out); err != nil {
		return nil, err
	}
	progress(o, "candidates: %d repos", len(repos))
	return repos, nil
}

// query converts a selector into a Hub listing request.
func query(s Sel, limit int) hubapi.Query {
	q := hubapi.Query{Limit: limit}
	switch s.Kind {
	case "search":
		q.Search = s.Value
	case "tag":
		q.Tag = s.Value
	case "author":
		q.Author = s.Value
	}
	return q
}

// queries builds the ordered, deduplicated query list: the built-in universe
// first, then the explicit selectors.
func (o Options) queries() ([]Sel, error) {
	var out []Sel
	if o.UseDefaults {
		for _, t := range DefaultTerms {
			out = append(out, Sel{Kind: "search", Value: t})
		}
		for _, t := range DefaultTags {
			out = append(out, Sel{Kind: "tag", Value: t})
		}
		for _, a := range DefaultAuthors {
			out = append(out, Sel{Kind: "author", Value: a})
		}
	}
	out = append(out, o.Queries...)
	seen := map[Sel]bool{}
	uniq := out[:0]
	for _, s := range out {
		s.Kind = strings.TrimSpace(s.Kind)
		s.Value = strings.TrimSpace(s.Value)
		switch s.Kind {
		case "search", "tag", "author":
		default:
			return nil, fmt.Errorf("hubcampaign: query kind %q is not search, tag or author", s.Kind)
		}
		if s.Value == "" {
			return nil, errors.New("hubcampaign: query value is empty")
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		uniq = append(uniq, s)
	}
	if len(uniq) == 0 {
		return nil, errors.New("hubcampaign: no queries; pass -search/-tag/-author or leave -defaults on")
	}
	return uniq, nil
}
