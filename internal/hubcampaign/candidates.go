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
	// Rank records the ranked listing when the universe came from one: the rows
	// exactly as the Hub returned them, so "why is this repo here" is answerable
	// from the file alone. It is absent for every other universe.
	Rank *RankFile `json:"rank,omitempty"`
}

// RankFile is the ranked listing a campaign's universe was taken from.
type RankFile struct {
	Sort     string               `json:"sort"`
	Limit    int                  `json:"limit"`
	Captured []hubapi.RankedModel `json:"captured"`
}

// listQuery is the value candidates.json records when the universe came from
// Options.Repos rather than a Hub query.
const listQuery = "-repos-file"

// listedCandidates turns an explicit repo list into candidates: order is kept
// (the list is the ranking), duplicates and blanks are dropped, and every entry
// carries the same reason so the file reads the same way a query-sourced one does.
func listedCandidates(ids []string) []Candidate {
	seen := make(map[string]bool, len(ids))
	out := make([]Candidate, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Candidate{ID: id, Why: []string{listQuery}})
	}
	return out
}

// writeListCandidates writes candidates.json from an explicit list. An explicit
// list is the universe: the file records the list as its one query so it still
// answers "where did this set come from", and the client is not consulted,
// because the list is the input rather than a search result.
func writeListCandidates(o Options) ([]Candidate, error) {
	o = o.withDefaults()
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("hubcampaign: %w", err)
	}
	repos := listedCandidates(o.Repos)
	label := o.ListLabel
	if label == "" {
		label = listQuery
	}
	file := CandidatesFile{Version: Version, Queries: []Sel{{Kind: "list", Value: label}}, Repos: repos}
	if err := writeJSON(o.path(fileCandidates), file); err != nil {
		return nil, err
	}
	progress(o, "candidates: %d repos from %s", len(repos), label)
	return repos, nil
}

// universeDiff reports how a cached universe differs from the requested one, or
// "" when it is the same question. It compares the selectors, the ranked listing
// and the list contents, because each of them changes which repos are in scope.
func universeDiff(cached CandidatesFile, o Options) string {
	want, err := o.queries()
	if err != nil {
		return "queries are invalid"
	}
	if len(cached.Queries) != len(want) {
		return "selector count differs"
	}
	for i := range want {
		if cached.Queries[i].Kind != want[i].Kind {
			return "selector " + want[i].Kind + ":" + want[i].Value
		}
		// A list's label ("-repo" versus "-repos-file") says how the ids were given,
		// not which ids they are, so the ids are compared below instead.
		if want[i].Kind != "list" && cached.Queries[i].Value != want[i].Value {
			return "selector " + want[i].Kind + ":" + want[i].Value
		}
	}
	if o.Rank != "" {
		if cached.Rank == nil || cached.Rank.Sort != o.Rank {
			return "rank " + o.Rank
		}
		if o.Top > 0 && len(cached.Repos) != o.Top {
			return fmt.Sprintf("top %d", o.Top)
		}
	}
	if len(o.Repos) > 0 {
		listed := listedCandidates(o.Repos)
		if len(listed) != len(cached.Repos) {
			return "repo list length"
		}
		for i := range listed {
			if listed[i].ID != cached.Repos[i].ID {
				return "repo " + listed[i].ID
			}
		}
	}
	return ""
}

// writeRankCandidates builds the universe from the Hub's own ranking. The rows are
// requested with the listing limit and then cut to Top, and the file keeps the
// rows as returned — including the ones beyond Top — because a ranking that moved
// between campaigns is easier to explain with the neighbours visible.
func writeRankCandidates(ctx context.Context, o Options) ([]Candidate, error) {
	limit := o.Limit
	if o.Top > limit {
		limit = o.Top
	}
	rows, err := o.Client.Top(ctx, hubapi.Rank{Sort: o.Rank, Limit: limit})
	if err != nil {
		return nil, fmt.Errorf("hubcampaign: rank %s: %w", o.Rank, err)
	}
	if o.Top > 0 && len(rows) > o.Top {
		rows = rows[:o.Top]
	}
	repos := make([]Candidate, 0, len(rows))
	for _, r := range rows {
		if r.ID == "" {
			continue
		}
		repos = append(repos, Candidate{ID: r.ID, Why: []string{"rank:" + o.Rank}})
	}
	file := CandidatesFile{
		Version: Version,
		Queries: []Sel{{Kind: "rank", Value: o.Rank}},
		Repos:   repos,
		Rank:    &RankFile{Sort: o.Rank, Limit: limit, Captured: rows},
	}
	if err := writeJSON(o.path(fileCandidates), file); err != nil {
		return nil, err
	}
	progress(o, "candidates: %d repos from rank %s (of %d rows requested)", len(repos), o.Rank, limit)
	return repos, nil
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
			// A cached universe is only this run's universe if it asked the same
			// question: -rank trendingScore after -rank downloads in the same
			// directory must not answer with the previous listing.
			if why := universeDiff(cached, o); why == "" {
				progress(o, "candidates: %d repos (cached, -refresh to recompute)", len(cached.Repos))
				return cached.Repos, nil
			} else {
				progress(o, "candidates: universe changed (%s), recomputing", why)
			}
		}
	}
	if o.Rank != "" {
		return writeRankCandidates(ctx, o)
	}
	if len(o.Repos) > 0 {
		return writeListCandidates(o)
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
// first, then the explicit selectors. An explicit repo list and a ranked listing
// are each their own universe, so each is the one query and the built-in search
// universe is not required (a -rank campaign must not silently add 43 search
// terms to a request that exists to answer "what are the top 10").
func (o Options) queries() ([]Sel, error) {
	if o.Rank != "" {
		return []Sel{{Kind: "rank", Value: o.Rank}}, nil
	}
	if len(o.Repos) > 0 {
		return []Sel{{Kind: "list", Value: listQuery}}, nil
	}
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
		case "search", "tag", "author", "list", "rank":
		default:
			return nil, fmt.Errorf("hubcampaign: query kind %q is not search, tag, author or list", s.Kind)
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
		return nil, errors.New("hubcampaign: no queries; pass -search/-tag/-author, -repos-file, or leave -defaults on")
	}
	return uniq, nil
}
