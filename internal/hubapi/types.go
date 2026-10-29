// Package hubapi is the Hugging Face Hub client the `sc4n hub` campaign uses.
//
// It exists so the campaign is one binary: the round that produced the 2026-10-24
// unsafe list was five Python scripts around four endpoints, and every one of them
// re-learned the same four things — the search/tag/author listing, the per-repo
// `/scan` verdict, the `?blobs=true` sibling sizes, and the `/resolve` download
// with its Range form. Those four are here, with the three properties a scanner's
// network layer must have:
//
//   - the token never leaves the Hub host: CheckRedirect drops Authorization when a
//     download is redirected to the CDN;
//   - every response is size-capped (MaxBody) and every call is retried only on the
//     statuses that mean "later" (429, 500, 502, 503, 504);
//   - the four "this repo is not readable" outcomes are distinct errors, so the
//     campaign can say gated/notfound/auth instead of failing the run.
//
// Nothing here executes or trusts an artifact; it moves bytes and JSON.
package hubapi

import "errors"

// Query is one listing request. Exactly one of Search, Tag, Author must be set.
type Query struct {
	// Search matches the model id as a substring (the Hub's `search=`).
	Search string
	// Tag matches a repo tag exactly (the Hub's `filter=`).
	Tag string
	// Author lists one account's models (the Hub's `author=`).
	Author string
	// Limit caps the result count; zero means 100, above 1000 is clamped.
	Limit int
}

// Rank is a model-listing order. The Hub publishes two volume signals and they
// answer different questions: SortDownloads ("downloads") is a *30-day* count —
// `?period=week` is accepted and ignored, measured 2026-10-25 — while
// SortTrending ("trendingScore") is the recent-window ranking and the only
// week-scale ordering the API exposes. A campaign must say which one it used, so
// the constant reaches candidates.json rather than a raw string.
type Rank struct {
	// Sort is one of the Sort* constants.
	Sort string
	// Limit caps the rows requested; zero means 100, above 1000 is clamped.
	Limit int
}

// The Hub's listing orders.
const (
	SortDownloads = "downloads"
	SortTrending  = "trendingScore"
	SortLikes     = "likes"
	SortModified  = "lastModified"
	SortCreated   = "createdAt"
)

// RankValid reports whether s is a listing order this client will request. The
// allowlist exists because the value becomes a query parameter: an arbitrary sort
// key is an arbitrary request.
func RankValid(s string) bool {
	switch s {
	case SortDownloads, SortTrending, SortLikes, SortModified, SortCreated:
		return true
	}
	return false
}

// RankedModel is one row of a ranked listing, with the metadata that makes the
// ranking auditable after the fact: a campaign file that recorded only ids could
// not answer "why was this repo in the set".
type RankedModel struct {
	ID            string  `json:"id"`
	Downloads     int64   `json:"downloads"`
	Likes         int64   `json:"likes"`
	TrendingScore float64 `json:"trendingScore"`
	LastModified  string  `json:"lastModified,omitempty"`
	PipelineTag   string  `json:"pipeline_tag,omitempty"`
	LibraryName   string  `json:"library_name,omitempty"`
	Private       bool    `json:"private,omitempty"`
}

// FileIssue is one row of the Hub's per-file scan verdict.
//
// Level is one of "unsafe", "suspicious", "caution" or "error"; "unsafe" means
// the Hub's malware or pickle scanner matched the file.
type FileIssue struct {
	Path  string `json:"path"`
	Level string `json:"level"`
}

// ScanVerdict is GET /api/models/{id}/scan.
type ScanVerdict struct {
	ScansDone bool        `json:"scansDone"`
	Files     []FileIssue `json:"filesWithIssues"`
}

// ModelInfo is the subset of GET /api/models/{id} that says why a repo may refuse
// a file. Gated is "" or "false" for an ungated repo, "auto" when access is granted
// as soon as the user accepts the terms and shares the gated fields, and "manual"
// when the owner has to approve the account.
type ModelInfo struct {
	Gated    string
	Disabled bool
	Private  bool
}

// HasGate reports whether the repo has an access gate of either mode.
func (m ModelInfo) HasGate() bool { return m.Gated == "auto" || m.Gated == "manual" }

// RepoFile is one sibling of a repo listing. Size is -1 when the Hub does not
// report one.
type RepoFile struct {
	Path string
	Size int64
}

// DownloadResult reports what one download produced. Status is the HTTP status of
// the response that carried the bytes (200, or 206 for a Range request).
type DownloadResult struct {
	Status int
	Bytes  int64
}

var (
	// ErrGated reports a 403: the repo or file requires accepting its gate.
	ErrGated = errors.New("hubapi: download is gated")
	// ErrAuth reports a 401: no token was sent, or it is not accepted.
	ErrAuth = errors.New("hubapi: authentication required")
	// ErrNotFound reports a 404: no such repo, or a repo disabled after being flagged.
	ErrNotFound = errors.New("hubapi: not found")
)
