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
