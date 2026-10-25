package hubapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is the client configuration. Every zero value has a working default.
type Config struct {
	// BaseURL is the Hub root, e.g. https://huggingface.co. https is required;
	// http is accepted only for a loopback host, which is what makes the client
	// testable against httptest without weakening the real path.
	BaseURL string
	// Token is the bearer token; empty means anonymous.
	Token string
	// UserAgent identifies sc4n in the Hub's logs.
	UserAgent string
	// Jobs is the caller's intended concurrency. The client is safe for
	// concurrent use; the field is carried so one Config describes the campaign.
	Jobs int
	// Timeout bounds one request, including the body copy.
	Timeout time.Duration
	// MaxBody caps a JSON response; a larger one is an error, not a truncation.
	MaxBody int64
}

// Client is a Hub API client. It is safe for concurrent use.
type Client struct {
	base    string
	token   string
	ua      string
	jobs    int
	maxBody int64
	hc      *http.Client
}

const (
	defaultBaseURL = "https://huggingface.co"
	defaultMaxBody = 32 << 20
	defaultTimeout = 60 * time.Second
	maxAttempts    = 4
	retryBaseDelay = 250 * time.Millisecond
)

// New validates cfg and returns a client.
func New(cfg Config) (*Client, error) {
	raw := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if raw == "" {
		raw = defaultBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("hubapi: base URL: %w", err)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("hubapi: base URL %q must be https (http is allowed only for a loopback host)", raw)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	maxBody := cfg.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	jobs := cfg.Jobs
	if jobs <= 0 {
		jobs = 8
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "sc4n-hub"
	}
	c := &Client{
		base:    raw,
		token:   strings.TrimSpace(cfg.Token),
		ua:      ua,
		jobs:    jobs,
		maxBody: maxBody,
	}
	first := u.Host
	c.hc = &http.Client{
		Timeout: timeout,
		// The Hub answers a file download with a redirect to its CDN. The bearer
		// token is for huggingface.co only; carrying it to another host would hand
		// a credential to whatever the Location names.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && req.URL.Host != first {
				req.Header.Del("Authorization")
			}
			if len(via) >= 10 {
				return errors.New("hubapi: stopped after 10 redirects")
			}
			return nil
		},
	}
	return c, nil
}

// Jobs is the concurrency the client was configured with.
func (c *Client) Jobs() int { return c.jobs }

// Models lists model ids for one query, in the Hub's order.
func (c *Client) Models(ctx context.Context, q Query) ([]string, error) {
	set := 0
	if q.Search != "" {
		set++
	}
	if q.Tag != "" {
		set++
	}
	if q.Author != "" {
		set++
	}
	if set != 1 {
		return nil, errors.New("hubapi: Query needs exactly one of Search, Tag, Author")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	v := url.Values{}
	v.Set("limit", strconv.Itoa(limit))
	v.Set("sort", "downloads")
	switch {
	case q.Search != "":
		v.Set("search", q.Search)
	case q.Tag != "":
		v.Set("filter", q.Tag)
	default:
		v.Set("author", q.Author)
	}
	var out []struct {
		ID string `json:"id"`
	}
	if err := c.getJSON(ctx, c.raw("/api/models")+"?"+v.Encode(), &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out))
	for _, m := range out {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	return ids, nil
}

// Scan returns one repo's per-file security verdict.
func (c *Client) Scan(ctx context.Context, id string) (ScanVerdict, error) {
	var v ScanVerdict
	err := c.getJSON(ctx, c.raw("/api/models/"+escapePath(id)+"/scan"), &v)
	return v, err
}

// Files lists a repo's siblings and their sizes.
func (c *Client) Files(ctx context.Context, id string) ([]RepoFile, error) {
	var info struct {
		Siblings []struct {
			RFilename string `json:"rfilename"`
			Size      *int64 `json:"size"`
			LFS       *struct {
				Size *int64 `json:"size"`
			} `json:"lfs"`
		} `json:"siblings"`
	}
	if err := c.getJSON(ctx, c.raw("/api/models/"+escapePath(id)+"?blobs=true"), &info); err != nil {
		return nil, err
	}
	out := make([]RepoFile, 0, len(info.Siblings))
	for _, s := range info.Siblings {
		size := int64(-1)
		if s.Size != nil {
			size = *s.Size
		}
		if s.LFS != nil && s.LFS.Size != nil && *s.LFS.Size > 0 {
			size = *s.LFS.Size
		}
		out = append(out, RepoFile{Path: s.RFilename, Size: size})
	}
	return out, nil
}

// Download fetches one file into w. When max > 0 it requests the range
// [off, off+max) and copies at most max bytes; when max <= 0 it fetches the whole
// file. The caller owns w and must not reuse a partially written file as if it
// were complete — the campaign writes to a temp path and renames.
func (c *Client) Download(ctx context.Context, id, path string, off, max int64, w io.Writer) (DownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.raw("/"+escapePath(id)+"/resolve/main/"+escapePath(path)), nil)
	if err != nil {
		return DownloadResult{}, err
	}
	c.auth(req)
	req.Header.Set("Accept-Encoding", "identity")
	if max > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+max-1))
	}
	resp, err := c.do(req)
	if err != nil {
		return DownloadResult{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return DownloadResult{Status: resp.StatusCode}, ErrAuth
	case http.StatusForbidden:
		return DownloadResult{Status: resp.StatusCode}, ErrGated
	case http.StatusNotFound:
		return DownloadResult{Status: resp.StatusCode}, ErrNotFound
	case http.StatusOK, http.StatusPartialContent:
	default:
		return DownloadResult{Status: resp.StatusCode}, fmt.Errorf("hubapi: download %s: HTTP %d", path, resp.StatusCode)
	}
	var r io.Reader = resp.Body
	if max > 0 {
		r = io.LimitReader(resp.Body, max)
	}
	n, err := io.Copy(w, r)
	res := DownloadResult{Status: resp.StatusCode, Bytes: n}
	if err != nil {
		return res, err
	}
	return res, nil
}

// getJSON performs one GET and decodes a size-capped JSON body.
func (c *Client) getJSON(ctx context.Context, raw string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	c.auth(req)
	req.Header.Set("Accept", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return ErrAuth
	case http.StatusForbidden:
		return ErrGated
	case http.StatusNotFound:
		return ErrNotFound
	default:
		return fmt.Errorf("hubapi: GET %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > c.maxBody {
		return fmt.Errorf("hubapi: response exceeds MaxBody (%d bytes)", c.maxBody)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("hubapi: GET %s: %w", req.URL.Path, err)
	}
	return nil
}

// do runs one request with the retry policy: only 429 and 5xx are retried, at most
// maxAttempts times, honouring Retry-After in seconds.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			req = req.Clone(req.Context())
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			if !sleepContext(req.Context(), retryBaseDelay<<uint(attempt), "") {
				return nil, req.Context().Err()
			}
			continue
		}
		if retryable(resp.StatusCode) {
			after := resp.Header.Get("Retry-After")
			resp.Body.Close()
			if attempt == maxAttempts-1 {
				return nil, fmt.Errorf("hubapi: %s: HTTP %d after %d attempts", req.URL.Path, resp.StatusCode, maxAttempts)
			}
			if !sleepContext(req.Context(), retryBaseDelay<<uint(attempt), after) {
				return nil, req.Context().Err()
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("hubapi: request failed")
	}
	return nil, lastErr
}

func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// sleepContext waits d, or the Retry-After value when it is a whole number of
// seconds, and reports false when the context ended first.
func sleepContext(ctx context.Context, d time.Duration, retryAfter string) bool {
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 {
		d = time.Duration(s) * time.Second
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (c *Client) auth(req *http.Request) {
	req.Header.Set("User-Agent", c.ua)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) raw(path string) string { return c.base + path }

// escapePath escapes each path segment, keeping the separators: repo ids are
// "owner/name" and file names may contain spaces, '%' or '#', which must reach the
// Hub encoded rather than altering the URL.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func isLoopback(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}
