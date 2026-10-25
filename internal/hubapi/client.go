package hubapi

import (
	"bytes"
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
	// Timeout bounds one JSON request, and for a download it bounds a *stall*: a
	// transfer that keeps delivering bytes is not cut off, one that delivers none
	// for Timeout is.
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
	timeout time.Duration
	hc      *http.Client
	// dl is the client for downloads: no whole-exchange deadline, because Timeout
	// means "no data for this long" there.
	dl *http.Client
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
		timeout: timeout,
	}
	first := u.Host
	// The Hub answers a file download with a redirect to its CDN. The bearer token
	// is for huggingface.co only; carrying it to another host would hand a
	// credential to whatever the Location names.
	redirect := func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && req.URL.Host != first {
			req.Header.Del("Authorization")
		}
		if len(via) >= 10 {
			return errors.New("hubapi: stopped after 10 redirects")
		}
		return nil
	}
	c.hc = &http.Client{Timeout: timeout, CheckRedirect: redirect}
	c.dl = &http.Client{CheckRedirect: redirect}
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

// ModelInfo returns a repo's gate mode and state. It costs one request, so the
// campaign calls it only after a 403.
func (c *Client) ModelInfo(ctx context.Context, id string) (ModelInfo, error) {
	var raw struct {
		// gated is `false` or a string ("auto" / "manual"), so it cannot be typed.
		Gated    any  `json:"gated"`
		Private  bool `json:"private"`
		Disabled bool `json:"disabled"`
	}
	if err := c.getJSON(ctx, c.raw("/api/models/"+escapePath(id)), &raw); err != nil {
		return ModelInfo{}, err
	}
	out := ModelInfo{Private: raw.Private, Disabled: raw.Disabled}
	switch v := raw.Gated.(type) {
	case string:
		out.Gated = v
	case bool:
		if v {
			// Not a documented spelling, but a repo that says `true` is gated and
			// saying so is better than reporting it ungated.
			out.Gated = "auto"
		}
	}
	return out, nil
}

// Download fetches one file into w. When max > 0 it requests the range
// [off, off+max) and copies at most max bytes; when max <= 0 it fetches the whole
// file. The caller owns w and must not reuse a partially written file as if it
// were complete — the campaign writes to a temp path and renames.
//
// Two properties matter for a 700 MiB checkpoint on a slow link, and both were
// learned from a real failure (the round's 699 MiB llamafile was reported as
// `error: context deadline exceeded ... while reading body`):
//
//   - Timeout bounds a *stall*, not the transfer: the request context is cancelled
//     only when no bytes have arrived for Timeout, so a large file that keeps
//     flowing is not cut off at 30s.
//   - A copy that fails mid-body is retried from the next byte with a Range
//     request, so a reset costs the remainder rather than the whole file. A server
//     that ignores the resume Range (200 instead of 206) is an error, because
//     appending a second full copy to w would corrupt the file.
func (c *Client) Download(ctx context.Context, id, path string, off, max int64, w io.Writer) (DownloadResult, error) {
	var (
		written  int64
		res      DownloadResult
		lastErr  error
		firstErr error
	)
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if !sleepContext(ctx, retryBaseDelay<<uint(attempt-1), "") {
				return res, ctx.Err()
			}
		}
		n, status, err := c.downloadOnce(ctx, id, path, off, max, written, w)
		res.Status = status
		written += n
		res.Bytes = written
		if err == nil {
			return res, nil
		}
		lastErr = err
		if firstErr == nil {
			firstErr = err
		}
		if errors.Is(err, ErrGated) || errors.Is(err, ErrAuth) || errors.Is(err, ErrNotFound) {
			return res, err
		}
		if errors.Is(err, errNoResume) {
			// The resume was the recovery attempt: report why it was needed, or the
			// message names the symptom and hides the cause.
			return res, fmt.Errorf("hubapi: download %s: %v; %w", path, firstErr, errNoResume)
		}
		if max > 0 && written >= max {
			// The requested range is complete even though the connection died on
			// the last read: nothing is missing.
			return res, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("hubapi: download failed")
	}
	return res, lastErr
}

// errNoResume reports a server that answered a resume Range with the whole file.
var errNoResume = errors.New("hubapi: server ignored the resume range")

// downloadOnce performs one attempt, appending at written bytes past off.
func (c *Client) downloadOnce(ctx context.Context, id, path string, off, max, written int64, w io.Writer) (int64, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.raw("/"+escapePath(id)+"/resolve/main/"+escapePath(path)), nil)
	if err != nil {
		return 0, 0, err
	}
	c.auth(req)
	req.Header.Set("Accept-Encoding", "identity")
	cur := off + written
	switch {
	case max > 0:
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", cur, off+max-1))
	case cur > 0:
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", cur))
	}

	// The idle timer replaces http.Client.Timeout for this path: the client used
	// here has no whole-exchange deadline.
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(c.timeout, cancel)
	defer idle.Stop()

	resp, err := doRequest(dctx, c.dl, req)
	if err != nil {
		if dctx.Err() != nil && ctx.Err() == nil {
			return 0, 0, fmt.Errorf("hubapi: download %s: no data for %s", path, c.timeout)
		}
		return 0, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return 0, resp.StatusCode, statusError(resp, ErrAuth)
	case http.StatusForbidden:
		return 0, resp.StatusCode, statusError(resp, ErrGated)
	case http.StatusNotFound:
		return 0, resp.StatusCode, ErrNotFound
	case http.StatusOK:
		if cur > off {
			return 0, resp.StatusCode, errNoResume
		}
	case http.StatusPartialContent:
	default:
		return 0, resp.StatusCode, fmt.Errorf("hubapi: download %s: HTTP %d", path, resp.StatusCode)
	}

	var r io.Reader = resp.Body
	if max > 0 {
		r = io.LimitReader(resp.Body, max-written)
	}
	buf := make([]byte, 256<<10)
	var n int64
	for {
		rd, rerr := r.Read(buf)
		if rd > 0 {
			if _, werr := w.Write(buf[:rd]); werr != nil {
				return n, resp.StatusCode, werr
			}
			n += int64(rd)
			idle.Reset(c.timeout)
		}
		if rerr == io.EOF {
			return n, resp.StatusCode, nil
		}
		if rerr != nil {
			if dctx.Err() != nil && ctx.Err() == nil {
				return n, resp.StatusCode, fmt.Errorf("hubapi: download %s: no data for %s", path, c.timeout)
			}
			return n, resp.StatusCode, rerr
		}
	}
}

// doRequest is where http.Client.Do is called, kept separate so the download path
// can use its own client.
func doRequest(ctx context.Context, hc *http.Client, req *http.Request) (*http.Response, error) {
	return hc.Do(req.WithContext(ctx))
}

// getJSON performs one GET and decodes a size-capped JSON body.
//
// An empty 200 body is retried before it is an error. The Hub's per-repo `/scan`
// endpoint answers 200 with no content while it is busy — observed twice in a
// 2390-repo probe, both fine seconds later — and a body-less 200 was previously
// reported as "unexpected end of JSON input", which marked the repo `error` and
// lost its verdict for the whole campaign.
func (c *Client) getJSON(ctx context.Context, raw string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.send(req, true)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(body)) == 0 {
			if attempt+1 < maxAttempts {
				if !sleepContext(ctx, retryBaseDelay<<uint(attempt), "") {
					return ctx.Err()
				}
				req = req.Clone(ctx)
				continue
			}
			return fmt.Errorf("hubapi: GET %s: empty body after %d attempts (the Hub answers 200 with no content while a scan is unavailable; re-run the stage)",
				req.URL.Path, maxAttempts)
		}
		if int64(len(body)) > c.maxBody {
			return fmt.Errorf("hubapi: response exceeds MaxBody (%d bytes)", c.maxBody)
		}
		if err := json.Unmarshal(body, v); err != nil {
			return fmt.Errorf("hubapi: GET %s: %w", req.URL.Path, err)
		}
		return nil
	}
}

// statusError turns a 401/403 into the matching sentinel plus the Hub's
// explanation. The Hub answers `X-Error-Message: Access to model <id> is restricted
// and you are not in the authorized list. Visit <url> to ask for access.` — the
// reason and the URL are exactly what an operator needs, and a bare sentinel threw
// both away.
func statusError(resp *http.Response, sentinel error) error {
	defer resp.Body.Close()
	msg := strings.TrimSpace(resp.Header.Get("X-Error-Message"))
	if msg == "" {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg = strings.TrimSpace(string(b))
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return sentinel
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return fmt.Errorf("%w: %s", sentinel, msg)
}

// send runs one request, maps the status and returns the response with its body
// open. The caller closes it.
func (c *Client) send(req *http.Request, jsonAccept bool) (*http.Response, error) {
	c.auth(req)
	if jsonAccept {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusUnauthorized:
		return nil, statusError(resp, ErrAuth)
	case http.StatusForbidden:
		return nil, statusError(resp, ErrGated)
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, ErrNotFound
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("hubapi: GET %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
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
