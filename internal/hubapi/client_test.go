package hubapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, base, token string) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: base, Token: token, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRejectsInsecureBase(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://example.com"}); err == nil {
		t.Fatal("http to a non-loopback host was accepted")
	}
	if _, err := New(Config{BaseURL: "ftp://example.com"}); err == nil {
		t.Fatal("non-http scheme accepted")
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
}

func TestModelsQueryParams(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		if r.URL.Path != "/api/models" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`[{"id":"b/b"},{"id":"a/a"}]`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	ids, err := c.Models(context.Background(), Query{Search: "pickle", Limit: 7})
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if len(ids) != 2 || ids[0] != "b/b" || ids[1] != "a/a" {
		t.Fatalf("ids = %v, want the Hub's order", ids)
	}
	for _, want := range []string{"limit=7", "sort=downloads", "search=pickle"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Errorf("query %q missing %s", got, want)
		}
	}
	if bytes.Contains([]byte(got), []byte("filter=")) || bytes.Contains([]byte(got), []byte("author=")) {
		t.Errorf("query %q sets an unrelated selector", got)
	}
}

func TestModelsRequiresOneSelector(t *testing.T) {
	c := testClient(t, "http://127.0.0.1:1", "")
	for _, q := range []Query{{}, {Search: "a", Tag: "b"}, {Search: "a", Author: "c"}} {
		if _, err := c.Models(context.Background(), q); err == nil {
			t.Errorf("Models(%+v) accepted an ambiguous query", q)
		}
	}
}

func TestModelsClampsLimit(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("limit")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	if _, err := c.Models(context.Background(), Query{Tag: "malware", Limit: 5000}); err != nil {
		t.Fatalf("Models: %v", err)
	}
	if got != "1000" {
		t.Fatalf("limit = %s, want 1000", got)
	}
	if _, err := c.Models(context.Background(), Query{Tag: "malware"}); err != nil {
		t.Fatalf("Models: %v", err)
	}
	if got != "100" {
		t.Fatalf("default limit = %s, want 100", got)
	}
}

func TestScanVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/models/org/name/scan" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"scansDone":true,"filesWithIssues":[{"path":"a.pkl","level":"unsafe"}]}`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	v, err := c.Scan(context.Background(), "org/name")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !v.ScansDone || len(v.Files) != 1 || v.Files[0].Path != "a.pkl" || v.Files[0].Level != "unsafe" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestScanAbsent(t *testing.T) {
	// A repo with no verdict carries none of the fields.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	v, err := c.Scan(context.Background(), "org/name")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.ScansDone || len(v.Files) != 0 {
		t.Fatalf("absent verdict decoded as %+v", v)
	}
}

func TestFilesSizes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("blobs") != "true" {
			t.Errorf("blobs not requested: %q", r.URL.RawQuery)
		}
		w.Write([]byte(`{"siblings":[
			{"rfilename":"a.bin","size":10},
			{"rfilename":"b.bin","size":5,"lfs":{"size":9007199254740993}},
			{"rfilename":"c.bin"},
			{"rfilename":"empty.bin","size":0}]}`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	files, err := c.Files(context.Background(), "org/name")
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	want := []RepoFile{
		{Path: "a.bin", Size: 10},
		{Path: "b.bin", Size: 9007199254740993},
		{Path: "c.bin", Size: -1},
		{Path: "empty.bin", Size: 0},
	}
	if len(files) != len(want) {
		t.Fatalf("files = %+v", files)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Errorf("files[%d] = %+v, want %+v", i, files[i], want[i])
		}
	}
}

func TestDownloadRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RequestURI(); got != "/org/name/resolve/main/dir/a%20b.bin" {
			t.Errorf("request URI = %q", got)
		}
		if got := r.Header.Get("Range"); got != "bytes=0-3" {
			t.Errorf("Range = %q", got)
		}
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("abcd"))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "tok")
	var buf bytes.Buffer
	res, err := c.Download(context.Background(), "org/name", "dir/a b.bin", 0, 4, &buf)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Status != http.StatusPartialContent || res.Bytes != 4 || buf.String() != "abcd" {
		t.Fatalf("result = %+v body %q", res, buf.String())
	}
}

func TestDownloadStripsAuthOnRedirect(t *testing.T) {
	var cdnAuth string
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnAuth = r.Header.Get("Authorization")
		w.Write([]byte("blob"))
	}))
	defer cdn.Close()
	var hubAuth string
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hubAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, cdn.URL+"/cdn/blob", http.StatusFound)
	}))
	defer hub.Close()
	c := testClient(t, hub.URL, "tok")
	var buf bytes.Buffer
	if _, err := c.Download(context.Background(), "org/name", "a.bin", 0, 0, &buf); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if hubAuth != "Bearer tok" {
		t.Fatalf("hub saw %q, want the bearer token", hubAuth)
	}
	if cdnAuth != "" {
		t.Fatalf("the CDN saw the token: %q", cdnAuth)
	}
	if buf.String() != "blob" {
		t.Fatalf("body = %q", buf.String())
	}
}

func TestDownloadKeepsAuthOnSameHostRedirect(t *testing.T) {
	var second string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			second = r.Header.Get("Authorization")
			w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, "/moved", http.StatusFound)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "tok")
	var buf bytes.Buffer
	if _, err := c.Download(context.Background(), "org/name", "a.bin", 0, 0, &buf); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if second != "Bearer tok" {
		t.Fatalf("same-host redirect dropped the token: %q", second)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrAuth},
		{http.StatusForbidden, ErrGated},
		{http.StatusNotFound, ErrNotFound},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		c := testClient(t, srv.URL, "")
		if _, err := c.Scan(context.Background(), "org/name"); !errors.Is(err, tc.want) {
			t.Errorf("scan %d: err = %v, want %v", tc.status, err, tc.want)
		}
		var buf bytes.Buffer
		if _, err := c.Download(context.Background(), "org/name", "a", 0, 0, &buf); !errors.Is(err, tc.want) {
			t.Errorf("download %d: err = %v, want %v", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

func TestRetryOn429ThenOK(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`[{"id":"a/b"}]`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	ids, err := c.Models(context.Background(), Query{Search: "x"})
	if err != nil {
		t.Fatalf("Models: %v", err)
	}
	if len(ids) != 1 || n != 2 {
		t.Fatalf("ids = %v after %d attempts", ids, n)
	}
}

func TestRetryGivesUp(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	if _, err := c.Models(context.Background(), Query{Search: "x"}); err == nil {
		t.Fatal("persistent 503 was reported as success")
	}
	if n != maxAttempts {
		t.Fatalf("attempts = %d, want %d", n, maxAttempts)
	}
}

func TestNoRetryOn404(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	if _, err := c.Scan(context.Background(), "org/name"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if n != 1 {
		t.Fatalf("404 retried %d times", n)
	}
}

func TestMaxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte(" "), 4096))
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, MaxBody: 1024})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Models(context.Background(), Query{Search: "x"}); err == nil {
		t.Fatal("an oversized response was accepted")
	}
}

func TestTokenPrecedence(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "token"), []byte("file-token\n"), 0o600)
	t.Setenv("HF_HOME", home)
	t.Setenv("HF_TOKEN", "")
	t.Setenv("HUGGING_FACE_HUB_TOKEN", "")

	if got, err := Token(""); err != nil || got != "file-token" {
		t.Fatalf("file token = %q, %v", got, err)
	}
	t.Setenv("HUGGING_FACE_HUB_TOKEN", "hub-token")
	if got, _ := Token(""); got != "hub-token" {
		t.Fatalf("HUGGING_FACE_HUB_TOKEN lost: %q", got)
	}
	t.Setenv("HF_TOKEN", "env-token")
	if got, _ := Token(""); got != "env-token" {
		t.Fatalf("HF_TOKEN did not win over HUGGING_FACE_HUB_TOKEN: %q", got)
	}

	explicit := filepath.Join(home, "explicit")
	os.WriteFile(explicit, []byte("explicit-token\n"), 0o600)
	if got, _ := Token(explicit); got != "explicit-token" {
		t.Fatalf("explicit file did not win: %q", got)
	}
	if _, err := Token(filepath.Join(home, "missing")); err == nil {
		t.Fatal("a named but missing token file was ignored")
	}
}

func TestTokenAbsentIsAnonymous(t *testing.T) {
	t.Setenv("HF_HOME", t.TempDir())
	t.Setenv("HF_TOKEN", "")
	t.Setenv("HUGGING_FACE_HUB_TOKEN", "")
	got, err := Token("")
	if err != nil || got != "" {
		t.Fatalf("Token = %q, %v; want empty and no error", got, err)
	}
}

func TestEscapePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"org/name", "org/name"},
		{"dir/a b.bin", "dir/a%20b.bin"},
		{"a#b", "a%23b"},
		{"a%2Fb", "a%252Fb"},
	} {
		got, err := escapePath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("escapePath(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", ".", "..", "org/..", "../etc/passwd", "a/./b", "a//b", "/leading", "trailing/", "a\x00b"} {
		if got, err := escapePath(bad); err == nil {
			t.Errorf("escapePath(%q) = %q, nil; want error", bad, got)
		}
	}
}

// The Hub's /scan endpoint answers 200 with an empty body while it is busy. Two
// such answers in a 2390-repo probe marked the repos `error` and lost their
// verdicts for the whole campaign, so the empty body is retried.
func TestEmptyBodyIsRetried(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write([]byte(`{"scansDone":false,"filesWithIssues":[]}`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	v, err := c.Scan(context.Background(), "org/name")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v.ScansDone || n != 3 {
		t.Fatalf("verdict = %+v after %d attempts", v, n)
	}
}

func TestEmptyBodyGivesUp(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	_, err := c.Scan(context.Background(), "org/name")
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("empty body")) {
		t.Fatalf("err = %v, want an empty-body error", err)
	}
	if n != maxAttempts {
		t.Fatalf("attempts = %d, want %d", n, maxAttempts)
	}
}

func body100() []byte {
	b := make([]byte, 100)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// A body that ends early is a reset, not a lost file: the download resumes at the
// byte it reached. The round's 699 MiB llamafile failed as "context deadline
// exceeded while reading body" before this.
func TestDownloadResumesAfterTruncatedBody(t *testing.T) {
	body := body100()
	var hits int32
	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ranges = append(ranges, r.Header.Get("Range"))
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Write(body[:10])
			return // fewer bytes than announced: the client sees an unexpected EOF
		}
		if got := r.Header.Get("Range"); got != "bytes=10-" {
			t.Errorf("resume Range = %q", got)
		}
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body[10:])
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	var buf bytes.Buffer
	res, err := c.Download(context.Background(), "org/name", "big.bin", 0, 0, &buf)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), body) || res.Bytes != 100 || hits != 2 {
		t.Fatalf("got %d bytes in %d attempts (ranges %v)", buf.Len(), hits, ranges)
	}
}

// A server that answers a resume with the whole file must not be appended to the
// partial copy: that would silently corrupt the artifact.
func TestDownloadRefusesIgnoredResume(t *testing.T) {
	body := body100()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Write(body[:10])
			return
		}
		w.Write(body) // 200 with the whole file, ignoring Range
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	var buf bytes.Buffer
	_, err := c.Download(context.Background(), "org/name", "big.bin", 0, 0, &buf)
	if !errors.Is(err, errNoResume) {
		t.Fatalf("err = %v, want errNoResume", err)
	}
	if buf.Len() != 10 {
		t.Fatalf("writer holds %d bytes; a second full copy must not be appended", buf.Len())
	}
	if hits != 2 {
		t.Fatalf("attempts = %d, want 2 (no retry after a resume refusal)", hits)
	}
}

// Timeout is a stall bound: a slow but flowing transfer longer than Timeout
// succeeds, and one that stops sending bytes fails with the stall named.
func TestDownloadTimeoutIsAStallBound(t *testing.T) {
	// 20 chunks 50 ms apart is 1 s of transfer against a 250 ms timeout: the total
	// exceeds the bound on purpose, while each gap is 5x under it, so a loaded host
	// cannot turn a flowing transfer into a stall.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 20; i++ {
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, Timeout: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := c.Download(context.Background(), "org/name", "slow.bin", 0, 0, &buf)
	if err != nil {
		t.Fatalf("a flowing transfer longer than Timeout failed: %v", err)
	}
	if res.Bytes != 20 || buf.Len() != 20 {
		t.Fatalf("got %d bytes, want 20", buf.Len())
	}
}

func TestDownloadStalledTransferFails(t *testing.T) {
	// This server ignores Range, so the stall cannot be recovered: the error must
	// still name the stall, not only the refused resume.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		time.Sleep(1500 * time.Millisecond)
		w.Write([]byte("y"))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, Timeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, err = c.Download(context.Background(), "org/name", "stall.bin", 0, 0, &buf)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("no data for")) {
		t.Fatalf("err = %v, want a no-data error", err)
	}
}

func TestDownloadRecoversFromStall(t *testing.T) {
	body := body100()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Content-Length", "100")
			w.Write(body[:40])
			w.(http.Flusher).Flush()
			time.Sleep(1500 * time.Millisecond) // 10x Timeout: the transfer stalls
			return
		}
		if got := r.Header.Get("Range"); got != "bytes=40-" {
			t.Errorf("resume Range = %q", got)
		}
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body[40:])
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, Timeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := c.Download(context.Background(), "org/name", "stall.bin", 0, 0, &buf)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), body) || res.Bytes != 100 {
		t.Fatalf("got %d bytes in %d attempts", buf.Len(), hits)
	}
}

func TestModelInfo(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{`{"gated":false,"siblings":[]}`, ""},
		{`{"gated":"auto"}`, "auto"},
		{`{"gated":"manual","disabled":false}`, "manual"},
		{`{"gated":true}`, "auto"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tc.body))
		}))
		c := testClient(t, srv.URL, "")
		info, err := c.ModelInfo(context.Background(), "org/name")
		if err != nil {
			t.Fatalf("%s: %v", tc.body, err)
		}
		if info.Gated != tc.want {
			t.Errorf("%s: gated = %q, want %q", tc.body, info.Gated, tc.want)
		}
		srv.Close()
	}
}

func TestGated403CarriesTheHubMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Error-Message", "Access to model org/name is restricted and you are not in the authorized list. Visit https://huggingface.co/org/name to ask for access.")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	var buf bytes.Buffer
	_, err := c.Download(context.Background(), "org/name", "a.bin", 0, 0, &buf)
	if !errors.Is(err, ErrGated) {
		t.Fatalf("err = %v, want ErrGated", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("huggingface.co/org/name")) {
		t.Fatalf("err = %v, want the Hub's explanation with the URL", err)
	}
}

// TestTopRequestsTheRanking pins the ranked listing: the sort key reaches the
// query string, the direction is most-first, and the metadata the ranking is made
// of is decoded rather than dropped. The sort allowlist is a request-shaping
// boundary, so an unknown key is refused before a request is made.
func TestTopRequestsTheRanking(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/models" {
			t.Errorf("path = %s, want /api/models", r.URL.Path)
		}
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `[{"id":"a/one","downloads":5,"likes":2,"trendingScore":91.5,"lastModified":"2026-10-01T00:00:00.000Z","pipeline_tag":"text-generation"},{"id":"b/two","downloads":1}]`)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.Top(context.Background(), Rank{Sort: SortTrending, Limit: 10})
	if err != nil {
		t.Fatalf("Top: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "a/one" || rows[1].ID != "b/two" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Downloads != 5 || rows[0].Likes != 2 || rows[0].TrendingScore != 91.5 || rows[0].PipelineTag != "text-generation" {
		t.Errorf("metadata not decoded: %+v", rows[0])
	}
	q, err := url.ParseQuery(gotQuery)
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("sort") != "trendingScore" || q.Get("direction") != "-1" || q.Get("limit") != "10" {
		t.Errorf("query = %q, want sort=trendingScore&direction=-1&limit=10", gotQuery)
	}
	if _, err := c.Top(context.Background(), Rank{Sort: "score; drop table"}); err == nil {
		t.Error("an unknown sort key was requested")
	}
}

func TestNewRejectsEmptyHostAndCRLFToken(t *testing.T) {
	for _, bad := range []string{"https://", "https:///api", "http://"} {
		if _, err := New(Config{BaseURL: bad}); err == nil {
			t.Errorf("New(%q) accepted empty host", bad)
		}
	}
	for _, tok := range []string{"abc\r\nX-Injected: 1", "abc\ndef", "abc\rdef"} {
		if _, err := New(Config{BaseURL: "http://127.0.0.1:1", Token: tok}); err == nil {
			t.Errorf("New accepted CRLF token %q", tok)
		}
	}
	c, err := New(Config{BaseURL: "http://127.0.0.1:1", Jobs: 16})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok || tr == nil || tr.MaxIdleConnsPerHost != 16 {
		t.Fatalf("transport MaxIdleConnsPerHost = %v, want 16", tr)
	}
}

func TestRedirectBlocksDowngradeAndStripsAuthOnSchemeChange(t *testing.T) {
	// 1. Non-loopback http redirect must be blocked.
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/leak", http.StatusFound)
	}))
	defer hub.Close()
	c := testClient(t, hub.URL, "tok")
	var buf bytes.Buffer
	if _, err := c.Download(context.Background(), "org/name", "a.bin", 0, 0, &buf); err == nil {
		t.Fatal("redirect to non-loopback http host was followed")
	}

	// 2. HTTPS -> HTTP redirect strips Authorization even on loopback/same-host.
	var httpAuth string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer plain.Close()

	tlsHub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/downgraded", http.StatusFound)
	}))
	defer tlsHub.Close()

	tc, err := New(Config{BaseURL: tlsHub.URL, Token: "secret-tok", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New TLS: %v", err)
	}
	// Trust the httptest TLS certificate while preserving our CheckRedirect.
	tc.dl.Transport = tlsHub.Client().Transport
	buf.Reset()
	if _, err := tc.Download(context.Background(), "org/name", "a.bin", 0, 0, &buf); err != nil {
		t.Fatalf("TLS->loopback HTTP download: %v", err)
	}
	if httpAuth != "" {
		t.Fatalf("Authorization leaked across HTTPS->HTTP redirect: %q", httpAuth)
	}

	// Verify same-host scheme downgrade check directly on CheckRedirect.
	u, _ := url.Parse("http://" + tlsHub.Listener.Addr().String() + "/downgraded")
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer secret-tok")
	viaReq, _ := http.NewRequest(http.MethodGet, tlsHub.URL+"/start", nil)
	if err := tc.dl.CheckRedirect(req, []*http.Request{viaReq}); err != nil {
		t.Fatalf("CheckRedirect loopback: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("same-host HTTPS->HTTP redirect kept Authorization: %q", got)
	}
}

func TestTraversalPathsRejectedWithoutRequest(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "tok")
	ctx := context.Background()

	if _, err := c.Scan(ctx, "org/../admin"); err == nil {
		t.Error("Scan accepted .. segment")
	}
	if _, err := c.Files(ctx, "./org"); err == nil {
		t.Error("Files accepted . segment")
	}
	if _, err := c.ModelInfo(ctx, "org/.."); err == nil {
		t.Error("ModelInfo accepted .. segment")
	}
	var buf bytes.Buffer
	if _, err := c.Download(ctx, "org/name", "../secret", 0, 0, &buf); err == nil {
		t.Error("Download accepted .. file path")
	}
	if hits != 0 {
		t.Fatalf("server received %d requests for invalid traversal paths, want 0", hits)
	}
}

func TestDownload416EmptyFileProbe(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Range", "bytes */0")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	var buf bytes.Buffer
	res, err := c.Download(context.Background(), "org/name", "empty.txt", 0, 1, &buf)
	if err != nil {
		t.Fatalf("Download 416 empty probe: %v", err)
	}
	if res.Bytes != 0 || res.Status != http.StatusRequestedRangeNotSatisfiable || hits != 1 {
		t.Fatalf("res=%+v hits=%d, want 0 bytes, 416, 1 attempt", res, hits)
	}
}

func TestDownloadOffGreaterThanZeroRejects200(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("0123456789abcdef"))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL, "")
	var buf bytes.Buffer
	_, err := c.Download(context.Background(), "org/name", "a.bin", 10, 4, &buf)
	if !errors.Is(err, errNoResume) {
		t.Fatalf("err = %v, want errNoResume", err)
	}
	if buf.Len() != 0 || hits != 1 {
		t.Fatalf("buf=%d hits=%d, want 0 bytes and 1 attempt", buf.Len(), hits)
	}
}

type failWriter struct{ err error }

func (f failWriter) Write(p []byte) (int, error) { return 0, f.err }

func TestDownloadRetryPolicy(t *testing.T) {
	// 429 with Retry-After: 0 retries and succeeds.
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("ok"))
	}))
	c := testClient(t, srv.URL, "")
	var buf bytes.Buffer
	res, err := c.Download(context.Background(), "org/name", "a.bin", 0, 0, &buf)
	srv.Close()
	if err != nil || res.Bytes != 2 || n != 2 {
		t.Fatalf("429 retry: res=%+v err=%v attempts=%d", res, err, n)
	}

	// Permanent 4xx statuses (400, 416 non-empty, 451) must not retry.
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestedRangeNotSatisfiable, http.StatusUnavailableForLegalReasons} {
		var attempts int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			if status == http.StatusRequestedRangeNotSatisfiable {
				w.Header().Set("Content-Range", "bytes */100")
			}
			w.WriteHeader(status)
		}))
		cl := testClient(t, s.URL, "")
		buf.Reset()
		_, err := cl.Download(context.Background(), "org/name", "a.bin", 200, 10, &buf)
		s.Close()
		if err == nil || attempts != 1 {
			t.Errorf("HTTP %d: err=%v attempts=%d, want immediate failure in 1 attempt", status, err, attempts)
		}
	}

	// Local io.Writer error must not retry.
	var wHits int32
	wsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&wHits, 1)
		w.Write([]byte("payload"))
	}))
	defer wsrv.Close()
	diskFull := errors.New("no space left on device")
	wc := testClient(t, wsrv.URL, "")
	_, err = wc.Download(context.Background(), "org/name", "a.bin", 0, 0, failWriter{err: diskFull})
	if !errors.Is(err, diskFull) || wHits != 1 {
		t.Fatalf("write error: err=%v attempts=%d, want diskFull in 1 attempt", err, wHits)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter("5", now); !ok || d != 5*time.Second {
		t.Errorf("parseRetryAfter(5) = %v, %v", d, ok)
	}
	if d, ok := parseRetryAfter("999999999999", now); !ok || d != maxRetryAfter {
		t.Errorf("parseRetryAfter(huge) = %v, %v; want %v", d, ok, maxRetryAfter)
	}
	if d, ok := parseRetryAfter("99999999999999999999999999", now); ok {
		t.Errorf("parseRetryAfter(overflow) = %v, %v; want false", d, ok)
	}
	future := now.Add(15 * time.Second).Format(http.TimeFormat)
	if d, ok := parseRetryAfter(future, now); !ok || d != 15*time.Second {
		t.Errorf("parseRetryAfter(HTTP-date +15s) = %v, %v", d, ok)
	}
	farFuture := now.Add(5 * time.Minute).Format(http.TimeFormat)
	if d, ok := parseRetryAfter(farFuture, now); !ok || d != maxRetryAfter {
		t.Errorf("parseRetryAfter(HTTP-date +5m) = %v, %v; want %v", d, ok, maxRetryAfter)
	}
	past := now.Add(-10 * time.Second).Format(http.TimeFormat)
	if d, ok := parseRetryAfter(past, now); !ok || d != 0 {
		t.Errorf("parseRetryAfter(past HTTP-date) = %v, %v; want 0", d, ok)
	}
}

func TestTokenRejectsNonENOENTAndCRLF(t *testing.T) {
	home := t.TempDir()
	// Make $HF_HOME/token a directory so os.ReadFile fails with EISDIR (non-ENOENT).
	if err := os.Mkdir(filepath.Join(home, "token"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HF_HOME", home)
	t.Setenv("HF_TOKEN", "")
	t.Setenv("HUGGING_FACE_HUB_TOKEN", "")
	if _, err := Token(""); err == nil {
		t.Fatal("Token silently swallowed non-ENOENT error on $HF_HOME/token")
	}

	// Reject embedded CR/LF in env var and file.
	t.Setenv("HF_TOKEN", "bad\r\nX-Injected: 1")
	if _, err := Token(""); err == nil {
		t.Fatal("Token accepted CRLF in HF_TOKEN")
	}
	t.Setenv("HF_TOKEN", "")

	badFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(badFile, []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Token(badFile); err == nil {
		t.Fatal("Token accepted multi-line token file")
	}
}
