package hubapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
		if got := escapePath(tc.in); got != tc.want {
			t.Errorf("escapePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
