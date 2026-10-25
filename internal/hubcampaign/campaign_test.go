package hubcampaign

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// pickleOSSystem is a minimal protocol-0 pickle: GLOBAL os.system, one string
// argument, REDUCE. It is the shape the pickle rules call critical.
const pickleOSSystem = "cos\nsystem\n(S'id'\ntR."

type fakeHub struct {
	repos    []string
	scans    map[string]string
	siblings map[string][]map[string]any
	files    map[string][]byte
	status   map[string]int // "id/path" -> HTTP status to answer with
	slice    int
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/models":
		var out []map[string]string
		for _, id := range h.repos {
			out = append(out, map[string]string{"id": id})
		}
		json.NewEncoder(w).Encode(out)
	case strings.HasSuffix(r.URL.Path, "/scan") && strings.HasPrefix(r.URL.Path, "/api/models/"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/models/"), "/scan")
		body, ok := h.scans[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, body)
	case strings.HasPrefix(r.URL.Path, "/api/models/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/models/")
		json.NewEncoder(w).Encode(map[string]any{"siblings": h.siblings[id]})
	case strings.Contains(r.URL.Path, "/resolve/main/"):
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/resolve/main/", 2)
		if len(parts) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := parts[0] + "/" + parts[1]
		if st, ok := h.status[key]; ok {
			w.WriteHeader(st)
			return
		}
		body, ok := h.files[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if rg := r.Header.Get("Range"); rg != "" && strings.HasPrefix(rg, "bytes=0-") {
			n, err := strconv.Atoi(strings.TrimPrefix(rg, "bytes=0-"))
			if err == nil && n+1 < len(body) {
				w.WriteHeader(http.StatusPartialContent)
				w.Write(body[:n+1])
				return
			}
		}
		w.Write(body)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func sibling(path string, size int64) map[string]any {
	return map[string]any{"rfilename": path, "size": size}
}

func newOptions(t *testing.T, srv *httptest.Server, dir string) Options {
	t.Helper()
	c, err := hubapi.New(hubapi.Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("hubapi.New: %v", err)
	}
	return Options{
		Dir:          dir,
		Tool:         report.Tool{Name: "sc4n", Version: "test"},
		Client:       c,
		Queries:      []Sel{{Kind: "search", Value: "evil"}},
		Limit:        10,
		Jobs:         2,
		FullLimit:    1 << 20,
		FlaggedLimit: 1 << 20,
		SliceSize:    4096,
		Stderr:       io.Discard,
	}
}

func runAll(t *testing.T, o Options) *CampaignReport {
	t.Helper()
	ctx := context.Background()
	if err := Run(ctx, o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep, err := Load(o)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rep
}

// TestRoundTrip is the whole campaign against a fake Hub: one repo the Hub calls
// unsafe, a pickle that sc4n calls critical, and a file too large to fetch whole.
func TestRoundTrip(t *testing.T) {
	pkl := []byte(pickleOSSystem)
	readme := []byte("# evil\n\nA model that does not exist.\n")
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{
			"o/evil": {
				sibling("evil.pkl", int64(len(pkl))),
				sibling("README.md", int64(len(readme))),
				sibling("big.bin", 100<<20),
			},
		},
		files: map[string][]byte{
			"o/evil/evil.pkl":  pkl,
			"o/evil/README.md": readme,
			"o/evil/big.bin":   bytes.Repeat([]byte{0}, 4096),
		},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	rep := runAll(t, newOptions(t, srv, dir))

	if len(rep.Repos) != 1 {
		t.Fatalf("repos = %+v", rep.Repos)
	}
	r := rep.Repos[0]
	if r.ID != "o/evil" || r.Status != "ok" {
		t.Fatalf("repo = %+v", r)
	}
	if len(r.Files) != 1 {
		t.Fatalf("files = %+v, want only the flagged one", r.Files)
	}
	f := r.Files[0]
	if f.Path != "evil.pkl" || f.HF != "unsafe" || f.Fetch != "full" || f.Coverage != "full" {
		t.Fatalf("file = %+v", f)
	}
	if f.Sc4n != "critical" {
		if b, err := os.ReadFile(filepath.Join(dir, fileScan)); err == nil {
			t.Logf("scan.json:\n%s", b)
		}
		t.Fatalf("sc4n = %q, want critical (rules %v)", f.Sc4n, f.Rules)
	}
	if f.Reason != "" {
		t.Errorf("reason = %q on a file with findings", f.Reason)
	}
	if len(f.Rules) == 0 || !strings.HasPrefix(f.Rules[0], "SC4N-PICKLE") {
		t.Errorf("rules = %v, want the pickle rules first", f.Rules)
	}
	if rep.Totals.Repos != 1 || rep.Totals.Files != 1 || rep.Totals.CoveredFull != 1 || rep.Totals.NotCovered != 0 {
		t.Fatalf("totals = %+v", rep.Totals)
	}
	if rep.Totals.Findings.Critical < 1 {
		t.Errorf("findings totals = %+v", rep.Totals.Findings)
	}

	// big.bin is not flagged, so it is not a row, but the fetch record proves it
	// was sliced rather than skipped.
	fd := readFetchDoc(t, dir)
	if len(fd.Repos) != 1 || len(fd.Repos[0].Files) != 3 {
		t.Fatalf("fetch = %+v", fd)
	}
	byPath := map[string]FetchFile{}
	for _, ff := range fd.Repos[0].Files {
		byPath[ff.Path] = ff
	}
	if byPath["big.bin"].Status != "slice" || byPath["big.bin"].Bytes != 4096 {
		t.Errorf("big.bin = %+v, want a 4096-byte slice", byPath["big.bin"])
	}
	if byPath["evil.pkl"].Status != "full" || byPath["evil.pkl"].Bytes != int64(len(pkl)) {
		t.Errorf("evil.pkl = %+v", byPath["evil.pkl"])
	}

	md, err := os.ReadFile(filepath.Join(dir, fileCampaignMD))
	if err != nil {
		t.Fatalf("campaign.md: %v", err)
	}
	if !strings.Contains(string(md), "| o/evil | ok | 1 |") {
		t.Errorf("campaign.md has no repo row:\n%s", md)
	}
}

// TestUnsafePathsAreNeverWritten covers the traversal names the real round met.
func TestUnsafePathsAreNeverWritten(t *testing.T) {
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{
			"o/evil": {
				sibling("../../etc/passwd", 10),
				sibling("sub/../x", 10),
				sibling("a\x00b", 10),
				sibling("evil.pkl", 10),
			},
		},
		files: map[string][]byte{"o/evil/evil.pkl": []byte(pickleOSSystem)},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if _, err := Verdicts(context.Background(), o); err != nil {
		t.Fatalf("Verdicts: %v", err)
	}
	if _, err := Fetch(context.Background(), o); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	fd := readFetchDoc(t, dir)
	got := map[string]string{}
	for _, f := range fd.Repos[0].Files {
		got[f.Path] = f.Status
	}
	for _, p := range []string{"../../etc/passwd", "sub/../x", "a\x00b"} {
		if got[p] != "unsafe-path" {
			t.Errorf("%q status = %q, want unsafe-path", p, got[p])
		}
	}
	// Nothing may exist outside the campaign directory.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "etc", "passwd")); err == nil {
		t.Fatal("a traversal path was written outside the campaign directory")
	}
	var written []string
	filepath.Walk(filepath.Join(dir, dirRepos), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			written = append(written, p)
		}
		return nil
	})
	if len(written) != 1 || !strings.HasSuffix(written[0], "evil.pkl") {
		t.Fatalf("written files = %v, want only the pickle", written)
	}
}

// TestGatedIsRecorded: a 403 is coverage "none" with reason "gated", never a
// silent skip.
func TestGatedIsRecorded(t *testing.T) {
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {sibling("evil.pkl", 30)}},
		status:   map[string]int{"o/evil/evil.pkl": http.StatusForbidden},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	rep := runAll(t, newOptions(t, srv, dir))
	f := rep.Repos[0].Files[0]
	if f.Fetch != "gated" || f.Coverage != "none" || f.Sc4n != "none" || f.Reason != "gated" {
		t.Fatalf("file = %+v", f)
	}
	if rep.Repos[0].Status != "gated" {
		t.Errorf("repo status = %q", rep.Repos[0].Status)
	}
	if rep.Totals.NotCovered != 1 || rep.Totals.BySc4n["none"] != 1 {
		t.Errorf("totals = %+v", rep.Totals)
	}
}

// TestJoinMemberAttribution: the worst finding inside a container names the member
// path, not just the file.
func TestJoinMemberAttribution(t *testing.T) {
	dir := t.TempDir()
	o := Options{
		Dir:   dir,
		Tool:  report.Tool{Name: "sc4n", Version: "test"},
		Level: "unsafe",
		Limit: 10,
	}
	must := func(name string, v any) {
		t.Helper()
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	must(fileVerdicts, VerdictsFile{Version: Version, Level: "unsafe", Repos: []RepoVerdict{{
		ID: "o/evil", Status: "ok", ScansDone: true,
		Files: []hubapi.FileIssue{{Path: "pytorch_model.bin", Level: "unsafe"}},
	}}})
	must(fileFetch, FetchDoc{Version: Version, Level: "unsafe", Repos: []RepoFetch{{
		ID: "o/evil", Status: "ok", Bytes: 10,
		Files: []FetchFile{{Path: "pytorch_model.bin", Status: "full", Bytes: 10}},
	}}})
	must(fileScan, map[string]any{
		"findings": []map[string]any{
			{"artifact": "o/evil/pytorch_model.bin:archive/data.pkl", "ruleId": "SC4N-PICKLE-REDUCE", "severity": "critical"},
			{"artifact": "o/evil/README.md", "ruleId": "SC4N-STRING-LOADER-FLAG", "severity": "high"},
		},
		"artifacts": []map[string]any{
			{"path": "o/evil/pytorch_model.bin", "format": "zip"},
			{"path": "o/evil/README.md", "format": "markdown"},
		},
	})

	rep, err := Join(o)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	f := rep.Repos[0].Files[0]
	if f.Sc4n != "critical" || f.Member != "o/evil/pytorch_model.bin:archive/data.pkl" {
		t.Fatalf("file = %+v", f)
	}
	if f.Format != "zip" {
		t.Errorf("format = %q", f.Format)
	}
	if len(rep.Repos[0].Extras) != 1 || rep.Repos[0].Extras[0].Path != "README.md" || rep.Repos[0].Extras[0].Sc4n != "high" {
		t.Fatalf("extras = %+v, want the README as the recall signal", rep.Repos[0].Extras)
	}
	if rep.Totals.CoveredFull != 1 || rep.Totals.Findings.Critical != 1 || rep.Totals.Findings.Max != "critical" {
		t.Fatalf("totals = %+v", rep.Totals)
	}
}

// TestReportDeterministic: the same inputs must produce the same bytes, or the
// report cannot be compared across runs.
func TestReportDeterministic(t *testing.T) {
	dir := t.TempDir()
	o := Options{Dir: dir, Tool: report.Tool{Name: "sc4n", Version: "test"}, Level: "unsafe", Limit: 10}
	must := func(name string, v any) {
		t.Helper()
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	must(fileVerdicts, VerdictsFile{Version: Version, Level: "unsafe", Repos: []RepoVerdict{
		{ID: "o/b", Status: "ok", ScansDone: true, Files: []hubapi.FileIssue{{Path: "b.bin", Level: "unsafe"}}},
		{ID: "o/a", Status: "ok", ScansDone: true, Files: []hubapi.FileIssue{{Path: "a.bin", Level: "unsafe"}}},
	}})
	must(fileFetch, FetchDoc{Version: Version, Level: "unsafe", Repos: []RepoFetch{
		{ID: "o/b", Status: "ok", Files: []FetchFile{{Path: "b.bin", Status: "full", Bytes: 3}}},
		{ID: "o/a", Status: "ok", Files: []FetchFile{{Path: "a.bin", Status: "full", Bytes: 3}}},
	}})
	must(fileScan, map[string]any{
		"findings": []map[string]any{
			{"artifact": "o/a/a.bin", "ruleId": "SC4N-LIMIT-CAP", "severity": "info"},
			{"artifact": "o/a/a.bin", "ruleId": "SC4N-UNICODE-ANOMALY", "severity": "medium"},
			{"artifact": "o/a/a.bin", "ruleId": "SC4N-STRING-C2", "severity": "high"},
		},
		"artifacts": []map[string]any{{"path": "o/a/a.bin", "format": "text"}, {"path": "o/b/b.bin", "format": "text"}},
	})

	rep, err := Join(o)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	dir2 := t.TempDir()
	o2 := o
	o2.Dir = dir2
	if err := Report(o, rep); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if err := Report(o2, rep); err != nil {
		t.Fatalf("Report: %v", err)
	}
	a, err := os.ReadFile(filepath.Join(dir, fileCampaign))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir2, fileCampaign))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("campaign.json differs between runs:\n%s\n---\n%s", a, b)
	}
	mdA, _ := os.ReadFile(filepath.Join(dir, fileCampaignMD))
	mdB, _ := os.ReadFile(filepath.Join(dir2, fileCampaignMD))
	if !bytes.Equal(mdA, mdB) {
		t.Fatal("campaign.md differs between runs")
	}
}

// TestBudgetRefusalIsReported: a campaign budget smaller than the first flagged
// file reports the file as uncovered, with the reason.
func TestBudgetRefusalIsReported(t *testing.T) {
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {sibling("evil.pkl", 64)}},
		files:    map[string][]byte{"o/evil/evil.pkl": []byte(pickleOSSystem)},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.TotalBudget = 4
	rep := runAll(t, o)
	f := rep.Repos[0].Files[0]
	if f.Fetch != "budget" || f.Coverage != "none" || f.Reason != "budget" {
		t.Fatalf("file = %+v", f)
	}
	if rep.Totals.NotCovered != 1 {
		t.Fatalf("totals = %+v", rep.Totals)
	}
	if _, err := os.Stat(filepath.Join(dir, dirRepos, "o", "evil", "evil.pkl")); err == nil {
		t.Fatal("a refused file was written")
	}
}

// TestFetchRefusesMismatchedLevel: the selection is a property of the verdict
// file, so a level change is an error naming the stage to re-run.
func TestFetchRefusesMismatchedLevel(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, fileVerdicts), VerdictsFile{
		Version: Version, Level: "unsafe",
		Repos: []RepoVerdict{{ID: "o/evil", Status: "ok"}},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := hubapi.New(hubapi.Config{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Fetch(context.Background(), Options{Dir: dir, Client: c, Level: "caution", Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "-stage verdicts") {
		t.Fatalf("err = %v, want a re-run-verdicts error", err)
	}
}

// TestMissingStageNamesTheOneToRun keeps the resume path discoverable.
func TestMissingStageNamesTheOneToRun(t *testing.T) {
	dir := t.TempDir()
	c, err := hubapi.New(hubapi.Config{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Dir: dir, Client: c, Stderr: io.Discard}
	for _, tc := range []struct {
		name string
		fn   func() error
		want string
	}{
		{"verdicts", func() error { _, err := Verdicts(context.Background(), o); return err }, "candidates"},
		{"fetch", func() error { _, err := Fetch(context.Background(), o); return err }, "verdicts"},
		{"join", func() error { _, err := Join(o); return err }, "verdicts"},
		{"scan", func() error { _, err := ScanTree(context.Background(), o); return err }, "fetch"},
	} {
		err := tc.fn()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want a hint naming %s", tc.name, err, tc.want)
		}
	}
}

// TestSafeFilePath is the traversal guard on its own, including the encoded forms
// the round met.
func TestSafeFilePath(t *testing.T) {
	good := []string{"README.md", "sub/a b.bin", "a.b/c.d", "100%.txt"}
	bad := []string{
		"", "/etc/passwd", "../x", "a/../b", "a//b", "a\x00b",
		"sub/..%00/test7.txt", "%2e%2e/%2e%2e/etc/traversal.txt", "a\\b",
	}
	for _, p := range good {
		if _, ok := safeFilePath(p); !ok {
			t.Errorf("%q rejected", p)
		}
	}
	for _, p := range bad {
		if _, ok := safeFilePath(p); ok {
			t.Errorf("%q accepted", p)
		}
	}
}

// TestHumanBytes keeps the progress formatting honest at the boundaries.
func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{0, "0B"},
		{1023, "1023B"},
		{1024, "1.0KiB"},
		{1 << 20, "1.0MiB"},
		{6 << 30, "6.0GiB"},
	} {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func readFetchDoc(t *testing.T, dir string) FetchDoc {
	t.Helper()
	var fd FetchDoc
	if err := readJSON(filepath.Join(dir, fileFetch), &fd); err != nil {
		t.Fatalf("fetch.json: %v", err)
	}
	return fd
}

var _ = fmt.Sprintf

// TestJoinRefusesStaleStages: a verdict file recomputed alone leaves a repo
// selected but never fetched, and the report would under-count coverage silently.
func TestJoinRefusesStaleStages(t *testing.T) {
	dir := t.TempDir()
	o := Options{Dir: dir, Level: "unsafe", Limit: 10, Stderr: io.Discard}
	if err := writeJSON(filepath.Join(dir, fileVerdicts), VerdictsFile{Version: Version, Level: "unsafe", Repos: []RepoVerdict{
		{ID: "o/one", Status: "ok", Files: []hubapi.FileIssue{{Path: "a", Level: "unsafe"}}},
		{ID: "o/two", Status: "ok", Files: []hubapi.FileIssue{{Path: "b", Level: "unsafe"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, fileFetch), FetchDoc{Version: Version, Level: "unsafe", Repos: []RepoFetch{
		{ID: "o/one", Status: "ok"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, fileScan), map[string]any{"findings": []any{}, "artifacts": []any{}}); err != nil {
		t.Fatal(err)
	}
	_, err := Join(o)
	if err == nil || !strings.Contains(err.Error(), "o/two") || !strings.Contains(err.Error(), "-stage fetch") {
		t.Fatalf("err = %v, want a stale-fetch error naming o/two", err)
	}
}
