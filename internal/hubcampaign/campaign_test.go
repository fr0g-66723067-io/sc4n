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
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
	"github.com/fr0g-66723067-io/sc4n/internal/policy"
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
	// gate maps a repo id to its `gated` value ("auto"/"manual"), served by the
	// metadata endpoint and by every resolve request.
	gate map[string]string
	// ranked, when set, is what the listing endpoint answers for a ranked request
	// (a request that carries sort=), and lastSort records the sort key asked for.
	ranked   []map[string]any
	lastSort string
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/models":
		if sort := r.URL.Query().Get("sort"); sort != "" && h.ranked != nil {
			h.lastSort = sort
			json.NewEncoder(w).Encode(h.ranked)
			return
		}
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
		gated := any(false)
		if g, ok := h.gate[id]; ok {
			gated = g
		}
		json.NewEncoder(w).Encode(map[string]any{"siblings": h.siblings[id], "gated": gated})
	case strings.Contains(r.URL.Path, "/resolve/main/"):
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/resolve/main/", 2)
		if len(parts) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := parts[0] + "/" + parts[1]
		if st, ok := h.status[key]; ok {
			w.Header().Set("X-Error-Message", "Access to model "+parts[0]+" is restricted and you are not in the authorized list. Visit https://huggingface.co/"+parts[0]+" to ask for access.")
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
	// The lead rule is not pinned: a new critical rank reorders the list, and what
	// this test is about is that the pickle rules are among the reported ones.
	if !slices.ContainsFunc(f.Rules, func(s string) bool { return strings.HasPrefix(s, "SC4N-PICKLE") }) {
		t.Errorf("rules = %v, want the pickle rules reported", f.Rules)
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
		gate:     map[string]string{"o/evil": "manual"},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	rep := runAll(t, newOptions(t, srv, dir))
	f := rep.Repos[0].Files[0]
	if f.Fetch != "gated" || f.Coverage != "none" || f.Sc4n != "none" || f.Reason != "gated" {
		t.Fatalf("file = %+v", f)
	}
	ff := readFetchDoc(t, dir).Repos[0].Files[0]
	if !strings.Contains(ff.Detail, "manual approval") || !strings.Contains(ff.Detail, "huggingface.co/o/evil") {
		t.Fatalf("detail = %q, want the manual-approval explanation and the URL", ff.Detail)
	}
	if rep.Repos[0].Status != "gated" {
		t.Errorf("repo status = %q", rep.Repos[0].Status)
	}
	if rep.Totals.NotCovered != 1 || rep.Totals.BySc4n["none"] != 1 {
		t.Errorf("totals = %+v", rep.Totals)
	}
}

// TestGateAutoIsNamed: the two gate modes need different advice, because only one
// of them is the account holder's to resolve.
func TestGateAutoIsNamed(t *testing.T) {
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {sibling("evil.pkl", 30)}},
		status:   map[string]int{"o/evil/evil.pkl": http.StatusForbidden},
		gate:     map[string]string{"o/evil": "auto"},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	for _, stage := range []func(context.Context, Options) error{
		func(c context.Context, o Options) error { _, err := Candidates(c, o); return err },
		func(c context.Context, o Options) error { _, err := Verdicts(c, o); return err },
		func(c context.Context, o Options) error { _, err := Fetch(c, o); return err },
	} {
		if err := stage(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	ff := readFetchDoc(t, dir).Repos[0].Files[0]
	if !strings.Contains(ff.Detail, "automatic approval") || !strings.Contains(ff.Detail, "accept them at") {
		t.Fatalf("detail = %q, want the terms-acceptance advice", ff.Detail)
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

// TestWholeFetchFallsBackToSlice: when the budget cannot admit the whole file but
// can admit the header, the file is fetched as a slice and says so — `budget` is
// reserved for "not even the header was fetched".
func TestWholeFetchFallsBackToSlice(t *testing.T) {
	body := make([]byte, 100<<10)
	copy(body, pickleOSSystem)
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"big.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {sibling("big.pkl", int64(len(body)))}},
		files:    map[string][]byte{"o/evil/big.pkl": body},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.FullLimit = 1 << 20
	o.TotalBudget = 8 << 10
	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Verdicts(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	ff := readFetchDoc(t, dir).Repos[0].Files[0]
	if ff.Status != "slice" || ff.Bytes != 4096 {
		t.Fatalf("file = %+v, want a 4096-byte slice", ff)
	}
	if !strings.Contains(ff.Detail, "header slice") {
		t.Errorf("detail = %q, want the downgrade stated", ff.Detail)
	}
	rep, err := Join(appendScan(t, o))
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if f := rep.Repos[0].Files[0]; f.Coverage != "partial" {
		t.Fatalf("coverage = %q, want partial", f.Coverage)
	}
}

// TestSliceFallbackRespectsRepoBudget: the repo budget is the binding one here, so
// the fallback must consult it too.
func TestSliceFallbackRespectsRepoBudget(t *testing.T) {
	body := make([]byte, 100<<10)
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"big.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {sibling("big.pkl", int64(len(body)))}},
		files:    map[string][]byte{"o/evil/big.pkl": body},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.FullLimit = 1 << 20
	o.RepoBudget = 2048 // smaller than one slice
	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Verdicts(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	ff := readFetchDoc(t, dir).Repos[0].Files[0]
	if ff.Status != "budget" {
		t.Fatalf("file = %+v, want budget when not even a slice fits", ff)
	}
}

// appendScan runs the scan stage, which the join needs.
func appendScan(t *testing.T, o Options) Options {
	t.Helper()
	if _, err := ScanTree(context.Background(), o); err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	return o
}

func TestCandidatesFromRepoList(t *testing.T) {
	dir := t.TempDir()
	o := Options{
		Dir:   dir,
		Tool:  report.Tool{Name: "sc4n", Version: "test"},
		Repos: []string{"a/one", " b/two ", "a/one", "", "c/three"},
	}
	// The list branch must not consult the Hub, so it is exercised with no client:
	// the list is the input, not a search result.
	repos, err := writeListCandidates(o)
	if err != nil {
		t.Fatalf("writeListCandidates: %v", err)
	}
	var ids []string
	for _, r := range repos {
		ids = append(ids, r.ID)
	}
	want := []string{"a/one", "b/two", "c/three"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("ids = %v, want %v (order kept, blanks and duplicates dropped)", ids, want)
	}
	var con CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &con); err != nil {
		t.Fatalf("read candidates.json: %v", err)
	}
	if len(con.Queries) != 1 || con.Queries[0].Kind != "list" || con.Queries[0].Value != listQuery {
		t.Fatalf("queries = %+v, want the one list query", con.Queries)
	}
	if len(con.Repos) != 3 || con.Repos[0].Why[0] != listQuery {
		t.Fatalf("repos = %+v", con.Repos)
	}
}

func TestLevelAnySelectsEveryCandidate(t *testing.T) {
	repos := []RepoVerdict{
		{ID: "a/ok", Status: "ok", ScansDone: true, Files: []hubapi.FileIssue{{Path: "x.bin", Level: "unsafe"}}},
		{ID: "b/unscanned", Status: "unscanned"},
		{ID: "c/gated", Status: "gated", Detail: "manual approval"},
		{ID: "d/error", Status: "error", Detail: "boom"},
	}
	for _, r := range repos {
		if !hasLevel(r, LevelAny) {
			t.Fatalf("%s not selected at level any", r.ID)
		}
	}
	if got := selectedRepos(repos, "unsafe"); len(got) != 1 || got[0].ID != "a/ok" {
		t.Fatalf("unsafe selected %+v, want only a/ok", got)
	}
	if got := selectedRepos(repos, LevelAny); len(got) != len(repos) {
		t.Fatalf("any selected %d of %d", len(got), len(repos))
	}
	if !levelValid("any") {
		t.Fatal("any is not a valid level")
	}
}

func TestListCampaignNeedsNoSearchQuery(t *testing.T) {
	o := Options{Repos: []string{"a/one"}, UseDefaults: false}
	qs, err := o.queries()
	if err != nil {
		t.Fatalf("queries with a repo list: %v", err)
	}
	if len(qs) != 1 || qs[0] != (Sel{Kind: "list", Value: listQuery}) {
		t.Fatalf("queries = %+v, want the one list query", qs)
	}
	// Without a list the default universe is still required.
	if _, err := (Options{UseDefaults: false}).queries(); err == nil {
		t.Fatal("a campaign with no selector and no list was accepted")
	}
}

// TestCoverageTotalsMatchTheTable pins the header line of campaign.md against the
// table under it. The header used to count only files that produced a finding, so
// a campaign of 379 files could say "59 fully covered, 164 partially, 48 not
// covered" — 271 — beside rows that summed to 379. Coverage is a fact about the
// bytes: a file read whole and found clean is fully covered.
func TestCoverageTotalsMatchTheTable(t *testing.T) {
	pkl := []byte(pickleOSSystem)
	readme := []byte("# clean\n\nA model with nothing in it.\n")
	hub := &fakeHub{
		repos: []string{"o/mixed"},
		scans: map[string]string{
			"o/mixed": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{
			"o/mixed": {
				sibling("evil.pkl", int64(len(pkl))),
				sibling("README.md", int64(len(readme))),
			},
		},
		files: map[string][]byte{
			"o/mixed/evil.pkl":  pkl,
			"o/mixed/README.md": readme,
		},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Level = LevelAny
	rep := runAll(t, o)

	tot := rep.Totals
	if tot.Files != 2 {
		t.Fatalf("files = %d, want both rows at level any", tot.Files)
	}
	if tot.CoveredFull != 2 || tot.CoveredPartial != 0 || tot.NotCovered != 0 {
		t.Fatalf("coverage totals = %d full, %d partial, %d none; want 2/0/0",
			tot.CoveredFull, tot.CoveredPartial, tot.NotCovered)
	}
	if sum := tot.CoveredFull + tot.CoveredPartial + tot.NotCovered; sum != tot.Files {
		t.Fatalf("coverage totals sum to %d, want Files=%d", sum, tot.Files)
	}
	md := campaignMarkdown(rep)
	if !strings.Contains(md, "- flagged files: 2 — 2 fully covered, 0 partially, 0 not covered") {
		t.Fatalf("header does not match its table:\n%s", md[:400])
	}
}

// rankedHub is the fake Hub for a ranked campaign: three models with the numbers
// the ordering is made of, each shipping one clean config file, so the campaign
// exercises probe, fetch, scan, join and report with no search terms at all.
func rankedHub(pkl []byte) *fakeHub {
	return &fakeHub{
		ranked: []map[string]any{
			{"id": "a/top", "downloads": 900, "likes": 9, "trendingScore": 900.0, "lastModified": "2026-10-01T00:00:00.000Z", "pipeline_tag": "text-generation"},
			{"id": "b/second", "downloads": 500, "likes": 5, "trendingScore": 500.0},
			{"id": "c/third", "downloads": 100, "likes": 1, "trendingScore": 100.0},
		},
		scans: map[string]string{
			"a/top":    `{"scansDone":true,"filesWithIssues":[]}`,
			"b/second": `{"scansDone":true,"filesWithIssues":[]}`,
			"c/third":  `{"scansDone":true,"filesWithIssues":[]}`,
		},
		siblings: map[string][]map[string]any{
			"a/top":    {sibling("config.json", 2)},
			"b/second": {sibling("config.json", 2)},
			"c/third":  {sibling("config.json", 2)},
		},
		files: map[string][]byte{
			"a/top/config.json":    []byte("{}"),
			"b/second/config.json": []byte("{}"),
			"c/third/config.json":  []byte("{}"),
		},
	}
}

// TestRankUniverse pins -rank/-top: the universe is the Hub's own ordering, the
// rows are cut to Top, the sort key reaches the listing request, candidates.json
// keeps the metadata the ordering was made of, and campaign.md says which ranking
// it used — the difference between a 30-day download count and the recent-window
// trending score is exactly what a reader must not have to guess.
func TestRankUniverse(t *testing.T) {
	hub := rankedHub(nil)
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Queries = nil
	o.UseDefaults = false
	o.Rank = hubapi.SortTrending
	o.Top = 2
	o.Level = LevelAny
	rep := runAll(t, o)

	if hub.lastSort != hubapi.SortTrending {
		t.Fatalf("listing sort = %q, want %q", hub.lastSort, hubapi.SortTrending)
	}
	if rep.Totals.Repos != 2 {
		t.Fatalf("repos = %d, want the top 2", rep.Totals.Repos)
	}
	var cands CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &cands); err != nil {
		t.Fatal(err)
	}
	if len(cands.Repos) != 2 || cands.Repos[0].ID != "a/top" || cands.Repos[1].ID != "b/second" {
		t.Fatalf("candidates = %+v", cands.Repos)
	}
	if len(cands.Repos[0].Why) != 1 || cands.Repos[0].Why[0] != "rank:"+hubapi.SortTrending {
		t.Errorf("why = %v", cands.Repos[0].Why)
	}
	if cands.Rank == nil || cands.Rank.Sort != hubapi.SortTrending {
		t.Fatalf("rank provenance = %+v", cands.Rank)
	}
	// The captured rows are what the Hub said, not what the campaign kept: a
	// ranking that moved is explained by the neighbours.
	if len(cands.Rank.Captured) != 2 {
		t.Fatalf("captured = %d rows", len(cands.Rank.Captured))
	}
	if cands.Rank.Captured[0].Downloads != 900 {
		t.Errorf("metadata not kept: %+v", cands.Rank.Captured[0])
	}
	if rep.Campaign.Rank == nil || rep.Campaign.Rank.Sort != hubapi.SortTrending ||
		rep.Campaign.Rank.Top != 2 || rep.Campaign.Rank.First != "a/top" || rep.Campaign.Rank.Last != "b/second" {
		t.Fatalf("campaign rank = %+v", rep.Campaign.Rank)
	}
	md, err := os.ReadFile(filepath.Join(dir, fileCampaignMD))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "top 2 by trendingScore (the Hub's recent-window ranking)") {
		t.Errorf("campaign.md does not name the ranking:\n%s", md)
	}
}

// TestRankRejectsTwoUniverses: a ranked listing and an explicit list answer
// different questions, and a campaign that silently preferred one would be
// reporting on a set the operator did not ask for.
func TestRankRejectsTwoUniverses(t *testing.T) {
	o := Options{Dir: t.TempDir(), Client: &hubapi.Client{}, Level: "unsafe"}
	o.Rank = hubapi.SortDownloads
	o.Repos = []string{"a/b"}
	if err := o.Validate(); err == nil {
		t.Error("rank + repos was accepted")
	}
	o.Repos = nil
	o.Queries = []Sel{{Kind: "search", Value: "evil"}}
	if err := o.Validate(); err == nil {
		t.Error("rank + search was accepted")
	}
	o.Queries = nil
	o.Top = 5
	if err := o.Validate(); err != nil {
		t.Fatalf("rank + top rejected: %v", err)
	}
	o1 := Options{Dir: t.TempDir(), Client: &hubapi.Client{}, Level: "unsafe", Top: 5}
	if err := o1.Validate(); err == nil {
		t.Error("-top without a universe was accepted")
	}
}

// TestBaselineMakesTheCampaignDifferential runs the same campaign twice: the
// second scan passes the first report as its baseline, so the campaign reports
// what changed and says how much it suppressed. This is the differential that used
// to be computed by hand from two JSON files.
func TestBaselineMakesTheCampaignDifferential(t *testing.T) {
	pkl := []byte(pickleOSSystem)
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {sibling("evil.pkl", int64(len(pkl)))}},
		files:    map[string][]byte{"o/evil/evil.pkl": pkl},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	first := runAll(t, o)
	if c := first.Totals.Findings.Critical; c < 1 {
		t.Fatalf("first run has no critical: %+v", first.Totals.Findings)
	}
	base, err := policy.LoadBaseline(filepath.Join(dir, fileScan))
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	o2 := newOptions(t, srv, dir)
	o2.Baseline = base
	o2.Refresh = true
	second := runAll(t, o2)
	if got := second.Totals.Findings.Critical; got != 0 {
		t.Errorf("second run still reports %d criticals", got)
	}
	if want := severityCount(first.Totals.Findings); second.Totals.Suppressed != want {
		t.Errorf("suppressed = %d, want %d (every finding of the first run)", second.Totals.Suppressed, want)
	}
	md, err := os.ReadFile(filepath.Join(dir, fileCampaignMD))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "already present in the baseline report were suppressed") {
		t.Error("campaign.md does not state the suppression")
	}
}

// TestByRuleSummary is the per-rule table a reviewer triages: counts by rule,
// most first, with the severest severity the rule was seen at.
func TestByRuleSummary(t *testing.T) {
	pkl := []byte(pickleOSSystem)
	hub := &fakeHub{
		repos:    []string{"o/evil"},
		scans:    map[string]string{"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`},
		siblings: map[string][]map[string]any{"o/evil": {sibling("evil.pkl", int64(len(pkl)))}},
		files:    map[string][]byte{"o/evil/evil.pkl": pkl},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	rep := runAll(t, newOptions(t, srv, dir))
	if len(rep.Totals.ByRule) == 0 {
		t.Fatal("no per-rule rows")
	}
	total := 0
	for _, rc := range rep.Totals.ByRule {
		total += rc.Count
		if rc.Rule == "" || rc.Severity == "" {
			t.Errorf("incomplete row %+v", rc)
		}
	}
	want := severityCount(rep.Totals.Findings)
	if total != want {
		t.Errorf("per-rule rows sum to %d, want %d", total, want)
	}
	for i := 1; i < len(rep.Totals.ByRule); i++ {
		if rep.Totals.ByRule[i-1].Count < rep.Totals.ByRule[i].Count {
			t.Fatalf("rows are not sorted by count: %+v", rep.Totals.ByRule)
		}
	}
	if rep.Totals.ByRule[0].Severity != "critical" {
		t.Errorf("first row severity = %q, want the severest", rep.Totals.ByRule[0].Severity)
	}
	md, err := os.ReadFile(filepath.Join(dir, fileCampaignMD))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "## Findings by rule") {
		t.Error("campaign.md has no per-rule table")
	}
}

// TestUniverseChangeBustsTheCache: a campaign directory reused for a different
// question must not answer with the previous listing. -rank trendingScore after
// -rank downloads is the case that matters, because both write candidates.json and
// the second run has no other way to notice.
func TestUniverseChangeBustsTheCache(t *testing.T) {
	hub := rankedHub(nil)
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Queries = nil
	o.UseDefaults = false
	o.Level = LevelAny
	o.Rank = hubapi.SortTrending
	o.Top = 2
	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatalf("Candidates(trending): %v", err)
	}
	var first CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &first); err != nil {
		t.Fatal(err)
	}
	if first.Rank == nil || first.Rank.Sort != hubapi.SortTrending {
		t.Fatalf("first rank = %+v", first.Rank)
	}

	// Same directory, different question: the same two rows in this fixture, but
	// the provenance must be the new sort, and the request must be made again.
	o2 := o
	o2.Rank = hubapi.SortDownloads
	if _, err := Candidates(context.Background(), o2); err != nil {
		t.Fatalf("Candidates(downloads): %v", err)
	}
	var second CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &second); err != nil {
		t.Fatal(err)
	}
	if second.Rank == nil || second.Rank.Sort != hubapi.SortDownloads {
		t.Fatalf("cached universe survived a rank change: %+v", second.Rank)
	}
	if hub.lastSort != hubapi.SortDownloads {
		t.Errorf("last listing sort = %q, want the new sort", hub.lastSort)
	}

	// The same question again is served from the file.
	o2.Top = 3
	if _, err := Candidates(context.Background(), o2); err != nil {
		t.Fatalf("Candidates(top 3): %v", err)
	}
	var third CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &third); err != nil {
		t.Fatal(err)
	}
	// -top is part of the question: raising it from 2 to 3 must widen the set.
	if len(third.Repos) != 3 {
		t.Fatalf("top 3 of a 3-row listing = %d repos, want 3", len(third.Repos))
	}
}

// TestListLabelRecordsHowTheUniverseWasGiven: candidates.json answers "where did
// this set come from", and "-repo" and "-repos-file" are different answers even
// though both carry ids. The label must also not count as a universe change, or a
// campaign re-run with the same ids through a file would recompute needlessly.
func TestListLabelRecordsHowTheUniverseWasGiven(t *testing.T) {
	hub := rankedHub(nil)
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Queries = nil
	o.UseDefaults = false
	o.Level = LevelAny
	o.Repos = []string{"a/top"}
	o.ListLabel = "-repo"
	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	var cands CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &cands); err != nil {
		t.Fatal(err)
	}
	if len(cands.Queries) != 1 || cands.Queries[0].Kind != "list" || cands.Queries[0].Value != "-repo" {
		t.Fatalf("queries = %+v, want list:-repo", cands.Queries)
	}

	// The same ids through a file is the same universe.
	o2 := o
	o2.ListLabel = "-repos-file"
	repos, err := Candidates(context.Background(), o2)
	if err != nil {
		t.Fatalf("Candidates(relabelled): %v", err)
	}
	if len(repos) != 1 || repos[0].ID != "a/top" {
		t.Fatalf("repos = %+v", repos)
	}
	var after CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &after); err != nil {
		t.Fatal(err)
	}
	if after.Queries[0].Value != "-repo" {
		t.Errorf("the label change forced a recompute (value is now %q)", after.Queries[0].Value)
	}
}

// TestDeclaredEmptyFileIsProvenEmpty pins the zero-byte plan. Download treats a
// max of 0 as "no cap", so a sibling declared as 0 bytes took the copy-to-EOF
// branch: the transfer was unbounded, the budget was charged nothing, and a Hub
// that declared 0 while serving a payload was stored and reported as a clean
// zero-byte file. The file is now proved empty with a one-byte probe, and a
// lied-about size is reported instead of stored.
func TestDeclaredEmptyFileIsProvenEmpty(t *testing.T) {
	hub := &fakeHub{
		repos: []string{"o/evil"},
		scans: map[string]string{
			"o/evil": `{"scansDone":true,"filesWithIssues":[{"path":"evil.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{"o/evil": {
			sibling("evil.pkl", 64),
			sibling("lied.txt", 0),
			sibling("empty.txt", 0),
		}},
		files: map[string][]byte{
			"o/evil/evil.pkl":  []byte(pickleOSSystem),
			"o/evil/lied.txt":  bytes.Repeat([]byte("A"), 1<<16),
			"o/evil/empty.txt": {},
		},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Level = LevelAny // a list campaign reviews every fetched file
	rep := runAll(t, o)
	byPath := map[string]FileReport{}
	for _, f := range rep.Repos[0].Files {
		byPath[f.Path] = f
	}
	if got := byPath["lied.txt"].Fetch; got != "size-mismatch" {
		t.Fatalf("lied.txt fetch = %q, want size-mismatch", got)
	}
	if _, err := os.Stat(filepath.Join(dir, dirRepos, "o", "evil", "lied.txt")); err == nil {
		t.Fatal("a file the Hub declared empty but served content for was stored")
	}
	if got := byPath["empty.txt"].Fetch; got != "full" {
		t.Fatalf("empty.txt fetch = %q, want full", got)
	}
	st, err := os.Stat(filepath.Join(dir, dirRepos, "o", "evil", "empty.txt"))
	if err != nil || st.Size() != 0 {
		t.Fatalf("empty.txt: stat=%v err=%v, want a zero-byte file", st, err)
	}
}

// TestJoinAttributesAColonNamedFile pins the attribution for a fetched file whose
// own name contains ':'. The artifact path was cut at the first ':' before the
// fetched set was consulted, so the finding landed on a top path that was never
// fetched and the real row reported sc4n: none — a false clean for exactly the
// file that had the finding.
func TestJoinAttributesAColonNamedFile(t *testing.T) {
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
	const file = "a:b.bin"
	must(fileVerdicts, VerdictsFile{Version: Version, Level: "unsafe", Repos: []RepoVerdict{{
		ID: "o/evil", Status: "ok", ScansDone: true,
		Files: []hubapi.FileIssue{{Path: file, Level: "unsafe"}},
	}}})
	must(fileFetch, FetchDoc{Version: Version, Level: "unsafe", Repos: []RepoFetch{{
		ID: "o/evil", Status: "ok", Bytes: 10,
		Files: []FetchFile{{Path: file, Status: "full", Bytes: 10}},
	}}})
	must(fileScan, map[string]any{
		"findings": []map[string]any{
			{"artifact": "o/evil/a:b.bin:archive/data.pkl", "ruleId": "SC4N-PICKLE-REDUCE", "severity": "critical"},
		},
		"artifacts": []map[string]any{{"path": file, "format": "zip"}},
	})

	rep, err := Join(o)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if len(rep.Repos[0].Files) != 1 {
		t.Fatalf("rows = %+v, want the one fetched file", rep.Repos[0].Files)
	}
	f := rep.Repos[0].Files[0]
	if f.Path != file || f.Sc4n != "critical" || f.Member != "o/evil/a:b.bin:archive/data.pkl" {
		t.Fatalf("file = %+v", f)
	}
}

func TestFetchUnknownSizeAndBudgetRefund(t *testing.T) {
	bodySmall := []byte(pickleOSSystem)
	bodyNext := bytes.Repeat([]byte("B"), 2048)
	hub := &fakeHub{
		repos: []string{"o/unknown"},
		scans: map[string]string{
			"o/unknown": `{"scansDone":true,"filesWithIssues":[{"path":"small.pkl","level":"unsafe"}]}`,
		},
		siblings: map[string][]map[string]any{
			"o/unknown": {
				{"rfilename": "small.pkl"}, // size omitted -> -1
				sibling("gated.bin", 3000),
				sibling("missing.bin", 3000),
				sibling("next.bin", int64(len(bodyNext))),
				sibling(".gitattributes", 12),
			},
		},
		status: map[string]int{
			"o/unknown/gated.bin":   http.StatusForbidden,
			"o/unknown/missing.bin": http.StatusNotFound,
		},
		files: map[string][]byte{
			"o/unknown/small.pkl":      bodySmall,
			"o/unknown/next.bin":       bodyNext,
			"o/unknown/.gitattributes": []byte("*.bin filter"),
		},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Level = LevelAny
	o.SliceSize = 4096
	// Total budget can only fit small.pkl + .gitattributes + next.bin if unused
	// reservations from small.pkl (4096 - len(bodySmall)), gated.bin (3000), and
	// missing.bin (3000) are refunded.
	o.RepoBudget = 4096
	o.TotalBudget = 4096

	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Verdicts(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}

	fd := readFetchDoc(t, dir)
	if len(fd.Repos) != 1 {
		t.Fatalf("repos = %+v", fd.Repos)
	}
	if fd.Repos[0].Status != "partial" {
		t.Fatalf("repo status = %q, want partial", fd.Repos[0].Status)
	}
	byPath := map[string]FetchFile{}
	for _, ff := range fd.Repos[0].Files {
		byPath[ff.Path] = ff
	}
	if ff := byPath["small.pkl"]; ff.Status != "full" || ff.Bytes != int64(len(bodySmall)) {
		t.Fatalf("unknown-size small.pkl = %+v, want full with %d bytes", ff, len(bodySmall))
	}
	if ff := byPath["next.bin"]; ff.Status != "full" || ff.Bytes != int64(len(bodyNext)) {
		t.Fatalf("next.bin = %+v, want full (budget refunded from gated/missing/unknown-size)", ff)
	}
	if ff, ok := byPath[".gitattributes"]; !ok || ff.Status != "full" {
		t.Fatalf(".gitattributes = %+v (present=%v), want fetched full", ff, ok)
	}
}

func TestFetchMixedFetchedAndGatedIsPartial(t *testing.T) {
	hub := &fakeHub{
		repos: []string{"o/mixed"},
		scans: map[string]string{
			"o/mixed": `{"scansDone":true,"filesWithIssues":[]}`,
		},
		siblings: map[string][]map[string]any{
			"o/mixed": {
				sibling("ok.txt", 4),
				sibling("secret.bin", 10),
			},
		},
		status: map[string]int{"o/mixed/secret.bin": http.StatusForbidden},
		files:  map[string][]byte{"o/mixed/ok.txt": []byte("good")},
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Level = LevelAny
	if _, err := Candidates(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Verdicts(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if got := readFetchDoc(t, dir).Repos[0].Status; got != "partial" {
		t.Fatalf("mixed fetched+gated repo status = %q, want partial", got)
	}
}

func TestCrossStageCacheStaleness(t *testing.T) {
	pkl := []byte(pickleOSSystem)
	hub := rankedHub(pkl)
	hub.files["a/top/evil.pkl"] = pkl
	hub.siblings["a/top"] = append(hub.siblings["a/top"], sibling("evil.pkl", int64(len(pkl))))
	srv := httptest.NewServer(hub)
	defer srv.Close()

	dir := t.TempDir()
	o := newOptions(t, srv, dir)
	o.Queries = nil
	o.UseDefaults = false
	o.Rank = hubapi.SortDownloads
	o.Top = 2
	o.Level = LevelAny

	// 1. Run with Top=2.
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("Run 1: %v", err)
	}

	// 2. Switching Top=2 -> Top=0 ("all rows up to Limit") must bust candidates cache
	// AND verdicts cache (candidate repo set changed from 2 to 3).
	o2 := o
	o2.Top = 0
	cands, err := Candidates(context.Background(), o2)
	if err != nil {
		t.Fatalf("Candidates(Top=0): %v", err)
	}
	if len(cands) != 3 {
		t.Fatalf("Top=0 after Top=2 got %d candidates, want 3", len(cands))
	}
	vs, err := Verdicts(context.Background(), o2)
	if err != nil {
		t.Fatalf("Verdicts after candidate change: %v", err)
	}
	if len(vs) != 3 {
		t.Fatalf("Verdicts reused stale 2-repo cache; got %d, want 3", len(vs))
	}

	// 3. Top > len(Hub rows) should cache cleanly on repeat without thrashing.
	o3 := o
	o3.Top = 10
	if _, err := Candidates(context.Background(), o3); err != nil {
		t.Fatalf("Candidates(Top=10): %v", err)
	}
	var cached CandidatesFile
	if err := readJSON(filepath.Join(dir, fileCandidates), &cached); err != nil {
		t.Fatal(err)
	}
	if why := universeDiff(cached, o3.withDefaults()); why != "" {
		t.Fatalf("universeDiff(Top=10 with 3 rows) = %q, want empty (cache hit)", why)
	}

	// 4. ScanTree cache must bust when Baseline changes without -refresh.
	base, err := policy.LoadBaseline(filepath.Join(dir, fileScan))
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	oBase := o
	oBase.Baseline = base
	oBase.Refresh = false
	sr, err := ScanTree(context.Background(), oBase)
	if err != nil {
		t.Fatalf("ScanTree with baseline: %v", err)
	}
	if sr.BySeverity[report.SeverityCritical] != 0 {
		t.Fatalf("ScanTree reused un-baselined cache: critical=%d", sr.BySeverity[report.SeverityCritical])
	}
}

func TestJoinHubLevelSeverityTopPathAndWindowsSlashes(t *testing.T) {
	dir := t.TempDir()
	o := Options{Dir: dir, Tool: report.Tool{Name: "sc4n", Version: "test"}, Level: LevelAny, Limit: 10}
	must := func(name string, v any) {
		t.Helper()
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			t.Fatal(err)
		}
	}
	must(fileVerdicts, VerdictsFile{Version: Version, Level: LevelAny, Repos: []RepoVerdict{{
		ID: "o/evil", Status: "ok", ScansDone: true,
		Files: []hubapi.FileIssue{
			{Path: "a:b.bin", Level: "caution"},
			{Path: "a:b.bin", Level: "unsafe"},
			{Path: "a:b.bin", Level: "suspicious"},
			{Path: "a", Level: "error"},
		},
	}}})
	must(fileFetch, FetchDoc{Version: Version, Level: LevelAny, Repos: []RepoFetch{{
		ID: "o/evil", Status: "ok",
		Files: []FetchFile{
			{Path: "a", Status: "full", Bytes: 1},
			{Path: "a:b.bin", Status: "full", Bytes: 10},
		},
	}}})
	must(fileScan, map[string]any{
		"findings": []map[string]any{
			{"artifact": `o\evil\a:b.bin:archive/data.pkl`, "ruleId": "SC4N-PICKLE-REDUCE", "severity": "critical"},
		},
		"artifacts": []map[string]any{
			{"path": `o\evil\a`, "format": "text"},
			{"path": `o\evil\a:b.bin`, "format": "zip"},
		},
	})
	rep, err := Join(o)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	byPath := map[string]FileReport{}
	for _, f := range rep.Repos[0].Files {
		byPath[f.Path] = f
	}
	if got := byPath["a:b.bin"]; got.HF != "unsafe" || got.Sc4n != "critical" || got.Format != "zip" {
		t.Fatalf("a:b.bin = %+v, want HF=unsafe Sc4n=critical Format=zip", got)
	}
	if got := byPath["a"]; got.Sc4n != "none" {
		t.Fatalf("a = %+v, want finding attributed to longest match a:b.bin instead", got)
	}
}

func TestPrefixBaselinePreservesContainerMemberPath(t *testing.T) {
	base := t.TempDir()
	k := "SC4N-PICKLE-REDUCE\x00o/evil/model.bin:archive/../data.pkl\x00ev"
	got := prefixBaseline(base, map[string]bool{k: true})
	want := "SC4N-PICKLE-REDUCE\x00" + filepath.Join(base, "o", "evil", "model.bin") + ":archive/../data.pkl\x00ev"
	if !got[want] {
		t.Fatalf("prefixBaseline = %v, want key %q", got, want)
	}
}

func TestVerdictsCancellationDoesNotWritePoisonedFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, fileCandidates), CandidatesFile{
		Version: Version,
		Repos:   []Candidate{{ID: "o/one"}, {ID: "o/two"}},
	}); err != nil {
		t.Fatal(err)
	}
	c, err := hubapi.New(hubapi.Config{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := Options{Dir: dir, Client: c, Queries: []Sel{{Kind: "search", Value: "x"}}}
	if _, err := Verdicts(ctx, o); err == nil {
		t.Fatal("Verdicts succeeded on cancelled context")
	}
	if _, err := os.Stat(filepath.Join(dir, fileVerdicts)); err == nil {
		t.Fatal("cancelled Verdicts wrote a poisoned verdicts.json")
	}
}

func TestCampaignMarkdownEscapesTableCells(t *testing.T) {
	rep := &CampaignReport{
		Campaign: CampaignInfo{Level: "unsafe", Queries: map[string][]string{}},
		Totals:   Totals{BySc4n: map[string]int{}},
		Repos: []RepoReport{{
			ID:     "o/a|b\nc",
			Status: "ok",
			Files:  []FileReport{{Path: "x|y\nz.pkl", Sc4n: "none", Reason: "no-findings", Format: "pickle"}},
			Extras: []ExtraReport{{Path: "e|f\ng.pkl", Sc4n: "high", Rules: []string{"R|1"}}},
			Sc4n:   RepoSc4n{BySeverity: map[string]int{}},
		}},
	}
	md := campaignMarkdown(rep)
	if !strings.Contains(md, `| o/a\|b c |`) {
		t.Errorf("repo cell not escaped:\n%s", md)
	}
	if !strings.Contains(md, `| x\|y z.pkl |`) {
		t.Errorf("miss file cell not escaped:\n%s", md)
	}
	if !strings.Contains(md, `| e\|f g.pkl |`) {
		t.Errorf("extra file cell not escaped:\n%s", md)
	}
}
