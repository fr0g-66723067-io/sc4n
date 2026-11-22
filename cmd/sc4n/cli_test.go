package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.bin"), []byte{0x00, 0x11, 0x22}, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitUsage},
		{"unknown command", []string{"nope"}, exitUsage},
		{"scan without a path", []string{"scan"}, exitUsage},
		{"unknown flag", []string{"scan", "-nope", dir}, exitUsage},
		{"negative max-depth", []string{"scan", "-max-depth", "-1", dir}, exitUsage},
		{"bad size", []string{"scan", "-max-ratio", "abc", dir}, exitUsage},
		{"bad output format", []string{"scan", "-format", "xml", dir}, exitUsage},
		{"attestation that is not JSON", []string{"scan", "-attestation", filepath.Join(dir, "a.txt"), dir}, exitUsage},
		{"attestation that is absent", []string{"scan", "-attestation", filepath.Join(dir, "absent.json"), dir}, exitUsage},
		{"missing path", []string{"scan", filepath.Join(dir, "absent")}, exitUnreadable},
		{"clean scan", []string{"scan", dir}, exitClean},
		{"hub without -out", []string{"hub"}, exitUsage},
		{"hub bad stage", []string{"hub", "-out", dir, "-stage", "nope"}, exitUsage},
		{"hub bad level", []string{"hub", "-out", dir, "-level", "nope"}, exitUsage},
		{"hub bad fail-on", []string{"hub", "-out", dir, "-fail-on", "bogus"}, exitUsage},
		{"hub bad size", []string{"hub", "-out", dir, "-slice", "abc"}, exitUsage},
		{"hub stray argument", []string{"hub", "-out", dir, "extra"}, exitUsage},
		{"help", []string{"help"}, exitClean},
		{"version", []string{"version"}, exitClean},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tc.args, &out, &errOut); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d (stderr: %s)", tc.args, got, tc.want, errOut.String())
			}
		})
	}
}

// TestHubCandidatesStage drives one stage against a fake Hub, which is the whole
// point of the stage split: a campaign can be resumed one stage at a time.
func TestHubCandidatesStage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("search"); got != "evil" {
			t.Errorf("search = %q", got)
		}
		w.Write([]byte(`[{"id":"o/evil"}]`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"hub", "-out", dir, "-stage", "candidates", "-defaults=false",
		"-search", "evil", "-api", srv.URL}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "candidates.json"))
	if err != nil {
		t.Fatalf("candidates.json: %v", err)
	}
	if !bytes.Contains(b, []byte(`"o/evil"`)) || !bytes.Contains(b, []byte(`search:evil`)) {
		t.Fatalf("candidates.json = %s", b)
	}
	if !strings.Contains(errOut.String(), "candidates: 1 repos") {
		t.Errorf("stderr = %q, want the stage progress line", errOut.String())
	}
}

func TestScanJSONIsByteIdenticalAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.pkl"), []byte("\x80\x04N."), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cfg.json"), []byte(`{"model_type":"bert"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	runOnce := func() string {
		var out, errOut bytes.Buffer
		if code := run([]string{"scan", "-format", "json", dir}, &out, &errOut); code != exitClean {
			t.Fatalf("scan exited %d: %s", code, errOut.String())
		}
		return out.String()
	}
	a, b := runOnce(), runOnce()
	if a != b {
		t.Fatalf("JSON output differs between runs:\n%s\n%s", a, b)
	}
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Artifacts     []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Format string `json:"format"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal([]byte(a), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "1" || len(doc.Artifacts) != 2 {
		t.Fatalf("unexpected document: %s", a)
	}
	if doc.Artifacts[0].Format != "json" || doc.Artifacts[1].Format != "pickle" {
		t.Fatalf("dispatch by content failed: %+v", doc.Artifacts)
	}
}

func TestScanWritesToOutAndPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.pkl"), []byte("\x80\x04N."), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "report.sarif")
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "-format", "sarif", "-out", outFile, dir}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("scan exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "artifact(s)") {
		t.Fatalf("no summary line on stdout: %q", out.String())
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []any  `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("-out file is not valid SARIF: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("SARIF header = %q with %d runs", doc.Version, len(doc.Runs))
	}
}

// TestInertFlagsAreWarnedAbout: each of these flags reaches exactly one output
// path, so with any other format the caller's intent is silently dropped. The
// -timings case was the worst of them — the warning excluded text while the text
// encoder ignores the timings map entirely, so `-timings -format text` was silent.
func TestInertFlagsAreWarnedAbout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want string // a fragment the warning must contain; "" means no warning
	}{
		{"timings with text", []string{"scan", "-timings", "-format", "text", dir}, "-timings has no effect with -format text"},
		{"timings with sarif", []string{"scan", "-timings", "-format", "sarif", dir}, "-timings has no effect with -format sarif"},
		{"color with json", []string{"scan", "-color", "-format", "json", dir}, "-color has no effect with -format json"},
		{"quiet with cyclonedx", []string{"scan", "-quiet", "-format", "cyclonedx", dir}, "-quiet has no effect with -format cyclonedx"},
		{"timings with json", []string{"scan", "-timings", "-format", "json", dir}, ""},
		{"color and quiet with text", []string{"scan", "-color", "-quiet", "-format", "text", dir}, ""},
		{"jobs with a path", []string{"scan", "-j", "4", dir}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tc.args, &out, &errOut); code != exitClean {
				t.Fatalf("scan exited %d: %s", code, errOut.String())
			}
			got := errOut.String()
			if tc.want == "" {
				if strings.Contains(got, "has no effect") {
					t.Fatalf("a warning fired for an effective flag: %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("stderr = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// TestJobsIsInertWithStdin: -stdin scans one stream on the calling goroutine, so
// the worker count is never read.
func TestJobsIsInertWithStdin(t *testing.T) {
	var out, errOut bytes.Buffer
	restore := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(`{"a":1}`); err != nil {
		t.Fatal(err)
	}
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = restore; r.Close() }()

	if code := run([]string{"scan", "-stdin", "-name", "x.json", "-j", "4"}, &out, &errOut); code != exitClean {
		t.Fatalf("scan exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "-j has no effect with -stdin") {
		t.Fatalf("stderr = %q, want the -j warning", errOut.String())
	}
}

func TestScanStdinRequiresName(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "-stdin"}, &out, &errOut); code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "-name") {
		t.Fatalf("error does not mention -name: %q", errOut.String())
	}
}

func TestRulesAndFormatsCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"rules"}, &out, &errOut); code != exitClean {
		t.Fatalf("rules exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "SC4N-PARSE-FAILED") {
		t.Fatalf("rule catalogue is missing registered rules: %s", out.String())
	}

	out.Reset()
	if code := run([]string{"rules", "-format", "json"}, &out, &errOut); code != exitClean {
		t.Fatalf("rules -format json exited %d", code)
	}
	var cat []struct {
		ID         string `json:"id"`
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		Class      string `json:"class"`
	}
	if err := json.Unmarshal(out.Bytes(), &cat); err != nil {
		t.Fatalf("rule catalogue is not valid JSON: %v", err)
	}
	if len(cat) == 0 || cat[0].ID == "" || cat[0].Class == "" {
		t.Fatalf("catalogue entries are incomplete: %+v", cat)
	}

	out.Reset()
	if code := run([]string{"formats"}, &out, &errOut); code != exitClean {
		t.Fatalf("formats exited %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "native") || !strings.Contains(out.String(), "depth legend") {
		t.Fatalf("formats output is incomplete: %s", out.String())
	}

	out.Reset()
	if code := run([]string{"rules", "-format", "xml"}, &out, &errOut); code != exitUsage {
		t.Fatalf("rules -format xml exited %d, want %d", code, exitUsage)
	}
	out.Reset()
	if code := run([]string{"formats", "extra"}, &out, &errOut); code != exitUsage {
		t.Fatalf("formats with an argument exited %d, want %d", code, exitUsage)
	}
}

func TestHashCommand(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"hash", p}, &out, &errOut); code != exitClean {
		t.Fatalf("hash exited %d: %s", code, errOut.String())
	}
	// Known digests for "hello world\n".
	if !strings.Contains(out.String(), "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447") {
		t.Fatalf("sha256 mismatch: %s", out.String())
	}
	if !strings.Contains(out.String(), "22596363b3de40b06f981fb85d82312e8c0ed511") {
		t.Fatalf("sha1 mismatch: %s", out.String())
	}

	out.Reset()
	if code := run([]string{"hash"}, &out, &errOut); code != exitUsage {
		t.Fatalf("hash with no path exited %d, want %d", code, exitUsage)
	}
	out.Reset()
	if code := run([]string{"hash", filepath.Join(dir, "absent")}, &out, &errOut); code != exitUnreadable {
		t.Fatalf("hash on a missing file exited %d, want %d", code, exitUnreadable)
	}
}

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0", 0, true},
		{"1024", 1024, true},
		{"1KiB", 1 << 10, true},
		{"1kib", 1 << 10, true},
		{"2M", 2 << 20, true},
		{"1GiB", 1 << 30, true},
		{"3g", 3 << 30, true},
		{"1TiB", 1 << 40, true},
		{"64GiB", 64 << 30, true},
		{"512B", 512, true},
		{"", 0, false},
		{"abc", 0, false},
		{"-1", 0, false},
		{"1XiB", 0, false},
	}
	for _, tc := range cases {
		got, err := parseSize(tc.in)
		if tc.ok && err != nil {
			t.Errorf("parseSize(%q): %v", tc.in, err)
			continue
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("parseSize(%q) accepted an invalid size (%d)", tc.in, got)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("parseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestBaselineGate is the plan's exit-code gate #7: a second run with the first
// run's report as a baseline must exit 0 and say how many findings it suppressed.
func TestBaselineGate(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "fixtures")
	if _, err := os.Stat(fixtures); err != nil {
		t.Skip("fixture corpus absent")
	}
	base := filepath.Join(t.TempDir(), "base.json")
	// Redacted findings are deliberately not baseline-suppressible, and the corpus
	// carries fixture secrets. Use a pickle finding, whose evidence is stable, to
	// exercise the suppression contract.
	target := filepath.Join(fixtures, "pickle_b64_exec.pkl")

	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "-format", "json", "-out", base, target}, &out, &errOut); code != exitFindings {
		t.Fatalf("first run exited %d, want %d (stderr: %s)", code, exitFindings, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code := run([]string{"scan", "-baseline", base, target}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("baseline run exited %d, want %d\nstderr: %s\nstdout: %s", code, exitClean, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "suppressed: ") {
		t.Fatalf("the summary line does not report the suppressed count: %q", out.String())
	}

	// A baseline that cannot be read is a usage error, not a clean run.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "-baseline", filepath.Join(base, "nope.json"), target}, &out, &errOut); code != exitUsage {
		t.Fatalf("unreadable baseline exited %d, want %d", code, exitUsage)
	}
}

// TestHFCacheScansEachBlobOnce builds a synthetic Hugging Face cache in a temp
// directory: two revisions whose snapshot entries are relative symlinks into
// blobs/, one of which is a malicious pickle. It asserts that the cache is
// scanned, that the malicious blob is reported under its snapshot path, and that
// the second revision pointing at the same blob does not produce a second scan.
func TestHFCacheScansEachBlobOnce(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "models--acme--tiny")
	const (
		revA = "0123456789abcdef0123456789abcdef01234567"
		revB = "89abcdef0123456789abcdef0123456789abcdef"
	)
	for _, p := range []string{
		filepath.Join(repo, "blobs"),
		filepath.Join(repo, "refs"),
		filepath.Join(repo, "snapshots", revA),
		filepath.Join(repo, "snapshots", revB),
	} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A pickle whose REDUCE calls os.system, built here rather than read from the
	// fixture corpus so the test owns its input.
	evil := []byte{0x80, 0x04, 0x95, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		'c', 'o', 's', '\n', 's', 'y', 's', 't', 'e', 'm', '\n',
		'\x8c', 0x02, 'i', 'd',
		'R', '.', 0x94}
	blob := filepath.Join(repo, "blobs", "aaaa1111")
	if err := os.WriteFile(blob, evil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, rev := range []string{revA, revB} {
		link := filepath.Join(repo, "snapshots", rev, "model.pkl")
		if err := os.Symlink(filepath.Join("..", "..", "blobs", "aaaa1111"), link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "refs", "main"), []byte(revA), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := run([]string{"scan", "-hf-cache", "-hf-cache-dir", dir, "-format", "json"}, &out, &errOut)
	if code != exitFindings {
		t.Fatalf("exit %d, want %d (stderr: %s)", code, exitFindings, errOut.String())
	}
	var doc struct {
		Artifacts []struct {
			Path string `json:"path"`
		} `json:"artifacts"`
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if len(doc.Artifacts) != 1 {
		t.Fatalf("scanned %d artifacts, want 1 (the two revisions share one blob): %+v", len(doc.Artifacts), doc.Artifacts)
	}
	if !strings.Contains(doc.Artifacts[0].Path, "snapshots/") {
		t.Fatalf("artifact is not named by its snapshot path: %q", doc.Artifacts[0].Path)
	}
	found := false
	for _, f := range doc.Findings {
		if f.RuleID == "SC4N-PICKLE-GLOBAL-CRITICAL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the malicious blob was not reported: %+v", doc.Findings)
	}

	// -hf-cache names its own scope; a path argument as well is a usage error.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "-hf-cache", "-hf-cache-dir", dir, "."}, &out, &errOut); code != exitUsage {
		t.Fatalf("-hf-cache with a path argument exited %d, want %d", code, exitUsage)
	}
	// A directory with no blobs is not a silent clean run, and it must still
	// produce the report the run was asked for.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "-hf-cache", "-hf-cache-dir", t.TempDir()}, &out, &errOut); code != exitUnreadable {
		t.Fatalf("empty cache exited %d, want %d", code, exitUnreadable)
	}
	if !strings.Contains(out.String(), "0 artifact(s)") {
		t.Fatalf("an empty cache produced no report: %q", out.String())
	}

	// A ref that is not a commit is a finding the expander recorded before the
	// walk, and rendering it is the whole reason the collector is passed in:
	// returning early made a cache whose refs are broken look empty.
	bad := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bad, "models--x", "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "models--x", "refs", "main"), []byte("not-a-commit"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "-hf-cache", "-hf-cache-dir", bad, "-format", "json"}, &out, &errOut); code != exitUnreadable {
		t.Fatalf("malformed ref exited %d, want %d", code, exitUnreadable)
	}
	if !strings.Contains(out.String(), "SC4N-HFCACHE-REF-MALFORMED") {
		t.Fatalf("the malformed ref was not rendered: %q", out.String())
	}
}

// TestPartialFlagSuppressesSliceFindings: a caller who fetched a byte prefix of a
// larger file has to be able to say so, or every extent check reports a violation
// the truncation caused. The flag exists because the hub campaign had this
// information internally and the CLI had no way to accept it.
func TestPartialFlagSuppressesSliceFindings(t *testing.T) {
	dir := t.TempDir()
	// A ModelProto header whose graph field declares 1 MiB past the end of the file.
	src := []byte{0x08, 0x07, 0x3a, 0x80, 0x80, 0x40}
	src = append(src, make([]byte, 16)...)
	p := filepath.Join(dir, "model.onnx")
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	scan := func(args ...string) string {
		var out, errOut bytes.Buffer
		code := run(append([]string{"scan", "-format", "json"}, append(args, dir)...), &out, &errOut)
		if code != exitClean && code != exitFindings {
			t.Fatalf("scan exited %d: %s", code, errOut.String())
		}
		return out.String()
	}
	plain := scan()
	if strings.Contains(plain, `"SC4N-PARTIAL-SLICE"`) {
		t.Fatalf("a whole-file scan reported a slice: %s", plain)
	}
	marked := scan("-partial", p)
	if !strings.Contains(marked, `"SC4N-PARTIAL-SLICE"`) {
		t.Fatalf("-partial did not report the slice: %s", marked)
	}
}

// TestHandWrittenAttestationMerges proves the attestation format is a contract
// with the harness, not with tools/sc4nconfirm: a file written by anything that
// observed a load produces SC4N-MALICE-DEMONSTRATED on the artifact whose full
// digest it names. This is the path a team takes when Docker is unavailable and
// the load happens in a VM or a pod.
func TestHandWrittenAttestationMerges(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "model.pkl")
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "pickle_gadget_os_system.pkl"))
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	if err := os.WriteFile(art, b, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	att := filepath.Join(dir, "attestation.json")
	body := `{"version":"sc4nconfirm/1","runs":[{"sha256":"` + hex.EncodeToString(sum[:]) +
		`","loader":"pickle.load","loaded":true,"exec":["/bin/sh -c -- touch /tmp/hand-written"]}]}`
	if err := os.WriteFile(att, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := run([]string{"scan", "-attestation", att, "-format", "json", art}, &out, &errOut)
	if code != exitFindings {
		t.Fatalf("scan exited %d, want %d (stderr: %s)", code, exitFindings, errOut.String())
	}
	var doc struct {
		Findings []struct {
			RuleID   string `json:"ruleId"`
			Severity string `json:"severity"`
			Evidence string `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v (output: %s)", err, out.String())
	}
	found := false
	for _, f := range doc.Findings {
		if f.RuleID != "SC4N-MALICE-DEMONSTRATED" {
			continue
		}
		found = true
		if f.Severity != "critical" {
			t.Errorf("demonstrated severity = %q, want critical", f.Severity)
		}
		if !strings.Contains(f.Evidence, "touch /tmp/hand-written") {
			t.Errorf("evidence does not name the observed program: %q", f.Evidence)
		}
	}
	if !found {
		t.Fatalf("no SC4N-MALICE-DEMONSTRATED for the attested artifact: %s", out.String())
	}
}
