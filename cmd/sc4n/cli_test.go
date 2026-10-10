package main

import (
	"bytes"
	"encoding/json"
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
		{"missing path", []string{"scan", filepath.Join(dir, "absent")}, exitUnreadable},
		{"clean scan", []string{"scan", dir}, exitClean},
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

	var out, errOut bytes.Buffer
	if code := run([]string{"scan", "-format", "json", "-out", base, fixtures}, &out, &errOut); code != exitFindings {
		t.Fatalf("first run exited %d, want %d (stderr: %s)", code, exitFindings, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code := run([]string{"scan", "-baseline", base, fixtures}, &out, &errOut)
	if code != exitClean {
		t.Fatalf("baseline run exited %d, want %d\nstderr: %s\nstdout: %s", code, exitClean, errOut.String(), out.String())
	}
	if !strings.Contains(out.String(), "suppressed: ") {
		t.Fatalf("the summary line does not report the suppressed count: %q", out.String())
	}

	// A baseline that cannot be read is a usage error, not a clean run.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"scan", "-baseline", filepath.Join(base, "nope.json"), fixtures}, &out, &errOut); code != exitUsage {
		t.Fatalf("unreadable baseline exited %d, want %d", code, exitUsage)
	}
}
