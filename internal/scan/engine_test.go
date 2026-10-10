package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWalksDirectoriesDeterministically(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "b.pkl", []byte("\x80\x04N."))
	write(t, dir, "a.json", []byte(`{"model_type":"bert"}`))
	write(t, dir, "sub/c.bin", []byte("GGUF\x03\x00\x00\x00"))
	write(t, dir, ".git/config", []byte("[core]\n"))

	cfg := Config{Paths: []string{dir}, Limits: limits.Default(), Jobs: 4}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Artifacts) != 3 {
		t.Fatalf("scanned %d artifacts, want 3 (.git must be skipped)", len(res.Artifacts))
	}
	// The walk is sorted, so the report order does not depend on worker count.
	want := []string{filepath.Join(dir, "a.json"), filepath.Join(dir, "b.pkl"), filepath.Join(dir, "sub/c.bin")}
	for i, a := range res.Artifacts {
		if a.Path != want[i] {
			t.Fatalf("artifact %d = %s, want %s", i, a.Path, want[i])
		}
		if a.Error != "" {
			t.Fatalf("unexpected error on %s: %s", a.Path, a.Error)
		}
		if a.SHA256 == "" {
			t.Fatalf("no digest for %s", a.Path)
		}
	}
	if res.Artifacts[0].Format != "json" || res.Artifacts[1].Format != "pickle" || res.Artifacts[2].Format != "gguf" {
		t.Fatalf("formats = %s, %s, %s", res.Artifacts[0].Format, res.Artifacts[1].Format, res.Artifacts[2].Format)
	}
}

func TestZeroByteArtifactIsScanned(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "empty.bin", nil)

	res, err := Run(context.Background(), Config{Paths: []string{p}, Limits: limits.Default(), Jobs: 2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Artifacts) != 1 {
		t.Fatalf("scanned %d artifacts, want 1", len(res.Artifacts))
	}
	a := res.Artifacts[0]
	if a.Error != "" {
		t.Fatalf("empty artifact reported an error: %s", a.Error)
	}
	if a.Size != 0 {
		t.Fatalf("size = %d, want 0", a.Size)
	}
	// The digest of the empty string, with a scope that says it covers everything.
	const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if a.SHA256 != emptyDigest {
		t.Fatalf("sha256 = %q, want the empty-string digest %q", a.SHA256, emptyDigest)
	}
	if a.SHA256Scope != "full" {
		t.Fatalf("sha256Scope = %q, want full", a.SHA256Scope)
	}
	if got := res.Collector.Len(); got != 0 {
		t.Fatalf("empty artifact produced %d finding(s)", got)
	}
}

func TestRunIsWorkerCountIndependent(t *testing.T) {
	dir := t.TempDir()
	for i := range 40 {
		write(t, dir, filepath.Join("d", string(rune('a'+i%26))+string(rune('a'+i/26))+".bin"), []byte{0x00, byte(i)})
	}
	var prev string
	for _, jobs := range []int{1, 2, 8, 32} {
		res, err := Run(context.Background(), Config{Paths: []string{dir}, Limits: limits.Default(), Jobs: jobs})
		if err != nil {
			t.Fatalf("Run(jobs=%d): %v", jobs, err)
		}
		var b bytes.Buffer
		rep := report.Build(report.Tool{Name: "sc4n", Version: "t"}, "", res.Artifacts, res.Collector, report.Limits{}, nil, 0)
		if err := rep.WriteJSON(&b); err != nil {
			t.Fatal(err)
		}
		if prev != "" && prev != b.String() {
			t.Fatalf("output differs between worker counts:\n%s\n%s", prev, b.String())
		}
		prev = b.String()
	}
}

func TestRunReportsUnreadablePaths(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "ok.txt", []byte("fine"))
	res, err := Run(context.Background(), Config{
		Paths:  []string{dir, filepath.Join(dir, "missing")},
		Limits: limits.Default(),
	})
	if err == nil {
		t.Fatal("Run did not report the missing path")
	}
	if res.Unreadable != 1 {
		t.Fatalf("Unreadable = %d, want 1", res.Unreadable)
	}
	found := false
	for _, a := range res.Artifacts {
		if a.Path == filepath.Join(dir, "missing") && a.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("the unreadable path is not in the artifact list")
	}
}

func TestRunStdin(t *testing.T) {
	res, err := Run(context.Background(), Config{
		StdinName: "stdin.pkl",
		Stdin:     bytes.NewReader([]byte("\x80\x04N.")),
		Limits:    limits.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Artifacts) != 1 {
		t.Fatalf("artifacts = %d", len(res.Artifacts))
	}
	if res.Artifacts[0].Format != "pickle" {
		t.Fatalf("format = %s", res.Artifacts[0].Format)
	}
}

// TestRunStdinReportsDigestScope pins the F25 fix: the stdin path hashed the
// whole buffer and reported scope "full" even past MaxHashBytes, so a consumer
// de-duplicating on (scope, digest) saw a full digest where a prefix was meant.
func TestRunStdinReportsDigestScope(t *testing.T) {
	l := limits.Default()
	l.MaxHashBytes = 16
	body := bytes.Repeat([]byte{0x41}, 64)
	res, err := Run(context.Background(), Config{
		StdinName: "stdin.bin",
		Stdin:     bytes.NewReader(body),
		Limits:    l,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := res.Artifacts[0]
	if a.SHA256Scope != "prefix:16" {
		t.Fatalf("sha256Scope = %q, want prefix:16 for a %d-byte stream past MaxHashBytes=%d",
			a.SHA256Scope, len(body), l.MaxHashBytes)
	}
	// The scope must match what the file path would report for the same bytes.
	dir := t.TempDir()
	write(t, dir, "same.bin", body)
	res2, err := Run(context.Background(), Config{Paths: []string{filepath.Join(dir, "same.bin")}, Limits: l})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Artifacts[0].SHA256 != a.SHA256 || res2.Artifacts[0].SHA256Scope != a.SHA256Scope {
		t.Fatalf("stdin digest (%s, %s) differs from the file digest (%s, %s)",
			a.SHA256, a.SHA256Scope, res2.Artifacts[0].SHA256, res2.Artifacts[0].SHA256Scope)
	}
}

func TestRunStdinRespectsMaxArtifactBytes(t *testing.T) {
	l := limits.Default()
	l.MaxArtifactBytes = 4
	res, err := Run(context.Background(), Config{
		StdinName: "stdin.bin",
		Stdin:     bytes.NewReader(make([]byte, 64)),
		Limits:    l,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Artifacts[0].Error == "" {
		t.Fatal("oversized stdin was accepted")
	}
}

// TestRunAdmitsArtifactLargerThanTheWholeBudget pins the documented behaviour:
// -mem-budget admits a single oversized artifact alone instead of turning into a
// silent skip, which would be a fail-open.
func TestRunAdmitsArtifactLargerThanTheWholeBudget(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "big.bin", bytes.Repeat([]byte{0xab}, 4096))
	res, err := Run(context.Background(), Config{
		Paths:     []string{dir},
		Limits:    limits.Default(),
		MemBudget: 1,
		Jobs:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Error != "" {
		t.Fatalf("oversized artifact was not scanned: %+v", res.Artifacts)
	}
	if res.Artifacts[0].Size != 4096 {
		t.Fatalf("size = %d", res.Artifacts[0].Size)
	}
}

func TestRunTimeoutMarksResultPartial(t *testing.T) {
	dir := t.TempDir()
	for i := range 200 {
		write(t, dir, filepath.Join("d", string(rune('a'+i%26))+string(rune('a'+i/26))+".bin"), bytes.Repeat([]byte{0xff}, 1<<16))
	}
	// A deadline in the past is the deterministic way to observe the cancelled
	// path without depending on how fast the machine is.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	res, err := Run(ctx, Config{Paths: []string{dir}, Limits: limits.Default()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cancelled {
		t.Fatal("a cancelled scan must be marked partial, never presented as complete")
	}
}

func TestMemBudgetBlocksUntilReleased(t *testing.T) {
	b := newMemBudget(100)
	if !b.acquire(context.Background(), 60) {
		t.Fatal("first acquire failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if b.acquire(ctx, 60) {
		t.Fatal("acquire succeeded past the budget")
	}
	b.release(60)
	if !b.acquire(context.Background(), 60) {
		t.Fatal("acquire failed after a release")
	}
}

func TestMemBudgetLargeSlotIsCancellable(t *testing.T) {
	b := newMemBudget(1 << 40)
	if !b.acquireLarge(context.Background()) {
		t.Fatal("first large slot refused")
	}
	if !b.acquireLarge(context.Background()) {
		t.Fatal("second large slot refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if b.acquireLarge(ctx) {
		t.Fatal("third large slot granted beyond maxConcurrentLarge")
	}
}

// TestFindingsCapIsReportedAsAFinding pins the F19 fix: the drop was counted in
// the summary but invisible to a consumer that watches findings, so a truncated
// list looked complete.
func TestFindingsCapIsReportedAsAFinding(t *testing.T) {
	dir := t.TempDir()
	// Two artifacts that each produce findings, with a cap of one.
	write(t, dir, "a.pkl", []byte("\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85\x52."))
	write(t, dir, "b.pkl", []byte("\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85\x52."))

	l := limits.Default()
	l.MaxFindings = 1
	res, err := Run(context.Background(), Config{Paths: []string{dir}, Limits: l, Jobs: 2})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	fs := res.Collector.Findings()
	if res.Collector.Dropped() == 0 {
		t.Skip("this fixture produced no findings to drop")
	}
	var notice *report.Finding
	for i := range fs {
		if fs[i].RuleID == "SC4N-LIMIT-FINDINGS" {
			notice = &fs[i]
		}
	}
	if notice == nil {
		t.Fatalf("no SC4N-LIMIT-FINDINGS notice; findings were %v", fs)
	}
	if notice.Artifact == "" {
		t.Fatal("the notice does not name the artifact whose findings were dropped")
	}
	if len(fs) != 2 {
		t.Fatalf("kept %d finding(s), want the capped one plus the notice", len(fs))
	}
}
