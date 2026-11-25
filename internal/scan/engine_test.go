package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// TestRunStdinRespectsMemBudget pins that a stdin stream is bounded by the run's
// memory budget, not only by MaxArtifactBytes: a stdin artifact is buffered in
// memory, so a stream larger than the budget must be reported rather than read
// without limit and then scanned silently.
func TestRunStdinRespectsMemBudget(t *testing.T) {
	res, err := Run(context.Background(), Config{
		StdinName: "stdin.bin",
		Stdin:     bytes.NewReader(make([]byte, 64<<20)),
		Limits:    limits.Default(),
		MemBudget: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Artifacts[0].Error == "" {
		t.Fatal("64 MiB via stdin under a 1 MiB budget was accepted without a finding")
	}
	var found bool
	for _, f := range res.Collector.Findings() {
		if f.RuleID != "SC4N-LIMIT-ARTIFACT" {
			continue
		}
		found = true
		if f.Extra["limit"] != "MemBudget" {
			t.Fatalf("limit = %q, want MemBudget (the binding cap)", f.Extra["limit"])
		}
	}
	if !found {
		t.Fatal("no SC4N-LIMIT-ARTIFACT finding for the over-budget stream")
	}
}

// TestRunStdinRespectsMaxArtifactBytesReportsFinding pins that the
// MaxArtifactBytes overflow is a finding, not only an artifact error: the file
// path emits SC4N-LIMIT-ARTIFACT and the stdin path must report the same thing.
func TestRunStdinRespectsMaxArtifactBytesReportsFinding(t *testing.T) {
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
	for _, f := range res.Collector.Findings() {
		if f.RuleID == "SC4N-LIMIT-ARTIFACT" {
			return
		}
	}
	t.Fatalf("no SC4N-LIMIT-ARTIFACT finding; findings = %v", res.Collector.Findings())
}

// slowStdin delivers one byte per tick and never reaches EOF: the shape a shell
// that holds a pipe's write end open produces. It proves the stdin read is
// interruptible, not merely chunked.
type slowStdin struct{ tick time.Duration }

func (s slowStdin) Read(p []byte) (int, error) {
	time.Sleep(s.tick)
	p[0] = 'x'
	return 1, nil
}

// TestRunStdinDeadlineInterruptsBlockedProducer pins that -timeout stops a stdin
// read that would otherwise stay open: the read must be interruptible, so a
// producer holding the write end open cannot pin the scan past the deadline.
func TestRunStdinDeadlineInterruptsBlockedProducer(t *testing.T) {
	res, err := Run(context.Background(), Config{
		StdinName: "stdin.bin",
		Stdin:     slowStdin{tick: 25 * time.Millisecond},
		Limits:    limits.Default(),
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Artifacts[0].Error; got != "scan deadline exceeded while reading stdin" {
		t.Fatalf("error = %q, want the deadline message", got)
	}
	if res.Unreadable != 1 {
		t.Fatalf("unreadable = %d, want 1 (the CLI exits 3 for this)", res.Unreadable)
	}
	if !res.Cancelled {
		t.Fatal("res.Cancelled = false, want true when stdin deadline fires")
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

// TestDuplicatePathsAreScannedOnce pins F29: the same path twice on the command
// line produced two artifact rows and two CycloneDX components with the same
// bom-ref, which the spec forbids.
func TestDuplicatePathsAreScannedOnce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.pkl")
	write(t, dir, "m.pkl", []byte("\x80\x04N."))
	res, err := Run(context.Background(), Config{Paths: []string{p, p, dir}, Limits: limits.Default(), Jobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Artifacts) != 1 {
		t.Fatalf("artifacts = %d, want 1 (the path given three ways is one artifact): %+v", len(res.Artifacts), res.Artifacts)
	}
	rep := report.Build(report.Tool{Name: "sc4n", Version: "t"}, "", res.Artifacts, res.Collector, report.Limits{}, nil, 0)
	var buf bytes.Buffer
	if err := rep.WriteCycloneDX(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Components {
		if seen[c.BOMRef] {
			t.Fatalf("duplicate bom-ref %q", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}
}

// failingSource is a Source whose sequential reader fails after the first byte,
// which is what a digest read hits when the underlying file goes away mid-scan.
type failingSource struct{ name string }

func (f failingSource) Name() string { return f.name }
func (f failingSource) Size() int64  { return 64 }
func (f failingSource) ReadAt(p []byte, off int64) (int, error) {
	return 0, errFailingSource
}
func (f failingSource) Bytes(off, n int64) ([]byte, error) { return nil, errFailingSource }
func (f failingSource) Reader(off int64) io.Reader         { return errReader{} }
func (f failingSource) Close() error                       { return nil }

var errFailingSource = errors.New("source: read failed")

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errFailingSource }

// TestDigestFailureIsReported: a digest read that fails used to return an empty
// digest and an empty scope with no error, so the row showed a size and no digest
// and nothing said why.
func TestDigestFailureIsReported(t *testing.T) {
	digest, scope, err := digestSource(failingSource{name: "gone.bin"}, 1<<20)
	if err == nil {
		t.Fatal("a failing digest read returned no error")
	}
	if digest != "" || scope != "" {
		t.Fatalf("digest=%q scope=%q on failure, want both empty", digest, scope)
	}
}

// TestSubFormatReportsBothFailures: the row's sub-format was an `else if`, so an
// artifact that failed to parse and could not be hashed reported only the parse
// error, leaving the empty digest unexplained.
func TestSubFormatReportsBothFailures(t *testing.T) {
	perr := errors.New("header: not a numpy file")
	derr := errors.New("source: read failed")

	both := subFormatFor(perr, derr)
	if !strings.Contains(both, perr.Error()) || !strings.Contains(both, derr.Error()) {
		t.Fatalf("both failures were not reported: %q", both)
	}
	if got := subFormatFor(perr, nil); got != "parse-error: "+perr.Error() {
		t.Fatalf("parse-only sub-format = %q", got)
	}
	if got := subFormatFor(nil, derr); got != "digest unavailable: "+derr.Error() {
		t.Fatalf("digest-only sub-format = %q", got)
	}
	if got := subFormatFor(nil, nil); got != "" {
		t.Fatalf("a clean row carried a sub-format: %q", got)
	}
}

// TestExpandBindsAnInRootSymlinkToTheRoot pins the entry shape the root-bound
// open depends on: a symlink whose target is inside the root is opened through
// os.Root at the link's spelling, so a replacement between the containment check
// and the open is refused rather than followed.
func TestExpandBindsAnInRootSymlinkToTheRoot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(target, []byte("plain text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "weights.bin")
	if err := os.Symlink("real.bin", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	entries, _, err := expand(context.Background(), Config{Paths: []string{dir}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for _, e := range entries {
		if e.Display != link {
			continue
		}
		if e.RootDir == "" || e.Rel != "weights.bin" {
			t.Fatalf("symlink entry = %+v, want RootDir set and Rel weights.bin", e)
		}
		return
	}
	t.Fatalf("the symlink produced no entry: %+v", entries)
}

// TestRootBoundEntryRefusesAnEscapingLink is the other half of the TOCTOU pair:
// an entry the walk resolved while the target was inside is opened through
// os.Root, so a link that now leaves the root is refused instead of reading the
// outside file. The post-scan mutation check alone reported this only after the
// out-of-root bytes had been read.
func TestRootBoundEntryRefusesAnEscapingLink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("token=ghp_0123456789abcdefghij\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "leak.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	res, err := Run(context.Background(), Config{
		Entries: []Entry{{Path: link, Display: "leak.txt", RootDir: root, Rel: "leak.txt"}},
		Limits:  limits.Default(),
		Jobs:    1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Error == "" {
		t.Fatalf("summaries = %+v, want one refused by the root open", res.Artifacts)
	}
	if len(res.Collector.Findings()) != 0 {
		t.Fatalf("the escaping target was scanned: %v", res.Collector.Findings())
	}
}

// TestRunSymlinkedAncestorDirectory pins that scanning a directory reached
// through a symlinked ancestor (e.g. /tmp/link/repo or macOS /tmp/...) succeeds
// rather than failing every file with "path escapes from parent".
func TestRunSymlinkedAncestorDirectory(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real", "repo")
	write(t, realDir, "sub/a.pkl", []byte("\x80\x04N."))
	linkParent := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "real"), linkParent); err != nil {
		t.Skipf("symlink: %v", err)
	}
	res, err := Run(context.Background(), Config{
		Paths:  []string{filepath.Join(linkParent, "repo")},
		Limits: limits.Default(),
		Jobs:   2,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("Unreadable = %d, artifacts = %+v", res.Unreadable, res.Artifacts)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Format != "pickle" {
		t.Fatalf("artifacts = %+v, want 1 pickle", res.Artifacts)
	}
}

// TestRunAcceptsAbsoluteInRootSymlinkFromRelativeRoot pins that an absolute
// symlink whose target stays inside a relative scan root (./repo/b.txt ->
// $PWD/repo/a.txt) is accepted as in-root both via directory scan and direct
// path scan.
func TestRunAcceptsAbsoluteInRootSymlinkFromRelativeRoot(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	aPath := write(t, repo, "a.txt", []byte("hello world\n"))
	bPath := filepath.Join(repo, "b.txt")
	if err := os.Symlink(aPath, bPath); err != nil {
		t.Skipf("symlink: %v", err)
	}
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	for _, target := range []string{"./repo", "./repo/b.txt"} {
		res, err := Run(context.Background(), Config{Paths: []string{target}, Limits: limits.Default()})
		if err != nil {
			t.Fatalf("Run(%q): %v", target, err)
		}
		if res.Unreadable != 0 {
			t.Fatalf("Run(%q): Unreadable = %d, artifacts = %+v", target, res.Unreadable, res.Artifacts)
		}
		for _, f := range res.Collector.Findings() {
			if f.RuleID == rulePathMutated.ID {
				t.Fatalf("Run(%q): unexpected false mutation finding: %+v", target, f)
			}
		}
	}
}

// TestRunSymlinkFollowNoFalseMutation pins that scanning a symlink without
// os.Root (SymlinkFollow) compares target Stat against target Stat rather than
// symlink Lstat against target Stat, avoiding false SC4N-PATH-ARTIFACT-MUTATED.
func TestRunSymlinkFollowNoFalseMutation(t *testing.T) {
	dir := t.TempDir()
	target := write(t, dir, "real.txt", []byte("longer than the symlink path payload\n"))
	link := filepath.Join(dir, "l.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	res, err := Run(context.Background(), Config{
		Entries:  []Entry{{Path: link, Display: link}},
		Limits:   limits.Default(),
		Symlinks: SymlinkFollow,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("Unreadable = %d, artifacts = %+v", res.Unreadable, res.Artifacts)
	}
	for _, f := range res.Collector.Findings() {
		if f.RuleID == rulePathMutated.ID {
			t.Fatalf("false mutation finding on symlink: %+v", f)
		}
	}
}

// TestRunRootBoundEntryUsesDisplayNameAsSourceName pins that -hf-cache entries
// (where Path is blobs/<sha> and Display is snapshots/<rev>/modeling_evil.py)
// pass Display to source.OpenFile so extension-aware parsers see the snapshot
// filename rather than the opaque blob digest.
func TestRunRootBoundEntryUsesDisplayNameAsSourceName(t *testing.T) {
	dir := t.TempDir()
	blobRel := filepath.Join("models--o--r", "blobs", strings.Repeat("a", 64))
	blobPath := write(t, dir, blobRel, []byte("import os\nos.system('id')\n"))
	display := "models--o--r/snapshots/" + strings.Repeat("1", 40) + "/modeling_evil.py"

	res, err := Run(context.Background(), Config{
		Entries: []Entry{{
			Path:    blobPath,
			Display: display,
			RootDir: dir,
			Rel:     filepath.ToSlash(blobRel),
		}},
		Limits: limits.Default(),
		Jobs:   1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Unreadable != 0 {
		t.Fatalf("Unreadable = %d, artifacts = %+v", res.Unreadable, res.Artifacts)
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Format != "python" {
		t.Fatalf("format = %+v, want python via Display name", res.Artifacts)
	}
}

func TestRunUnreadableSubdirectoryReportsPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores chmod 000")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(sub, 0o755) }()

	res, err := Run(context.Background(), Config{Paths: []string{dir}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Unreadable != 1 {
		t.Fatalf("Unreadable = %d, want 1", res.Unreadable)
	}
	if len(res.Artifacts) != 1 || strings.Contains(res.Artifacts[0].Error, "special file") ||
		!strings.Contains(strings.ToLower(res.Artifacts[0].Error), "permission denied") {
		t.Fatalf("unreadable subdir error = %q, want permission denied", res.Artifacts[0].Error)
	}
}

func TestExpandCancelsOnContextDone(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.txt", []byte("hi"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, Config{Paths: []string{dir}, Limits: limits.Default()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Cancelled {
		t.Fatal("expected res.Cancelled = true for pre-cancelled context")
	}
}

func TestNoteFindingsCapUsesConfigMaxFindingsAndRejectsNegative(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.pkl", []byte("\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85\x52."))
	write(t, dir, "b.pkl", []byte("\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85\x52."))

	if _, err := Run(context.Background(), Config{Paths: []string{dir}, Limits: limits.Default(), MaxFindings: -1}); err == nil {
		t.Fatal("negative MaxFindings was accepted")
	}
	res, err := Run(context.Background(), Config{Paths: []string{dir}, Limits: limits.Default(), MaxFindings: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Collector.Findings() {
		if f.RuleID == "SC4N-LIMIT-FINDINGS" {
			if f.Extra["cap"] != "1" {
				t.Fatalf("cap = %q, want 1", f.Extra["cap"])
			}
			return
		}
	}
	t.Fatalf("no SC4N-LIMIT-FINDINGS emitted; findings=%v", res.Collector.Findings())
}

func TestMarkSeenDuplicateIsDeterministicAndPreservesSubFormat(t *testing.T) {
	dir := t.TempDir()
	p1 := write(t, dir, "first.bin", []byte("same bytes"))
	p2 := write(t, dir, "second.bin", []byte("same bytes"))
	entries := []Entry{
		{Path: p2, Display: "z_second.bin", Digest: "deadbeef"},
		{Path: p1, Display: "a_first.bin", Digest: "deadbeef"},
	}
	// Run across multiple trials with parallel workers to verify deterministic winner.
	for range 10 {
		res, err := Run(context.Background(), Config{Entries: entries, Limits: limits.Default(), Jobs: 4})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(res.Artifacts) != 2 {
			t.Fatalf("artifacts = %d, want 2", len(res.Artifacts))
		}
		if res.Artifacts[0].Path != "a_first.bin" || res.Artifacts[0].SubFormat != "" {
			t.Fatalf("first = %+v, want a_first.bin with empty SubFormat", res.Artifacts[0])
		}
		if res.Artifacts[1].Path != "z_second.bin" || res.Artifacts[1].SubFormat != "duplicate of a_first.bin" {
			t.Fatalf("second = %+v, want duplicate of a_first.bin", res.Artifacts[1])
		}
	}
}
