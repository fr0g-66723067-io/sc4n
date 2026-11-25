package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func newTestCtx(t *testing.T, depth int) (*artifact.Ctx, *report.Collector) {
	t.Helper()
	c := report.NewCollector(0)
	l := limits.Default()
	sess := artifact.NewSession(c, "", l)
	ctx := sess.NewCtx("test", l)
	ctx.Depth = depth
	return ctx, c
}

func run(t *testing.T, path string, data string) map[string]bool {
	t.Helper()
	ctx, c := newTestCtx(t, 0)
	AnalyzeFile(ctx, path, []byte(data))
	out := map[string]bool{}
	for _, f := range c.Findings() {
		out[f.RuleID] = true
	}
	return out
}

func want(t *testing.T, got map[string]bool, rule string) {
	t.Helper()
	if !got[rule] {
		t.Fatalf("missing %s; got %v", rule, got)
	}
}

func TestPthExecutable(t *testing.T) {
	want(t, run(t, "pkg/x.pth", "import os\nos.system(\"id\")\n"), "SC4N-REPO-PTH")
}

func TestPthPathsAreClean(t *testing.T) {
	got := run(t, "pkg/x.pth", "/usr/local/lib\n./src\n")
	if got["SC4N-REPO-PTH"] {
		t.Fatal("an ordinary path line must not be reported")
	}
}

func TestStartEntryPoint(t *testing.T) {
	want(t, run(t, "startup.start", "evilpkg.hook:run\n"), "SC4N-REPO-START")
}

func TestStartProseIsClean(t *testing.T) {
	got := run(t, "notes.start", "just some text about: nothing\n")
	if got["SC4N-REPO-START"] {
		t.Fatal("prose without a dotted entry point must not be reported")
	}
}

func TestSetupHookCmdclass(t *testing.T) {
	want(t, run(t, "setup.py", "from setuptools import setup\nsetup(cmdclass={})\n"), "SC4N-REPO-SETUP-HOOK")
}

func TestSetupPlainIsClean(t *testing.T) {
	got := run(t, "setup.py", "from setuptools import setup\nsetup(name=\"x\", version=\"1.0\")\n")
	if got["SC4N-REPO-SETUP-HOOK"] {
		t.Fatal("plain metadata setup.py must not be reported")
	}
}

func TestBuildBackendBad(t *testing.T) {
	want(t, run(t, "pyproject.toml", "[build-system]\nbuild-backend = \"evil.build\"\n"), "SC4N-REPO-BUILD-BACKEND")
}

func TestBuildBackendAllowed(t *testing.T) {
	got := run(t, "pyproject.toml", "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"setuptools.build_meta\"\n")
	if got["SC4N-REPO-BUILD-BACKEND"] {
		t.Fatal("setuptools.build_meta must be allowed")
	}
}

func TestSiteCustomize(t *testing.T) {
	want(t, run(t, "sitecustomize.py", "print(1)\n"), "SC4N-REPO-SITE-CUSTOMIZE")
}

func TestWorkflowPRT(t *testing.T) {
	yml := "on:\n  pull_request_target:\nsteps:\n  - run: echo \"${{ github.event.pull_request.title }}\"\n"
	want(t, run(t, ".github/workflows/x.yml", yml), "SC4N-REPO-WORKFLOW-PRT")
}

func TestWorkflowPullRequestIsClean(t *testing.T) {
	yml := "on:\n  pull_request:\nsteps:\n  - run: echo \"${{ github.event.pull_request.title }}\"\n"
	got := run(t, ".github/workflows/x.yml", yml)
	if got["SC4N-REPO-WORKFLOW-PRT"] {
		t.Fatal("pull_request (not pull_request_target) must not be reported")
	}
}

func TestWheelAtDepthZero(t *testing.T) {
	ctx, c := newTestCtx(t, 0)
	AnalyzeFile(ctx, "repo/evil.whl", []byte("PK\x03\x04"))
	got := map[string]bool{}
	for _, f := range c.Findings() {
		got[f.RuleID] = true
	}
	want(t, got, "SC4N-REPO-WHEEL-IN-MODEL")
}

func TestWheelNestedIsQuiet(t *testing.T) {
	ctx, c := newTestCtx(t, 1)
	AnalyzeFile(ctx, "outer.zip:evil.whl", []byte("PK\x03\x04"))
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-REPO-WHEEL-IN-MODEL" {
			t.Fatal("a wheel nested inside another archive must not fire the tree-level rule")
		}
	}
}

func TestDockerfileAndSpaceApp(t *testing.T) {
	want(t, run(t, "Dockerfile", "FROM scratch\n"), "SC4N-REPO-DOCKERFILE")
	want(t, run(t, "app.py", "print(1)\n"), "SC4N-REPO-SPACE-APP")
}

func TestPycOrphan(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "x.pyc")
	if err := os.WriteFile(orphan, []byte{0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, c := newTestCtx(t, 0)
	AnalyzeFile(ctx, orphan, []byte{0x00})
	found := false
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-REPO-PYC-ORPHAN" {
			found = true
		}
	}
	if !found {
		t.Fatal("an orphan .pyc must be reported")
	}

	// With a sibling .py it must be quiet.
	if err := os.WriteFile(filepath.Join(dir, "y.py"), []byte("x=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pyc := filepath.Join(dir, "y.pyc")
	if err := os.WriteFile(pyc, []byte{0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx2, c2 := newTestCtx(t, 0)
	AnalyzeFile(ctx2, pyc, []byte{0x00})
	for _, f := range c2.Findings() {
		if f.RuleID == "SC4N-REPO-PYC-ORPHAN" {
			t.Fatal("a .pyc with a sibling .py must not be reported")
		}
	}
}

func TestCaresAbout(t *testing.T) {
	yes := []string{"setup.py", "a/pyproject.toml", "x.pth", "y.start", "z.pyc", "evil.whl", "pkg.tar.gz",
		"sitecustomize.py", "usercustomize.py", "Dockerfile", "app.py", ".github/workflows/ci.yml"}
	for _, p := range yes {
		if !caresAbout(p) {
			t.Errorf("caresAbout(%q) = false, want true", p)
		}
	}
	no := []string{"model.py", "README.md", "config.json", "notes.txt", "data.yml"}
	for _, p := range no {
		if caresAbout(p) {
			t.Errorf("caresAbout(%q) = true, want false", p)
		}
	}
	if !caresAbout("evil.whl:sub/x.pth") {
		t.Error("a .pth inside a wheel must be recognised via its last segment")
	}
}

// TestPackageArchivePointerIsNotAHighFinding pins the calibration of
// SC4N-REPO-WHEEL-IN-MODEL: its basis is the file *name*, and a name cannot tell an
// sdist from dataset.tar.gz. At high severity it made `-fail-on high` fail on a
// repository that merely ships a data tarball, while the identical bytes named
// .tgz produced nothing — a verdict that depends on the suffix is the reasoning this
// package's own sibling rules (Dockerfile, app.py) explicitly do not use for a high
// finding.
func TestPackageArchivePointerIsNotAHighFinding(t *testing.T) {
	ctx, c := newTestCtx(t, 0)
	AnalyzeFile(ctx, "dataset.tar.gz", []byte("not a package archive\n"))
	AnalyzeFile(ctx, "dataset.tgz", []byte("not a package archive\n"))
	var seen int
	for _, f := range c.Findings() {
		if f.RuleID != ruleWheelInModel.ID {
			continue
		}
		seen++
		if f.Severity >= report.SeverityHigh {
			t.Errorf("%s reported at %v; a name-only pointer must not reach the default -fail-on threshold",
				f.Artifact, f.Severity)
		}
		if f.Confidence >= report.ConfidenceMedium {
			t.Errorf("%s reported at %v confidence; the basis is the file name", f.Artifact, f.Confidence)
		}
	}
	if seen != 2 {
		t.Errorf("the pointer fired %d time(s) for the two spellings, want 2: a .tgz is the same package "+
			"archive as a .tar.gz", seen)
	}
}

func TestSetupHookInTopLevelIfSuiteIsReported(t *testing.T) {
	want(t, run(t, "setup.py", "if True:\n    import os\n    os.system('id')\n"), "SC4N-REPO-SETUP-HOOK")
}

func TestBackendPathShadowingAllowlistedBackendIsReported(t *testing.T) {
	got := run(t, "pyproject.toml", "[build-system]\nrequires = []\nbuild-backend = \"setuptools.build_meta\"\nbackend-path = [\"src\"]\n")
	want(t, got, "SC4N-REPO-BACKEND-PATH")
}

func TestUniversalSkipsBinaryPthCheckpoints(t *testing.T) {
	// A >4 MiB PyTorch checkpoint named .pth must NOT emit SC4N-REPO-TRUNCATED.
	big := bytes.Repeat([]byte{0x50, 0x4b, 0x03, 0x04}, (repoMaxBytes/4)+16)
	for _, f := range []artifact.Format{
		artifact.FormatTorchNew, artifact.FormatTorchLegacy,
		artifact.FormatPickle, artifact.FormatZip, artifact.FormatSevenZip,
	} {
		c := report.NewCollector(0)
		l := limits.Default()
		sess := artifact.NewSession(c, "", l)
		ctx := sess.NewCtx("weights.pth", l)
		src := source.Mem("weights.pth", big)
		universal(ctx, src, f)
		src.Close()
		for _, finding := range c.Findings() {
			if finding.RuleID == "SC4N-REPO-TRUNCATED" || finding.RuleID == "SC4N-REPO-PTH" {
				t.Errorf("binary .pth format %s falsely emitted %s", f, finding.RuleID)
			}
		}
	}
	// A text .pth file still runs pthRule.
	c := report.NewCollector(0)
	l := limits.Default()
	sess := artifact.NewSession(c, "", l)
	ctx := sess.NewCtx("evil.pth", l)
	src := source.Mem("evil.pth", []byte("import os; os.system('id')\n"))
	universal(ctx, src, artifact.FormatPython)
	src.Close()
	found := false
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-REPO-PTH" {
			found = true
		}
	}
	if !found {
		t.Fatal("text .pth did not emit SC4N-REPO-PTH via universal")
	}
}

func TestSetupHookClassBodyAndNestedDef(t *testing.T) {
	// Class body executes at setup/import time.
	want(t, run(t, "setup.py", "import os\nclass Evil:\n    os.system('id')\n"), "SC4N-REPO-SETUP-HOOK")
	// Control-flow nested inside a def does NOT run at module scope.
	got := run(t, "setup.py", "import os\ndef helper():\n    if True:\n        os.system('id')\n")
	if got["SC4N-REPO-SETUP-HOOK"] {
		t.Fatal("call inside def -> if was falsely reported as module-scope setup hook")
	}
}

func TestBuildBackendTOMLEdgeCases(t *testing.T) {
	cases := []string{
		"[build-system] # PEP 517\nbuild-backend = \"evil.build\"\n",
		"[ build-system ]\n\"build-backend\" = 'evil.build'\n",
		"build-system.build-backend = \"evil.build\"\n",
		"\"build-system\".\"build-backend\" = \"evil.build\"\n",
	}
	for _, toml := range cases {
		want(t, run(t, "pyproject.toml", toml), "SC4N-REPO-BUILD-BACKEND")
	}
}

func TestWorkflowPRTFlexibleExpressions(t *testing.T) {
	cases := []string{
		"on:\n  pull_request_target:\nsteps:\n  - run: echo \"${{github.event.issue.title}}\"\n",
		"on:\n  pull_request_target:\nsteps:\n  - run: echo \"${{ toJSON(github.event.pull_request.title) }}\"\n",
		"on:\n  pull_request_target:\nsteps:\n  - run: echo \"${{ github.head_ref }}\"\n",
	}
	for _, yml := range cases {
		want(t, run(t, ".github/workflows/ci.yml", yml), "SC4N-REPO-WORKFLOW-PRT")
	}
}

func TestPycOrphanPEP3147AndWindowsDriveColon(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "__pycache__")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foo.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// PEP 3147 bytecode with parent ../foo.py must NOT be reported as orphan.
	cached := filepath.Join(cacheDir, "foo.cpython-312.pyc")
	if err := os.WriteFile(cached, []byte{0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, c := newTestCtx(t, 0)
	AnalyzeFile(ctx, cached, []byte{0x00})
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-REPO-PYC-ORPHAN" {
			t.Fatal("PEP 3147 __pycache__/foo.cpython-312.pyc with ../foo.py falsely flagged as orphan")
		}
	}
	// PEP 3147 bytecode with NO parent ../ghost.py MUST be reported as orphan.
	ghost := filepath.Join(cacheDir, "ghost.cpython-312.pyc")
	if err := os.WriteFile(ghost, []byte{0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx2, c2 := newTestCtx(t, 0)
	AnalyzeFile(ctx2, ghost, []byte{0x00})
	found := false
	for _, f := range c2.Findings() {
		if f.RuleID == "SC4N-REPO-PYC-ORPHAN" {
			found = true
		}
	}
	if !found {
		t.Fatal("orphan PEP 3147 __pycache__/ghost.cpython-312.pyc was not reported")
	}
	// Windows drive colons are not container separators; archive chains are.
	if hasContainerColon(`C:\models\__pycache__\foo.cpython-312.pyc`) {
		t.Fatal("Windows drive colon treated as container separator")
	}
	if !hasContainerColon("archive.zip:foo.pyc") {
		t.Fatal("container separator colon not detected")
	}
}
