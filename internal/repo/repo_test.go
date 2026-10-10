package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
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
