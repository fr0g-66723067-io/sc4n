package repo

import (
	"bytes"
	"os"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// repoMaxBytes caps how much of a matched file the universal layer reads. Every
// file this package cares about is small (a config, a workflow, a .pth, a small
// script); the cap exists so a name-matched but enormous file cannot be pulled
// into memory, and a file larger than this is still analysed on its first
// MaxRepoBytes.
const repoMaxBytes = 4 << 20

func init() {
	artifact.RegisterUniversal("repo-files", universal)
}

// universal is the engine integration: for every artifact whose display name is
// one of the files this package analyses, it reads the bytes (capped) and runs
// AnalyzeFile. The name test runs first, so an unrelated artifact is not read.
//
// The display name may carry a `container:member` chain (a .pth inside a wheel
// reached as `evil.whl:x.pth`), so matching unwraps the last ':' segment as well.
func universal(ctx *artifact.Ctx, s source.Source, f artifact.Format) {
	name := ctx.Sink.Artifact()
	if !caresAbout(name) {
		return
	}
	// Several rules need only the name (the wheel pointer, the startup-module
	// names, the .pyc sibling stat); reading their bytes would be wasted work and,
	// for a wheel, megabytes of it.
	if !needsBytes(name) {
		AnalyzeFile(ctx, name, nil)
		return
	}
	n := s.Size()
	cap := int64(repoMaxBytes)
	if lim := ctx.Limits.MaxStringBlob; lim > 0 && lim < cap {
		cap = lim
	}
	if n > cap {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", n, cap, "repo file truncated before analysis")
		n = cap
	}
	if n < 0 {
		return
	}
	data, err := s.Bytes(0, n)
	if err != nil && len(data) == 0 {
		return
	}
	AnalyzeFile(ctx, name, data)
}

// needsBytes reports whether a rule for path reads the file's contents.
func needsBytes(path string) bool {
	base := baseName(path)
	switch base {
	case "setup.py", "pyproject.toml":
		return true
	}
	if strings.HasSuffix(base, ".pth") || strings.HasSuffix(base, ".start") {
		return true
	}
	return isWorkflow(path)
}

// caresAbout reports whether path (whole or its last ':' segment) is a file one of
// the rules analyses.
func caresAbout(path string) bool {
	base := baseName(path)
	switch base {
	case "setup.py", "pyproject.toml", "sitecustomize.py", "usercustomize.py", "Dockerfile", "app.py":
		return true
	}
	if strings.HasPrefix(base, "Dockerfile.") {
		return true
	}
	switch {
	case strings.HasSuffix(base, ".pth"),
		strings.HasSuffix(base, ".start"),
		strings.HasSuffix(base, ".pyc"),
		strings.HasSuffix(base, ".whl"),
		strings.HasSuffix(base, ".tar.gz"):
		return true
	}
	return isWorkflow(path)
}

// isWorkflow reports whether path is a file under .github/workflows ending in
// .yml or .yaml.
func isWorkflow(path string) bool {
	if !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
		return false
	}
	return strings.Contains(path, ".github/workflows/")
}

// baseName returns the final path element of a display name, after any member
// chain (`a.whl:b.pth` -> `b.pth`) and after any directory separators.
func baseName(path string) string {
	if i := strings.LastIndexByte(path, ':'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// AnalyzeFile runs the repository-file rules for one path under a scanned root. It
// decides internally whether path is a file it cares about, so it is safe to call
// for any path with any bytes; data may be truncated relative to the file on disk
// (the caller's read cap), which only means a match past the cap is not seen.
func AnalyzeFile(ctx *artifact.Ctx, path string, data []byte) {
	base := baseName(path)
	switch {
	case base == "setup.py":
		setupHookRule(ctx, data)
	case base == "pyproject.toml":
		buildBackendRule(ctx, data)
	case base == "sitecustomize.py" || base == "usercustomize.py":
		ctx.Sink.Emit(ruleSiteCustomize, 0,
			base+" is imported automatically at interpreter startup; its module body runs in every interpreter in this environment")
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		ctx.Sink.Emit(ruleDockerfile, 0,
			base+" is executed when its image is built; sc4n does not parse Dockerfiles, so review it")
	case base == "app.py":
		ctx.Sink.Emit(ruleSpaceApp, 0,
			base+" is the Gradio entry point a Hugging Face Space runs on container start")
	case strings.HasSuffix(base, ".pth"):
		pthRule(ctx, data)
	case strings.HasSuffix(base, ".start"):
		startRule(ctx, data)
	case strings.HasSuffix(base, ".pyc"):
		pycOrphanRule(ctx, path)
	case strings.HasSuffix(base, ".whl") || strings.HasSuffix(base, ".tar.gz"):
		// Only a package archive in the scanned tree, not one nested inside another
		// archive: at depth > 0 it is a member and its own container walk covers it.
		if ctx.Depth == 0 {
			ctx.Sink.Emit(ruleWheelInModel, 0,
				base+" is an installable package archive; its members are scanned separately as an archive")
		}
	}
	if isWorkflow(path) {
		workflowRule(ctx, data)
	}
}

// pthRule reports a .pth line that executes code. site.py executes a line that
// begins with `import` (at interpreter start), so such a line is code execution
// with no import required.
func pthRule(ctx *artifact.Ctx, data []byte) {
	for _, ln := range lines(data) {
		t := strings.TrimLeft(string(ln.text), " \t")
		if strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "import\t") || strings.HasPrefix(t, "exec ") || t == "exec" {
			ctx.Sink.Emit(rulePth, ln.off, "line executes at interpreter start: "+truncate(t))
		}
	}
}

// startRule reports `pkg.mod:callable` entry-point lines in a .start file.
func startRule(ctx *artifact.Ctx, data []byte) {
	for _, ln := range lines(data) {
		t := strings.TrimSpace(string(ln.text))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if looksLikeEntryPoint(t) {
			ctx.Sink.Emit(ruleStart, ln.off, "startup entry point: "+truncate(t))
		}
	}
}

// looksLikeEntryPoint matches `dotted.name:callable` (both sides dotted
// identifiers), the Python 3.15 *.start form.
func looksLikeEntryPoint(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return false
	}
	return isDottedIdent(s[:i]) && isDottedIdent(s[i+1:])
}

func isDottedIdent(s string) bool {
	part := false
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '.':
			if !part {
				return false
			}
			part = false
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			part = true
		default:
			return false
		}
	}
	return part
}

// setupHookRule reports a custom install command or a module-scope shell/exec
// sink in setup.py.
func setupHookRule(ctx *artifact.Ctx, data []byte) {
	s := string(data)
	if off := indexFrom(data, "cmdclass", 0); off >= 0 {
		ctx.Sink.Emit(ruleSetupHook, int64(off), "cmdclass replaces a setuptools command; the hook runs during pip install")
	}
	for _, name := range []string{"install", "develop", "build_py", "sdist", "egg_info", "build_ext"} {
		needle := "def " + name
		if off := indexFrom(data, needle, 0); off >= 0 {
			// Require a plausible command class body: the next non-space byte after
			// the name is '(' or ':'.
			rest := s[off+len(needle):]
			rest = strings.TrimLeft(rest, " \t")
			if strings.HasPrefix(rest, "(") || strings.HasPrefix(rest, ":") {
				ctx.Sink.Emit(ruleSetupHook, int64(off), "defines a "+name+" command hook that runs during install")
			}
		}
	}
	for _, ln := range lines(data) {
		if len(ln.text) == 0 || ln.text[0] == ' ' || ln.text[0] == '\t' {
			continue // indented: inside a function/class, not module scope
		}
		t := strings.TrimLeft(string(ln.text), " \t")
		if strings.HasPrefix(t, "#") {
			continue
		}
		for _, sink := range []string{"os.system", "os.popen", "subprocess.", "urllib.request", "requests.",
			"socket.", "shutil.rmtree", "exec(", "eval(", "__import__(", "compile("} {
			if strings.HasPrefix(t, sink) {
				ctx.Sink.Emit(ruleSetupHook, ln.off, "module-scope call runs during install: "+truncate(t))
			}
		}
	}
}

// buildBackendRule extracts the [build-system] build-backend value textually
// (there is no TOML dependency in the plan) and reports a value outside the
// known-good set.
func buildBackendRule(ctx *artifact.Ctx, data []byte) {
	value, off, ok := buildBackendValue(data)
	if !ok {
		return
	}
	if allowedBackends[value] {
		return
	}
	ctx.Sink.EmitExtra(ruleBuildBackend, int64(off), "build-backend = "+truncate(value),
		map[string]string{"build-backend": value})
}

var allowedBackends = map[string]bool{
	"setuptools.build_meta":            true,
	"setuptools.build_meta:__legacy__": true,
	"hatchling.build":                  true,
	"flit_core.buildapi":               true,
	"poetry.core.masonry.api":          true,
	"maturin":                          true,
	"scikit_build_core.build":          true,
}

// buildBackendValue finds `build-backend` under `[build-system]` and returns its
// value, the offset of the value, and whether it was found.
func buildBackendValue(data []byte) (string, int, bool) {
	ls := lines(data)
	section := ""
	for _, ln := range ls {
		t := strings.TrimSpace(string(ln.text))
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = t
			continue
		}
		if section != "[build-system]" {
			continue
		}
		key, val, ok := splitTOMLKeyValue(t)
		if !ok || key != "build-backend" {
			continue
		}
		valOffset := int(ln.off) + strings.Index(string(ln.text), val)
		return val, valOffset, true
	}
	return "", 0, false
}

// splitTOMLKeyValue splits `key = "value"` (the only form the rule needs) and
// unquotes the value.
func splitTOMLKeyValue(t string) (key, val string, ok bool) {
	eq := strings.IndexByte(t, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(t[:eq])
	val = strings.TrimSpace(t[eq+1:])
	// Drop a trailing comment outside quotes.
	if i := strings.IndexByte(val, '#'); i >= 0 {
		val = strings.TrimSpace(val[:i])
	}
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			return key, val[1 : len(val)-1], true
		}
	}
	return key, val, true
}

// workflowRule matches the pull_request_target + `${{ github.event.* }}` in a
// `run:` pattern textually. There is no YAML library linked by design, so the
// finding states the co-occurrence it saw.
func workflowRule(ctx *artifact.Ctx, data []byte) {
	if indexFrom(data, "pull_request_target", 0) < 0 {
		return
	}
	evOff := indexFrom(data, "${{ github.event.", 0)
	if evOff < 0 {
		return
	}
	if indexFrom(data, "run:", 0) < 0 {
		return
	}
	// Emit at the interpolation, which is the risky site.
	ctx.Sink.Emit(ruleWorkflowPRT, int64(evOff),
		"pull_request_target workflow interpolates ${{ github.event.* }} into a run: step (textual match; no YAML parser)")
}

// pycOrphanRule reports a .pyc with no .py sibling. It only fires for a real path
// (never for an archive member), and only when the .pyc itself is on disk, so it
// cannot misfire on a synthetic or stdin name.
func pycOrphanRule(ctx *artifact.Ctx, path string) {
	if strings.Contains(path, ":") {
		return
	}
	if _, err := os.Stat(path); err != nil {
		return
	}
	sibling := strings.TrimSuffix(path, "c")
	if _, err := os.Stat(sibling); err == nil {
		return
	}
	ctx.Sink.Emit(rulePycOrphan, 0, "no .py source beside this .pyc, so its bytecode was not analysed")
}

type line struct {
	off  int64
	text []byte
}

// lines splits data into lines, recording each line's byte offset.
func lines(data []byte) []line {
	var out []line
	start := 0
	for i := range data {
		if data[i] == '\n' {
			out = append(out, line{off: int64(start), text: data[start:i]})
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, line{off: int64(start), text: data[start:]})
	}
	return out
}

// indexFrom is bytes.Index for a string needle, from offset from.
func indexFrom(data []byte, needle string, from int) int {
	if from < 0 {
		from = 0
	}
	if len(needle) == 0 || from >= len(data) {
		return -1
	}
	i := bytes.Index(data[from:], []byte(needle))
	if i < 0 {
		return -1
	}
	return from + i
}

func truncate(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
