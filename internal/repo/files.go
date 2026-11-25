package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"

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
	// A `.pth` file can be either a Python site.py path-configuration text file
	// or a PyTorch binary checkpoint (zip/pickle/torch-legacy/archive). Skip
	// binary/archive/model formats before the 4 MiB truncation check so large
	// PyTorch checkpoints named `.pth` never emit false SC4N-REPO-TRUNCATED.
	if strings.HasSuffix(baseName(name), ".pth") && !isTextPthFormat(f) {
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
		ctx.Sink.EmitExtra(ruleRepoTroncated, 0,
			"repository file is "+strconv.FormatInt(n, 10)+" bytes but only the first "+strconv.FormatInt(cap, 10)+" were analysed",
			map[string]string{"size": strconv.FormatInt(n, 10), "cap": strconv.FormatInt(cap, 10), "file": baseName(name)})
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

// isTextPthFormat reports whether a sniffed format can be a Python site.py
// `.pth` text file rather than a binary PyTorch checkpoint or archive.
func isTextPthFormat(f artifact.Format) bool {
	switch f {
	case artifact.FormatPython, artifact.FormatText, artifact.FormatUTF16, artifact.FormatUnknown:
		return true
	}
	return false
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
		strings.HasSuffix(base, ".tar.gz"),
		strings.HasSuffix(base, ".tgz"):
		return true
	}
	return isWorkflow(path)
}

// isWorkflow reports whether path is a file under .github/workflows ending in
// .yml or .yaml.
func isWorkflow(path string) bool {
	path = strings.ReplaceAll(path, "\\", "/")
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
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
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
	case strings.HasSuffix(base, ".whl"), strings.HasSuffix(base, ".tar.gz"), strings.HasSuffix(base, ".tgz"):
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
			ctx.Sink.Emit(rulePth, ln.off, "line executes at interpreter start: "+report.TruncateEvidence(t, 120))
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
			ctx.Sink.Emit(ruleStart, ln.off, "startup entry point: "+report.TruncateEvidence(t, 120))
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
	type block struct {
		indent int
		kind   string
	}
	var stack []block
	for _, ln := range lines(data) {
		raw := string(ln.text)
		t := strings.TrimLeft(raw, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indent := len(raw) - len(t)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		// Class bodies execute at module scope during import/setup; only def
		// bodies (including any nested control-flow inside a def) are deferred.
		inDef := false
		for _, fr := range stack {
			if fr.kind == "def" {
				inDef = true
				break
			}
		}
		if !inDef {
			for _, sink := range []string{
				"os.system", "os.popen", "subprocess.", "urllib.request", "requests.",
				"socket.", "shutil.rmtree", "exec(", "eval(", "__import__(", "compile(",
			} {
				if strings.HasPrefix(t, sink) {
					ctx.Sink.Emit(ruleSetupHook, ln.off, "module-scope call runs during install: "+report.TruncateEvidence(t, 120))
				}
			}
		}
		if strings.HasPrefix(t, "async def ") {
			stack = append(stack, block{indent: indent, kind: "def"})
			continue
		}
		for _, kw := range []string{"def ", "class ", "if ", "elif ", "else:", "try:", "except", "finally:", "for ", "while ", "with ", "async with ", "async for "} {
			if strings.HasPrefix(t, kw) {
				kind := strings.TrimRight(strings.TrimSpace(kw), ":")
				stack = append(stack, block{indent: indent, kind: kind})
				break
			}
		}
	}
}

// buildBackendRule extracts the [build-system] build-backend value textually
// (there is no TOML dependency in the plan) and reports a value outside the
// known-good set.
func buildBackendRule(ctx *artifact.Ctx, data []byte) {
	if path, poff, ok := buildSystemKey(data, "backend-path"); ok {
		ctx.Sink.EmitExtra(ruleBackendPath, int64(poff),
			"backend-path = "+report.TruncateEvidence(path, 120)+" shadows the build backend with repository code",
			map[string]string{"backend-path": path})
	}
	value, off, ok := buildBackendValue(data)
	if !ok {
		return
	}
	if allowedBackends[value] {
		return
	}
	ctx.Sink.EmitExtra(ruleBuildBackend, int64(off), "build-backend = "+report.TruncateEvidence(value, 120),
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

// buildSystemKey finds a key under [build-system] (or a top-level dotted key
// `build-system.<key>`) and returns its unquoted value and byte offset.
func buildSystemKey(data []byte, key string) (string, int, bool) {
	section := ""
	for _, ln := range lines(data) {
		t := stripTOMLComment(string(ln.text))
		if t == "" {
			continue
		}
		if sec, ok := parseTOMLSection(t); ok {
			section = sec
			continue
		}
		k, val, ok := splitTOMLKeyValue(t)
		if !ok {
			continue
		}
		if (section == "build-system" && k == key) || (section == "" && k == "build-system."+key) {
			idx := strings.Index(string(ln.text), val)
			if idx < 0 {
				idx = 0
			}
			return val, int(ln.off) + idx, true
		}
	}
	return "", 0, false
}

// buildBackendValue finds `build-backend` under `[build-system]` (or top-level
// `build-system.build-backend`) and returns its value, offset and whether found.
func buildBackendValue(data []byte) (string, int, bool) {
	return buildSystemKey(data, "build-backend")
}

// stripTOMLComment removes an unquoted `# ...` comment from a TOML line and
// trims surrounding whitespace.
func stripTOMLComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if quote == '"' && c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '#' {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
}

// parseTOMLSection parses a `[section]` header (allowing interior whitespace
// and quoted segments) and returns its canonical dotted name.
func parseTOMLSection(t string) (string, bool) {
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return "", false
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	if strings.HasPrefix(inner, "[") && strings.HasSuffix(inner, "]") {
		inner = strings.TrimSpace(inner[1 : len(inner)-1])
	}
	key, ok := parseTOMLKey(inner)
	if !ok {
		return "", false
	}
	return key, true
}

// parseTOMLKey normalises a bare, quoted or dotted TOML key (`build-system`,
// `"build-backend"`, `'build-system'.build-backend`).
func parseTOMLKey(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	var parts []string
	var cur strings.Builder
	var quote byte
	flush := func() bool {
		p := strings.TrimSpace(cur.String())
		cur.Reset()
		if p == "" {
			return false
		}
		parts = append(parts, unquoteTOML(p))
		return true
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			if quote == '"' && c == '\\' && i+1 < len(raw) {
				cur.WriteByte(c)
				cur.WriteByte(raw[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			cur.WriteByte(c)
			continue
		}
		if c == '.' {
			if !flush() {
				return "", false
			}
			continue
		}
		cur.WriteByte(c)
	}
	if quote != 0 || !flush() {
		return "", false
	}
	return strings.Join(parts, "."), true
}

func unquoteTOML(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

// splitTOMLKeyValue splits `key = "value"` (with bare, quoted or dotted keys)
// and unquotes the value.
func splitTOMLKeyValue(t string) (key, val string, ok bool) {
	eq := -1
	var quote byte
	for i := 0; i < len(t); i++ {
		c := t[i]
		if quote != 0 {
			if quote == '"' && c == '\\' && i+1 < len(t) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '=' {
			eq = i
			break
		}
	}
	if eq < 0 {
		return "", "", false
	}
	key, ok = parseTOMLKey(t[:eq])
	if !ok {
		return "", "", false
	}
	val = strings.TrimSpace(t[eq+1:])
	val = unquoteTOML(val)
	return key, val, true
}

// workflowRule matches the pull_request_target + `${{ ... github.event.* / github.head_ref ... }}`
// in a `run:` pattern textually. There is no YAML library linked by design, so
// the finding states the co-occurrence it saw.
func workflowRule(ctx *artifact.Ctx, data []byte) {
	if indexFrom(data, "pull_request_target", 0) < 0 {
		return
	}
	evOff := findUntrustedWorkflowExpr(data)
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

// findUntrustedWorkflowExpr locates the first `${{ ... }}` interpolation that
// references `github.event.` or `github.head_ref`, tolerating arbitrary
// whitespace and wrapping expressions (e.g. `toJSON(github.event.issue.title)`).
func findUntrustedWorkflowExpr(data []byte) int {
	pos := 0
	for pos < len(data) {
		open := indexFrom(data, "${{", pos)
		if open < 0 {
			return -1
		}
		close := indexFrom(data, "}}", open+3)
		if close < 0 {
			close = len(data)
		}
		expr := data[open+3 : close]
		if bytes.Contains(expr, []byte("github.event.")) || bytes.Contains(expr, []byte("github.head_ref")) {
			return open
		}
		if close >= len(data) {
			break
		}
		pos = close + 2
	}
	return -1
}

// pycOrphanRule reports a .pyc with no .py sibling. It only fires for a real path
// (never for an archive member), and only when the .pyc itself is on disk, so it
// cannot misfire on a synthetic or stdin name. PEP 3147 bytecode files under
// `__pycache__/<name>.<tag>.pyc` resolve their source at `../<name>.py`.
func pycOrphanRule(ctx *artifact.Ctx, path string) {
	if hasContainerColon(path) {
		return
	}
	if _, err := os.Stat(path); err != nil {
		return
	}
	sibling := strings.TrimSuffix(path, "c")
	if _, err := os.Stat(sibling); err == nil {
		return
	}
	dir := filepath.Dir(path)
	if filepath.Base(dir) == "__pycache__" {
		stem := strings.TrimSuffix(filepath.Base(path), ".pyc")
		if dot := strings.IndexByte(stem, '.'); dot > 0 {
			parentPy := filepath.Join(filepath.Dir(dir), stem[:dot]+".py")
			if _, err := os.Stat(parentPy); err == nil {
				return
			}
		}
	}
	ctx.Sink.Emit(rulePycOrphan, 0, "no .py source beside this .pyc, so its bytecode was not analysed")
}

// hasContainerColon reports whether path carries a container-member `:` rather
// than a Windows drive prefix (`C:...`).
func hasContainerColon(path string) bool {
	start := 0
	if len(path) >= 2 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' {
		start = 2
	}
	return strings.IndexByte(path[start:], ':') >= 0
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
