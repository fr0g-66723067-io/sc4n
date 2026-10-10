package pysrc

import (
	"bytes"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Parser registration for Python source and notebooks.
//
// Dispatch is by content, but a .py file has no magic. The sniffer therefore uses
// source.Name() (which is the path, or the `container:member` name inside an
// archive) for the extension hint and falls back to a content heuristic for a
// Python file with an unhelpful name. The name is checked first: an extension
// that is known and does not plausibly mean Python is rejected outright, because
// the content heuristic cannot separate Python from the languages that share its
// comment marker and statement shapes (C++, TypeScript, WGSL, shell, Markdown
// headings). The heuristic is then deliberately strict: a file it does not
// recognise falls through to the shallow text scanner, which is honest about not
// having analysed it, rather than being mis-lexed as Python.

func init() {
	// These run above the generic protobuf sniffer ("onnx-proto" at 60) so a
	// Python file or an .ipynb document is not mistaken for a protobuf message;
	// they stay below the unambiguous magic/pickle sniffers.
	artifact.RegisterSniffer("notebook", 68, sniffNotebook)
	artifact.RegisterSniffer("python-src", 66, sniffPython)
	artifact.RegisterParser(artifact.FormatPython, pythonParser{})
	artifact.RegisterParser(artifact.FormatNotebook, notebookParser{})
}

type pythonParser struct{}

func (pythonParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	data, err := s.Bytes(0, s.Size())
	if err != nil && len(data) == 0 {
		return err
	}
	Analyze(ctx, data)
	return nil
}

type notebookParser struct{}

func (notebookParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	data, err := s.Bytes(0, s.Size())
	if err != nil && len(data) == 0 {
		return err
	}
	AnalyzeNotebook(ctx, data)
	return nil
}

// lastSegment returns the part of a display name after the last ':' so that a
// member name (`model.pt:code/x.py`) still exposes its own basename for the
// extension hint.
func lastSegment(name string) string {
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func lowerExt(name string) string {
	name = lastSegment(name)
	i := strings.LastIndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

var pythonExts = map[string]bool{"py": true, "pyi": true, "pyw": true, "pth": true}

// otherLanguageExts names extensions the artifact format map does not know and
// that unambiguously belong to another language. They are rejected before the
// content heuristic runs. The heuristic scored 2149 of the 3613 files in
// llama.cpp's index-src as Python (only 220 are .py) because `#` is the comment
// marker of C, C++, shell, YAML, TOML and Makefile and the heading marker of
// Markdown, while `import`, `class`, `return` and `@` are shared with
// TypeScript, C++, Swift, Kotlin, GLSL and WGSL; the misroute produced 177
// findings, three of them critical, on non-Python files.
var otherLanguageExts = map[string]bool{
	"c": true, "h": true, "cc": true, "cpp": true, "cxx": true, "hpp": true, "hh": true, "hxx": true,
	"cu": true, "cuh": true, "m": true, "mm": true,
	"ts": true, "tsx": true, "js": true, "jsx": true, "mjs": true, "cjs": true,
	"svelte": true, "vue": true,
	"sh": true, "bash": true, "zsh": true, "fish": true, "ps1": true, "bat": true, "cmd": true,
	"kt": true, "kts": true, "swift": true, "java": true, "go": true, "rs": true, "rb": true,
	"php": true, "pl": true, "pm": true, "r": true, "sql": true,
	"css": true, "scss": true, "sass": true, "less": true, "html": true, "htm": true, "xml": true,
	"toml": true, "ini": true, "cfg": true, "conf": true, "cmake": true, "nix": true,
	"glsl": true, "wgsl": true, "metal": true, "cl": true, "comp": true, "tex": true,
	"asm": true, "s": true, "vim": true, "idl": true, "pro": true, "spec": true, "gbnf": true,
	"mk": true, "dockerfile": true, "properties": true, "in": true, "out": true,
	"patch": true, "diff": true,
}

// templateExts are the names a chat template is shipped under. A template is not
// Python source even when its first lines are comments and `import`s: llama.cpp's
// models/templates holds three templates that pythonLooksLike scored as Python,
// which cost them their template analysis and added a false extension-mismatch.
var templateExts = map[string]bool{"jinja": true, "jinja2": true, "j2": true, "tmpl": true}

// sniffPython recognises Python source.
func sniffPython(s source.Source, l limits.Limits) (artifact.Format, bool) {
	n := s.Size()
	if n < 1 {
		return artifact.FormatUnknown, false
	}
	probe := n
	if probe > 16384 {
		probe = 16384
	}
	head, err := s.Bytes(0, probe)
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return artifact.FormatUnknown, false
	}
	ext := lowerExt(s.Name())
	if templateExts[ext] {
		// The name says template. jinja-template (67) runs before this sniffer
		// and will have claimed it; this guard keeps the answer the same if that
		// registration is ever reordered.
		return artifact.FormatUnknown, false
	}
	if pythonExts[ext] {
		return artifact.FormatPython, true
	}
	if ext != "" {
		// A known extension that does not plausibly mean Python, or an extension
		// that names another language, settles it: the content heuristic below
		// cannot tell Python from the languages that share its shapes.
		if !artifact.ExtensionPlausible(lastSegment(s.Name()), artifact.FormatPython) || otherLanguageExts[ext] {
			return artifact.FormatUnknown, false
		}
	}
	if pythonLooksLike(head) {
		return artifact.FormatPython, true
	}
	return artifact.FormatUnknown, false
}

// pythonLooksLike is a content test for a Python source with no useful extension.
// It requires a strong construct (`def `, `class `, `async def `, `if __name__`,
// `from `, `print(`) and several statement-starting constructs, so that prose,
// TOML, YAML, C++, TypeScript, WGSL and a one-line .start entry point are not
// claimed. The comment marker `#` and the decorator `@` are deliberately not
// counted: `#` is the comment marker of C, C++, shell, YAML, TOML and Makefile
// and the heading marker of Markdown, and `@` is WGSL/Java/Kotlin annotation
// syntax, so counting them claimed whole source trees as Python.
func pythonLooksLike(head []byte) bool {
	if bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n\ufeff"), []byte("#!")) {
		first := head
		if i := bytes.IndexByte(head, '\n'); i >= 0 {
			first = head[:i]
		}
		if bytes.Contains(first, []byte("python")) {
			return true
		}
	}
	score := 0
	strong := false
	for _, line := range bytes.Split(head, []byte{'\n'}) {
		t := strings.TrimLeft(string(line), " \t")
		switch {
		case strings.HasPrefix(t, "def "), strings.HasPrefix(t, "class "),
			strings.HasPrefix(t, "async def "), strings.HasPrefix(t, "if __name__"),
			strings.HasPrefix(t, "from "), strings.HasPrefix(t, "print("):
			strong = true
			score++
		case strings.HasPrefix(t, "import "), strings.HasPrefix(t, "elif "),
			strings.HasPrefix(t, "else:"), strings.HasPrefix(t, "try:"),
			strings.HasPrefix(t, "with "), strings.HasPrefix(t, "return "):
			score++
		}
	}
	return strong && score >= 3
}

// sniffNotebook recognises an .ipynb document.
func sniffNotebook(s source.Source, l limits.Limits) (artifact.Format, bool) {
	n := s.Size()
	if n < 2 {
		return artifact.FormatUnknown, false
	}
	probe := n
	if probe > 65536 {
		probe = 65536
	}
	head, err := s.Bytes(0, probe)
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	trimmed := bytes.TrimLeft(head, " \t\r\n\ufeff")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return artifact.FormatUnknown, false
	}
	if lowerExt(s.Name()) == "ipynb" {
		return artifact.FormatNotebook, true
	}
	if bytes.Contains(head, []byte(`"cells"`)) && bytes.Contains(head, []byte(`"cell_type"`)) {
		return artifact.FormatNotebook, true
	}
	return artifact.FormatUnknown, false
}
