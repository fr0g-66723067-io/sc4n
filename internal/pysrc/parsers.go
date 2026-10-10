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
// Python file with an unhelpful name. The heuristic is deliberately strict: a file
// it does not recognise falls through to the shallow text scanner, which is
// honest about not having analysed it, rather than being mis-lexed as Python.

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
	if pythonExts[lowerExt(s.Name())] {
		return artifact.FormatPython, true
	}
	if pythonLooksLike(head) {
		return artifact.FormatPython, true
	}
	return artifact.FormatUnknown, false
}

// pythonLooksLike is a content test for a Python source with no useful extension.
// It requires several statement-starting constructs so that prose, TOML, YAML and
// a one-line .start entry point are not claimed.
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
	for _, line := range bytes.Split(head, []byte{'\n'}) {
		t := strings.TrimLeft(string(line), " \t")
		switch {
		case strings.HasPrefix(t, "def "), strings.HasPrefix(t, "class "),
			strings.HasPrefix(t, "import "), strings.HasPrefix(t, "from "),
			strings.HasPrefix(t, "async def "), strings.HasPrefix(t, "@"),
			strings.HasPrefix(t, "if __name__"), strings.HasPrefix(t, "elif "),
			strings.HasPrefix(t, "else:"), strings.HasPrefix(t, "try:"),
			strings.HasPrefix(t, "with "), strings.HasPrefix(t, "return "),
			strings.HasPrefix(t, "print("), strings.HasPrefix(t, "#"):
			score++
		}
	}
	return score >= 3
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
