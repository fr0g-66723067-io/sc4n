package pysrc

import (
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
)

// Notebook handling.
//
// A .ipynb file is JSON, but a finding inside a cell is useless if it points at
// the wrong line. sc4n therefore reconstructs each code cell's source and, in
// parallel, records for every reconstructed line the line of the .ipynb file it
// came from, so `Sink.EmitAt` reports the line a reviewer would open in Jupyter.
// The mapping exploits nbformat's own layout: source is normally an array of
// strings, one per line, each with its trailing newline, so each array element's
// physical line is that line's line in the file. A single-string source maps every
// line to the string's own line, which is the best that can be done without
// re-escaping the JSON.
//
// IPython magics and shell escapes are reported separately from ordinary Python
// findings, because they are executed by the notebook kernel rather than being
// valid Python the lexer would see.

// notebookCell is one reconstructed code cell.
type notebookCell struct {
	text  []byte
	lines []int // lines[k] is the original 1-based line of text's line k+1
}

// AnalyzeNotebook analyses the code cells of an .ipynb document.
func AnalyzeNotebook(ctx *artifact.Ctx, raw []byte) {
	raw = capSource(ctx, raw)
	li := newLineIndex(raw)
	for _, cell := range notebookCells(raw, li) {
		analyze(ctx, cell.text, cell.lines)
		notebookMagic(ctx, cell)
	}
}

// notebookCells extracts every code cell from the raw JSON. It is a bounded,
// hand-written scan rather than encoding/json because it needs byte offsets, and
// because a malformed notebook must yield whatever cells are readable rather than
// an error that hides the rest.
func notebookCells(raw []byte, li lineIndex) []notebookCell {
	var out []notebookCell
	for _, obj := range topLevelObjects(raw, "cells") {
		if !cellIsCode(raw, obj) {
			continue
		}
		text, lines := sourceValue(raw, obj, li)
		if len(text) == 0 {
			continue
		}
		out = append(out, notebookCell{text: text, lines: lines})
	}
	return out
}

// topLevelObjects returns the byte ranges [start,end) of every object in the JSON
// array that follows key. It tracks string and escape state so braces inside
// strings do not confuse the depth count.
func topLevelObjects(raw []byte, key string) [][2]int {
	ki := findKey(raw, key)
	if ki < 0 {
		return nil
	}
	i := skipSpace(raw, ki+len(key)+2)
	if i >= len(raw) || raw[i] != ':' {
		return nil
	}
	i = skipSpace(raw, i+1)
	if i >= len(raw) || raw[i] != '[' {
		return nil
	}
	i++
	var objs [][2]int
	depth := 0
	objStart := -1
	for i < len(raw) {
		c := raw[i]
		switch c {
		case '"':
			i = skipJSONString(raw, i)
			continue
		case '{':
			if depth == 0 {
				objStart = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && objStart >= 0 {
					objs = append(objs, [2]int{objStart, i + 1})
					objStart = -1
				}
			}
		case ']':
			if depth == 0 {
				return objs
			}
		}
		i++
	}
	return objs
}

// cellIsCode reports whether the object's "cell_type" is "code".
func cellIsCode(raw []byte, obj [2]int) bool {
	ki := findKeyIn(raw, obj, "cell_type")
	if ki < 0 {
		return false
	}
	i := skipSpace(raw, ki+len("cell_type")+2)
	if i >= len(raw) || raw[i] != ':' {
		return false
	}
	i = skipSpace(raw, i+1)
	if i >= len(raw) || raw[i] != '"' {
		return false
	}
	end := skipJSONString(raw, i)
	if end > len(raw) {
		end = len(raw)
	}
	return strings.Trim(string(raw[i:end]), "\"") == "code"
}

// sourceValue reconstructs a cell's source and its line map. It handles both the
// array-of-strings form and the single-string form.
func sourceValue(raw []byte, obj [2]int, li lineIndex) ([]byte, []int) {
	ki := findKeyIn(raw, obj, "source")
	if ki < 0 {
		return nil, nil
	}
	i := skipSpace(raw, ki+len("source")+2)
	if i >= len(raw) || raw[i] != ':' {
		return nil, nil
	}
	i = skipSpace(raw, i+1)
	if i >= len(raw) {
		return nil, nil
	}

	var text []byte
	var lines []int
	atLineStart := true
	appendPart := func(partStart, partEnd int) {
		line := 1
		if l, _ := li.at(int32(partStart)); l > 0 {
			line = l
		}
		dec := unescapeJSON(raw[partStart:partEnd])
		for _, c := range dec {
			if atLineStart {
				lines = append(lines, line)
				atLineStart = false
			}
			text = append(text, c)
			if c == '\n' {
				atLineStart = true
			}
		}
	}

	switch raw[i] {
	case '"':
		end := skipJSONString(raw, i)
		if end <= i+1 {
			return nil, nil
		}
		appendPart(i+1, end-1)
	case '[':
		i++
		for i < len(raw) {
			i = skipSpace(raw, i)
			if i >= len(raw) {
				break
			}
			if raw[i] == ']' {
				break
			}
			if raw[i] == ',' {
				i++
				continue
			}
			if raw[i] == '"' {
				end := skipJSONString(raw, i)
				if end <= i+1 {
					break
				}
				appendPart(i+1, end-1)
				i = end
				continue
			}
			i++
		}
	default:
		return nil, nil
	}
	return text, lines
}

// notebookMagic reports IPython magics and shell escapes.
func notebookMagic(ctx *artifact.Ctx, cell notebookCell) {
	lines := strings.Split(string(cell.text), "\n")
	for k, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue
		}
		origLine := 1
		if k < len(cell.lines) && cell.lines[k] > 0 {
			origLine = cell.lines[k]
		}
		col := len(line) - len(trimmed) + 1
		var what string
		switch {
		case strings.HasPrefix(trimmed, "!"):
			what = "shell escape (!cmd)"
		case strings.HasPrefix(trimmed, "%%bash"):
			what = "cell magic %%bash"
		case strings.HasPrefix(trimmed, "%%sh"):
			what = "cell magic %%sh"
		case strings.HasPrefix(trimmed, "%%javascript"):
			what = "cell magic %%javascript"
		case strings.HasPrefix(trimmed, "%%html"):
			what = "cell magic %%html"
		case strings.HasPrefix(trimmed, "%%writefile"):
			what = "cell magic %%writefile"
		case strings.HasPrefix(trimmed, "%run"):
			what = "line magic %run"
		case strings.HasPrefix(trimmed, "%system"):
			what = "line magic %system"
		}
		if what != "" {
			ctx.Sink.EmitAt(ruleNotebookMagic, origLine, col,
				what+": "+report.TruncateEvidence(trimmed, 160))
		}
	}
}

// ---- minimal JSON scanning ----------------------------------------------------

func skipSpace(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// skipJSONString returns the index just past the string beginning at the quote at
// i, or len(b) if unterminated.
func skipJSONString(b []byte, i int) int {
	if i >= len(b) || b[i] != '"' {
		return i
	}
	i++
	for i < len(b) {
		switch b[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return i + 1
		}
		i++
	}
	return len(b)
}

// findKey returns the index of the `"key"` token in b, or -1.
func findKey(b []byte, key string) int {
	needle := "\"" + key + "\""
	return indexBytes(b, []byte(needle))
}

// findKeyIn is findKey restricted to the [start,end) object range, with offsets
// returned absolute in raw.
func findKeyIn(raw []byte, obj [2]int, key string) int {
	if obj[0] < 0 || obj[1] > len(raw) || obj[0] >= obj[1] {
		return -1
	}
	rel := findKey(raw[obj[0]:obj[1]], key)
	if rel < 0 {
		return -1
	}
	return obj[0] + rel
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for k := range needle {
			if haystack[i+k] != needle[k] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// unescapeJSON decodes the JSON string body b (without the surrounding quotes)
// for the escapes nbformat uses in source lines. Unknown escapes are kept
// verbatim; the result is capped so a pathological cell cannot allocate.
func unescapeJSON(b []byte) []byte {
	const cap = 1 << 20
	out := make([]byte, 0, minInt(len(b), cap))
	for i := 0; i < len(b) && len(out) < cap; i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		switch b[i+1] {
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 'r':
			out = append(out, '\r')
		case '"':
			out = append(out, '"')
		case '\\':
			out = append(out, '\\')
		case '/':
			out = append(out, '/')
		case 'u':
			if i+5 < len(b) {
				if v, ok := hex4(b[i+2 : i+6]); ok {
					out = appendRune(out, v)
					i += 5
					continue
				}
			}
			out = append(out, b[i])
		default:
			out = append(out, b[i], b[i+1])
		}
		i++
	}
	return out
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var v rune
	for i := 0; i < 4; i++ {
		d, ok := hexVal(b[i])
		if !ok {
			return 0, false
		}
		v = v<<4 | rune(d)
	}
	return v, true
}

func appendRune(b []byte, r rune) []byte {
	if r < 0x80 {
		return append(b, byte(r))
	}
	if r < 0x800 {
		return append(b, byte(0xC0|r>>6), byte(0x80|r&0x3F))
	}
	if r >= 0xD800 && r <= 0xDFFF {
		// A lone surrogate: keep it as an escape-ish placeholder rather than
		// producing invalid UTF-8.
		return append(b, '?')
	}
	return append(b, byte(0xE0|r>>12), byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
