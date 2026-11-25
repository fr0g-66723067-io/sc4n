package pysrc

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Notebook handling.
//
// A .ipynb file is JSON, but a finding inside a cell is useless if it points at
// the wrong line. sc4n therefore walks the notebook structurally with
// encoding/json's token stream (so string decoys in metadata and \uXXXX escapes
// in keys/values cannot hide code cells), reconstructs each code cell's source
// and, in parallel, records for every reconstructed line the physical line of
// the .ipynb file it came from via json.Decoder.InputOffset.
//
// IPython magics and shell escapes are reported separately from ordinary Python
// findings, because they are executed by the notebook kernel rather than being
// valid Python the lexer would see.

// maxNotebookCellBytes caps the decoded source size of one notebook cell. A
// cell exceeding it is truncated and reported with SC4N-LIMIT-STRING rather
// than silently cropped.
const maxNotebookCellBytes = 1 << 20

// notebookCell is one reconstructed code cell.
type notebookCell struct {
	text  []byte
	lines []int // lines[k] is the original 1-based line of text's line k+1
}

type sourcePart struct {
	line int
	text string
}

// AnalyzeNotebook analyses the code cells of an .ipynb document.
func AnalyzeNotebook(ctx *artifact.Ctx, raw []byte) {
	raw = capSource(ctx, raw)
	li := newLineIndex(raw)
	for _, cell := range notebookCells(ctx, raw, li) {
		analyze(ctx, cell.text, cell.lines)
		notebookMagic(ctx, cell)
	}
}

// notebookCells extracts every code cell structurally from the raw JSON.
// Streaming through json.Decoder yields any cells decoded before a syntax error
// in a malformed notebook rather than discarding the entire file.
func notebookCells(ctx *artifact.Ctx, raw []byte, li lineIndex) []notebookCell {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil
	}
	var out []notebookCell
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return out
		}
		key, ok := kt.(string)
		if !ok {
			return out
		}
		if key != "cells" {
			if err := skipJSONValue(dec); err != nil {
				return out
			}
			continue
		}
		valTok, err := dec.Token()
		if err != nil {
			return out
		}
		if d, ok := valTok.(json.Delim); !ok || d != '[' {
			if ok && d == '{' {
				if err := skipJSONContainer(dec); err != nil {
					return out
				}
			}
			continue
		}
		for dec.More() {
			cell, ok, err := readCellObject(ctx, dec, raw, li)
			if err != nil {
				return out
			}
			if ok && len(cell.text) > 0 {
				out = append(out, cell)
			}
		}
		// Consume closing ']'.
		if _, err := dec.Token(); err != nil {
			return out
		}
	}
	return out
}

// readCellObject decodes one element of the top-level "cells" array.
func readCellObject(ctx *artifact.Ctx, dec *json.Decoder, raw []byte, li lineIndex) (notebookCell, bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return notebookCell{}, false, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return notebookCell{}, false, nil
	}
	if d != '{' {
		if d == '[' {
			if err := skipJSONContainer(dec); err != nil {
				return notebookCell{}, false, err
			}
		}
		return notebookCell{}, false, nil
	}
	var cellType string
	var parts []sourcePart
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return buildCell(ctx, cellType, parts), cellType == "code", err
		}
		key, ok := kt.(string)
		if !ok {
			return notebookCell{}, false, nil
		}
		switch key {
		case "cell_type":
			vt, err := dec.Token()
			if err != nil {
				return buildCell(ctx, cellType, parts), cellType == "code", err
			}
			if s, ok := vt.(string); ok {
				cellType = s
			} else if vd, ok := vt.(json.Delim); ok && (vd == '{' || vd == '[') {
				if err := skipJSONContainer(dec); err != nil {
					return notebookCell{}, false, err
				}
			}
		case "source":
			prev := dec.InputOffset()
			vt, err := dec.Token()
			if err != nil {
				return buildCell(ctx, cellType, parts), cellType == "code", err
			}
			switch v := vt.(type) {
			case string:
				off := findJSONStringStart(raw, prev, dec.InputOffset())
				line := 1
				if l, _ := li.at(int32(off)); l > 0 {
					line = l
				}
				parts = append(parts, sourcePart{line: line, text: v})
			case json.Delim:
				if v == '[' {
					for dec.More() {
						eprev := dec.InputOffset()
						et, err := dec.Token()
						if err != nil {
							return buildCell(ctx, cellType, parts), cellType == "code", err
						}
						if s, ok := et.(string); ok {
							off := findJSONStringStart(raw, eprev, dec.InputOffset())
							line := 1
							if l, _ := li.at(int32(off)); l > 0 {
								line = l
							}
							parts = append(parts, sourcePart{line: line, text: s})
						} else if ed, ok := et.(json.Delim); ok && (ed == '{' || ed == '[') {
							if err := skipJSONContainer(dec); err != nil {
								return notebookCell{}, false, err
							}
						}
					}
					if _, err := dec.Token(); err != nil {
						return buildCell(ctx, cellType, parts), cellType == "code", err
					}
				} else if v == '{' {
					if err := skipJSONContainer(dec); err != nil {
						return notebookCell{}, false, err
					}
				}
			}
		default:
			if err := skipJSONValue(dec); err != nil {
				return buildCell(ctx, cellType, parts), cellType == "code", err
			}
		}
	}
	// Consume closing '}'.
	if _, err := dec.Token(); err != nil {
		return buildCell(ctx, cellType, parts), cellType == "code", err
	}
	if cellType != "code" {
		return notebookCell{}, false, nil
	}
	return buildCell(ctx, cellType, parts), true, nil
}

// buildCell joins a code cell's source parts into a byte buffer + line map,
// enforcing maxNotebookCellBytes and emitting SC4N-LIMIT-STRING on truncation.
func buildCell(ctx *artifact.Ctx, cellType string, parts []sourcePart) notebookCell {
	if cellType != "code" || len(parts) == 0 {
		return notebookCell{}
	}
	var total int64
	for _, p := range parts {
		total += int64(len(p.text))
	}
	var text []byte
	var lines []int
	atLineStart := true
	truncated := false
	for _, p := range parts {
		for i := 0; i < len(p.text); i++ {
			if len(text) >= maxNotebookCellBytes {
				truncated = true
				break
			}
			c := p.text[i]
			if atLineStart {
				lines = append(lines, p.line)
				atLineStart = false
			}
			text = append(text, c)
			if c == '\n' {
				atLineStart = true
			}
		}
		if truncated {
			break
		}
	}
	if truncated && ctx != nil && ctx.Sink != nil {
		limits.Emit(ctx.Sink, limits.RuleString, "MaxNotebookCellBytes", total, maxNotebookCellBytes, "notebook cell source truncated")
	}
	return notebookCell{text: text, lines: lines}
}

// findJSONStringStart locates the opening '"' of a JSON string token whose
// decoder input offsets span [prev, cur).
func findJSONStringStart(raw []byte, prev, cur int64) int64 {
	if prev < 0 {
		prev = 0
	}
	if cur > int64(len(raw)) {
		cur = int64(len(raw))
	}
	if prev >= cur {
		return prev
	}
	if q := bytes.IndexByte(raw[prev:cur], '"'); q >= 0 {
		return prev + int64(q)
	}
	return prev
}

// skipJSONValue consumes one complete JSON value from dec.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
		return skipJSONContainer(dec)
	}
	return nil
}

// skipJSONContainer consumes tokens until the container whose opening delimiter
// was already read has been closed.
func skipJSONContainer(dec *json.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
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
