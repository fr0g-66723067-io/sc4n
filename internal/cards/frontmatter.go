package cards

import "strings"

// frontmatter is the subset of YAML that Hugging Face model and dataset cards
// actually use: top-level scalars, inline lists and block lists. It exists so
// that card fields can be resolved by name without linking a YAML library.
type frontmatter struct {
	scalars map[string]string
	lists   map[string][]string
}

// parseFrontmatter parses the leading `---`-delimited YAML block of text.
//
// It reports ok=false when the block is present but does not match the subset,
// which is the signal for SC4N-CARD-PARSE. Text that has no frontmatter block at
// all returns (nil, true): there was nothing to parse, which is not an error.
//
// A nested mapping (an indented line that is not a `- ` list item) is skipped
// rather than treated as a parse failure: it is valid YAML that this subset does
// not model, and the standard `model-index:` block of an evaluated model card is
// exactly that shape. List items inside such a block are still appended to the
// enclosing key's list, which is harmless because no rule reads those values as a
// list of instructions.
func parseFrontmatter(text string) (*frontmatter, bool) {
	if !strings.HasPrefix(text, "---") {
		return nil, true
	}
	nl := strings.IndexByte(text, '\n')
	if nl < 0 {
		return nil, false
	}
	if strings.TrimRight(text[:nl], " \t\r") != "---" {
		return nil, true
	}
	fm := &frontmatter{scalars: map[string]string{}, lists: map[string][]string{}}
	curKey := ""
	closed := false
	for _, line := range strings.Split(text[nl+1:], "\n") {
		line = strings.TrimRight(line, "\r")
		t := strings.TrimSpace(line)
		if t == "---" || t == "..." {
			closed = true
			break
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "- ") || t == "-" {
			if curKey == "" {
				return nil, false
			}
			fm.lists[curKey] = append(fm.lists[curKey], unquoteYAML(strings.TrimSpace(strings.TrimPrefix(t, "-"))))
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Indented and not a list item: the value of the current key is a
			// nested mapping, which this subset does not model. The line is skipped
			// rather than fatal: every model card with evaluation results carries a
			// `model-index:` block of that shape, and calling a valid card
			// unparseable costs the structured scan for nothing (68 cards of the
			// 273-model HF campaign).
			continue
		}
		colon := strings.IndexByte(t, ':')
		if colon <= 0 {
			return nil, false
		}
		key := strings.TrimSpace(t[:colon])
		val := strings.TrimSpace(t[colon+1:])
		curKey = key
		switch {
		case val == "":
			// A block list may follow; curKey already points at it.
		case strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]"):
			inner := strings.TrimSpace(val[1 : len(val)-1])
			for _, p := range strings.Split(inner, ",") {
				if p = strings.TrimSpace(p); p != "" {
					fm.lists[key] = append(fm.lists[key], unquoteYAML(p))
				}
			}
		default:
			fm.scalars[key] = unquoteYAML(val)
		}
	}
	if !closed {
		return nil, false
	}
	return fm, true
}

// unquoteYAML strips matching single or double quotes from a scalar.
func unquoteYAML(s string) string {
	if len(s) < 2 || (s[0] != '"' && s[0] != '\'') || s[len(s)-1] != s[0] {
		return s
	}
	inner := s[1 : len(s)-1]
	if s[0] == '"' {
		inner = strings.ReplaceAll(inner, `\"`, `"`)
		inner = strings.ReplaceAll(inner, `\\`, `\`)
		return inner
	}
	return strings.ReplaceAll(inner, "''", "'")
}
