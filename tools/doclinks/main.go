// Command doclinks checks the repository's Markdown links.
//
// Documentation is part of the interface here: a reader holding a finding
// follows a link from README to the triage guide to the rule catalogue, and a
// dead one is the documentation equivalent of a panic. The check is mechanical
// and offline:
//
//   - a relative link must resolve to a file in the tree;
//   - a `#anchor` part must match a heading (GitHub's slug rule: lowercased,
//     spaces to hyphens, punctuation dropped) or an explicit
//     `<a id="...">` in the target document;
//   - external links are not fetched, because a build must not depend on the
//     network.
//
// `make docs-links` runs it; CI runs the same target.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	linkRe    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	anchorRe  = regexp.MustCompile(`<a id="([^"]+)"></a>`)
	headingRe = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	fenceRe   = regexp.MustCompile("^\\s*```")
	slugDrop  = regexp.MustCompile(`[^\p{L}\p{N}\- _]`)
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	broken, docs, err := check(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doclinks: %v\n", err)
		os.Exit(1)
	}
	if broken > 0 {
		fmt.Printf("doclinks: %d broken link(s)\n", broken)
		os.Exit(1)
	}
	fmt.Printf("doclinks: %d document(s), no broken links\n", docs)
}

// check reports the broken links in root's Markdown, and how many documents were
// read. It returns rather than exiting so the gate itself can be tested.
func check(root string) (broken, count int, err error) {
	docs, err := markdownFiles(root)
	if err != nil {
		return 0, 0, err
	}
	anchors := make(map[string]map[string]bool, len(docs))
	for _, d := range docs {
		b, err := os.ReadFile(filepath.Join(root, d))
		if err != nil {
			return 0, 0, err
		}
		anchors[d] = anchorsOf(string(b))
	}

	for _, d := range docs {
		b, err := os.ReadFile(filepath.Join(root, d))
		if err != nil {
			return 0, 0, err
		}
		for _, m := range linksIn(string(b)) {
			target := m
			if i := strings.IndexAny(target, "?#"); i >= 0 {
				if i > 0 && strings.HasPrefix(target[i:], "?") {
					// A query-only link (…md?plain=1) keeps the path part.
					target = target[:i]
					if target == "" {
						continue
					}
				}
			}
			path, anchor := splitAnchor(target)
			if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "mailto:") {
				continue
			}
			dst := d
			if path != "" {
				dst = filepath.ToSlash(filepath.Join(filepath.Dir(d), path))
				dst = filepath.ToSlash(filepath.Clean(dst))
				if _, err := os.Stat(filepath.Join(root, dst)); err != nil {
					fmt.Printf("%s: dead link %q (no %s)\n", d, m, dst)
					broken++
					continue
				}
			}
			if anchor == "" {
				continue
			}
			set, ok := anchors[dst]
			if !ok {
				// The target is not a Markdown file (a source file, a fixture), so
				// it cannot carry a heading this check can see.
				continue
			}
			if !set[anchor] {
				fmt.Printf("%s: dead anchor %q in %s\n", d, m, dst)
				broken++
			}
		}
	}
	return broken, len(docs), nil
}

// markdownFiles returns README.md and every docs/*.md relative to root.
func markdownFiles(root string) ([]string, error) {
	out := []string{"README.md"}
	entries, err := os.ReadDir(filepath.Join(root, "docs"))
	if os.IsNotExist(err) {
		// A tree with only a README is still a tree with links to check.
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			out = append(out, "docs/"+e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// linksIn returns link destinations, skipping fenced code blocks so a command
// example is not read as a link.
func linksIn(doc string) []string {
	var out []string
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		if fenceRe.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range linkRe.FindAllStringSubmatch(line, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

// anchorsOf collects the anchors a document offers: explicit <a id> markers and
// the GitHub slug of every heading, with duplicate slugs numbered the way GitHub
// numbers them (x, x-1, x-2).
func anchorsOf(doc string) map[string]bool {
	set := map[string]bool{}
	seen := map[string]int{}
	for _, m := range anchorRe.FindAllStringSubmatch(doc, -1) {
		set[m[1]] = true
	}
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		if fenceRe.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		h := headingRe.FindStringSubmatch(line)
		if h == nil {
			continue
		}
		slug := slugify(h[2])
		if slug == "" {
			continue
		}
		if n, dup := seen[slug]; dup {
			seen[slug] = n + 1
			set[fmt.Sprintf("%s-%d", slug, n)] = true
			continue
		}
		seen[slug] = 1
		set[slug] = true
	}
	return set
}

func slugify(text string) string {
	s := strings.ToLower(text)
	s = strings.ReplaceAll(s, "`", "")
	s = slugDrop.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, " ", "-")
	return s
}

func splitAnchor(link string) (path, anchor string) {
	if i := strings.Index(link, "#"); i >= 0 {
		return link[:i], link[i+1:]
	}
	return link, ""
}
