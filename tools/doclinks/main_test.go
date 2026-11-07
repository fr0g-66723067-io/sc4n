package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeDoc drops one Markdown file into a throwaway tree.
func writeDoc(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The gate must fail on the two mistakes that actually happen: a link to a file
// that does not exist, and an anchor that names a heading the target no longer
// has. A checker that passes everything is worse than none, because it gets
// cited as proof the docs are intact.
func TestBrokenLinksAreReported(t *testing.T) {
	cases := []struct {
		name     string
		readme   string
		other    string
		wantBad  int
		wantDocs int
	}{
		{
			name:     "resolving link and anchor",
			readme:   "See [the guide](docs/guide.md#how-to-act).\n",
			other:    "# Guide\n\n## How to act\n",
			wantBad:  0,
			wantDocs: 2,
		},
		{
			name:     "dead file",
			readme:   "See [the guide](docs/missing.md).\n",
			wantBad:  1,
			wantDocs: 1,
		},
		{
			name:     "dead anchor",
			readme:   "See [the guide](docs/guide.md#not-there).\n",
			other:    "# Guide\n\n## How to act\n",
			wantBad:  1,
			wantDocs: 2,
		},
		{
			name:     "explicit anchor marker",
			readme:   "See [triage](docs/guide.md#load-path-code).\n",
			other:    "# Guide\n",
			wantBad:  1,
			wantDocs: 2,
		},
		{
			name:     "fenced code is not a link",
			readme:   "```\nsee [x](nowhere.md)\n```\n",
			wantBad:  0,
			wantDocs: 1,
		},
		{
			name:     "external links are not fetched",
			readme:   "[spec](https://example.invalid/x) and [mail](mailto:a@b)\n",
			wantBad:  0,
			wantDocs: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeDoc(t, root, "README.md", tc.readme)
			if tc.other != "" {
				writeDoc(t, root, "docs/guide.md", tc.other)
			}
			bad, docs, err := check(root)
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if bad != tc.wantBad {
				t.Errorf("broken = %d, want %d", bad, tc.wantBad)
			}
			if docs != tc.wantDocs {
				t.Errorf("documents = %d, want %d", docs, tc.wantDocs)
			}
		})
	}
}

// A rule description may contain Markdown syntax (the Jinja gadget chain is
// written `[i](...)`), so the catalogue escapes it. This pins the escape, because
// the failure mode is a dead link in generated documentation, not a compile error.
func TestEscapedDescriptionIsNotALink(t *testing.T) {
	root := t.TempDir()
	writeDoc(t, root, "README.md", "[x](docs/rules.md)\n")
	writeDoc(t, root, "docs/rules.md", "chain: __subclasses__()[i]\\\\(...)\n")
	bad, _, err := check(root)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if bad != 0 {
		t.Fatalf("an escaped parenthesis was read as a link: %d broken", bad)
	}
	if got := linksIn("chain: __subclasses__()[i]\\(...)\n"); len(got) != 0 {
		t.Fatalf("linksIn found %v in escaped text", got)
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"What sc4n does not do":                          "what-sc4n-does-not-do",
		"Grading: capability, constructed, demonstrated": "grading-capability-constructed-demonstrated",
		"`sc4n rules` and formats":                       "sc4n-rules-and-formats",
		"Severity × confidence":                          "severity--confidence",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
