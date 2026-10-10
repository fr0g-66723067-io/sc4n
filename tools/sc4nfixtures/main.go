// Command sc4nfixtures generates sc4n's test fixtures.
//
// The fixtures are generated rather than downloaded: the reference scan host has
// no Python, no torch, no picklescan and no network access to a model hub, and a
// real malicious sample must never be committed to a repository. Generating them
// also means the generator is the specification — each fixture's doc comment says
// which attack it reproduces and where that attack was published, and
// testdata/fixtures/expectations.json says which rules must and must not fire on
// it.
//
// Regeneration is deterministic: every fixture is written from fixed bytes with no
// timestamps, no random keys and no host information, so `make fixtures` followed
// by `git status --short testdata/` must show nothing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// fixtureSet collects the files to write.
type fixtureSet struct {
	root  string
	files map[string][]byte
	order []string
}

func newFixtureSet(root string) *fixtureSet {
	return &fixtureSet{root: root, files: map[string][]byte{}}
}

func (f *fixtureSet) add(name string, data []byte) {
	if _, dup := f.files[name]; dup {
		panic("fixture " + name + " written twice")
	}
	f.files[name] = data
	f.order = append(f.order, name)
}

func (f *fixtureSet) addText(name, text string) { f.add(name, []byte(text)) }

// write lays the set out on disk and returns the number of files written.
func (f *fixtureSet) write() (int, error) {
	for _, name := range f.order {
		full := filepath.Join(f.root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return 0, err
		}
		if err := os.WriteFile(full, f.files[name], 0o644); err != nil {
			return 0, err
		}
	}
	return len(f.order), nil
}

// expectation is one fixture's rule contract.
type expectation struct {
	// Expect lists rules that MUST fire for the fixture.
	Expect []string `json:"expect"`
	// Forbid lists rules that MUST NOT fire. It is the more valuable half: it is
	// how "the allowlisted-callable case must not be reported as a gadget" is
	// enforced rather than asserted in prose.
	Forbid []string `json:"forbid,omitempty"`
	// Notes explains what the fixture reproduces and where it was published.
	Notes string `json:"notes"`
}

type expectationFile struct {
	Version  int                    `json:"version"`
	Fixtures map[string]expectation `json:"fixtures"`
	Benign   map[string]expectation `json:"benign"`
}

func main() {
	out := flag.String("out", "testdata/fixtures", "output directory")
	flag.Parse()

	f := newFixtureSet(*out)
	pickleFixtures(f)

	n, err := f.write()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sc4nfixtures:", err)
		os.Exit(1)
	}

	exp := buildExpectations()
	blob, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sc4nfixtures:", err)
		os.Exit(1)
	}
	blob = append(blob, '\n')
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "sc4nfixtures:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*out, "expectations.json"), blob, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "sc4nfixtures:", err)
		os.Exit(1)
	}
	names := make([]string, 0, len(f.order))
	names = append(names, f.order...)
	sort.Strings(names)
	fmt.Printf("wrote %d fixture(s) and expectations.json to %s\n", n, *out)
}
