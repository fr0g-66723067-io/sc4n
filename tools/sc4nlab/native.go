package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// nativeCandidates is the fixed probe list. The lab resolves its two seed
// classes from it with readelf — never with the code under test — so the row
// that says "this ELF imports system()" is derived by a tool the scanner does
// not share code with.
func nativeCandidates() []string {
	return []string{"/bin/sh", "/bin/ls", "/usr/lib/x86_64-linux-gnu/libz.so.1"}
}

// execSymbols are the imported names that make an ELF dangerous to load in a
// process that trusts it. They are the same set the scanner's own rule will use
// (Step 8b); the lab resolves seeds by asking readelf, which is the independent
// half.
func execSymbols() []string {
	return []string{
		"system", "popen", "execl", "execle", "execlp", "execv",
		"execve", "execvp", "fork", "vfork", "dlopen", "ptrace",
	}
}

// resolveNativeSeeds finds one ELF that imports process-control symbols and one
// that does not. It returns an explanation when either class is missing, which
// becomes the profile's unavailable note instead of a guessed seed.
func resolveNativeSeeds() (execELF, plainELF string, err error) {
	var cands []string
	for _, p := range nativeCandidates() {
		if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() {
			cands = append(cands, p)
		}
	}
	if len(cands) == 0 {
		return "", "", fmt.Errorf("no candidate ELF in %v", nativeCandidates())
	}
	var notes []string
	for _, p := range cands {
		syms, e := importedSymbols(p)
		if e != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", p, e))
			continue
		}
		if execELF == "" && hasAny(syms, execSymbols()) {
			execELF = p
		}
		if plainELF == "" && !hasAny(syms, execSymbols()) {
			plainELF = p
		}
	}
	if execELF == "" {
		notes = append(notes, "no ELF imports process-control symbols")
	}
	if plainELF == "" {
		notes = append(notes, "no ELF without process-control imports")
	}
	if len(notes) > 0 {
		return execELF, plainELF, fmt.Errorf("%s", strings.Join(notes, "; "))
	}
	return execELF, plainELF, nil
}

// importedSymbols asks readelf for the dynamic symbol table.
func importedSymbols(path string) ([]string, error) {
	out, err := exec.Command("readelf", "-W", "--dyn-syms", path).CombinedOutput() // #nosec G204 -- fixed probe list
	if err != nil {
		return nil, fmt.Errorf("readelf: %v", err)
	}
	var syms []string
	for _, line := range strings.Split(string(out), "\n") {
		// Format: "   Num: Value Size Type Bind Vis Ndx Name"
		// An import is an undefined dynamic symbol: Ndx is UND.
		fields := strings.Fields(line)
		if len(fields) < 8 || !strings.HasSuffix(fields[0], ":") {
			continue
		}
		if fields[6] != "UND" {
			continue
		}
		syms = append(syms, strings.TrimSuffix(fields[7], "@"))
	}
	return syms, nil
}

func hasAny(syms, want []string) bool {
	set := make(map[string]bool, len(want))
	for _, w := range want {
		set[w] = true
	}
	for _, s := range syms {
		// Versioned names read "system@@GLIBC_2.2.5"; readelf -W prints the
		// version in the Name column, so split before comparing.
		base := s
		if i := strings.IndexByte(base, '@'); i >= 0 {
			base = base[:i]
		}
		if set[base] {
			return true
		}
	}
	return false
}

// nativeOps is the native profile's table, built after seed resolution so the
// Build closures capture the two chosen paths.
func nativeOps(execELF, plainELF string) []op {
	return []op{
		{
			Name: "native-member-sh",
			Build: func(out string, seed int64) (string, error) {
				return buildNativeZip(out, "native-member-sh", "pkg.whl", "libcudart.so", execELF)
			},
			Oracle:   newHostValid("readelf", "readelf", "-h"),
			Expected: []string{"SC4N-ARCHIVE-NATIVE-MEMBER", "SC4N-POLYGLOT-NATIVE", "SC4N-NATIVE-EXEC-IMPORTS"},
		},
		{
			Name: "native-member-z",
			Build: func(out string, seed int64) (string, error) {
				return buildNativeZip(out, "native-member-z", "pkg.whl", "libz-helper.so", plainELF)
			},
			Oracle:   newHostValid("readelf", "readelf", "-h"),
			Expected: []string{"SC4N-ARCHIVE-NATIVE-MEMBER", "SC4N-POLYGLOT-NATIVE"},
			Forbid:   []string{"SC4N-NATIVE-EXEC-IMPORTS"},
		},
		{
			Name: "native-standalone-sh",
			Build: func(out string, seed int64) (string, error) {
				full, rel, err := mutantPath(out, "native-standalone-sh", "libfoo.so")
				if err != nil {
					return "", err
				}
				b, err := os.ReadFile(execELF)
				if err != nil {
					return "", err
				}
				return rel, os.WriteFile(full, b, 0o644)
			},
			Oracle:   newHostValid("readelf", "readelf", "-h"),
			Expected: []string{"SC4N-NATIVE-VALID", "SC4N-NATIVE-EXEC-IMPORTS"},
		},
	}
}

// buildNativeZip puts the ELF in a wheel as a stored member.
func buildNativeZip(out, opName, name, member, elf string) (string, error) {
	full, rel, err := mutantPath(out, opName, name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(elf)
	if err != nil {
		return "", err
	}
	if err := zipStore(full, member, b); err != nil {
		return "", err
	}
	return rel, nil
}

// runNative resolves the seeds, builds the table and validates each mutant with
// readelf. The oracle validates the *member bytes*, not the zip: the archive's
// own integrity is the containers profile's job (`7z t`), and readelf -h on a
// zip correctly fails.
func runNative(ctx context.Context, o options, out string) ([]Row, string, bool) {
	execELF, plainELF, err := resolveNativeSeeds()
	if err != nil {
		// A profile with no resolvable seed class reports every row unavailable
		// rather than guessing a binary, and the reason is the note.
		rows := []Row{
			{Operator: "native-member-sh", Verdict: verdictUnavailable, OracleNote: err.Error()},
			{Operator: "native-member-z", Verdict: verdictUnavailable, OracleNote: err.Error()},
			{Operator: "native-standalone-sh", Verdict: verdictUnavailable, OracleNote: err.Error()},
		}
		return rows, "readelf", true
	}
	ops := nativeOps(execELF, plainELF)
	for i := range ops {
		// The row's oracle checks the bytes, so give it the member rather than
		// the archive.
		if strings.HasSuffix(ops[i].Name, "-member-sh") || strings.HasSuffix(ops[i].Name, "-member-z") {
			elf := execELF
			if strings.HasSuffix(ops[i].Name, "-member-z") {
				elf = plainELF
			}
			ops[i].Oracle = &memberOracle{inner: newHostValid("readelf", "readelf", "-h"), member: elf}
		}
	}
	return runOps(ctx, ops, o, out, "readelf")
}

// memberOracle validates the underlying ELF of a zip mutant by running the host
// tool on the source file. It exists because the mutant's interesting bytes are
// a member: `readelf -h pkg.whl` is expected to fail, and a row that reported
// "invalid" for that would be measuring the wrong thing.
type memberOracle struct {
	inner  Oracle
	member string
}

func (m *memberOracle) Name() string                   { return m.inner.Name() }
func (m *memberOracle) Available() error               { return m.inner.Available() }
func (m *memberOracle) Validate(string) (bool, string) { return m.inner.Validate(m.member) }

// sortBySizeAsc is the graph seed order: smallest first, so the run picks the
// cheap models before the 23 MB ones.
func sortBySizeAsc(paths []string) {
	sort.SliceStable(paths, func(i, j int) bool {
		a, b := sizeOf(paths[i]), sizeOf(paths[j])
		if a != b {
			return a < b
		}
		return paths[i] < paths[j]
	})
}

func sizeOf(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}
