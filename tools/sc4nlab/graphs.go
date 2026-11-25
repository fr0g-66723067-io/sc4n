package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// runGraphs mutates ONNX models inside the pinned oracle image.
//
// Every mutant is produced by mutate.py (onnx is not a Go library) and then
// validated by a second container invocation whose result is the row's
// oracle. The scan is still Go: the mutant lands on disk and the real engine
// reads it.
func runGraphs(ctx context.Context, o options, out string) ([]Row, string, bool) {
	ops := graphOps()
	seeds, notLoaded, err := graphSeeds(ctx, o, out, ops[0])
	if err != nil {
		rows := make([]Row, 0, len(ops))
		for _, g := range ops {
			rows = append(rows, Row{
				Operator: g.Name, Verdict: verdictUnavailable,
				OracleNote: err.Error(), Expected: g.Expected, Forbidden: g.Forbidden,
			})
		}
		return rows, "docker", true
	}
	if len(seeds) == 0 {
		note := "no onnx seed under " + o.seeds
		if notLoaded != "" {
			note += "; " + notLoaded
		}
		rows := make([]Row, 0, len(ops))
		for _, g := range ops {
			rows = append(rows, Row{
				Operator: g.Name, Verdict: verdictUnavailable,
				OracleNote: note, Expected: g.Expected, Forbidden: g.Forbidden,
			})
		}
		return rows, "docker", true
	}

	var rows []Row
	for _, g := range ops {
		for _, seed := range seeds {
			base := seedFindings(o, seed)
			r := Row{Operator: g.Name, Expected: g.Expected, Forbidden: g.Forbidden, Baseline: base}
			rel, err := mutate(ctx, o, out, g, seed)
			if err != nil {
				// A seed that does not load is dropped once, above; an operator that
				// makes a model the checker rejects is a broken operator, and the
				// note carries mutate.py's own words.
				r.Verdict = verdictUnavailable
				r.OracleNote = err.Error()
				rows = append(rows, r)
				continue
			}
			r.Mutant = rel
			oracle := &dockerOracle{
				name:  "docker",
				image: o.oracleImage,
				dir:   out,
				mode:  g.Mode,
			}
			if err := oracle.Available(); err != nil {
				r.Verdict = verdictUnavailable
				r.OracleNote = err.Error()
				rows = append(rows, r)
				continue
			}
			valid, note := oracle.Validate(filepath.Join(out, rel))
			r.Valid = valid
			r.OracleNote = note
			if !valid {
				r.Verdict = verdictInvalid
				if !o.keepInvalid {
					_ = os.Remove(filepath.Join(out, rel))
				}
			}
			rows = append(rows, r)
		}
	}
	return rows, "docker", false
}

// graphSeeds selects the models to mutate. It is self-correcting: a candidate
// that mutate.py cannot load (a header slice, a mis-sniffed blob) is dropped
// with a note instead of producing an "invalid" row per operator, so a corpus
// of slices degrades to "no seeds" rather than to noise.
func graphSeeds(ctx context.Context, o options, out string, first graphOp) ([]string, string, error) {
	if err := os.MkdirAll(filepath.Join(out, "seeds"), 0o755); err != nil {
		return nil, "", err
	}
	var cands []string
	if st, err := os.Stat(o.seeds); err != nil || !st.IsDir() {
		return nil, "", fmt.Errorf("seed root %s: %v", o.seeds, errOr(err, "not a directory"))
	}
	err := filepath.WalkDir(o.seeds, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable seed dir is not a run failure
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".onnx") {
			return nil
		}
		if st, e := d.Info(); e == nil && st.Size() > 64<<20 {
			return nil // the 23 MB int8 models are the ceiling; bigger ones are the corpus's job
		}
		cands = append(cands, path)
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	sortBySizeAsc(cands)
	if len(cands) == 0 {
		return nil, "", fmt.Errorf("no .onnx under %s", o.seeds)
	}
	var seeds []string
	var notes []string
	for _, c := range cands {
		if len(seeds) >= max(1, o.n) {
			break
		}
		rel, err := mutate(ctx, o, filepath.Join(out, "seeds"), first, c)
		if err != nil {
			notes = append(notes, filepath.Base(c)+": "+err.Error())
			continue
		}
		_ = os.Remove(filepath.Join(out, "seeds", rel))
		seeds = append(seeds, c)
	}
	return seeds, strings.Join(notes, "; "), nil
}

// seedKey returns a collision-resistant filename prefix for seed by appending
// a short hash of the cleaned seed path, so two seeds named model.onnx in
// different subdirectories do not overwrite each other's mutants or arg files.
func seedKey(seed string) string {
	base := strings.TrimSuffix(filepath.Base(seed), filepath.Ext(seed))
	sum := sha256.Sum256([]byte(filepath.Clean(seed)))
	return base + "_" + hex.EncodeToString(sum[:4])
}

// mutate runs mutate.py in the pinned image for one (operator, seed) pair and
// returns the mutant path relative to out.
func mutate(ctx context.Context, o options, out string, g graphOp, seed string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker: %w", err)
	}
	py, err := stageScripts(filepath.Join(out, "oracle"))
	if err != nil {
		return "", err
	}
	dir := filepath.Join(out, "mutants", g.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	seedDir := filepath.Dir(seed)
	key := seedKey(seed)
	outName := key + "__" + g.Name + ".onnx"
	argName := "arg-" + key + ".json"
	arg, err := json.Marshal(map[string]string{
		"seed": "/s/" + filepath.Base(seed),
		"out":  "/o/" + outName,
		"op":   g.Name,
	})
	if err != nil {
		return "", err
	}
	if err := writeFile(filepath.Join(dir, argName), arg); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none",
		"--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--tmpfs", "/tmp",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", seedDir+":/s:ro",
		"-v", dir+":/o",
		"-v", py+":/opt/sc4nlab:ro",
		o.oracleImage,
		"python3", "/opt/sc4nlab/mutate.py", "/o/"+argName) // #nosec G204 -- fixed image, lab-owned dirs
	outb, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", lastLine(string(outb)))
	}
	return filepath.ToSlash(filepath.Join("mutants", g.Name, outName)), nil
}

// seedFindings is the rule set the seed produces on its own, recorded in every
// row so classify can tell a rule the mutation introduced from one the seed
// already carried.
func seedFindings(o options, seed string) []string {
	findings, _ := scanOne(o, filepath.Dir(seed), filepath.Base(seed))
	seen := make(map[string]bool, len(findings))
	var ids []string
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
		}
	}
	sort.Strings(ids)
	return ids
}

func errOr(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	return err.Error() + ": " + fallback
}
