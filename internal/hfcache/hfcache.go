// Package hfcache expands a Hugging Face Hub cache directory into the set of
// blobs worth scanning.
//
// An HF cache is content-addressed and full of symlinks:
//
//	models--<org>--<repo>/
//	  blobs/<sha256>                       the real bytes, downloaded once
//	  snapshots/<commit>/<file>  ->  ../../blobs/<sha256>
//	  refs/<name>                           a 40-hex commit
//	  .no_exist/<commit>/<file>             a marker for a file that was probed
//	                                        and found absent (zero bytes)
//
// Walking the tree naively scans the same blob once per revision that references
// it, which on a popular model (twenty revisions, a handful of large files) is a
// twentyfold cost for identical findings. Expand therefore resolves every snapshot
// entry to its blob and returns *one* Entry per blob, labelled with the first
// snapshot path and any ref names that point at its commit. `scan.Entry.Digest` is
// set to the blob name so the engine can also label later duplicates.
//
// Containment: the cache directory is the root. Every symlink is resolved through
// os.Root, so a link whose target leaves the root is reported (SC4N-HFCACHE-
// SYMLINK-ESCAPE) and never yielded as a scan target; the scan engine is told to
// follow symlinks, and this is the check that makes that safe.
//
// Explicitly out of scope, so a reader does not infer coverage: blobs that no
// snapshot references are not listed; `.no_exist/` markers are skipped; and a blob
// that is a git-LFS *pointer* (the real bytes were never downloaded) is returned
// as an ordinary entry and scanned as text, which is honest but means the weights
// behind the pointer were not scanned.
package hfcache

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Entry is one scan target discovered in the cache. It mirrors the fields the
// scan engine needs without importing it, so the CLI is free to map it.
type Entry struct {
	// Path is the absolute path of the blob (the symlink target), which is what
	// the engine opens.
	Path string
	// Display is the cache-relative snapshot path the blob is reachable from, for
	// findings.
	Display string
	// Digest is the blob's content key (its file name), so the engine can label
	// an entry that is reached a second time.
	Digest string
	// Revision is a comma-separated list of refs/<name> labels whose commit points
	// at this snapshot, when any.
	Revision string
}

// DefaultDir is the standard Hugging Face Hub cache location.
func DefaultDir() string {
	if hf := os.Getenv("HF_HOME"); hf != "" {
		return filepath.Join(hf, "hub")
	}
	if h := os.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".cache", "huggingface", "hub")
	}
	return ""
}

// Expand walks dir and returns one Entry per unique blob, sorted by Display. It is
// deterministic. Structural problems (an escaping symlink, a missing blob, a
// malformed ref) are reported through c when c is non-nil and are otherwise
// skipped.
//
// Findings are stamped with the cache-relative path they concern, the same string
// the engine uses as the artifact name for a scanned entry, so a finding resolves
// to a component in every encoder. Nothing here invents a "hf-cache:" prefix: it
// was neither a path nor a member separator, and it made the CycloneDX
// vulnerability's affects[].ref point at a component that no bom-ref declared.
func Expand(dir string, c *report.Collector) ([]Entry, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errors.New("hfcache: " + dir + " is not a directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	repos, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []Entry

	for _, repo := range repos {
		if !repo.IsDir() || !strings.HasPrefix(repo.Name(), "models--") {
			continue
		}
		repoRel := repo.Name()
		refs := readRefs(root, c, repoRel)

		snapDir := path.Join(repoRel, "snapshots")
		err := filepath.WalkDir(filepath.Join(dir, filepath.FromSlash(snapDir)),
			func(p string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if d.IsDir() {
					if d.Name() == ".no_exist" && p != filepath.Join(dir, filepath.FromSlash(snapDir)) {
						return filepath.SkipDir
					}
					return nil
				}
				rel, rerr := filepath.Rel(dir, p)
				if rerr != nil {
					return nil
				}
				relSlash := filepath.ToSlash(rel)

				blobRel, display, ok := resolveEntry(root, c, relSlash)
				if !ok {
					return nil
				}
				// The resolved blob path, not its basename, is the identity. In
				// a symlinked hub cache the basename is the blob's digest, but a
				// cache copied or extracted without symlinks resolves to the
				// snapshot file itself, whose basename is just "config.json" —
				// keying on that silently dropped every repository after the
				// first, findings and all.
				key := blobRel
				if seen[key] {
					return nil
				}
				seen[key] = true

				commit := snapshotCommit(relSlash)
				out = append(out, Entry{
					Path:     filepath.Join(dir, filepath.FromSlash(blobRel)),
					Display:  display,
					Digest:   digestOf(blobRel),
					Revision: strings.Join(refs[commit], ","),
				})
				return nil
			})
		if err != nil {
			return nil, err
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Display < out[j].Display })
	return out, nil
}

// digestOf returns the content key of a resolved blob path: in the hub layout the
// blob file is named by its digest, so its basename is the digest; a cache without
// symlinks resolves to the snapshot file instead, and there the path is the only
// stable identifier (the basename would be "config.json" for every repository).
func digestOf(blobRel string) string {
	if base := path.Base(blobRel); isHexDigest(base) {
		return base
	}
	return blobRel
}

// isHexDigest reports whether s looks like a blob digest (40 hex for sha1, 64 for
// sha256), which is how the hub names files under blobs/.
func isHexDigest(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// resolveEntry turns a snapshot-relative path into the blob it points at. It
// returns the blob path relative to the cache root, the display name for findings,
// and false when the entry must be skipped.
func resolveEntry(root *os.Root, c *report.Collector, relSlash string) (blobRel, display string, ok bool) {
	display = relSlash
	fi, err := root.Lstat(relSlash)
	if err != nil {
		emit(c, RuleBlobMissing, display, "snapshot entry could not be stat'd: "+err.Error())
		return "", "", false
	}
	target := relSlash
	if fi.Mode()&os.ModeSymlink != 0 {
		link, lerr := root.Readlink(relSlash)
		if lerr != nil {
			emit(c, RuleSymlinkEscape, display, "snapshot symlink could not be read: "+lerr.Error())
			return "", "", false
		}
		if path.IsAbs(link) || filepath.IsAbs(link) {
			emit(c, RuleSymlinkEscape, display, "snapshot symlink is absolute: "+link)
			return "", "", false
		}
		joined := path.Clean(path.Join(path.Dir(relSlash), filepath.ToSlash(link)))
		if joined == ".." || strings.HasPrefix(joined, "../") {
			emit(c, RuleSymlinkEscape, display, "snapshot symlink escapes the cache root: "+link)
			return "", "", false
		}
		target = joined
	}
	tfi, err := root.Stat(target)
	if err != nil {
		emit(c, RuleBlobMissing, display, "resolved blob is missing: "+target)
		return "", "", false
	}
	if tfi.IsDir() {
		return "", "", false
	}
	return target, display, true
}

// readRefs reads refs/<name> files into a commit -> ref names map.
func readRefs(root *os.Root, c *report.Collector, repoRel string) map[string][]string {
	out := map[string][]string{}
	refRoot := path.Join(repoRel, "refs")
	_ = filepath.WalkDir(filepath.Join(root.Name(), filepath.FromSlash(refRoot)),
		func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil
			}
			rel, rerr := filepath.Rel(root.Name(), p)
			if rerr != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			b, err := root.ReadFile(relSlash)
			if err != nil {
				return nil
			}
			name := strings.TrimPrefix(relSlash, repoRel+"/refs/")
			commit := strings.TrimSpace(string(b))
			if !isCommit(commit) {
				emit(c, RuleRefMalformed, relSlash, "refs/"+name+" is not a 40-hex commit")
				return nil
			}
			out[commit] = append(out[commit], name)
			return nil
		})
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// snapshotCommit extracts the commit directory from
// `models--o--r/snapshots/<commit>/...`.
func snapshotCommit(relSlash string) string {
	parts := strings.Split(relSlash, "/")
	for i, p := range parts {
		if p == "snapshots" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func isCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func emit(c *report.Collector, r *report.Rule, name, evidence string) {
	if c == nil {
		return
	}
	c.For(name).Emit(r, 0, evidence)
}
