package hubcampaign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/hubapi"
)

// FetchFile is one file's fetch outcome. Status is one of full, slice, gated,
// missing, size-mismatch, budget, unsafe-path, error or dir; every one of them is
// a statement about coverage, so a file is never absent from the list.
// size-mismatch is a Hub that declares 0 bytes and serves content: nothing is
// stored, because storing it would be an unbounded transfer charged as zero.
type FetchFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Status string `json:"status"`
	Bytes  int64  `json:"bytes"`
	HTTP   int    `json:"http"`
	Detail string `json:"detail,omitempty"`
}

// RepoFetch is one selected repo's fetch outcome.
type RepoFetch struct {
	ID     string      `json:"id"`
	Status string      `json:"status"`
	Bytes  int64       `json:"bytes"`
	Files  []FetchFile `json:"files"`
	Detail string      `json:"detail,omitempty"`
}

// FetchDoc is fetch.json.
type FetchDoc struct {
	Version int         `json:"version"`
	Level   string      `json:"level"`
	Repos   []RepoFetch `json:"repos"`
}

// planned is one sibling after the listing rules have been applied.
type planned struct {
	path    string
	size    int64
	flagged bool
	unsafe  bool
}

// Fetch downloads the flagged repos' files and writes fetch.json.
//
// Selection is a property of the verdict file, which is why a mismatched level is
// an error rather than a silent re-selection: re-probing is a network stage, and
// a fetch that quietly changed the universe would make the report lie about what
// it covered.
func Fetch(ctx context.Context, o Options) ([]RepoFetch, error) {
	o = o.withDefaults()
	if err := o.Validate(); err != nil {
		return nil, err
	}
	var vs VerdictsFile
	if err := readJSON(o.path(fileVerdicts), &vs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing(fileVerdicts, "verdicts")
		}
		return nil, err
	}
	if vs.Level != o.Level {
		return nil, fmt.Errorf("hubcampaign: %s was probed for level %s; re-run -stage verdicts",
			fileVerdicts, vs.Level)
	}
	if err := os.MkdirAll(o.reposDir(), 0o755); err != nil {
		return nil, fmt.Errorf("hubcampaign: %w", err)
	}

	// A re-run keeps what a previous run already fetched: resuming a 6 GiB
	// campaign must not re-download it, and the recorded bytes are what makes the
	// kept file provably the one the record describes.
	prior := map[string]FetchFile{}
	if !o.Refresh {
		var pf FetchDoc
		if err := readJSON(o.path(fileFetch), &pf); err == nil {
			for _, r := range pf.Repos {
				for _, f := range r.Files {
					if f.Status == "full" || f.Status == "slice" {
						prior[key(r.ID, f.Path)] = f
					}
				}
			}
		}
	}

	f := &fetcher{o: o, ctx: ctx, left: o.TotalBudget, prior: prior, gates: map[string]string{}}
	selected := selectedRepos(vs.Repos, o.Level)
	out := make([]RepoFetch, 0, len(selected))
	var total int64
	for _, v := range selected {
		r := f.repo(v)
		total += r.Bytes
		out = append(out, r)
	}
	doc := FetchDoc{Version: Version, Level: o.Level, Repos: out}
	if err := writeJSON(o.path(fileFetch), doc); err != nil {
		return nil, err
	}
	progress(o, "fetch: %d repos, %s", len(out), humanBytes(total))
	return out, nil
}

// fetcher carries the campaign-wide byte budget across repos.
type fetcher struct {
	o     Options
	ctx   context.Context
	left  int64
	prior map[string]FetchFile
	// gates caches the per-repo explanation of a 403, so a repo with five gated
	// files costs one metadata request, not five.
	gates map[string]string
}

func (f *fetcher) repo(v RepoVerdict) RepoFetch {
	r := RepoFetch{ID: v.ID, Status: "ok"}
	owner, name, ok := safeRepoID(v.ID)
	if !ok {
		r.Status = "error"
		r.Detail = "unsafe repo id"
		return r
	}
	flagged := map[string]bool{}
	for _, fi := range v.Files {
		if fi.Level == f.o.Level {
			flagged[fi.Path] = true
		}
	}
	files, err := f.o.Client.Files(f.ctx, v.ID)
	if err != nil {
		r.Status = "error"
		r.Detail = err.Error()
		return r
	}

	var entries []planned
	var dirs []FetchFile
	for _, fi := range files {
		if strings.HasSuffix(fi.Path, "/") {
			dirs = append(dirs, FetchFile{Path: fi.Path, Size: fi.Size, Status: "dir"})
			continue
		}
		_, safe := safeFilePath(fi.Path)
		entries = append(entries, planned{
			path: fi.Path, size: fi.Size, flagged: flagged[fi.Path], unsafe: !safe,
		})
	}
	// A total order, so two runs fetch in the same sequence: flagged first, then
	// size ascending, then path.
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.flagged != b.flagged {
			return a.flagged
		}
		if a.size != b.size {
			return a.size < b.size
		}
		return a.path < b.path
	})

	repoBudget := f.o.RepoBudget
	var fetched, gated, failed, refused int
	for _, e := range entries {
		ff := f.file(v.ID, owner, name, e, &repoBudget)
		switch ff.Status {
		case "full", "slice":
			fetched++
		case "gated":
			gated++
		case "budget":
			refused++
		default:
			failed++
		}
		r.Files = append(r.Files, ff)
		r.Bytes += ff.Bytes
	}
	n := len(r.Files)
	r.Files = append(r.Files, dirs...)

	switch {
	case n > 0 && gated == n:
		r.Status = "gated"
	case gated > 0 || failed > 0 || refused > 0:
		r.Status = "partial"
	default:
		r.Status = "ok"
	}
	return r
}

// file fetches one file, charging the repo and campaign budgets as it decides.
func (f *fetcher) file(id, owner, name string, e planned, repoBudget *int64) FetchFile {
	ff := FetchFile{Path: e.path, Size: e.size, Status: "error"}
	if e.unsafe {
		ff.Status = "unsafe-path"
		ff.Detail = "path escapes the campaign directory"
		return ff
	}
	segs, _ := safeFilePath(e.path)
	rel := filepath.Join(append([]string{owner, name}, segs...)...)
	target := filepath.Join(f.o.reposDir(), rel)

	if p, ok := f.prior[key(id, e.path)]; ok && p.Bytes > 0 {
		if st, err := os.Stat(target); err == nil && st.Mode().IsRegular() && st.Size() == p.Bytes {
			*repoBudget -= p.Bytes
			f.left -= p.Bytes
			return p
		}
	}

	whole, need := f.plan(e)
	downgraded := false
	if need > *repoBudget || need > f.left {
		// A whole fetch refused by either budget falls back to a header slice when
		// one fits: `budget` then means "not even the header was fetched", which is
		// a different claim from "only the header was". The round's 6.0 GiB run
		// refused files whose slice would have cost 2 MiB.
		if whole {
			if sn := f.sliceNeed(e); sn <= *repoBudget && sn <= f.left {
				whole, need, downgraded = false, sn, true
			}
		}
	}
	if need > *repoBudget || need > f.left {
		ff.Status = "budget"
		ff.Detail = fmt.Sprintf("needs %s; %s left for the repo and %s for the campaign",
			humanBytes(need), humanBytes(*repoBudget), humanBytes(f.left))
		return ff
	}
	*repoBudget -= need
	f.left -= need
	// Always refund any unused reservation (failure, 403 gated, 404 missing, or
	// an unknown-size file smaller than SliceSize) so later files keep the budget.
	defer func() {
		if refund := need - ff.Bytes; refund > 0 {
			*repoBudget += refund
			f.left += refund
		}
	}()
	if downgraded {
		ff.Detail = fmt.Sprintf("whole file does not fit the byte budget; fetched a %s header slice",
			humanBytes(need))
	}

	if need == 0 {
		// A file the Hub declares as 0 bytes costs no budget, but it still has to
		// be proven empty. Download treats max<=0 as "no cap" and copies to EOF,
		// so fetching it the ordinary way let a Hub that declares 0 and serves a
		// payload write an unbounded file and wait on it with nothing charged.
		// One byte is enough to tell an empty file from a lied-about one.
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			ff.Detail = err.Error()
			return ff
		}
		res, derr := f.o.Client.Download(f.ctx, id, e.path, 0, 1, io.Discard)
		if derr != nil {
			f.downloadFailure(&ff, id, res, derr)
			return ff
		}
		if res.Bytes > 0 {
			ff.Status = "size-mismatch"
			ff.HTTP = res.Status
			ff.Detail = "the Hub declares 0 bytes but served content; nothing was stored"
			return ff
		}
		fh, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			ff.Detail = err.Error()
			return ff
		}
		if err := fh.Close(); err != nil {
			ff.Detail = err.Error()
			return ff
		}
		ff.Status = "full"
		ff.HTTP = res.Status
		return ff
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		ff.Detail = err.Error()
		return ff
	}
	part := target + ".part"
	fh, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		ff.Detail = err.Error()
		return ff
	}
	res, derr := f.o.Client.Download(f.ctx, id, e.path, 0, need, fh)
	if derr == nil {
		derr = fh.Sync()
	}
	if cerr := fh.Close(); derr == nil {
		derr = cerr
	}
	if derr != nil {
		os.Remove(part)
		f.downloadFailure(&ff, id, res, derr)
		return ff
	}
	// When the Hub did not declare a size (e.size < 0), we requested up to
	// SliceSize bytes; receiving fewer bytes means the server hit EOF and sent
	// the entire file.
	if res.Bytes != need {
		if e.size < 0 && res.Bytes < need {
			whole = true
		} else {
			os.Remove(part)
			ff.Detail = fmt.Sprintf("the Hub served %d bytes where %d were requested; the partial file was not renamed", res.Bytes, need)
			return ff
		}
	}
	if err := os.Rename(part, target); err != nil {
		os.Remove(part)
		ff.Detail = err.Error()
		return ff
	}
	ff.Status = "full"
	if !whole {
		ff.Status = "slice"
	}
	ff.Bytes = res.Bytes
	ff.HTTP = res.Status
	if whole && e.size >= 0 && res.Bytes != e.size {
		ff.Detail = fmt.Sprintf("the Hub listed %d bytes and served %d", e.size, res.Bytes)
	}
	return ff
}

// downloadFailure fills ff from a Download error. Every transfer failure is
// reported here so the empty-file probe and an ordinary fetch cannot drift.
func (f *fetcher) downloadFailure(ff *FetchFile, id string, res hubapi.DownloadResult, derr error) {
	ff.HTTP = res.Status
	switch {
	case errors.Is(derr, hubapi.ErrGated):
		ff.Status = "gated"
		ff.Detail = f.gateDetail(id, derr)
	case errors.Is(derr, hubapi.ErrAuth):
		ff.Status = "gated"
		ff.Detail = "the Hub rejected the token (401); check -token-file / HF_TOKEN"
	case errors.Is(derr, hubapi.ErrNotFound):
		ff.Status = "missing"
		ff.Detail = "the Hub has no such file (repo disabled after being flagged?)"
	default:
		ff.Detail = derr.Error()
	}
}

// gateDetail says why the Hub refused the file and what, if anything, the operator
// can do about it.
//
// The distinction is the whole answer to "can the tool handle this gate": with
// automatic approval the account accepts the terms once (in a browser — accepting
// legal terms is the account holder's act, not the scanner's) and the same token
// then downloads the file; with manual approval nothing but the owner can grant
// access, and no client-side retry can change that.
func (f *fetcher) gateDetail(id string, err error) string {
	if d, ok := f.gates[id]; ok {
		return d
	}
	var d string
	info, ierr := f.o.Client.ModelInfo(f.ctx, id)
	switch {
	case ierr == nil && info.Disabled:
		d = "gated: the repository is disabled on the Hub; nothing client-side can reopen it"
	case ierr == nil && info.Gated == "manual":
		d = fmt.Sprintf("gated: manual approval — the owner must grant this account access; request it at https://huggingface.co/%s", id)
	case ierr == nil && info.Gated == "auto":
		d = fmt.Sprintf("gated: automatic approval — this account has not accepted the terms; accept them at https://huggingface.co/%s and re-run -stage fetch", id)
	case ierr != nil:
		d = fmt.Sprintf("gated: %v (gate mode unknown: %v)", err, ierr)
	default:
		d = fmt.Sprintf("gated: %v", err)
	}
	f.gates[id] = d
	return d
}

// sliceNeed is the byte count a header slice of e costs.
func (f *fetcher) sliceNeed(e planned) int64 {
	need := f.o.SliceSize
	if e.size >= 0 && e.size < need {
		need = e.size
	}
	return need
}

// plan decides whole-file versus slice and how many bytes that needs.
func (f *fetcher) plan(e planned) (whole bool, need int64) {
	if e.size == 0 {
		return true, 0
	}
	if e.size > 0 && (e.size <= f.o.FullLimit || (e.flagged && e.size <= f.o.FlaggedLimit)) {
		return true, e.size
	}
	return false, f.sliceNeed(e)
}

// humanBytes formats a byte count for a progress or detail line.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
