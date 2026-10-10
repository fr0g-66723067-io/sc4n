// Package scan drives a scan: it expands the paths it was given into a
// deterministic work list, runs one artifact per worker, and merges the results
// in a fixed order.
//
// The two properties that make sc4n usable as a CI gate are implemented here:
//
//   - determinism: the work list is sorted, each artifact is handled by exactly
//     one worker (no intra-artifact fan-out, which would interleave finding
//     order), and the report sorts what it emits. Two runs over the same bytes
//     produce byte-identical JSON.
//   - bounded memory: a size-weighted budget admits large artifacts, with a
//     stricter cap on how many multi-gigabyte files are mapped at once, and a file
//     large enough to matter is memory-mapped rather than read.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Entry is one artifact to scan.
type Entry struct {
	// Path is where the bytes are read from.
	Path string
	// Display is the name used in findings. It defaults to Path.
	Display string
	// Digest, when set, is a content key: an entry whose digest was already
	// scanned is recorded as a duplicate. The hf-cache walker sets it from the
	// blob file name so that one blob referenced from twenty revisions is
	// scanned once and labelled afterwards.
	Digest string
}

// Config is the scan request.
type Config struct {
	// Paths are files or directories to scan.
	Paths []string
	// Entries, when non-empty, replaces Paths (used by the hf-cache walker and
	// by tests).
	Entries []Entry
	// StdinName, when non-empty, reads exactly one artifact from Stdin under that
	// name, which is what -stdin -name does.
	StdinName string
	// Stdin is the reader for StdinName.
	Stdin io.Reader

	Limits limits.Limits
	// Jobs is the worker count; zero means runtime.NumCPU().
	Jobs int
	// MemBudget caps the total size of artifacts mapped at once.
	MemBudget int64
	// Root is the containment root for path-shaped values.
	Root string
	// DeepStats enables the informational weight-statistics rules.
	DeepStats bool
	// Timeout, when non-zero, bounds the whole scan.
	Timeout time.Duration
	// MaxFindings is the finding cap; zero means the limits default.
	MaxFindings int
	// Collector, when non-nil, receives every finding instead of a fresh
	// collector. It exists for the hf-cache expander, which runs *before* the
	// walk and has its own structural findings (a symlink that escapes the
	// cache, a referenced blob that is missing) to report into the same document
	// as the artifacts it yields.
	Collector *report.Collector
}

// Result is the outcome of a scan.
type Result struct {
	Collector  *report.Collector
	Artifacts  []report.ArtifactSummary
	Unreadable int
	Timings    map[string]int64
	// Cancelled is true when the deadline stopped the walk early, so a partial
	// result is never presented as a complete one.
	Cancelled bool
}

const (
	// defaultMemBudget is the total size of artifacts admitted concurrently.
	defaultMemBudget = 1 << 30
	// largeArtifact is the size at which the stricter concurrency cap applies.
	largeArtifact = 1 << 30
	// maxConcurrentLarge is how many >= 1 GiB artifacts may be in flight.
	maxConcurrentLarge = 2
)

// Run performs the scan. It never returns a nil Result once the walk started:
// individual unreadable paths are recorded on their ArtifactSummary and counted
// in Unreadable, because a directory containing one unreadable file is still
// worth scanning. The returned error is only the first path-expansion error.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	l, err := cfg.Limits.Normalize()
	if err != nil {
		return nil, err
	}
	jobs := cfg.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	budget := cfg.MemBudget
	if budget <= 0 {
		budget = defaultMemBudget
	}
	maxFindings := cfg.MaxFindings
	if maxFindings == 0 {
		maxFindings = l.MaxFindings
	}

	collector := cfg.Collector
	if collector == nil {
		collector = report.NewCollector(maxFindings)
	}
	sess := artifact.NewSession(collector, cfg.Root, l)
	sess.DeepStats = cfg.DeepStats

	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	start := time.Now()
	res := &Result{Collector: collector, Timings: map[string]int64{}}

	if cfg.StdinName != "" {
		// The stdin artifact goes through the same admission control as a file
		// artifact: a stream's length is unknown up front, so the budget bounds
		// how much may be buffered rather than being charged after the fact.
		b := newMemBudget(budget)
		sum := scanStdin(ctx, sess, cfg, l, b)
		res.Artifacts = []report.ArtifactSummary{sum}
		if sum.Error != "" {
			res.Unreadable = 1
		}
		noteFindingsCap(collector, l)
		res.Timings["total_ms"] = report.Millis(time.Since(start))
		return res, nil
	}

	expandStart := time.Now()
	entries, walkErr := expand(cfg)
	res.Timings["expand_ms"] = report.Millis(time.Since(expandStart))

	if len(entries) > 0 {
		b := newMemBudget(budget)
		var next atomic.Int64
		var wg sync.WaitGroup
		var mu sync.Mutex
		cancelled := atomic.Bool{}

		workers := min(jobs, len(entries))
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					if ctx.Err() != nil {
						cancelled.Store(true)
						return
					}
					i := int(next.Add(1)) - 1
					if i >= len(entries) {
						return
					}
					sum := scanOne(ctx, sess, entries[i], l, b)
					mu.Lock()
					res.Artifacts = append(res.Artifacts, sum)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		sort.SliceStable(res.Artifacts, func(i, j int) bool { return res.Artifacts[i].Path < res.Artifacts[j].Path })
		for _, a := range res.Artifacts {
			if a.Error != "" {
				res.Unreadable++
			}
		}
		res.Cancelled = cancelled.Load()
	}
	noteFindingsCap(collector, l)
	res.Timings["total_ms"] = report.Millis(time.Since(start))
	return res, walkErr
}

// noteFindingsCap records that the finding list is incomplete. The drop is
// counted in Report.Dropped either way, but a consumer that watches *findings*
// (a SARIF upload, a CI gate) sees only the list: without a finding of its own,
// a truncated list is indistinguishable from a complete one. The notice is
// appended through Note, because the cap it describes would otherwise drop it.
func noteFindingsCap(c *report.Collector, l limits.Limits) {
	dropped := c.Dropped()
	if dropped == 0 {
		return
	}
	c.NoteRule(limits.RuleFindings, c.FirstDroppedArtifact(), 0,
		strconv.Itoa(dropped)+" finding(s) were dropped at the MaxFindings cap of "+
			strconv.Itoa(l.MaxFindings)+"; raise -max-findings to see them all",
		map[string]string{
			"limit":   "MaxFindings",
			"dropped": strconv.Itoa(dropped),
			"cap":     strconv.Itoa(l.MaxFindings),
		})
}

// scanStdin reads one artifact from the configured reader through the same
// admission control and deadline as a file artifact. A stream's length is not
// known up front, so the read is bounded by min(MaxArtifactBytes, MemBudget): a
// producer that never stops is reported as a limit finding rather than buffered
// without bound, and the read loop observes ctx so -timeout stops a stream that
// stays open without producing.
func scanStdin(ctx context.Context, sess *artifact.Session, cfg Config, l limits.Limits, b *memBudget) report.ArtifactSummary {
	name := cfg.StdinName
	sum := report.ArtifactSummary{Path: name, Format: artifact.FormatUnknown.String()}
	capBytes, capLimit := readCap(l.MaxArtifactBytes, b.total)
	data, err := readStdinCapped(ctx, cfg.Stdin, capBytes, capLimit)
	if err != nil {
		var capErr *stdinCapError
		if errors.As(err, &capErr) {
			// The same rule the file path emits when source.Open refuses an
			// oversized file, so a consumer sees one cap finding shape whether
			// the artifact came from a path or from stdin.
			limits.Emit(sess.Collector.For(name), limits.RuleArtifact, capErr.limit, capErr.value, capErr.cap, name)
		}
		sum.Error = err.Error()
		return sum
	}
	size := int64(len(data))

	// The large-artifact slot is acquired before the byte budget, as in
	// scanOne: a task holding a large slot and waiting for bytes cannot starve
	// a task that holds bytes, because byte holders are already running.
	if size >= largeArtifact {
		if !b.acquireLarge(ctx) {
			sum.Error = "scan deadline exceeded while waiting for a large-artifact slot"
			return sum
		}
		defer b.releaseLarge()
	}
	if !b.acquire(ctx, size) {
		sum.Error = "scan deadline exceeded while waiting for the memory budget"
		return sum
	}
	defer b.release(size)

	src := source.Mem(name, data)
	defer src.Close()
	sum.Size = size
	// The same digestSource the file path uses, so a -stdin run past MaxHashBytes
	// reports sha256Scope="prefix" instead of claiming a full digest it did not
	// compute.
	sum.SHA256, sum.SHA256Scope = digestSource(src, l.MaxHashBytes)
	f, perr := scanGuarded(sess, src, name, l)
	sum.Format = f.String()
	if perr != nil {
		// The same finding the file path emits: without it a -stdin run reports a
		// clean row for an artifact whose parser failed.
		sess.Collector.For(name).EmitExtra(artifact.RuleParseFailed, 0, perr.Error(), nil)
		sum.SubFormat = "parse-error: " + perr.Error()
	}
	return sum
}

// readCap returns the largest stdin stream that may be buffered and the name of
// the limit that bound it. A stdin artifact is held in memory (it is not
// memory-mapped and has no path to re-read), so the artifact-size cap alone is
// not enough: the run's memory budget applies too, and the smaller of the two
// wins. The name travels with the cap so the finding points at the knob the
// operator can raise.
func readCap(maxArtifact, memBudget int64) (int64, string) {
	if memBudget > 0 && memBudget < maxArtifact {
		return memBudget, "MemBudget"
	}
	return maxArtifact, "MaxArtifactBytes"
}

// stdinCapError reports that a stdin stream exceeded its read cap before EOF.
// It is a distinct type so scanStdin can emit the limit finding with the right
// cap name; a plain read error is reported only as the artifact's error.
type stdinCapError struct {
	limit string
	value int64
	cap   int64
}

func (e *stdinCapError) Error() string {
	return "stdin exceeds " + strconv.FormatInt(e.cap, 10) + " bytes (" + e.limit + ")"
}

// errStdinDeadline is the exact message scanStdin reports when the deadline
// stopped the read. It is a sentinel rather than a wrapped ctx.Err() so the
// artifact's error text is fixed and a consumer can match it.
var errStdinDeadline = errors.New("scan deadline exceeded while reading stdin")

// stdinRead is one chunk, or a terminal error, from the background reader.
type stdinRead struct {
	buf []byte
	err error
}

// readStdinCapped reads one artifact from r, bounded by capBytes. Reads run on a
// background goroutine so that a producer which holds the write end open without
// producing (a shell, a socket) cannot pin the scan past its deadline: the loop
// returns as soon as ctx is done, whether or not the blocked Read ever returns.
// A stream that exceeds capBytes is refused with a *stdinCapError rather than
// truncated, so a partially read artifact is never scanned as if complete.
func readStdinCapped(ctx context.Context, r io.Reader, capBytes int64, capLimit string) ([]byte, error) {
	// done unblocks the reader goroutine when this function returns early, so a
	// cap or deadline failure does not leak it to its next read.
	done := make(chan struct{})
	defer close(done)
	ch := make(chan stdinRead, 1)
	go func() {
		defer close(ch)
		for {
			buf := make([]byte, 1<<20)
			n, err := r.Read(buf)
			if n > 0 {
				select {
				case ch <- stdinRead{buf: buf[:n]}:
				case <-done:
					return
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					select {
					case ch <- stdinRead{err: err}:
					case <-done:
					case <-ctx.Done():
					}
				}
				return
			}
		}
	}()

	var buf []byte
	for {
		select {
		case <-ctx.Done():
			return nil, errStdinDeadline
		case c, ok := <-ch:
			if !ok {
				return buf, nil
			}
			if c.err != nil {
				return nil, c.err
			}
			if total := int64(len(buf)) + int64(len(c.buf)); total > capBytes {
				return nil, &stdinCapError{limit: capLimit, value: total, cap: capBytes}
			}
			buf = append(buf, c.buf...)
		}
	}
}

// scanOne opens, hashes and scans one entry, releasing its budget when done.
func scanOne(ctx context.Context, sess *artifact.Session, e Entry, l limits.Limits, b *memBudget) report.ArtifactSummary {
	name := e.Display
	if name == "" {
		name = e.Path
	}
	sum := report.ArtifactSummary{Path: name, Format: artifact.FormatUnknown.String()}

	fi, err := os.Lstat(e.Path)
	if err != nil {
		sum.Error = err.Error()
		return sum
	}
	// A symlink is followed (the hf-cache layout is built out of relative
	// symlinks); the containment check happens in the hf-cache expander, which
	// resolves through os.Root before yielding the path.
	size := fi.Size()
	if fi.Mode()&os.ModeSymlink != 0 {
		if st, serr := os.Stat(e.Path); serr == nil {
			size = st.Size()
		} else {
			sum.Error = serr.Error()
			return sum
		}
	}
	sum.Size = size

	// The large-artifact slot is acquired before the byte budget: a task holding
	// a large slot and waiting for bytes cannot starve a task that holds bytes,
	// because byte holders are already running and will release.
	if size >= largeArtifact {
		if !b.acquireLarge(ctx) {
			sum.Error = "scan deadline exceeded while waiting for a large-artifact slot"
			return sum
		}
		defer b.releaseLarge()
	}
	if !b.acquire(ctx, size) {
		sum.Error = "scan deadline exceeded while waiting for the memory budget"
		return sum
	}
	defer b.release(size)

	src, err := source.Open(e.Path, l)
	if err != nil {
		if errors.Is(err, source.ErrTooLarge) {
			limits.Emit(sess.Collector.For(name), limits.RuleArtifact, "MaxArtifactBytes", size, l.MaxArtifactBytes, e.Path)
		}
		sum.Error = err.Error()
		return sum
	}
	defer src.Close()

	// The digest is computed concurrently with the parse. On an mmap-backed
	// source it is a second sequential pass over the mapping: page-cache
	// bandwidth, not resident memory, and it hides behind the parse.
	var (
		digest, scope string
		hashWG        sync.WaitGroup
	)
	hashWG.Add(1)
	go func() {
		defer hashWG.Done()
		digest, scope = digestSource(src, l.MaxHashBytes)
	}()

	f, perr := scanGuarded(sess, src, name, l)
	hashWG.Wait()

	sum.SHA256 = digest
	sum.SHA256Scope = scope
	sum.Format = f.String()
	if perr != nil {
		sess.Collector.For(name).EmitExtra(artifact.RuleParseFailed, 0, perr.Error(), nil)
		sum.SubFormat = "parse-error: " + perr.Error()
	}
	if e.Digest != "" {
		// The dedup key is the digest *and* its scope, so a prefix digest of a
		// huge blob can never collide with the full digest of a small one.
		key := scope + ":" + e.Digest
		if prev, first := sess.MarkSeen(key, name); !first {
			sum.SubFormat = "duplicate of " + prev
		}
	}
	return sum
}

// scanGuarded runs the dispatch and parser for one artifact, converting a parser
// panic into a finding. A parser bug must not take down a scan of an untrusted
// tree: the one thing sc4n must never do is crash on crafted input.
func scanGuarded(sess *artifact.Session, src source.Source, name string, l limits.Limits) (f artifact.Format, err error) {
	defer func() {
		if r := recover(); r != nil {
			sess.Collector.For(name).EmitExtra(ruleInternalPanic, 0,
				fmt.Sprintf("internal panic while parsing: %v", r), nil)
			f = artifact.FormatUnknown
			err = fmt.Errorf("internal panic: %v", r)
		}
	}()
	return artifact.Scan(sess.NewCtx(name, l), src)
}

// memBudget is size-weighted admission control. It exists so that a directory
// containing twenty 5 GiB files cannot map 100 GiB of address space on a 14 GiB
// host: each worker acquires its artifact's size before opening it.
type memBudget struct {
	total int64
	mu    sync.Mutex
	cond  *sync.Cond
	used  int64
	large chan struct{}
}

func newMemBudget(total int64) *memBudget {
	b := &memBudget{total: total, large: make(chan struct{}, maxConcurrentLarge)}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *memBudget) acquire(ctx context.Context, n int64) bool {
	if n > b.total {
		// A single artifact larger than the whole budget is admitted alone;
		// refusing it would make -mem-budget a way to silently skip files.
		n = b.total
	}
	stop := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		b.cond.Broadcast()
		b.mu.Unlock()
	})
	defer stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used+n > b.total {
		if ctx.Err() != nil {
			return false
		}
		b.cond.Wait()
	}
	b.used += n
	return true
}

func (b *memBudget) release(n int64) {
	if n > b.total {
		n = b.total
	}
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
	b.cond.Broadcast()
}

func (b *memBudget) acquireLarge(ctx context.Context) bool {
	select {
	case b.large <- struct{}{}:
		return true
	default:
	}
	select {
	case b.large <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *memBudget) releaseLarge() { <-b.large }

// digestSource hashes the whole source. It reads through the section reader
// rather than ReadAt so that a large mapping is read with the kernel's sequential
// readahead instead of a stream of independent pread calls.
// digestBuf is the buffer the digest pass hashes through. It is deliberately much
// larger than io.Copy's 32 KiB default: sha256's Write path reaches its full rate
// only on multi-megabyte chunks, and on a 13 GiB artifact the difference between
// 32 KiB and 4 MiB per call is the difference between ~300 MB/s and ~2 GB/s — the
// digest is the dominant cost of scanning a large, well-formed artifact, because
// everything else reads only the header.
var digestBufPool = sync.Pool{New: func() any { b := make([]byte, 4<<20); return &b }}

// digestSource returns the artifact's sha256 and what that digest covers.
//
// max caps the bytes hashed (Limits.MaxHashBytes). A capped digest is not a
// lesser *finding*, it is a lesser *identity*, so the scope travels with it in
// the report rather than being implied.
func digestSource(s source.Source, max int64) (string, string) {
	size := s.Size()
	if max <= 0 || max > size {
		max = size
	}
	h := sha256.New()
	if max == 0 {
		// An empty artifact. io.CopyBuffer panics on a zero-length buffer, and
		// there are no bytes to copy in any case.
		return hex.EncodeToString(h.Sum(nil)), "full"
	}
	bufp := digestBufPool.Get().(*[]byte)
	defer digestBufPool.Put(bufp)
	// The clamp keeps the buffer non-empty even if a future caller passes a
	// zero cap with a non-zero size.
	buf := (*bufp)[:min(int64(len(*bufp)), max)]
	if _, err := io.CopyBuffer(h, io.LimitReader(s.Reader(0), max), buf); err != nil {
		return "", ""
	}
	scope := "full"
	if max < size {
		scope = "prefix:" + strconv.FormatInt(max, 10)
	}
	return hex.EncodeToString(h.Sum(nil)), scope
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// skipDirs are directory names that never hold scan targets. Everything else is
// walked, including dotfiles, because .pth and .start files (the site-packages
// startup vectors) are dot-prefixed.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"__pycache__":  true,
}

// expand turns the configuration into a sorted work list. The first path-expansion
// error is returned alongside the list so the CLI can exit 3 for a path the user
// named and could not be opened, while still scanning everything else.
func expand(cfg Config) ([]Entry, error) {
	if len(cfg.Entries) > 0 {
		out := append([]Entry(nil), cfg.Entries...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
		return dedupeEntries(out), nil
	}
	var out []Entry
	var firstErr error
	for _, p := range cfg.Paths {
		fi, err := os.Stat(p)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p, err)
			}
			// Record the path so the report names the one that was unreadable.
			out = append(out, Entry{Path: p, Display: p})
			continue
		}
		if !fi.IsDir() {
			out = append(out, Entry{Path: p, Display: p})
			continue
		}
		walkErr := filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				// An unreadable directory does not abort the walk; it becomes a
				// recorded entry so the summary counts it.
				out = append(out, Entry{Path: path, Display: path})
				return nil
			}
			if d.IsDir() {
				if path != p && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			out = append(out, Entry{Path: path, Display: path})
			return nil
		})
		if walkErr != nil && firstErr == nil {
			firstErr = walkErr
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return dedupeEntries(out), firstErr
}

// dedupeEntries drops a repeated path, keeping the first entry. The same path can
// arrive twice -- `sc4n scan a.bin a.bin`, or a directory and a file inside it --
// and scanning it twice is wasted work that also produced two CycloneDX
// components with the same bom-ref, which the spec forbids. The input is already
// sorted, so the survivor is deterministic.
func dedupeEntries(in []Entry) []Entry {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, e := range in {
		key := e.Path
		if key == "" {
			key = e.Display
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}
