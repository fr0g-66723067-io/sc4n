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
	// Revision is a comma-separated list of refs/<name> labels whose commit
	// points at this entry, when the source knows them (the hf-cache walker
	// reads them from refs/). It reaches the report so a finding can be
	// attributed to the revision the user was actually using.
	Revision string
	// Skip, when set, is why this entry is reported instead of read. It exists
	// for the entry an expander already knows cannot be opened as an artifact: a
	// directory walk that meets a FIFO, a socket or a device node. os.Open on a
	// FIFO blocks until a writer appears, and a blocked syscall is not
	// interruptible by the scan deadline, so one pipe in a scanned tree hung the
	// whole run with no finding and no exit code — the one outcome a scanner must
	// never produce. The error text reaches the artifact summary and the
	// unreadable-path count.
	Skip error
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
	// Partial names artifacts whose bytes are a truncated copy (a header slice of
	// a larger file), so a rule that compares a declared extent against the file on
	// disk can report "unverifiable" instead of a violation. Paths are as the
	// report names them, or relative to Root.
	Partial []string
	// DeepStats enables the informational weight-statistics rules.
	DeepStats bool
	// Timeout, when non-zero, bounds the whole scan.
	Timeout time.Duration
	// MaxFindings is the finding cap; zero means the limits default.
	MaxFindings int
	// Baseline, when non-empty, is the fingerprint set a previous report stands
	// for. Suppression runs here, before the finding cap, so a baselined finding
	// cannot consume a cap slot and evict a new one.
	Baseline map[string]bool
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
	// Suppressed is the number of findings -baseline removed. It is reported here
	// rather than by the caller because suppression must run before the finding
	// cap for the cap to mean what it says.
	Suppressed int
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

	// With a baseline the scan runs uncapped and the cap is applied after
	// suppression: a baselined finding must not consume a cap slot, or a new
	// finding is evicted by an old one and the reported suppressed count is
	// whatever happened to fit.
	limit := maxFindings
	if len(cfg.Baseline) > 0 {
		limit = 0
	}
	collector := cfg.Collector
	if collector == nil {
		collector = report.NewCollector(limit)
	}
	sess := artifact.NewSession(collector, cfg.Root, l)
	sess.SetPartial(cfg.Partial)
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
		if len(cfg.Baseline) > 0 {
			res.Suppressed = collector.Suppress(cfg.Baseline)
			collector.Cap(maxFindings)
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
	if len(cfg.Baseline) > 0 {
		res.Suppressed = collector.Suppress(cfg.Baseline)
		collector.Cap(maxFindings)
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
	var derr error
	sum.SHA256, sum.SHA256Scope, derr = digestSource(src, l.MaxHashBytes)
	if derr != nil {
		sum.SubFormat = "digest unavailable: " + derr.Error()
	}
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

	if e.Skip != nil {
		sum.Error = e.Skip.Error()
		return sum
	}

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
			if st.IsDir() {
				// A directory reached through an entry list is not an artifact;
				// there is nothing to read and the contents are walked under their
				// own path.
				return sum
			}
			// A link that resolves to a pipe, a socket or a device node is the
			// same hang as a pipe found directly: report it instead of opening it.
			if !st.Mode().IsRegular() {
				sum.Error = notRegular(e.Path, st.Mode()).Error()
				return sum
			}
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
		digestErr     error
		hashWG        sync.WaitGroup
	)
	hashWG.Add(1)
	go func() {
		defer hashWG.Done()
		digest, scope, digestErr = digestSource(src, l.MaxHashBytes)
	}()

	f, perr := scanGuarded(sess, src, name, l)
	hashWG.Wait()

	sum.SHA256 = digest
	sum.SHA256Scope = scope
	sum.Format = f.String()
	sum.Revision = e.Revision
	// A row can fail both ways, and each failure is a separate fact about it: the
	// `else if` meant a parse failure hid the missing digest, which the report
	// otherwise states rather than leaving an empty digest unexplained.
	if perr != nil {
		sess.Collector.For(name).EmitExtra(artifact.RuleParseFailed, 0, perr.Error(), nil)
	}
	sum.SubFormat = subFormatFor(perr, digestErr)
	if e.Digest != "" {
		// A guard, not the primary mechanism: the hf-cache expander already
		// de-duplicates a cache on the resolved blob path, so this normally never
		// fires. It stays because one map lookup per artifact is cheap insurance
		// for any future walker that yields the same bytes twice.
		//
		// The dedup key is the digest *and* its scope, so a prefix digest of a
		// huge blob can never collide with the full digest of a small one.
		key := scope + ":" + e.Digest
		if prev, first := sess.MarkSeen(key, name); !first {
			sum.SubFormat = "duplicate of " + prev
		}
	}
	return sum
}

// subFormatFor describes why a row was not fully scanned. A parse failure and a
// digest failure are separate facts and can both be true, so neither may hide the
// other: a row whose bytes could not be read for hashing says so even when the
// parser also rejected it.
func subFormatFor(perr, digestErr error) string {
	switch {
	case perr != nil && digestErr != nil:
		return "parse-error: " + perr.Error() + "; digest unavailable: " + digestErr.Error()
	case perr != nil:
		return "parse-error: " + perr.Error()
	case digestErr != nil:
		return "digest unavailable: " + digestErr.Error()
	}
	return ""
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
// digestSource hashes the artifact, up to max bytes. It returns an error rather
// than an empty digest so a caller can say *why* a scanned artifact has no
// digest: silently returning "" left a row with a size, no digest and no error,
// which reads as an artifact that simply has no digest.
func digestSource(s source.Source, max int64) (string, string, error) {
	size := s.Size()
	if max <= 0 || max > size {
		max = size
	}
	h := sha256.New()
	if max == 0 {
		// An empty artifact. io.CopyBuffer panics on a zero-length buffer, and
		// there are no bytes to copy in any case.
		return hex.EncodeToString(h.Sum(nil)), "full", nil
	}
	bufp := digestBufPool.Get().(*[]byte)
	defer digestBufPool.Put(bufp)
	// The clamp keeps the buffer non-empty even if a future caller passes a
	// zero cap with a non-zero size.
	buf := (*bufp)[:min(int64(len(*bufp)), max)]
	if _, err := io.CopyBuffer(h, io.LimitReader(s.Reader(0), max), buf); err != nil {
		return "", "", err
	}
	scope := "full"
	if max < size {
		scope = "prefix:" + strconv.FormatInt(max, 10)
	}
	return hex.EncodeToString(h.Sum(nil)), scope, nil
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// skipDirs are directory names that never hold scan targets. Everything else is
// walked, including dotfiles, because .pth and .start files (the site-packages
// startup vectors) are dot-prefixed.
// notRegular is the reason an entry that is not a regular file is reported rather
// than read. The kind is spelled out because "unreadable" tells a reviewer the
// wrong thing: this is a file the scanner deliberately did not open, not one it
// failed to open.
func notRegular(path string, mode os.FileMode) error {
	kind := "special file"
	switch {
	case mode&os.ModeNamedPipe != 0:
		kind = "named pipe"
	case mode&os.ModeSocket != 0:
		kind = "socket"
	case mode&os.ModeDevice != 0:
		kind = "device node"
	case mode&os.ModeSymlink != 0:
		kind = "symlink"
	}
	return fmt.Errorf("%s is a %s, not a regular file: it was not opened, because reading it can block the scan", path, kind)
}

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
			// A symlink is followed by scanOne (the hf-cache layout is built out
			// of them), so it is not skipped here; anything else that is not a
			// regular file is recorded, never opened: reading a FIFO blocks until
			// a writer appears, which hangs the scan rather than failing it.
			if !d.Type().IsRegular() && d.Type()&os.ModeSymlink == 0 {
				out = append(out, Entry{Path: path, Display: path, Skip: notRegular(path, d.Type())})
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				// A link that resolves to a directory is not an artifact. The walk
				// does not descend into it (filepath.WalkDir does not follow links)
				// and the directory's own contents are scanned through their real
				// path, so reporting the link as an unreadable path made a completely
				// readable tree exit 3 on a benign `models/current -> models/v3`.
				if st, err := os.Stat(path); err == nil && st.IsDir() {
					return nil
				}
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
