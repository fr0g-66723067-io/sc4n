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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/malice"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Entry is one artifact to scan.
type Entry struct {
	// Path is where the bytes are read from.
	Path string
	// RootDir and Rel, when set, open the file as root.Open(Rel) instead of by
	// path. os.Root refuses a path that escapes the directory, so a symlink or
	// directory swap between the walk and the open cannot read a different file.
	RootDir string
	Rel     string
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

// SymlinkPolicy bounds where a symbolic link met during a directory walk may
// resolve.
type SymlinkPolicy int

const (
	// SymlinkRoot is the default: a link must resolve inside the tree being
	// scanned. A target outside it is not opened and is recorded with the escape
	// named, so the artifact summary and the exit code say the tree was left.
	//
	// It is the default because the walk is the only path-expansion seam that had
	// no containment: `ln -s /etc/shadow repo/leak.txt && sc4n scan repo` read the
	// outside file and reported a clean scan.
	SymlinkRoot SymlinkPolicy = iota
	// SymlinkFollow reads a file link wherever it resolves. It is the pre-0.1
	// behaviour and exists for a tree that is deliberately assembled out of links
	// into a shared cache. A link that resolves to a directory is still not
	// descended into — filepath.WalkDir does not follow links — so following does
	// not widen the walk, only what a file link may read.
	SymlinkFollow
)

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
	// Symlinks says what a symbolic link met during the walk may resolve to.
	// The zero value refuses a target outside the walk root, which is what makes
	// `sc4n scan ./model` a scan of ./model.
	Symlinks SymlinkPolicy
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
	// Attestations, when non-nil, is the effect record tools/sc4nconfirm
	// produced for artifacts that were loaded in a disposable container. It is
	// keyed by full digest: the same bytes scanned anywhere carry the same
	// verdict, and a path key would mis-merge the moment the same artifact is
	// scanned from a different root.
	Attestations *malice.Index
	// ExplicitZeroDepth preserves Limits.MaxDepth == 0 across Limits.Normalize,
	// so an explicit -max-depth 0 disables container recursion instead of
	// resetting to the default depth.
	ExplicitZeroDepth bool
	// ExplicitFullHash preserves Limits.MaxHashBytes == 0 across
	// Limits.Normalize, so an explicit -max-hash 0 digests the entire artifact
	// instead of resetting to the default prefix cap.
	ExplicitFullHash bool
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
	if cfg.ExplicitZeroDepth && cfg.Limits.MaxDepth == 0 {
		l.MaxDepth = 0
	}
	if cfg.ExplicitFullHash && cfg.Limits.MaxHashBytes == 0 {
		l.MaxHashBytes = 0
	}
	if cfg.MaxFindings < 0 {
		return nil, fmt.Errorf("scan: MaxFindings is negative (%d)", cfg.MaxFindings)
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
	collector.SetSuppress(cfg.Baseline)
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
		sum, cancelled := scanStdin(ctx, sess, cfg, l, b)
		res.Artifacts = []report.ArtifactSummary{sum}
		res.Cancelled = cancelled
		if sum.Error != "" {
			res.Unreadable = 1
		}
		res.Suppressed = collector.Suppressed()
		noteFindingsCap(collector, maxFindings)
		res.Timings["total_ms"] = report.Millis(time.Since(start))
		return res, nil
	}

	expandStart := time.Now()
	entries, expandCancelled, walkErr := expand(ctx, cfg)
	res.Timings["expand_ms"] = report.Millis(time.Since(expandStart))
	if expandCancelled {
		res.Cancelled = true
	}

	if len(entries) > 0 {
		b := newMemBudget(budget)
		var next atomic.Int64
		var wg sync.WaitGroup
		var mu sync.Mutex
		outcomes := make([]scanOutcome, 0, len(entries))
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
					out := scanOne(ctx, sess, entries[i], l, b, cfg.Attestations)
					mu.Lock()
					outcomes = append(outcomes, out)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		// Sort outcomes by artifact path before assigning duplicate labels so
		// the winner of MarkSeen is deterministic regardless of worker timing,
		// and never overwrite a parse or digest error already recorded on the row.
		sort.SliceStable(outcomes, func(i, j int) bool { return outcomes[i].sum.Path < outcomes[j].sum.Path })
		res.Artifacts = make([]report.ArtifactSummary, 0, len(outcomes))
		for i := range outcomes {
			sum := outcomes[i].sum
			if outcomes[i].dedupKey != "" {
				if prev, first := sess.MarkSeen(outcomes[i].dedupKey, sum.Path); !first {
					dup := "duplicate of " + prev
					if sum.SubFormat == "" {
						sum.SubFormat = dup
					} else {
						sum.SubFormat += "; " + dup
					}
				}
			}
			if sum.Error != "" {
				res.Unreadable++
			}
			res.Artifacts = append(res.Artifacts, sum)
		}
		if cancelled.Load() {
			res.Cancelled = true
		}
	}
	res.Suppressed = collector.Suppressed()
	noteFindingsCap(collector, maxFindings)
	res.Timings["total_ms"] = report.Millis(time.Since(start))
	return res, walkErr
}

type scanOutcome struct {
	sum      report.ArtifactSummary
	dedupKey string
}

// noteFindingsCap records that the finding list is incomplete. The drop is
// counted in Report.Dropped either way, but a consumer that watches *findings*
// (a SARIF upload, a CI gate) sees only the list: without a finding of its own,
// a truncated list is indistinguishable from a complete one. The notice is
// appended through Note, because the cap it describes would otherwise drop it.
func noteFindingsCap(c *report.Collector, maxFindings int) {
	dropped := c.Dropped()
	if dropped == 0 {
		return
	}
	c.NoteRule(limits.RuleFindings, c.FirstDroppedArtifact(), 0,
		strconv.Itoa(dropped)+" finding(s) were dropped at the MaxFindings cap of "+
			strconv.Itoa(maxFindings)+"; raise -max-findings to see them all",
		map[string]string{
			"limit":   "MaxFindings",
			"dropped": strconv.Itoa(dropped),
			"cap":     strconv.Itoa(maxFindings),
		})
}

// scanStdin reads one artifact from the configured reader through the same
// admission control and deadline as a file artifact. A stream's length is not
// known up front, so the read is bounded by min(MaxArtifactBytes, MemBudget): a
// producer that never stops is reported as a limit finding rather than buffered
// without bound, and the read loop observes ctx so -timeout stops a stream that
// stays open without producing.
func scanStdin(ctx context.Context, sess *artifact.Session, cfg Config, l limits.Limits, b *memBudget) (report.ArtifactSummary, bool) {
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
		return sum, errors.Is(err, errStdinDeadline)
	}
	size := int64(len(data))

	// The large-artifact slot is acquired before the byte budget, as in
	// scanOne: a task holding a large slot and waiting for bytes cannot starve
	// a task that holds bytes, because byte holders are already running.
	if size >= largeArtifact {
		if !b.acquireLarge(ctx) {
			sum.Error = "scan deadline exceeded while waiting for a large-artifact slot"
			return sum, true
		}
		defer b.releaseLarge()
	}
	if !b.acquire(ctx, size) {
		sum.Error = "scan deadline exceeded while waiting for the memory budget"
		return sum, true
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
	if r := cfg.Attestations.For(sum.SHA256Scope, sum.SHA256); r != nil {
		malice.Merge(sess.Collector, name, r)
	}
	f, perr := scanGuarded(sess, src, name, l)
	sum.Format = f.String()
	if perr != nil {
		// The same finding the file path emits: without it a -stdin run reports a
		// clean row for an artifact whose parser failed.
		sess.Collector.For(name).EmitExtra(artifact.RuleParseFailed, 0, perr.Error(), nil)
		sum.SubFormat = "parse-error: " + perr.Error()
	}
	return sum, false
}

// readCap returns the largest stdin stream that may be buffered and the name of
// the limit that bound it. A stdin artifact is held in memory (it is not
// memory-mapped and has no path to re-read), so the artifact-size cap alone is
// not enough: the run's memory budget applies too, and the smaller of the two
// wins. The name travels with the cap so the finding points at the knob the
// operator can raise.
func readCap(maxArtifact, memBudget int64) (int64, string) {
	if maxArtifact <= 0 || (memBudget > 0 && memBudget < maxArtifact) {
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
	ch := make(chan stdinRead)
	ack := make(chan struct{})
	go func() {
		defer close(ch)
		tmp := make([]byte, 64<<10)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				select {
				case ch <- stdinRead{buf: tmp[:n]}:
				case <-done:
					return
				case <-ctx.Done():
					return
				}
				select {
				case <-ack:
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
			select {
			case ack <- struct{}{}:
			case <-ctx.Done():
				return nil, errStdinDeadline
			}
		}
	}
}

// scanOne opens, hashes and scans one entry, releasing its budget when done.
func scanOne(ctx context.Context, sess *artifact.Session, e Entry, l limits.Limits, b *memBudget, att *malice.Index) scanOutcome {
	name := e.Display
	if name == "" {
		name = e.Path
	}
	sum := report.ArtifactSummary{Path: name, Format: artifact.FormatUnknown.String()}

	if e.Skip != nil {
		sum.Error = e.Skip.Error()
		return scanOutcome{sum: sum}
	}

	var (
		root   *os.Root
		opened *os.File
		before os.FileInfo
	)
	if e.RootDir != "" {
		var rerr error
		root, rerr = os.OpenRoot(e.RootDir)
		if rerr != nil {
			sum.Error = rerr.Error()
			return scanOutcome{sum: sum}
		}
		defer root.Close()
		f, oerr := root.Open(e.Rel)
		if oerr != nil {
			sum.Error = oerr.Error()
			return scanOutcome{sum: sum}
		}
		opened = f
		fi, serr := f.Stat()
		if serr != nil {
			_ = f.Close()
			sum.Error = serr.Error()
			return scanOutcome{sum: sum}
		}
		if !fi.Mode().IsRegular() {
			_ = f.Close()
			sum.Error = notRegular(e.Path, fi.Mode()).Error()
			return scanOutcome{sum: sum}
		}
		before = fi
		sum.Size = fi.Size()
	}

	var (
		fi  os.FileInfo
		err error
	)
	if opened != nil {
		fi = before
	} else {
		fi, err = os.Lstat(e.Path)
	}
	if err != nil {
		if opened != nil {
			_ = opened.Close()
		}
		sum.Error = err.Error()
		return scanOutcome{sum: sum}
	}
	// A symlink is followed (the hf-cache layout is built out of relative
	// symlinks); the containment check happens in the hf-cache expander, which
	// resolves through os.Root before yielding the path.
	size := fi.Size()
	if opened == nil && fi.Mode()&os.ModeSymlink != 0 {
		if st, serr := os.Stat(e.Path); serr == nil {
			size = st.Size()
			// Record the resolved target's Stat as `before` so the post-scan
			// comparison against os.Stat(e.Path) compares target-to-target
			// instead of comparing the symlink's Lstat against the target's Stat.
			before = st
			if st.IsDir() {
				// A directory reached through an entry list is not an artifact;
				// there is nothing to read and the contents are walked under their
				// own path.
				return scanOutcome{sum: sum}
			}
			// A link that resolves to a pipe, a socket or a device node is the
			// same hang as a pipe found directly: report it instead of opening it.
			if !st.Mode().IsRegular() {
				sum.Error = notRegular(e.Path, st.Mode()).Error()
				return scanOutcome{sum: sum}
			}
		} else {
			sum.Error = serr.Error()
			return scanOutcome{sum: sum}
		}
	}
	sum.Size = size
	if before == nil {
		before = fi
	}
	if opened == nil && fi.Mode()&os.ModeSymlink == 0 && !fi.Mode().IsRegular() {
		sum.Error = notRegular(e.Path, fi.Mode()).Error()
		return scanOutcome{sum: sum}
	}

	// The large-artifact slot is acquired before the byte budget: a task holding
	// a large slot and waiting for bytes cannot starve a task that holds bytes,
	// because byte holders are already running and will release.
	if size >= largeArtifact {
		if !b.acquireLarge(ctx) {
			if opened != nil {
				_ = opened.Close()
			}
			sum.Error = "scan deadline exceeded while waiting for a large-artifact slot"
			return scanOutcome{sum: sum}
		}
		defer b.releaseLarge()
	}
	if !b.acquire(ctx, size) {
		if opened != nil {
			_ = opened.Close()
		}
		sum.Error = "scan deadline exceeded while waiting for the memory budget"
		return scanOutcome{sum: sum}
	}
	defer b.release(size)

	var src source.Source
	if opened != nil {
		src, err = source.OpenFile(opened, name, l)
	} else {
		src, err = source.Open(e.Path, l)
	}
	if err != nil {
		if opened != nil {
			_ = opened.Close()
		}
		if errors.Is(err, source.ErrTooLarge) {
			limits.Emit(sess.Collector.For(name), limits.RuleArtifact, "MaxArtifactBytes", size, l.MaxArtifactBytes, e.Path)
		}
		sum.Error = err.Error()
		return scanOutcome{sum: sum}
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
	if before != nil {
		var after os.FileInfo
		var aerr error
		if root != nil {
			after, aerr = root.Stat(e.Rel)
		} else {
			after, aerr = os.Stat(e.Path)
		}
		if aerr != nil || !sameFileState(before, after) {
			detail := "the artifact changed while it was scanned"
			if aerr != nil {
				detail += ": " + aerr.Error()
			}
			sess.Collector.For(name).Emit(rulePathMutated, 0, detail)
			sum.Error = detail
		}
	}

	sum.SHA256 = digest
	sum.SHA256Scope = scope
	sum.Format = f.String()
	sum.Revision = e.Revision
	// The demonstrated grade, if the operator attested these bytes. It is
	// merged here, after the digest the attestation is keyed by, and it is one
	// finding at offset 0 per artifact, so the merge is order-independent.
	if r := att.For(scope, digest); r != nil {
		malice.Merge(sess.Collector, name, r)
	}
	// A row can fail both ways, and each failure is a separate fact about it: the
	// `else if` meant a parse failure hid the missing digest, which the report
	// otherwise states rather than leaving an empty digest unexplained.
	if perr != nil {
		sess.Collector.For(name).EmitExtra(artifact.RuleParseFailed, 0, perr.Error(), nil)
	}
	sum.SubFormat = subFormatFor(perr, digestErr)
	var dedupKey string
	if e.Digest != "" && sum.Error == "" {
		// The dedup key is the digest *and* its scope, so a prefix digest of a
		// huge blob can never collide with the full digest of a small one.
		// Actual MarkSeen assignment happens after worker join in sorted path
		// order so duplicate labels are deterministic.
		dedupKey = scope + ":" + e.Digest
	}
	return scanOutcome{sum: sum, dedupKey: dedupKey}
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

// bindRoot binds an entry to the root it was checked against, so it is opened
// through os.Root: a pathname open follows a link a writer can substitute between
// the containment check and the read, and os.Root refuses one that leaves the
// root. A path outside the root keeps its pathname open — the operator named it,
// and the root policy does not cover it.
func bindRoot(e Entry, root string) Entry {
	if root == "" {
		return e
	}
	croot := canonicalPath(root)
	cpath := canonicalPath(e.Path)
	rel, err := filepath.Rel(croot, cpath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return e
	}
	e.RootDir, e.Rel = croot, rel
	return e
}

// expand turns the configuration into a sorted work list. The first path-expansion
// error is returned alongside the list so the CLI can exit 3 for a path the user
// named and could not be opened, while still scanning everything else.
func expand(ctx context.Context, cfg Config) ([]Entry, bool, error) {
	if len(cfg.Entries) > 0 {
		out := append([]Entry(nil), cfg.Entries...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
		return dedupeEntries(out), ctx.Err() != nil, nil
	}
	var out []Entry
	var firstErr error
	cancelled := false
	for _, p := range cfg.Paths {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		display := p
		lfi, lerr := os.Lstat(p)
		if lerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p, lerr)
			}
			out = append(out, Entry{Path: p, Display: p})
			continue
		}
		root := cfg.Root
		if lfi.Mode()&os.ModeSymlink != 0 {
			target, terr := filepath.EvalSymlinks(p)
			if terr != nil {
				out = append(out, Entry{Path: p, Display: p, Skip: terr})
				continue
			}
			if root == "" {
				root = filepath.Dir(p)
			}
			if cfg.Symlinks == SymlinkRoot && !withinRoot(root, target) {
				out = append(out, Entry{Path: p, Display: p, Skip: symlinkEscape(p, target)})
				continue
			}
			p = target
		}
		fi, err := os.Stat(p)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p, err)
			}
			out = append(out, Entry{Path: p, Display: display})
			continue
		}
		if !fi.IsDir() {
			// Only a regular file under the root policy is bound: os.Root.Open
			// would block on a FIFO, and -symlinks follow deliberately reads where
			// the link resolves.
			e := Entry{Path: p, Display: display}
			if cfg.Symlinks == SymlinkRoot && fi.Mode().IsRegular() {
				e = bindRoot(e, root)
			}
			out = append(out, e)
			continue
		}
		// Keep both the walked directory spelling (for computing Rel against the
		// paths WalkDir yields) and the canonical root (for containment checks and
		// os.OpenRoot). Using EvalSymlinks(p) as the base of filepath.Rel broke
		// whenever p had a symlinked ancestor (e.g. /tmp/link/repo or macOS /tmp):
		// WalkDir yields /tmp/link/repo/file, whose Rel against /tmp/real/repo
		// started with ".." and os.Root rejected every file.
		walkRoot := filepath.Clean(p)
		root = canonicalPath(p)
		walkErr := filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				cancelled = true
				return filepath.SkipAll
			}
			if err != nil {
				out = append(out, Entry{Path: path, Display: path, Skip: err})
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				out = append(out, Entry{Path: path, Display: path, Skip: ierr})
				return nil
			}
			if info.IsDir() {
				if path != p && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			// d.Info follows the link for a symlink entry on some filesystems,
			// so the mode is the authority: a symlink to a directory must not be
			// descended into, and a FIFO must never be opened.
			if info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() {
				out = append(out, Entry{Path: path, Display: path, Skip: notRegular(path, info.Mode())})
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, lerr := filepath.EvalSymlinks(path)
				if lerr != nil {
					out = append(out, Entry{Path: path, Display: path, Skip: lerr})
					return nil
				}
				escape := cfg.Symlinks == SymlinkRoot && !withinRoot(root, target)
				st, serr := os.Stat(path)
				if serr == nil && st.IsDir() {
					// A link that resolves to a directory is not an artifact. The
					// walk does not descend into it (filepath.WalkDir does not follow
					// links) and the directory's own contents are scanned through
					// their real path, so reporting the link as an unreadable path
					// made a completely readable tree exit 3 on a benign
					// `models/current -> models/v3`. A directory link that leaves the
					// tree is recorded instead of being dropped: an entire subtree
					// outside the root would otherwise be unscanned with no trace.
					if escape {
						out = append(out, Entry{Path: path, Display: path,
							Skip: symlinkEscape(path, target)})
					}
					return nil
				}
				if escape {
					out = append(out, Entry{Path: path, Display: path,
						Skip: symlinkEscape(path, target)})
					return nil
				}
				// A regular in-root target is opened through os.Root: relative
				// symlinks are opened at the link's own spelling so os.Root catches
				// a replacement between walk and open; absolute symlinks that stay
				// inside root are opened at the target's root-relative path because
				// os.Root refuses absolute symlinks even when the target is in-root.
				if cfg.Symlinks == SymlinkRoot && serr == nil && st.Mode().IsRegular() {
					if raw, rlerr := os.Readlink(path); rlerr == nil && filepath.IsAbs(raw) {
						if relTarget, rerr := filepath.Rel(root, canonicalPath(target)); rerr == nil && relTarget != "." && relTarget != ".." && !strings.HasPrefix(relTarget, ".."+string(filepath.Separator)) {
							out = append(out, Entry{Path: path, Display: path, RootDir: root, Rel: relTarget})
							return nil
						}
					} else if rel, rerr := filepath.Rel(walkRoot, path); rerr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						out = append(out, Entry{Path: path, Display: path, RootDir: root, Rel: rel})
						return nil
					}
				}
				out = append(out, Entry{Path: target, Display: path})
				return nil
			}
			rel, rerr := filepath.Rel(walkRoot, path)
			if rerr != nil {
				rel = filepath.Base(path)
			}
			out = append(out, Entry{Path: path, Display: path, RootDir: root, Rel: rel})
			return nil
		})
		if walkErr != nil && firstErr == nil {
			firstErr = walkErr
		}
		if cancelled {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return dedupeEntries(out), cancelled, firstErr
}

// canonicalPath resolves p to an absolute, symlink-free path where possible so
// containment comparisons do not fail when one side is relative and the other is
// absolute (for example, an absolute symlink inside a relative scan root).
func canonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

// withinRoot reports whether target resolves inside root. Both are canonicalized
// (absolute + symlinks resolved) so a relative root and an absolute target
// compare cleanly.
func withinRoot(root, target string) bool {
	croot := canonicalPath(root)
	ctarget := canonicalPath(target)
	rel, err := filepath.Rel(croot, ctarget)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// symlinkEscape is the error an out-of-root link is recorded with: it names the
// link, the target and the flag that relaxes the rule, because the exit code alone
// (3, unreadable) does not say the scan read less than the tree it was given.
func symlinkEscape(path, target string) error {
	return fmt.Errorf("%s is a symlink out of the scan root (%s): it was not opened; pass -symlinks follow to read it", path, target)
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
