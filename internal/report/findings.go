// Package report holds sc4n's finding model, rule registry and output encoders.
//
// Every parser emits through a Sink bound to one artifact, so a finding can never
// carry the wrong artifact name, and every rule's severity/CWE live in exactly
// one place (the Rule the parser was compiled against) rather than being copied
// at each call site.
package report

import (
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Severity is a total order, not a set: policy compares by value.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// severityNames is indexed by Severity. String reports "unknown" for an index
// outside the array, which no well-formed Finding produces; the zero value is
// SeverityInfo and prints "info".
var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity accepts the names produced by String, plus the empty string,
// which means the zero value (info) — so an unset -fail-on is the documented
// default rather than a usage error.
func ParseSeverity(s string) (Severity, error) {
	if s == "" {
		return SeverityInfo, nil
	}
	for i, n := range severityNames {
		if n == s {
			return Severity(i), nil
		}
	}
	return SeverityInfo, fmt.Errorf("report: unknown severity %q", s)
}

// AtLeast reports whether s is at least min, which is the -fail-on predicate.
func (s Severity) AtLeast(min Severity) bool { return s >= min }

// Confidence expresses how many independent conditions a finder checked, which
// is what separates "this pickle calls os.system" from "this GGUF's byte order
// could be either". It is orthogonal to Severity and is reported separately.
type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

var confidenceNames = [...]string{"low", "medium", "high"}

func (c Confidence) String() string {
	if int(c) < 0 || int(c) >= len(confidenceNames) {
		return "unknown"
	}
	return confidenceNames[c]
}

// Finding is one reportable observation. Offsets are absolute within the
// artifact the finding names, so two runs over the same bytes sort identically.
type Finding struct {
	RuleID           string            `json:"ruleId"`
	Title            string            `json:"title"`
	Severity         Severity          `json:"-"`
	Confidence       Confidence        `json:"-"`
	CWE              []string          `json:"cwe,omitempty"`
	Class            string            `json:"class,omitempty"`
	Artifact         string            `json:"artifact"`
	Offset           int64             `json:"offset"`
	Line             *int              `json:"line,omitempty"`
	Col              *int              `json:"col,omitempty"`
	Evidence         string            `json:"evidence,omitempty"`
	EvidenceRedacted bool              `json:"evidenceRedacted,omitempty"`
	Extra            map[string]string `json:"extra,omitempty"`
}

// SeverityName and ConfidenceName exist so the JSON/SARIF encoders do not need a
// custom marshaler for a type whose only job is a total order.
func (f Finding) SeverityName() string   { return f.Severity.String() }
func (f Finding) ConfidenceName() string { return f.Confidence.String() }

// Collector accumulates findings and is the only mutable report state.
// Emission order is *not* the output order: the encoders sort, so that a
// worker-pool run and a serial run produce identical bytes.
//
// When a limit is set, findings is a min-heap by value rather than a list in
// emission order (see Add), so the memory the collector holds is bounded by the
// limit rather than by how many findings a crafted artifact can produce.
type Collector struct {
	mu       sync.Mutex
	findings []Finding
	limit    int
	dropped  int
	// firstDropped is the artifact of the most valuable finding the cap
	// discarded. Findings are ranked by value and the cap keeps the top limit, so
	// the most valuable discarded finding is where the retained list starts to be
	// incomplete — and, unlike arrival order, it is the same on every run, which
	// is what keeps a SC4N-LIMIT-FINDINGS notice byte-identical between runs.
	firstDropped string
	bestDropped  *Finding
	// suppress is the baseline fingerprint set. Add checks it before the cap so
	// a baselined finding consumes no slot and a new finding cannot be evicted by
	// an old one.
	suppress   map[string]bool
	suppressed int
}

// NewCollector returns a Collector that keeps at most limit findings. A limit of
// zero means unlimited, which only tests should use.
func NewCollector(limit int) *Collector { return &Collector{limit: limit} }

// findingHeap is a min-heap of retained findings ordered by value: the root is
// the *least* valuable finding, so an incoming finding that beats it evicts it.
// It is how the cap keeps the limit most valuable findings without sorting the
// whole stream, and — because severity leads the order — without letting a flood
// of low-severity findings evict a critical one.
type findingHeap []Finding

func (h findingHeap) Len() int           { return len(h) }
func (h findingHeap) Less(i, j int) bool { return moreValuable(h[j], h[i]) }
func (h findingHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *findingHeap) Push(x any)        { *h = append(*h, x.(Finding)) }

func (h *findingHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// Add records one already-populated finding, evicting the least valuable retained
// finding when the cap is full. The eviction is decided by value, not by arrival
// order, so the surviving set is the same however the workers interleave: a
// finding at or above -fail-on can never be dropped in favour of a less severe
// one, which is what makes "exit 0" mean "nothing at the threshold was hidden".
func (c *Collector) Add(f Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !f.EvidenceRedacted && c.suppress[Fingerprint(f)] {
		c.suppressed++
		return
	}
	if c.limit <= 0 {
		c.findings = append(c.findings, f)
		return
	}
	h := findingHeap(c.findings)
	if len(h) < c.limit {
		heap.Push(&h, f)
		c.findings = h
		return
	}
	if !moreValuable(f, h[0]) {
		// f is not more valuable than the least valuable finding retained, which
		// the heap root is, so f is what the cap discards.
		c.discard(f)
		return
	}
	c.discard(h[0])
	h[0] = f
	heap.Fix(&h, 0)
	c.findings = h
}

// SetSuppress installs a baseline fingerprint set. Suppression is checked at Add,
// before the finding cap, so baselined findings consume no cap slots.
func (c *Collector) SetSuppress(fp map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.suppress = fp
}

// Suppressed returns how many findings a baseline removed.
func (c *Collector) Suppressed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.suppressed
}

// discard records that the cap dropped one finding, keeping the most valuable
// discarded finding so a SC4N-LIMIT-FINDINGS notice can name the artifact whose
// list is most worth re-reading and does not vary with arrival order.
func (c *Collector) discard(f Finding) {
	c.dropped++
	if c.bestDropped != nil && !moreValuable(f, *c.bestDropped) {
		return
	}
	b := f
	c.bestDropped = &b
	c.firstDropped = f.Artifact
}

// NoteRule records a finding that the cap does not apply to, copying the rule's
// metadata the way Sink.EmitExtra does. It exists for the one notice a capped
// report owes its reader — SC4N-LIMIT-FINDINGS — which would otherwise be
// dropped by the very cap it is describing.
func (c *Collector) NoteRule(r *Rule, artifact string, off int64, evidence string, extra map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, Finding{
		RuleID:     r.ID,
		Title:      r.Title,
		Severity:   r.Severity,
		Confidence: r.Confidence,
		CWE:        r.CWE,
		Class:      r.Class,
		Artifact:   artifact,
		Offset:     off,
		Evidence:   evidence,
		Extra:      extra,
	})
}

// Dropped is the number of findings discarded because the cap was reached.
func (c *Collector) Dropped() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// FirstDroppedArtifact is the artifact whose findings the cap started discarding,
// or "" when nothing was dropped.
func (c *Collector) FirstDroppedArtifact() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstDropped
}

// Len is the current finding count.
func (c *Collector) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.findings)
}

// Findings returns a copy, sorted deterministically. Callers may mutate the
// returned slice.
func (c *Collector) Findings() []Finding {
	c.mu.Lock()
	out := make([]Finding, len(c.findings))
	copy(out, c.findings)
	c.mu.Unlock()
	sortFindings(out)
	return out
}

// MaxSeverity returns the highest severity recorded, which is what the exit code
// depends on.
func (c *Collector) MaxSeverity() Severity {
	c.mu.Lock()
	defer c.mu.Unlock()
	max := SeverityInfo
	for _, f := range c.findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// CountBySeverity returns counts indexed by severity.
func (c *Collector) CountBySeverity() [5]int {
	var counts [5]int
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.findings {
		if int(f.Severity) >= 0 && int(f.Severity) < len(counts) {
			counts[f.Severity]++
		}
	}
	return counts
}

// Suppress removes findings whose fingerprint is in the set, returning how many
// were removed. Fingerprints come from internal/policy's baseline loader.
func (c *Collector) Suppress(fp map[string]bool) int {
	if len(fp) == 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.findings[:0]
	n := 0
	for _, f := range c.findings {
		if !f.EvidenceRedacted && fp[Fingerprint(f)] {
			n++
			continue
		}
		kept = append(kept, f)
	}
	c.findings = kept
	return n
}

// Cap truncates the finding list to the limit most valuable findings and returns
// the number discarded. It exists so the cap can be applied *after* baseline
// suppression: when a baseline is in play the scan runs uncapped, because a
// baselined finding must not consume a cap slot and evict a genuinely new
// finding. The selection is by value, exactly as Add's is, so a capped run and a
// suppressed-then-capped run agree on what they keep.
//
// It leaves findings ordered by value; a later Add would need the heap rebuilt,
// which no caller does — the cap is applied once the scan is complete.
func (c *Collector) Cap(limit int) int {
	if limit <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.findings) <= limit {
		return 0
	}
	sort.Slice(c.findings, func(i, j int) bool { return moreValuable(c.findings[i], c.findings[j]) })
	n := len(c.findings) - limit
	// The slice is now ordered by value, so the most valuable discarded finding —
	// the first one in value order — is exactly the one at the boundary.
	c.discard(c.findings[limit])
	c.dropped += n - 1
	c.findings = c.findings[:limit]
	return n
}

// Sink is a Collector bound to one artifact name. Parsers hold a Sink, never the
// Collector, so a container parser that recurses into a member re-binds the
// artifact name for its inner findings.
type Sink struct {
	c        *Collector
	artifact string
	// seen holds the fingerprint of every finding already emitted for this
	// artifact. The same bytes are scanned by more than one layer — a tokenizer
	// document's decoded values and its raw text, a template's text and its
	// indicator pass — and a fact is a fact however many layers saw it: 159
	// (rule, artifact, offset) keys in the 273-model HF campaign carried 2-5
	// identical findings. The map is per artifact, so it is bounded by the
	// artifact's own findings.
	seen map[[2]uint64]struct{}
}

// For returns a Sink for artifact.
func (c *Collector) For(artifact string) *Sink { return &Sink{c: c, artifact: artifact} }

// Artifact is the name this Sink stamps onto findings.
func (s *Sink) Artifact() string { return s.artifact }

// Named returns a Sink for a nested member, preserving the outer name as a
// prefix so a finding inside a member still identifies its container.
//
// The new Sink starts with an empty seen map: a member is a different artifact,
// so its findings are deduplicated against their own artifact and not the
// container's.
func (s *Sink) Named(member string) *Sink {
	return &Sink{c: s.c, artifact: s.artifact + ":" + member}
}

// duplicate reports whether this exact finding was already emitted for this
// artifact. pos is the byte offset for the offset emitters and the packed
// line/column for the position emitters.
//
// A duplicate returns before the finding reaches the cap, so the cap's dropped
// counter is not touched: the first copy was either retained or counted as
// dropped, and the second is the same fact, not a second one.
// maxSinkSeen bounds the per-artifact dedupe map. The collector's MaxFindings
// bounds retained findings, but a crafted stream can emit a million distinct
// keys that are all dropped; beyond this cap deduplication stops rather than
// growing the map with them.
const maxSinkSeen = 1 << 16

func (s *Sink) duplicate(r *Rule, pos uint64, evidence string) bool {
	if s.seen == nil {
		s.seen = make(map[[2]uint64]struct{})
	}
	var key [2]uint64
	for i, h := range [2]hash.Hash64{fnv.New64a(), fnv.New64()} {
		io.WriteString(h, r.ID)
		h.Write([]byte{0})
		io.WriteString(h, s.artifact)
		h.Write([]byte{0})
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], pos)
		h.Write(b[:])
		io.WriteString(h, evidence)
		key[i] = h.Sum64()
	}
	if _, ok := s.seen[key]; ok {
		return true
	}
	if len(s.seen) >= maxSinkSeen {
		return false
	}
	s.seen[key] = struct{}{}
	return false
}

// position packs a line/column pair for the dedupe key.
func position(line, col int) uint64 { return uint64(line)<<32 | uint64(uint32(col)) }

// Emit records a finding for r at off with the given evidence snippet. Severity,
// title, CWE and class come from the rule, so a call site cannot drift.
func (s *Sink) Emit(r *Rule, off int64, evidence string) {
	s.EmitExtra(r, off, evidence, nil)
}

// EmitExtra is Emit with additional machine-readable fields (for example
// `location`, `resolved`, `entropy`).
func (s *Sink) EmitExtra(r *Rule, off int64, evidence string, extra map[string]string) {
	if s.duplicate(r, uint64(off), evidence) {
		return
	}
	s.c.Add(Finding{
		RuleID:     r.ID,
		Title:      r.Title,
		Severity:   r.Severity,
		Confidence: r.Confidence,
		CWE:        r.CWE,
		Class:      r.Class,
		Artifact:   s.artifact,
		Offset:     off,
		Evidence:   evidence,
		Extra:      extra,
	})
}

// EmitRedacted is EmitExtra for a finding whose evidence must not be reproduced
// verbatim, because it contains a secret value. The evidence text is still
// recorded (so a baseline fingerprint stays stable) but the flag tells every
// consumer to treat it as sensitive, and the text itself is masked.
func (s *Sink) EmitRedacted(r *Rule, off int64, evidence string, extra map[string]string) {
	if s.duplicate(r, uint64(off), evidence) {
		return
	}
	s.c.Add(Finding{
		RuleID:           r.ID,
		Title:            r.Title,
		Severity:         r.Severity,
		Confidence:       r.Confidence,
		CWE:              r.CWE,
		Class:            r.Class,
		Artifact:         s.artifact,
		Offset:           off,
		Evidence:         evidence,
		EvidenceRedacted: true,
		Extra:            extra,
	})
}

// EmitAt is Emit with a source line/column instead of a byte offset, for the
// source-analysis rules.
func (s *Sink) EmitAt(r *Rule, line, col int, evidence string) {
	s.EmitAtExtra(r, line, col, evidence, nil)
}

// EmitAtExtra is EmitExtra with a line/column instead of a byte offset.
func (s *Sink) EmitAtExtra(r *Rule, line, col int, evidence string, extra map[string]string) {
	if s.duplicate(r, position(line, col), evidence) {
		return
	}
	l, c := line, col
	s.c.Add(Finding{
		RuleID:     r.ID,
		Title:      r.Title,
		Severity:   r.Severity,
		Confidence: r.Confidence,
		CWE:        r.CWE,
		Class:      r.Class,
		Artifact:   s.artifact,
		Offset:     0,
		Line:       &l,
		Col:        &c,
		Evidence:   evidence,
		Extra:      extra,
	})
}

// moreValuable reports whether a should be kept in preference to b when the
// finding cap has to choose between them. Severity leads, so a flood of
// low-severity findings can never evict a critical one; the report's own order
// breaks ties, so the surviving set is a deterministic function of the findings
// and not of the order the workers finished in. compareFindings is a total order,
// which makes this one too — that is what lets the cap be a bounded heap.
func moreValuable(a, b Finding) bool {
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	return compareFindings(a, b) < 0
}

// compareFindings is the report's total order: artifact, offset, line, column,
// rule ID, evidence, then the remaining reported fields, so that two findings
// which agree on the first six still have a fixed relative order. sortFindings
// uses it for output and moreValuable uses it to break severity ties.
func compareFindings(a, b Finding) int {
	if c := strings.Compare(a.Artifact, b.Artifact); c != 0 {
		return c
	}
	if c := compareInt64(a.Offset, b.Offset); c != 0 {
		return c
	}
	if c := compareInt(lineOf(a), lineOf(b)); c != 0 {
		return c
	}
	if c := compareInt(colOf(a), colOf(b)); c != 0 {
		return c
	}
	if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}
	if c := strings.Compare(a.Evidence, b.Evidence); c != 0 {
		return c
	}
	if c := strings.Compare(a.Title, b.Title); c != 0 {
		return c
	}
	if c := strings.Compare(a.Class, b.Class); c != 0 {
		return c
	}
	if c := compareInt(int(a.Severity), int(b.Severity)); c != 0 {
		return c
	}
	if c := compareInt(int(a.Confidence), int(b.Confidence)); c != 0 {
		return c
	}
	if a.EvidenceRedacted != b.EvidenceRedacted {
		if a.EvidenceRedacted {
			return 1
		}
		return -1
	}
	if c := compareStrings(a.CWE, b.CWE); c != 0 {
		return c
	}
	return strings.Compare(extraString(a.Extra), extraString(b.Extra))
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func compareInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func compareStrings(a, b []string) int {
	n := min(len(a), len(b))
	for i := range n {
		if c := strings.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	return compareInt(len(a), len(b))
}

// extraString renders an Extra map in a fixed key order, so a comparison never
// depends on Go's map iteration order.
func extraString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\x00')
	}
	return b.String()
}

// sortFindings orders by the report's total order, so the output is a function of
// the findings rather than of the order they were emitted in.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return compareFindings(fs[i], fs[j]) < 0 })
}

func lineOf(f Finding) int {
	if f.Line == nil {
		return 0
	}
	return *f.Line
}

func colOf(f Finding) int {
	if f.Col == nil {
		return 0
	}
	return *f.Col
}

// Fingerprint identifies a finding across runs for baseline suppression: the rule
// plus the artifact plus a hash of the evidence window. It deliberately excludes
// the byte offset, because editing an unrelated part of a file shifts every later
// offset and would otherwise un-suppress an entire baseline. The evidence is
// hashed rather than embedded so a baseline never contains payload text.
//
// A *redacted* finding is the exception: its evidence is a constant masking
// string, so without a position every redacted finding of one rule in one file
// collides, and baselining a file with two secrets then suppresses a third secret
// added later. For a redacted finding the byte offset is the only identity it has,
// and the offset-stability argument above is about evidence windows, not about
// secrets: a secret's identity is where it sits.
func Fingerprint(f Finding) string {
	var b strings.Builder
	b.Grow(len(f.RuleID) + len(f.Artifact) + 40)
	b.WriteString(f.RuleID)
	b.WriteByte('\x00')
	b.WriteString(f.Artifact)
	b.WriteByte('\x00')
	if f.EvidenceRedacted {
		b.WriteString("at:")
		b.WriteString(strconv.FormatInt(f.Offset, 10))
		return b.String()
	}
	sum := sha256.Sum256([]byte(f.Evidence))
	b.WriteString(hex.EncodeToString(sum[:12]))
	return b.String()
}

// SeverityBand returns GitHub's numeric security-severity for a severity, which
// is the value SARIF consumers use to rank alerts: critical 9.5, high 8.0,
// medium 5.5, low 3.0, info 0.0 (matching GitHub's documented bands of 9.0+/7.0-
// 8.9/4.0-6.9/0.1-3.9).
func SeverityBand(s Severity) string {
	switch s {
	case SeverityCritical:
		return "9.5"
	case SeverityHigh:
		return "8.0"
	case SeverityMedium:
		return "5.5"
	case SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// SARIFLevel maps a severity onto SARIF's three-value level, which is what makes
// a result visible in GitHub code scanning. Anything that is not an error is at
// most a note-or-warning, never silently dropped.
func SARIFLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
