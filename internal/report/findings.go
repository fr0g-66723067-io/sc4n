// Package report holds sc4n's finding model, rule registry and output encoders.
//
// Every parser emits through a Sink bound to one artifact, so a finding can never
// carry the wrong artifact name, and every rule's severity/CWE live in exactly
// one place (the Rule the parser was compiled against) rather than being copied
// at each call site.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// severityNames is indexed by Severity. "unknown" is unreachable for a
// well-formed Finding and exists so that a zero-value Finding prints something
// honest rather than "info".
var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity accepts the names produced by String, plus the empty string
// which means the zero value (info).
func ParseSeverity(s string) (Severity, error) {
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
	Resolved         *bool             `json:"resolved,omitempty"`
	Extra            map[string]string `json:"extra,omitempty"`
}

// SeverityName and ConfidenceName exist so the JSON/SARIF encoders do not need a
// custom marshaler for a type whose only job is a total order.
func (f Finding) SeverityName() string   { return f.Severity.String() }
func (f Finding) ConfidenceName() string { return f.Confidence.String() }

// Collector accumulates findings in emission order and is the only mutable
// report state. Emission order is *not* the output order: the encoders sort, so
// that a worker-pool run and a serial run produce identical bytes.
type Collector struct {
	mu       sync.Mutex
	findings []Finding
	limit    int
	dropped  int
	// firstDropped is the artifact of the first finding the cap discarded. It is
	// what a SC4N-LIMIT-FINDINGS notice is attributed to, so the reader can see
	// which artifact's findings are incomplete rather than only that some are.
	firstDropped string
}

// NewCollector returns a Collector that keeps at most limit findings. A limit of
// zero means unlimited, which only tests should use.
func NewCollector(limit int) *Collector { return &Collector{limit: limit} }

// Add records one already-populated finding.
func (c *Collector) Add(f Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limit > 0 && len(c.findings) >= c.limit {
		if c.dropped == 0 {
			c.firstDropped = f.Artifact
		}
		c.dropped++
		return
	}
	c.findings = append(c.findings, f)
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
		if fp[Fingerprint(f)] {
			n++
			continue
		}
		kept = append(kept, f)
	}
	c.findings = kept
	return n
}

// Cap truncates the finding list to limit and returns the number discarded. It
// exists so the cap can be applied *after* baseline suppression: when a baseline
// is in play the scan runs uncapped, because a baselined finding must not consume
// a cap slot and evict a genuinely new finding.
func (c *Collector) Cap(limit int) int {
	if limit <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.findings) <= limit {
		return 0
	}
	n := len(c.findings) - limit
	if c.dropped == 0 {
		c.firstDropped = c.findings[limit].Artifact
	}
	c.dropped += n
	c.findings = c.findings[:limit]
	return n
}

// Sink is a Collector bound to one artifact name. Parsers hold a Sink, never the
// Collector, so a container parser that recurses into a member re-binds the
// artifact name for its inner findings.
type Sink struct {
	c        *Collector
	artifact string
}

// For returns a Sink for artifact.
func (c *Collector) For(artifact string) *Sink { return &Sink{c: c, artifact: artifact} }

// Artifact is the name this Sink stamps onto findings.
func (s *Sink) Artifact() string { return s.artifact }

// Named returns a Sink for a nested member, preserving the outer name as a
// prefix so a finding inside a member still identifies its container.
func (s *Sink) Named(member string) *Sink {
	return &Sink{c: s.c, artifact: s.artifact + ":" + member}
}

// Emit records a finding for r at off with the given evidence snippet. Severity,
// title, CWE and class come from the rule, so a call site cannot drift.
func (s *Sink) Emit(r *Rule, off int64, evidence string) {
	s.EmitExtra(r, off, evidence, nil)
}

// EmitExtra is Emit with additional machine-readable fields (for example
// `location`, `resolved`, `entropy`).
func (s *Sink) EmitExtra(r *Rule, off int64, evidence string, extra map[string]string) {
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

// sortFindings orders by (Artifact, Offset, RuleID) then by line/col so that the
// result is a total order even when two findings share artifact and offset.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Artifact != b.Artifact {
			return a.Artifact < b.Artifact
		}
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		if la, lb := lineOf(a), lineOf(b); la != lb {
			return la < lb
		}
		if ca, cb := colOf(a), colOf(b); ca != cb {
			return ca < cb
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Evidence < b.Evidence
	})
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
