package report

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"
)

// SchemaVersion is bumped when the JSON payload changes shape. Consumers pin it.
const SchemaVersion = "1"

// Tool identifies the producer in every output format.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ArtifactSummary is one scanned file. SHA256 is computed streaming while the
// file is being scanned, never in a second pass.
type ArtifactSummary struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	// SHA256Scope says what SHA256 covers: "full" for the whole artifact, or
	// "prefix:<bytes>" when the artifact is larger than Limits.MaxHashBytes and
	// only its first bytes were digested. It is always present when SHA256 is,
	// because a prefix digest presented as a file digest is exactly the kind of
	// silent truncation the rest of this tool refuses to do.
	SHA256Scope string `json:"sha256Scope,omitempty"`
	Format      string `json:"format"`
	SubFormat   string `json:"subFormat,omitempty"`
	// Revision names the refs/<name> labels a cache entry is reachable from, when
	// the source knows them (-hf-cache). The snapshot path already carries the
	// commit, so this is what names the *branch* the user pinned.
	Revision string `json:"revision,omitempty"`
	// Error is set when the path could not be opened or read. It is *not* a
	// finding: an unreadable path is a tool/layout problem, reported with exit
	// code 3, while an unreadable *member* is a finding, because a container
	// that hides a member from the scanner is exactly the modelscan fail-open
	// shape.
	Error string `json:"error,omitempty"`
	// NotScanned marks a row that no scan produced: it exists only because a
	// finding named a path that has no summary (the hf-cache expander reporting a
	// missing blob, say), so every encoder's reference resolves. Such a row must
	// not be counted as a scanned artifact — that is how a scan of one file
	// declared three.
	NotScanned bool `json:"notScanned,omitempty"`
}

// Limits is the effective budget echoed into the report, so a reader can tell a
// genuinely small finding set from a truncated scan.
type Limits struct {
	MaxArtifactBytes     int64 `json:"maxArtifactBytes"`
	MaxHeaderBytes       int64 `json:"maxHeaderBytes"`
	MaxDepth             int   `json:"maxDepth"`
	MaxEntries           int   `json:"maxEntries"`
	MaxArrayElements     int   `json:"maxArrayElements"`
	MaxDecompressedBytes int64 `json:"maxDecompressedBytes"`
	MaxRatio             int64 `json:"maxRatio"`
	MaxStringBlob        int64 `json:"maxStringBlob"`
	MaxRetainedText      int64 `json:"maxRetainedText"`
	MaxChatTemplates     int   `json:"maxChatTemplates"`
	MaxHashBytes         int64 `json:"maxHashBytes"`
	MaxSpillBytes        int64 `json:"maxSpillBytes"`
	MaxFindings          int   `json:"maxFindings"`
	MaxStackDepth        int   `json:"maxStackDepth"`
}

// dedupeArtifacts drops a repeated summary for the same path, keeping the first.
// Two identical paths on the command line are one artifact, and a CycloneDX
// bom-ref must be unique.
func dedupeArtifacts(arts []ArtifactSummary) []ArtifactSummary {
	seen := make(map[string]bool, len(arts))
	out := arts[:0]
	for _, a := range arts {
		if seen[a.Path] {
			continue
		}
		seen[a.Path] = true
		out = append(out, a)
	}
	return out
}

// declareFindingArtifacts appends a summary for every path a finding names that no
// summary covers, so that every encoder's reference resolves: CycloneDX requires
// each affects[].ref to name a declared bom-ref, and SARIF needs a location that
// is not a fabricated path. A producer can legitimately report on something it did
// not scan -- the hf-cache expander reports a missing blob or a malformed ref, and
// names a path that therefore has no summary -- and that is exactly when a dangling
// reference would otherwise appear.
func declareFindingArtifacts(arts []ArtifactSummary, findings []Finding) []ArtifactSummary {
	have := newArtifactIndex(arts)
	var extra []ArtifactSummary
	declared := map[string]bool{}
	for _, f := range findings {
		path, _, covered := have.resolve(f.Artifact)
		if covered {
			// A declared row already covers this name, so every encoder's
			// reference resolves and there is nothing to declare.
			continue
		}
		// Nothing declared covers this name. The finding is about the name
		// itself (a path the scan could not open, a cache ref), so declare it
		// whole: truncating at a colon would invent a path that does not exist,
		// which is how "a:b.pkl" used to become a phantom "a".
		path = f.Artifact
		if path == "" || declared[path] {
			continue
		}
		declared[path] = true
		extra = append(extra, ArtifactSummary{
			Path:       path,
			Format:     "unknown",
			SubFormat:  "not scanned: named by a finding",
			NotScanned: true,
		})
	}
	if len(extra) == 0 {
		return arts
	}
	sort.SliceStable(extra, func(i, j int) bool { return extra[i].Path < extra[j].Path })
	return append(arts, extra...)
}

// artifactIndex answers "is this a declared row?" for the encoders that must map
// a finding's artifact name onto the row it belongs to.
type artifactIndex map[string]bool

func newArtifactIndex(arts []ArtifactSummary) artifactIndex {
	ix := make(artifactIndex, len(arts))
	for _, a := range arts {
		if a.Path != "" {
			ix[a.Path] = true
		}
	}
	return ix
}

// resolve maps a finding's artifact name to the summary row it belongs to and the
// member chain inside it. Sink.Named stamps a finding inside a container as
// "outer:member", but a path may itself contain ':' (a Windows drive letter, a
// URL, or a file literally named "a:b.pkl"), so the separator cannot be found by
// splitting at the first colon: the declared rows are the authority. An exact
// match wins; otherwise the longest row path P for which the name is P+":"+rest
// wins; otherwise ok is false and the caller decides. The scan is backwards over
// the name's colons, so it costs O(len(name)) per finding, not O(rows).
func (ix artifactIndex) resolve(artifact string) (path, member string, ok bool) {
	if ix[artifact] {
		return artifact, "", true
	}
	for i := len(artifact) - 1; i > 0; i-- {
		if artifact[i] != ':' {
			continue
		}
		if p := artifact[:i]; ix[p] {
			return p, artifact[i+1:], true
		}
	}
	return "", "", false
}

// Report is the complete scan result.
type Report struct {
	SchemaVersion string            `json:"schemaVersion"`
	Tool          Tool              `json:"tool"`
	Root          string            `json:"root,omitempty"`
	Artifacts     []ArtifactSummary `json:"artifacts"`
	Findings      []Finding         `json:"findings"`
	// Suppressed is the number of findings removed by -baseline.
	Suppressed int `json:"suppressed,omitempty"`
	// Dropped is the number of findings discarded because MaxFindings was hit.
	Dropped int `json:"dropped,omitempty"`
	// Timings is present only when -timings was passed, so that two runs of the
	// same scan differ only in a field a diffing consumer opts into.
	Timings map[string]int64 `json:"timings,omitempty"`
	// Limits echoes the effective budget.
	Limits Limits `json:"limits"`
	// Unreadable is the number of named artifacts that could not be opened, and
	// Cancelled records that the walk stopped early. Both are needed by SARIF,
	// whose invocation otherwise claims a clean, complete run: a SARIF consumer
	// that is told nothing about a partial scan records it as a full one.
	Unreadable int  `json:"unreadable,omitempty"`
	Cancelled  bool `json:"cancelled,omitempty"`
}

// Scanned is the number of artifact rows an actual scan produced, i.e. the rows
// minus the ones synthesised only so a finding's reference resolves.
func (r *Report) Scanned() int {
	n := len(r.Artifacts)
	for _, a := range r.Artifacts {
		if a.NotScanned {
			n--
		}
	}
	return n
}

// ExecutionSuccessful reports whether the scan covered everything it was asked
// to: every named path was opened and the walk was not cancelled.
func (r *Report) ExecutionSuccessful() bool {
	return r.Unreadable == 0 && !r.Cancelled
}

// executionNotifications names what stopped the run from being complete, so a
// consumer sees the reason rather than only a false flag.
func (r *Report) executionNotifications() []sarifNotification {
	var out []sarifNotification
	if r.Unreadable > 0 {
		out = append(out, sarifNotification{
			Level:   "error",
			Message: sarifText{Text: strconv.Itoa(r.Unreadable) + " path(s) could not be opened or read, so the scan is partial"},
		})
	}
	if r.Cancelled {
		out = append(out, sarifNotification{
			Level:   "warning",
			Message: sarifText{Text: "the scan was cancelled before every artifact was visited, so the result is partial"},
		})
	}
	return out
}

// Build assembles a Report from a Collector.
func Build(t Tool, root string, arts []ArtifactSummary, c *Collector, lim Limits, timings map[string]int64, suppressed int) *Report {
	arts = dedupeArtifacts(arts)
	findings := c.Findings()
	arts = declareFindingArtifacts(arts, findings)
	sort.SliceStable(arts, func(i, j int) bool { return arts[i].Path < arts[j].Path })
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          t,
		Root:          root,
		Artifacts:     arts,
		Findings:      findings,
		Suppressed:    suppressed,
		Dropped:       c.Dropped(),
		Timings:       timings,
		Limits:        lim,
	}
}

// findingJSON is Finding with severities rendered as names, which is what every
// consumer actually reads. It exists rather than a MarshalJSON on Finding so that
// the field *order* stays visible in one place.
type findingJSON struct {
	RuleID           string            `json:"ruleId"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Confidence       string            `json:"confidence"`
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

// reportJSON mirrors Report with the name-rendered findings.
type reportJSON struct {
	SchemaVersion string            `json:"schemaVersion"`
	Tool          Tool              `json:"tool"`
	Root          string            `json:"root,omitempty"`
	Summary       summaryJSON       `json:"summary"`
	Artifacts     []ArtifactSummary `json:"artifacts"`
	Findings      []findingJSON     `json:"findings"`
	Suppressed    int               `json:"suppressed,omitempty"`
	Dropped       int               `json:"dropped,omitempty"`
	Timings       map[string]int64  `json:"timings,omitempty"`
	Limits        Limits            `json:"limits"`
}

type summaryJSON struct {
	Artifacts      int            `json:"artifacts"`
	Findings       int            `json:"findings"`
	MaxSeverity    string         `json:"maxSeverity"`
	BySeverity     map[string]int `json:"bySeverity"`
	Suppressed     int            `json:"suppressed,omitempty"`
	Dropped        int            `json:"dropped,omitempty"`
	UnreadablePath int            `json:"unreadablePaths,omitempty"`
	// Scanned counts the rows an actual scan produced, i.e. Artifacts minus the
	// rows synthesised only so a finding's reference resolves. A consumer that
	// wants "how many files did this scan read" reads this, not Artifacts.
	Scanned int `json:"scanned"`
	// Cancelled records that the walk stopped early (a deadline), so a consumer
	// that reads only the summary cannot mistake a partial scan for a clean one.
	// It sits beside unreadablePaths because both are run-level facts about how
	// much of the requested scope was actually visited.
	Cancelled bool `json:"cancelled,omitempty"`
}

func (r *Report) toJSON() reportJSON {
	out := reportJSON{
		SchemaVersion: r.SchemaVersion,
		Tool:          r.Tool,
		Root:          r.Root,
		Artifacts:     r.Artifacts,
		Suppressed:    r.Suppressed,
		Dropped:       r.Dropped,
		Timings:       r.Timings,
		Limits:        r.Limits,
	}
	if out.Artifacts == nil {
		out.Artifacts = []ArtifactSummary{}
	}
	out.Findings = make([]findingJSON, 0, len(r.Findings))
	max := SeverityInfo
	by := map[string]int{}
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
		by[f.Severity.String()]++
		out.Findings = append(out.Findings, findingJSON{
			RuleID:           f.RuleID,
			Title:            f.Title,
			Severity:         f.Severity.String(),
			Confidence:       f.Confidence.String(),
			CWE:              f.CWE,
			Class:            f.Class,
			Artifact:         f.Artifact,
			Offset:           f.Offset,
			Line:             f.Line,
			Col:              f.Col,
			Evidence:         f.Evidence,
			EvidenceRedacted: f.EvidenceRedacted,
			Extra:            f.Extra,
		})
	}
	out.Summary = summaryJSON{
		Artifacts:   len(r.Artifacts),
		Findings:    len(r.Findings),
		MaxSeverity: max.String(),
		BySeverity:  by,
		Suppressed:  r.Suppressed,
		Dropped:     r.Dropped,
		Cancelled:   r.Cancelled,
	}
	out.Summary.Scanned = len(r.Artifacts)
	for _, a := range r.Artifacts {
		if a.Error != "" {
			out.Summary.UnreadablePath++
		}
		if a.NotScanned {
			out.Summary.Scanned--
		}
	}
	return out
}

// WriteJSON emits the canonical JSON payload, newline-terminated.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r.toJSON())
}

// MarshalJSON emits the same *fields* as WriteJSON, so a consumer cannot get two
// different payloads depending on which entry point it used. The bytes differ in
// one respect: WriteJSON indents two spaces and appends a newline (the CLI's
// contract, and what the determinism test pins), while json.Marshal produces the
// compact form. A consumer that wants the CLI's bytes calls WriteJSON.
func (r *Report) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.toJSON())
}

// Millis is a convenience for the timings map.
func Millis(d time.Duration) int64 { return d.Milliseconds() }
