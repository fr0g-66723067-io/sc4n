package report

import (
	"encoding/json"
	"io"
	"sort"
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
	// Error is set when the path could not be opened or read. It is *not* a
	// finding: an unreadable path is a tool/layout problem, reported with exit
	// code 3, while an unreadable *member* is a finding, because a container
	// that hides a member from the scanner is exactly the modelscan fail-open
	// shape.
	Error string `json:"error,omitempty"`
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
	MaxHashBytes         int64 `json:"maxHashBytes"`
	MaxSpillBytes        int64 `json:"maxSpillBytes"`
	MaxFindings          int   `json:"maxFindings"`
	MaxStackDepth        int   `json:"maxStackDepth"`
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
}

// Build assembles a Report from a Collector.
func Build(t Tool, root string, arts []ArtifactSummary, c *Collector, lim Limits, timings map[string]int64, suppressed int) *Report {
	sort.SliceStable(arts, func(i, j int) bool { return arts[i].Path < arts[j].Path })
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          t,
		Root:          root,
		Artifacts:     arts,
		Findings:      c.Findings(),
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
	Resolved         *bool             `json:"resolved,omitempty"`
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
			Resolved:         f.Resolved,
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
	}
	for _, a := range r.Artifacts {
		if a.Error != "" {
			out.Summary.UnreadablePath++
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

// MarshalJSON makes a bare json.Marshal(report) emit the same bytes as WriteJSON
// (minus the trailing newline), so a consumer cannot get two different payloads
// depending on which entry point it used.
func (r *Report) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.toJSON())
}

// Millis is a convenience for the timings map.
func Millis(d time.Duration) int64 { return d.Milliseconds() }
