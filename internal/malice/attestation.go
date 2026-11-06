package malice

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Version is the attestation format tools/sc4nconfirm writes. A scanner refuses
// any other value rather than guessing at field meanings: the attestation is an
// input from another process, and a silently ignored field would turn "the
// harness recorded a connect" into "the artifact did nothing".
const Version = "sc4nconfirm/1"

// maxAttestationBytes bounds the document a scan will read. An attestation is
// one small record per artifact; anything larger is a wrong file, not evidence.
const maxAttestationBytes = 8 << 20

// Attestation is one harness run's output.
type Attestation struct {
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is what one load of one artifact did. The effect lists hold the observed
// argv, the dialled address, the path opened outside the artifact directory, and
// the path written; they are sorted by the producer and again here, so two scans
// of the same attestation produce identical bytes.
type Run struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path,omitempty"`
	Loader string `json:"loader,omitempty"`
	Loaded bool   `json:"loaded"`
	Error  string `json:"error,omitempty"`
	// MissingModules names the modules a failed load could not import. It is
	// recorded, never graded: "we could not load it" is not "it did nothing".
	MissingModules []string `json:"missingModules,omitempty"`
	Exec           []string `json:"exec,omitempty"`
	Connect        []string `json:"connect,omitempty"`
	OpenedOutside  []string `json:"openedOutside,omitempty"`
	Wrote          []string `json:"wrote,omitempty"`
}

// Effects is the number of recorded effects, the test for whether a run
// demonstrated anything.
func (r *Run) Effects() int {
	if r == nil {
		return 0
	}
	return len(r.Exec) + len(r.Connect) + len(r.OpenedOutside) + len(r.Wrote)
}

// Index is a loaded attestation, keyed by full artifact digest.
type Index struct {
	mu      sync.Mutex
	byKey   map[string]*Run
	matched map[*Run]bool
}

// Load reads and validates an attestation document.
//
// Every error here is fatal to the flag rather than a per-artifact note: a
// malformed attestation is an operator mistake, and continuing would silently
// drop the demonstration the operator asked for.
func Load(path string) (*Index, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not an attestation file", path)
	}
	if fi.Size() > maxAttestationBytes {
		return nil, fmt.Errorf("%s is %d bytes, above the %d-byte attestation limit", path, fi.Size(), maxAttestationBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b, path)
}

func parse(b []byte, name string) (*Index, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var a Attestation
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if a.Version != Version {
		return nil, fmt.Errorf("%s: version %q, want %q", name, a.Version, Version)
	}
	if len(a.Runs) == 0 {
		return nil, fmt.Errorf("%s: no runs", name)
	}
	ix := &Index{byKey: make(map[string]*Run, len(a.Runs)), matched: make(map[*Run]bool)}
	for i := range a.Runs {
		r := &a.Runs[i]
		if len(r.SHA256) != 64 {
			return nil, fmt.Errorf("%s: run %d: sha256 %q is not a 64-character hex digest", name, i, r.SHA256)
		}
		digest := strings.ToLower(r.SHA256)
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("%s: run %d: sha256 %q is not hex: %w", name, i, r.SHA256, err)
		}
		key := "full:" + digest
		if prev, dup := ix.byKey[key]; dup {
			return nil, fmt.Errorf("%s: run %d: second entry for digest %s (first loader %q); one artifact must have one attestation",
				name, i, digest[:12], prev.Loader)
		}
		sort.Strings(r.Exec)
		sort.Strings(r.Connect)
		sort.Strings(r.OpenedOutside)
		sort.Strings(r.Wrote)
		sort.Strings(r.MissingModules)
		ix.byKey[key] = r
	}
	return ix, nil
}

// For returns the run for a digest, or nil. scope is the digest scope the scan
// computed: only a full digest identifies an artifact, so a prefix digest never
// matches and an artifact hashed with -max-hash cannot be attested. The match is
// counted so the caller can report an attestation that matched nothing, which is
// otherwise indistinguishable from an attestation that found nothing.
func (ix *Index) For(scope, digest string) *Run {
	if ix == nil || scope != "full" || len(digest) != 64 {
		return nil
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r := ix.byKey["full:"+strings.ToLower(digest)]
	if r != nil {
		ix.matched[r] = true
	}
	return r
}

// Len is the number of runs in the attestation.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.byKey)
}

// Matched is the number of distinct runs that matched a scanned artifact.
func (ix *Index) Matched() int {
	if ix == nil {
		return 0
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.matched)
}

// Merge emits the demonstrated grade for one artifact when the attestation
// recorded an effect for its digest.
func Merge(c *report.Collector, artifact string, r *Run) {
	if c == nil || r == nil || r.Effects() == 0 {
		return
	}
	Demonstrated(c.For(artifact), 0, describe(r), effectExtra(r))
}

// describe is the evidence sentence: what ran, where it dialled, what it touched.
func describe(r *Run) string {
	var b strings.Builder
	loader := r.Loader
	if loader == "" {
		loader = "the default loader"
	}
	fmt.Fprintf(&b, "loading with %s ", loader)
	switch {
	case len(r.Exec) > 0:
		b.WriteString("executed " + listing(r.Exec))
	case len(r.OpenedOutside) > 0 || len(r.Wrote) > 0 || len(r.Connect) > 0:
		// The load produced effects before it finished, so "was attempted"
		// would understate it: something ran.
		b.WriteString("ran")
	case r.Loaded:
		b.WriteString("succeeded")
	default:
		b.WriteString("was attempted")
	}
	if len(r.Connect) > 0 {
		b.WriteString("; attempted to connect to " + listing(r.Connect))
	}
	if len(r.OpenedOutside) > 0 {
		b.WriteString("; tried to open " + listing(r.OpenedOutside) + " outside the artifact directory")
	}
	if len(r.Wrote) > 0 {
		b.WriteString("; wrote " + listing(r.Wrote))
	}
	if len(r.MissingModules) > 0 {
		b.WriteString("; missing modules " + listing(r.MissingModules))
	}
	b.WriteString(" (container, no network, read-only root)")
	return b.String()
}

// maxListed bounds how many entries of one effect list reach the evidence text,
// so a payload that execs a thousand processes cannot make one finding huge.
const maxListed = 3

func listing(items []string) string {
	if len(items) <= maxListed {
		return strings.Join(quoteAll(items), ", ")
	}
	return strings.Join(quoteAll(items[:maxListed]), ", ") + fmt.Sprintf(" and %d more", len(items)-maxListed)
}

func quoteAll(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = quote(s)
	}
	return out
}

// quote renders a command or path for evidence. It truncates rather than
// escaping into a wall of backslashes: the extra fields carry the whole value.
func quote(s string) string {
	const max = 80
	if len(s) > max {
		s = s[:max] + "..."
	}
	return `"` + strings.ReplaceAll(s, `"`, `'`) + `"`
}

// effectExtra is the machine-readable half: counts and the loader, never the
// payload text, which is already in the evidence and can be long or binary.
func effectExtra(r *Run) map[string]string {
	return map[string]string{
		"loader":        r.Loader,
		"loaded":        fmt.Sprint(r.Loaded),
		"exec":          fmt.Sprint(len(r.Exec)),
		"connect":       fmt.Sprint(len(r.Connect)),
		"openedOutside": fmt.Sprint(len(r.OpenedOutside)),
		"wrote":         fmt.Sprint(len(r.Wrote)),
	}
}
