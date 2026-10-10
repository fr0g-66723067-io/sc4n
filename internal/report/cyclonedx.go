package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

// CycloneDX 1.6 ML-BOM output.
//
// A CycloneDX document is a bill of materials first and an advisory list second,
// so the artifacts sc4n scanned become components of type
// machine-learning-model, each carrying its SHA-256 and its sniffed format, and
// the findings become vulnerabilities that reference those components by bom-ref.
// That is the shape a consumer needs to answer "which of my models is affected"
// from a scanner run.
//
// The document is deterministic: the serial number is derived from the content
// rather than random, and metadata.timestamp is omitted rather than set to the
// current time, so two runs over the same tree produce identical bytes. A
// consumer that needs a timestamp can add one; a consumer that diffs BOMs cannot
// remove one.

const specVersion = "1.6"

type cdxBOM struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []cdxComponent     `json:"components"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Tools []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxVulnerability struct {
	ID          string        `json:"id"`
	Source      cdxSource     `json:"source"`
	Description string        `json:"description,omitempty"`
	Detail      string        `json:"detail,omitempty"`
	Ratings     []cdxRating   `json:"ratings,omitempty"`
	Affects     []cdxAffect   `json:"affects"`
	Properties  []cdxProperty `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Severity string     `json:"severity"`
	Method   string     `json:"method"`
	Vector   string     `json:"vector,omitempty"`
	Source   *cdxSource `json:"source,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

// WriteCycloneDX emits a CycloneDX 1.6 ML-BOM.
func (r *Report) WriteCycloneDX(w io.Writer) error {
	// A local copy, never r.Tool.Version: writing one format must not change what
	// a later WriteJSON on the same *Report emits.
	version := r.Tool.Version
	if version == "" {
		version = "dev"
	}
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: specVersion,
		Version:     1,
		Metadata: cdxMetadata{Tools: []cdxTool{{
			Vendor:  "fr0g",
			Name:    r.Tool.Name,
			Version: version,
		}}},
		Components: make([]cdxComponent, 0, len(r.Artifacts)),
	}

	refs := make(map[string]string, len(r.Artifacts))
	for _, a := range r.Artifacts {
		ref := "sc4n:" + a.Path
		refs[a.Path] = ref
		c := cdxComponent{
			Type:    "machine-learning-model",
			BOMRef:  ref,
			Name:    a.Path,
			Version: "",
			Properties: []cdxProperty{
				{Name: "sc4n:format", Value: a.Format},
			},
		}
		if a.SubFormat != "" {
			c.Properties = append(c.Properties, cdxProperty{Name: "sc4n:subFormat", Value: a.SubFormat})
		}
		// A CycloneDX hash is a claim about the whole component, so a capped
		// digest must not be published as one: it is recorded as a property
		// instead, where the scope is part of the value. This is the same rule the
		// JSON report follows with sha256Scope.
		if a.SHA256 != "" {
			if a.SHA256Scope == "" || a.SHA256Scope == "full" {
				c.Hashes = []cdxHash{{Alg: "SHA-256", Content: a.SHA256}}
			} else {
				c.Properties = append(c.Properties,
					cdxProperty{Name: "sc4n:sha256", Value: a.SHA256},
					cdxProperty{Name: "sc4n:sha256Scope", Value: a.SHA256Scope})
			}
		}
		if a.Error != "" {
			c.Properties = append(c.Properties, cdxProperty{Name: "sc4n:error", Value: a.Error})
		}
		bom.Components = append(bom.Components, c)
	}

	for _, f := range r.Findings {
		path, member := splitArtifact(f.Artifact)
		ref, ok := refs[path]
		if !ok {
			ref = "sc4n:" + f.Artifact
		}
		v := cdxVulnerability{
			ID: f.RuleID,
			Source: cdxSource{
				Name: "sc4n",
				URL:  informationURI,
			},
			Description: f.Title,
			Detail:      f.Evidence,
			Ratings: []cdxRating{{
				Severity: cdxSeverity(f.Severity),
				Method:   "other",
				Vector:   strings.Join(f.CWE, ","),
			}},
			Affects: []cdxAffect{{Ref: ref}},
			Properties: []cdxProperty{
				{Name: "sc4n:confidence", Value: f.Confidence.String()},
				{Name: "sc4n:fingerprint", Value: Fingerprint(f)},
				{Name: "sc4n:offset", Value: strconv.FormatInt(f.Offset, 10)},
			},
		}
		if member != "" {
			v.Properties = append(v.Properties, cdxProperty{Name: "sc4n:member", Value: member})
		}
		if f.Line != nil {
			v.Properties = append(v.Properties, cdxProperty{Name: "sc4n:line", Value: strconv.Itoa(*f.Line)})
		}
		for _, kv := range sortedExtra(f.Extra) {
			v.Properties = append(v.Properties, cdxProperty{Name: "sc4n:" + kv[0], Value: kv[1]})
		}
		bom.Vulnerabilities = append(bom.Vulnerabilities, v)
	}

	bom.SerialNumber = serialNumber(r, version)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// serialNumber derives a deterministic RFC 4122 version-5-shaped URN from the
// document's own content, so that a BOM identifies its content rather than its
// run.
func serialNumber(r *Report, version string) string {
	h := sha256.New()
	h.Write([]byte(r.SchemaVersion))
	h.Write([]byte(r.Tool.Name))
	h.Write([]byte(version))
	for _, a := range r.Artifacts {
		h.Write([]byte(a.Path))
		h.Write([]byte(a.SHA256))
		h.Write([]byte(a.Format))
	}
	for _, f := range r.Findings {
		h.Write([]byte(Fingerprint(f)))
	}
	sum := h.Sum(nil)
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return "urn:uuid:" + string(dst)
}

func cdxSeverity(s Severity) string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// sortedExtra renders a finding's Extra map as sorted key/value pairs, so that a
// map (whose iteration order Go randomises) cannot make two runs of the same scan
// differ.
func sortedExtra(m map[string]string) [][2]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, m[k]})
	}
	return out
}
