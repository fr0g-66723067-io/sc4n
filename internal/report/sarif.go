package report

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// SARIF 2.1.0 output.
//
// Three consumer details drive the shape:
//
//   - GitHub code scanning only surfaces a result when its ruleId appears in
//     tool.driver.rules and its level is error/warning/note, so every emitted
//     finding's rule is included in the descriptor list, and
//   - GitHub ranks alerts by properties.security-severity using the bands
//     9.0+/7.0-8.9/4.0-6.9/0.1-3.9, which is why the numeric band is emitted both
//     on the rule and on the result, and
//   - GitHub de-duplicates on the primaryLocationLineHash entry of
//     partialFingerprints — "Code scanning only uses the primaryLocationLineHash"
//     (https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
//     — so that is the key every result carries, not a tool-named one.
//
// GitHub caps one upload at 25 000 results and a 10 MB gzipped SARIF file. sc4n
// does not truncate: -max-findings is the caller's lever, and a run that exceeds
// the cap is a run whose findings need triage, not silent sampling.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Results     []sarifResult     `json:"results"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	Help                 *sarifHelp     `json:"help,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Class            string   `json:"class,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

// sarifNotification is a run-level message that is not a finding: the scan
// completed, but not over everything it was asked to cover.
type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProp   `json:"properties"`
}

type sarifResultProp struct {
	SecuritySeverity string            `json:"security-severity,omitempty"`
	Confidence       string            `json:"confidence,omitempty"`
	CWE              []string          `json:"cwe,omitempty"`
	Extra            map[string]string `json:"extra,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int        `json:"startLine"`
	StartColumn int        `json:"startColumn,omitempty"`
	ByteOffset  int64      `json:"byteOffset,omitempty"`
	ByteLength  int        `json:"byteLength,omitempty"`
	Snippet     *sarifText `json:"snippet,omitempty"`
}

const informationURI = "https://github.com/fr0g-66723067-io/sc4n"

// WriteSARIF emits a SARIF 2.1.0 log.
func (r *Report) WriteSARIF(w io.Writer) error {
	arts := newArtifactIndex(r.Artifacts)
	rules := Rules()
	index := make(map[string]int, len(rules))
	descriptors := make([]sarifRule, 0, len(rules))
	for i, ru := range rules {
		index[ru.ID] = i
		descriptors = append(descriptors, sarifRule{
			ID:               ru.ID,
			Name:             ruleName(ru.ID),
			ShortDescription: sarifText{Text: ru.Title},
			FullDescription:  &sarifText{Text: ru.Description},
			Help:             &sarifHelp{Text: ru.Description + refsSuffix(ru), Markdown: helpMarkdown(ru)},
			HelpURI:          firstRef(ru),
			DefaultConfiguration: sarifConfig{
				Level: SARIFLevel(ru.Severity),
			},
			Properties: sarifRuleProps{
				Tags:             ruleTags(ru),
				Precision:        ru.Confidence.String(),
				SecuritySeverity: SeverityBand(ru.Severity),
				Class:            ru.Class,
			},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool.Name,
				Version:        r.Tool.Version,
				InformationURI: informationURI,
				Rules:          descriptors,
			}},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful:        r.ExecutionSuccessful(),
				ToolExecutionNotifications: r.executionNotifications(),
			}},
			Results: make([]sarifResult, 0, len(r.Findings)),
			Properties: map[string]any{
				// artifactsScanned counts the rows a scan produced; the rows that
				// exist only so a finding's location resolves are declared
				// separately, so "3 artifacts" can no longer mean one file plus
				// two synthetic rows.
				"artifactsScanned":  r.Scanned(),
				"artifactsDeclared": len(r.Artifacts) - r.Scanned(),
				"suppressed":        r.Suppressed,
				"dropped":           r.Dropped,
			},
		}},
	}

	// GitHub code scanning de-duplicates on primaryLocationLineHash, and the value
	// it generates itself is "<hash>:<count>". Fingerprint deliberately excludes
	// the byte offset (see report.Fingerprint), so two findings of one rule with
	// identical evidence in one file share it: emitting a constant count for both
	// made the values byte-identical and GitHub merged the second alert into the
	// first. The count is the 1-based occurrence of that fingerprint within the
	// artifact, which is what makes the two values distinct while the fingerprint
	// itself — the baseline identity — stays unchanged.
	occurrences := map[string]int{}
	for _, f := range r.Findings {
		ri, ok := index[f.RuleID]
		if !ok {
			// A finding whose rule is not in the registry would be dropped by
			// GitHub code scanning, so it is described on the fly rather than
			// lost. Every RuleID the CLI emits comes from DefineRule, so this is
			// a programming error rather than an input shape — and GitHub's SARIF
			// support page makes shortDescription, fullDescription and help
			// required on a reportingDescriptor, so all three are filled in.
			ri = len(log.Runs[0].Tool.Driver.Rules)
			unregistered := "rule " + f.RuleID + " is not in sc4n's rule registry"
			log.Runs[0].Tool.Driver.Rules = append(log.Runs[0].Tool.Driver.Rules, sarifRule{
				ID:                   f.RuleID,
				Name:                 ruleName(f.RuleID),
				ShortDescription:     sarifText{Text: f.Title},
				FullDescription:      &sarifText{Text: unregistered},
				Help:                 &sarifHelp{Text: unregistered},
				DefaultConfiguration: sarifConfig{Level: SARIFLevel(f.Severity)},
				Properties:           sarifRuleProps{Tags: f.CWE, Precision: f.Confidence.String(), SecuritySeverity: SeverityBand(f.Severity)},
			})
		}
		path, member, found := arts.resolve(f.Artifact)
		if !found {
			// A name no row covers (a path the scan could not open): the location
			// is the name itself, and there is no member chain to name.
			path, member = f.Artifact, ""
		}
		region := sarifRegion{
			StartLine:  1,
			ByteOffset: f.Offset,
			ByteLength: len(f.Evidence),
		}
		if f.Line != nil {
			region.StartLine = *f.Line
		}
		if f.Col != nil {
			region.StartColumn = *f.Col
		}
		if f.Evidence != "" {
			region.Snippet = &sarifText{Text: oneLine(f.Evidence, 512)}
		}
		msg := f.Title + " (" + f.RuleID + ")"
		if member != "" {
			msg += " in member " + member
		}
		if f.Evidence != "" {
			msg += ": " + oneLine(f.Evidence, 512)
		}
		// GitHub code scanning reads only the primaryLocationLineHash
		// fingerprint for de-duplication (see the sarif-support page linked
		// from the package header), so that is the key emitted; the value is
		// our own stable fingerprint plus the occurrence count the format calls
		// for. A second, tool-named key would have no reader.
		fp := Fingerprint(f)
		key := f.Artifact + "\x00" + fp
		occurrences[key]++
		res := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ri,
			Level:     SARIFLevel(f.Severity),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: pathURI(path)},
				Region:           region,
			}}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fp + ":" + strconv.Itoa(occurrences[key]),
			},
			Properties: sarifResultProp{
				SecuritySeverity: SeverityBand(f.Severity),
				Confidence:       f.Confidence.String(),
				CWE:              f.CWE,
				Extra:            f.Extra,
			},
		}
		log.Runs[0].Results = append(log.Runs[0].Results, res)
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func ruleName(id string) string {
	return strings.ReplaceAll(strings.TrimPrefix(id, "SC4N-"), "-", "_")
}

func ruleTags(r *Rule) []string {
	tags := make([]string, 0, len(r.CWE)+len(r.Tags)+3)
	tags = append(tags, "security")
	tags = append(tags, "ml-model-scanning")
	if r.Class != "" {
		tags = append(tags, r.Class)
	}
	tags = append(tags, r.CWE...)
	tags = append(tags, r.Tags...)
	return dedup(tags)
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func firstRef(r *Rule) string {
	if len(r.Refs) > 0 {
		return r.Refs[0]
	}
	return ""
}

func refsSuffix(r *Rule) string {
	if len(r.Refs) == 0 {
		return ""
	}
	return "\n\nReferences:\n  " + strings.Join(r.Refs, "\n  ")
}

func helpMarkdown(r *Rule) string {
	var b strings.Builder
	b.WriteString("## " + r.ID + " — " + r.Title + "\n\n")
	b.WriteString(r.Description + "\n")
	b.WriteString("\n| field | value |\n|---|---|\n")
	b.WriteString("| severity | " + r.Severity.String() + " |\n")
	b.WriteString("| confidence | " + r.Confidence.String() + " |\n")
	b.WriteString("| class | " + r.Class + " |\n")
	if len(r.CWE) > 0 {
		b.WriteString("| CWE | " + strings.Join(r.CWE, ", ") + " |\n")
	}
	if len(r.Refs) > 0 {
		b.WriteString("\nReferences:\n")
		for _, ref := range r.Refs {
			b.WriteString("- " + ref + "\n")
		}
	}
	return b.String()
}

// pathURI renders a relative path as SARIF's artifactLocation.uri. A URI with a
// scheme (say http: for a hypothetical remote reference) is passed through
// untouched; everything else is percent-encoded with forward slashes.
func pathURI(p string) string {
	if strings.Contains(p, "://") {
		return p
	}
	clean := filepath.ToSlash(p)
	u := url.URL{Path: clean}
	return strings.TrimPrefix(u.String(), "./")
}
