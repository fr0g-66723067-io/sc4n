package limits

import (
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// The rule set for budget exhaustion. Every rule here exists to make a cap
// *visible*: a parser that silently stops at a cap is indistinguishable, from the
// outside, from a parser that found nothing, and that confusion is exactly how
// modelscan's fail-open ZIP iterator reported CLEAN on an artifact it had failed
// to read (modelscan issue #354).
//
// Severity rationale:
//   - ratio/decompressed: a cap that fires here is the signature of a
//     decompression bomb, so these are high.
//   - depth/entries/artifact-size: a cap that fires here usually means a
//     pathological but not necessarily hostile file, so these are medium.
//   - string blob and finding count: tool-level hygiene, low and info.

// RuleDepth fires when container nesting exceeds MaxDepth.
var RuleDepth = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-DEPTH",
	Title:      "Container nesting exceeds MaxDepth",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-674"},
	Class:      "limits",
	Description: "The artifact nests containers (archive inside archive, or archive inside compression) " +
		"deeper than MaxDepth allows, so scanning stopped at this level and the nested content was not " +
		"analysed. Legitimate model repositories nest at most three levels (joblib inside gzip, a pickle " +
		"inside a zip). A deeper nest is a way to move a payload past a depth-limited scanner, so treat " +
		"this finding as \"not fully scanned\", not as \"clean\".",
	Refs: []string{"https://cwe.mitre.org/data/definitions/674.html"},
})

// RuleEntries fires when an archive declares or contains more members than
// MaxEntries.
var RuleEntries = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-ENTRIES",
	Title:      "Archive member count exceeds MaxEntries",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-770"},
	Class:      "limits",
	Description: "The archive has more members than MaxEntries permits. Scanning stopped after the cap, so " +
		"members beyond it were not analysed. A very large member count is the cheap way to exhaust a " +
		"scanner's time or memory budget before it reaches the payload.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/770.html"},
})

// RuleRatio fires when one compression layer expands past MaxRatio.
var RuleRatio = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-RATIO",
	Title:      "Decompression ratio exceeds MaxRatio",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-409"},
	Class:      "limits",
	Description: "One compression layer expands by more than MaxRatio (default 200:1). Two readings are " +
		"possible and both are worth stopping at: a decompression bomb aimed at the scanner, or a member " +
		"whose expansion is so large that the extracted payload cannot be analysed in memory. Decompression " +
		"stopped at the cap, so the member is only partly analysed.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/409.html"},
})

// RuleDecompressed fires when the cumulative decompressed bytes of one archive
// pass MaxDecompressedBytes.
var RuleDecompressed = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-DECOMPRESSED",
	Title:      "Cumulative decompressed bytes exceed the cap",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-409"},
	Class:      "limits",
	Description: "The archive decompressed to more than MaxDecompressedBytes in total. Scanning stopped at " +
		"the cap, so later members were not analysed. Raise -max-decompress only on a host with the " +
		"corresponding headroom.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/409.html"},
})

// RuleArtifact fires when a file exceeds MaxArtifactBytes.
var RuleArtifact = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-ARTIFACT",
	Title:      "File exceeds MaxArtifactBytes",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-770"},
	Class:      "limits",
	Description: "The file is larger than MaxArtifactBytes, so it was not opened. The path is reported as " +
		"unreadable and the run exits 3. Either the file is genuinely outside the intended scan scope or " +
		"it was inflated to push the scanner past its budget.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/770.html"},
})

// RuleString fires when a single string/blob would exceed MaxStringBlob.
var RuleString = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-STRING",
	Title:      "String or blob exceeds MaxStringBlob",
	Severity:   report.SeverityLow,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-770"},
	Class:      "limits",
	Description: "A single declared string, metadata value or embedded blob is larger than MaxStringBlob, " +
		"so it was truncated before analysis. Truncation is reported rather than silent: an indicator " +
		"positioned after the truncation point would not be seen.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/770.html"},
})

// RuleFindings fires when the finding cap is reached.
var RuleFindings = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-FINDINGS",
	Title:      "Finding count reached MaxFindings",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        nil,
	Class:      "limits",
	Description: "The scan produced more findings than MaxFindings, so later findings were dropped and " +
		"counted in the report's \"dropped\" summary field. Raise -max-findings to see all of them; the " +
		"drop is always reported so a truncated finding list is never mistaken for a complete one.",
})

// Emit reports that limit name was hit. detail is appended to the evidence so the
// reader sees the actual value, not just the cap's name.
func Emit(sink *report.Sink, r *report.Rule, limit string, value, cap int64, detail string) {
	ev := limit + " reached: " + strconv.FormatInt(value, 10) + " > " + strconv.FormatInt(cap, 10)
	if detail != "" {
		ev += "; " + detail
	}
	sink.EmitExtra(r, 0, ev, map[string]string{
		"limit": limit,
		"value": strconv.FormatInt(value, 10),
		"cap":   strconv.FormatInt(cap, 10),
	})
}

// RuleSpill fires when a single archive member exceeds MaxSpillBytes and could not
// be materialised for parsing.
var RuleSpill = report.DefineRule(report.Rule{
	ID:         "SC4N-LIMIT-SPILL",
	Title:      "Archive member exceeds MaxSpillBytes",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-770"},
	Class:      "limits",
	Description: "A compressed archive member is larger than MaxSpillBytes, so it was not materialised " +
		"for parsing. The member's own container checks (name, link, CRC) still ran; its *content* was " +
		"not analysed, and the finding says so rather than leaving a reader to assume a clean member.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/770.html"},
})
