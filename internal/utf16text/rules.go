// The UTF-16 text rule set.
//
// The rule is informational on purpose: decoding the file changes what the
// scanner reads, not whether the file is hostile. It exists so that a clean report
// on a UTF-16 card says "decoded and scanned" rather than "not recognised", which
// is the same contract SC4N-PTE-UNVERIFIED and SC4N-COREML-PROGRAM-UNVERIFIED
// carry for their formats.
package utf16text

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleUTF16 reports that the artifact was decoded from UTF-16 before scanning.
var RuleUTF16 = report.DefineRule(report.Rule{
	ID:         "SC4N-CONTENT-UTF16",
	Title:      "Text artifact was UTF-16 and was decoded before scanning",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        nil,
	Class:      "format",
	Description: "The artifact's bytes are UTF-16 text (a byte-order mark, or ASCII interleaved with " +
		"NUL bytes). Every content heuristic in sc4n is byte-oriented, so the undecoded file looks " +
		"binary: the text sniffer does not see prose, the model-card analyser never runs and the " +
		"indicator engine reads the interleaving as data. sc4n decoded the whole file to UTF-8 and " +
		"re-dispatched it, so format sniffing, the card analyser and the indicator engine all read the " +
		"text. Offsets in findings on the decoded text are offsets into the decoded bytes. This " +
		"finding is informational and exists so that a clean report is read as \"decoded and " +
		"scanned\".",
	Refs: []string{"https://www.unicode.org/faq/utf_bom.html"},
	Tags: []string{"encoding", "text"},
})
