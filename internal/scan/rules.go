// Package scan's rule set: the two ways a scan can be *incomplete* rather than
// clean. Both are reported as findings so that "no malicious-code finding" is
// never read as "this artifact is safe".
package scan

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// ruleParseFailed fires when a format parser returned an error, which means the
// artifact's structures were not walked to the end.
var ruleParseFailed = report.DefineRule(report.Rule{
	ID:         "SC4N-PARSE-FAILED",
	Title:      "Format parser could not walk the artifact to the end",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-755"},
	Class:      "structure",
	Description: "The parser for this artifact's sniffed format returned an error part-way through, so " +
		"whatever lies past that point was not analysed. This is reported as a finding rather than as a " +
		"silent skip because a truncated walk is the classic way to make a scanner report CLEAN: modelscan " +
		"issue #354 is an unreadable ZIP entry placed before archive/data.pkl. Read the evidence for the " +
		"failing structure and treat the artifact as unscanned beyond that point.",
	Refs: []string{"https://github.com/protectai/modelscan/issues/354"},
	Tags: []string{"scanner-evasion"},
})

// ruleInternalPanic fires when a parser panicked. It is always a sc4n bug, and it
// is reported rather than crashing the scan so that one hostile file cannot take
// down a CI job over an entire repository.
var ruleInternalPanic = report.DefineRule(report.Rule{
	ID:         "SC4N-INTERNAL-PANIC",
	Title:      "sc4n internal error while parsing (scanner bug)",
	Severity:   report.SeverityLow,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-617"},
	Class:      "structure",
	Description: "A parser panicked and the panic was contained, so this artifact is only partially " +
		"analysed. The panic is always a sc4n bug rather than a property of the artifact, and the evidence " +
		"records the panic value; please report it with the artifact or a reduced reproducer. The remaining " +
		"artifacts in the same run were still scanned.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/617.html"},
})
