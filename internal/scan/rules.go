// Package scan's rule set: the way a scan can be *incomplete* rather than clean.
// It is reported as a finding so that "no malicious-code finding" is never read as
// "this artifact is safe".
package scan

import "github.com/fr0g-66723067-io/sc4n/internal/report"

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
