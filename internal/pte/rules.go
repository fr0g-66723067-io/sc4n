// The ExecuTorch / PTE rule set.
//
// The honest finding here is the informational one. sc4n v1 verifies the header
// arithmetic and scans the opaque segment region, but it does not decode the
// flatbuffer program graph, and a scanner that stayed silent about that would make
// "no findings" mean "clean" when it actually means "not deep-parsed". So the
// informational rule is mandatory, not decorative.
package pte

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleUnverified reports that a valid PTE was recognised but not deep-parsed.
var RuleUnverified = report.DefineRule(report.Rule{
	ID:         "SC4N-PTE-UNVERIFIED",
	Title:      "ExecuTorch program is recognised but not deep-parsed",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        nil,
	Class:      "format",
	Description: "The file has a valid ExecuTorch `.pte` header (flatbuffer root offset plus the `ET` " +
		"file magic at offset 4), but sc4n v1 does not decode the flatbuffer program graph or the " +
		"operator set it references. Those operators are native code on the device, so the file's " +
		"behaviour is decided by the runtime the device ships. This finding exists so that a clean " +
		"report on a `.pte` is read as \"recognised, shallowly analysed\" rather than \"analysed and safe\".",
	Refs: []string{"https://docs.pytorch.org/executorch/stable/pte-file-format.html"},
	Tags: []string{"executorch", "shallow"},
})

// RuleStruct reports a `.pte` whose header arithmetic is invalid.
var RuleStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-PTE-STRUCT",
	Title:      "ExecuTorch program header is invalid",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "format",
	Description: "The `.pte` header does not satisfy its own layout: the file magic is not `ET` plus two " +
		"ASCII digits at offset 4, the flatbuffer root offset points outside the file, or the optional " +
		"extended header's declared size, program-data size or segment region is out of range. A loader " +
		"that trusts these fields reads a different byte range than sc4n inspected, so a malformed header " +
		"is treated as a mismatch rather than a parse detail.",
	Refs: []string{"https://docs.pytorch.org/executorch/stable/pte-file-format.html"},
	Tags: []string{"executorch", "malformed"},
})

// RuleNative reports a validated native executable inside the segment region.
var RuleNative = report.DefineRule(report.Rule{
	ID:         "SC4N-PTE-NATIVE",
	Title:      "Native executable embedded in ExecuTorch segment data",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-506"},
	Class:      "polyglot",
	Description: "A validated ELF/PE/Mach-O header was found inside the segment region the extended " +
		"header declares. The runtime maps that region and hands it to the device backend, and the " +
		"universal polyglot layer only inspects the first and last MiB of a file, so an executable " +
		"positioned in the middle of a large segment region would otherwise go unseen. The header was " +
		"validated with the standard library's own parser, so this is a real image and not four " +
		"coincidental bytes.",
	Refs: []string{"https://docs.pytorch.org/executorch/stable/pte-file-format.html"},
	Tags: []string{"executorch", "embedded-native"},
})
