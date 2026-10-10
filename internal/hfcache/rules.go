// The hf-cache rule set.
//
// These fire on the *cache structure* rather than on a blob, and they exist
// because the cache is the thing sc4n is told to trust: it decides which bytes a
// scan even sees. A symlink that resolves outside the cache makes the "scan a
// downloaded model" operation read an arbitrary file; a ref that is not a commit
// means the labels attached to findings are wrong; a missing blob means a snapshot
// entry silently contributed nothing.
package hfcache

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleSymlinkEscape reports a snapshot symlink that leaves the cache root.
var RuleSymlinkEscape = report.DefineRule(report.Rule{
	ID:         "SC4N-HFCACHE-SYMLINK-ESCAPE",
	Title:      "Hugging Face cache symlink escapes the cache root",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-22", "CWE-59"},
	Class:      "path",
	Description: "A snapshot entry is a symlink that is absolute or whose target leaves the cache " +
		"directory. The genuine cache layout uses relative links into ../../blobs, so an escaping link " +
		"is either corruption or an attempt to make a model scan read a file outside the cache. sc4n " +
		"resolves every link through os.Root and refuses to yield an entry that leaves the root, so the " +
		"named file was NOT scanned; the finding records the request rather than the read.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/59.html"},
	Tags: []string{"hf-cache", "path"},
})

// RuleBlobMissing reports a snapshot entry whose blob does not exist.
var RuleBlobMissing = report.DefineRule(report.Rule{
	ID:         "SC4N-HFCACHE-BLOB-MISSING",
	Title:      "Hugging Face cache snapshot entry has no blob",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "format",
	Description: "A snapshot entry (or its symlink target) could not be stat'd. Either the link is " +
		"dangling or the blob it names is absent, so the file contributes no bytes to the scan. Reporting " +
		"it keeps a partially-populated cache from being mistaken for a fully-scanned one.",
	Tags: []string{"hf-cache", "missing"},
})

// RuleRefMalformed reports a refs/<name> file that is not a 40-hex commit.
var RuleRefMalformed = report.DefineRule(report.Rule{
	ID:         "SC4N-HFCACHE-REF-MALFORMED",
	Title:      "Hugging Face cache ref is not a commit hash",
	Severity:   report.SeverityLow,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "format",
	Description: "A file under refs/ does not contain a 40-hex commit hash. The refs are what label a " +
		"blob with a human-meaningful revision in the report, so a malformed ref means a finding cannot " +
		"be attributed to the revision the user was actually using. The blob is still scanned; only its " +
		"label is missing.",
	Tags: []string{"hf-cache", "provenance"},
})
