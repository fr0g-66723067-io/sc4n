package onnx

// The ONNX rule set. Each rule cites the advisory that makes it a detector
// rather than a style opinion.
//
// Two advisory identifiers in this space are easy to get wrong, and the whole
// setattr/attribute-injection family depends on which one is which:
//
//   - GHSA-p433-9wv8-28xj IS CVE-2026-34447 (external-data path handling).
//   - GHSA-538c-55jv-c5g9 IS CVE-2026-34445 (attribute injection via
//     external_data keys), NOT CVE-2026-34447.
//
// The remaining evidence for this family: CVE-2022-25882 (external-data path
// traversal), CVE-2024-27318 (bypass of the fix for 25882), CVE-2026-27489 =
// GHSA-3r9x-f23j-gc73 (symlink arbitrary read bypassing the relative-path
// check), and GHSA-cmw6-hcpp-c6jp (hardlink bypass).

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// ruleExternalTraversal reports an external_data location that is not a
// relative POSIX path under the model's own directory.
//
// Severity is critical because this is the published arbitrary-file-read
// primitive: the loader opens whatever the value names and hands its bytes back
// as tensor content, so a model file can be turned into a reader for
// /etc/passwd, a private key or a cloud credential file. Every named evasion is
// listed in the description so a reviewer can see which shape was seen.
var ruleExternalTraversal = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-EXTERNAL-TRAVERSAL",
	Title:      "ONNX external tensor data escapes the model directory",
	Severity:   report.SeverityCritical,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-22", "CWE-73"},
	Class:      "path",
	Description: "external_data 'location' must be a relative POSIX path resolved against the directory " +
		"holding the model. This finding means it is absolute, contains a '..' segment before cleaning, " +
		"contains a NUL, uses a drive letter or UNC prefix, starts with '~', is a URL, or resolves outside " +
		"the scan root. The loader reads the named file and returns its bytes as tensor content, so the " +
		"artifact is a file-read primitive rather than a model. Evidence: CVE-2022-25882 (traversal), " +
		"CVE-2024-27318 (bypass of that fix), CVE-2026-34447 = GHSA-p433-9wv8-28xj.",
	Refs: []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2022-25882",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-27318",
		"https://github.com/advisories/GHSA-p433-9wv8-28xj",
	},
	Tags: []string{"onnx", "file-read"},
})

// ruleExternalKey reports an external_data key outside the loader's whitelist.
//
// The whitelist is exactly {location, offset, length, checksum, basepath}. The
// unpatched loader assigned every key/value pair onto an object as an attribute,
// which is why a key like "__class__" is the attribute-injection half of
// CVE-2026-34445 = GHSA-538c-55jv-c5g9. Dunder keys are additionally marked in
// the evidence, because that is the shape that names a Python protocol slot
// rather than a data field.
var ruleExternalKey = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-EXTERNAL-KEY",
	Title:      "ONNX external_data uses a key outside the loader whitelist",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-915"},
	Class:      "code",
	Description: "The hardened loader accepts exactly {location, offset, length, checksum, basepath} in " +
		"external_data and rejects everything else. An out-of-whitelist key is either a typo the loader " +
		"will ignore or, when it is a dunder name such as '__class__' or '__reduce__', input to a " +
		"setattr-shaped sink that overwrites a protocol attribute instead of a data field. That is the " +
		"attribute-injection half of CVE-2026-34445 = GHSA-538c-55jv-c5g9 (not CVE-2026-34447, which is " +
		"the path-handling bug GHSA-p433-9wv8-28xj).",
	Refs: []string{
		"https://github.com/advisories/GHSA-538c-55jv-c5g9",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-34445",
	},
	Tags: []string{"onnx", "attribute-injection"},
})

// ruleExternalBounds reports an external_data offset/length that is not a
// non-negative decimal integer, is petabyte-scale, or points past the end of the
// file it names.
//
// The loader parses these strings itself and used the result as an allocation
// size, so out-of-range values are the OOM/DoS half of the same advisory family
// as ruleExternalKey.
var ruleExternalBounds = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-EXTERNAL-BOUNDS",
	Title:      "ONNX external_data offset/length is out of bounds",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-190", "CWE-400"},
	Class:      "resource",
	Description: "external_data carries 'offset' and 'length' as decimal strings. This finding means the " +
		"value is not a non-negative decimal integer (a negative, hexadecimal or non-numeric value), is " +
		"petabyte-scale (>= 1 PiB, far above any published model and enough to overflow an allocation " +
		"computed from it), or runs past the end of the file it names. The loader sized a read from this " +
		"value before validating it, so the artifact is an allocation/DoS primitive.",
	Refs: []string{
		"https://github.com/advisories/GHSA-538c-55jv-c5g9",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-34445",
	},
	Tags: []string{"onnx", "dos"},
})

// ruleExternalSymlink reports an external_data path whose final component is a
// symlink.
//
// A relative path that passes every string check can still leave the model
// directory through a link planted next to the model, which is exactly the
// bypass CVE-2026-27489 = GHSA-3r9x-f23j-gc73 fixed; GHSA-cmw6-hcpp-c6jp is the
// hardlink twin. sc4n resolves the reference through os.Root, so the check is
// made against the same containment the hardened loader uses.
var ruleExternalSymlink = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-EXTERNAL-SYMLINK",
	Title:      "ONNX external_data resolves through a symlink",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceMedium,
	CWE:        []string{"CWE-59"},
	Class:      "path",
	Description: "The referenced external tensor file exists and is a symbolic link (or has a symlinked " +
		"final component). A relative path that passes every string-shaped check can still leave the model " +
		"directory through a link planted beside the model, which is the bypass class of CVE-2026-27489 = " +
		"GHSA-3r9x-f23j-gc73; GHSA-cmw6-hcpp-c6jp is the hardlink twin. Reported only when the path " +
		"resolves inside the scan root with os.Root.",
	Refs: []string{
		"https://github.com/advisories/GHSA-3r9x-f23j-gc73",
		"https://github.com/advisories/GHSA-cmw6-hcpp-c6jp",
	},
	Tags: []string{"onnx", "symlink"},
})

// ruleCustomDomain reports a node or opset import in a non-standard domain.
//
// A domain outside {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training",
// "ai.onnx.training"} names an operator the runtime must supply as native code:
// the model file cannot contain the implementation, so the artifact's behaviour
// is a property of the host's plugin set. That is why custom domains are the
// documented ONNX supply-chain surface rather than a syntax error.
var ruleCustomDomain = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-CUSTOM-DOMAIN",
	Title:      "ONNX operator is in a non-standard domain",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-829"},
	Class:      "code",
	Description: "A node or opset import names a domain outside the ONNX-defined sets, so the operator it " +
		"binds to (or the whole op set it imports) has to be provided by a native extension of the " +
		"runtime. The model file contains no implementation, so what runs is decided by the host's plugin " +
		"set; a reviewer must confirm that the named domain is expected for this artifact.",
	Refs: []string{"https://onnx.ai/onnx/repo-docs/IR.html"},
	Tags: []string{"onnx", "native-code"},
})

// ruleFunction reports a model-local FunctionProto or a node overload binding.
//
// Model-local functions are subgraphs supplied by the file itself: they are not
// operator schemas from the specification, and a node referencing one by
// overload bypasses the standard op resolution path. The bodies are fully
// attacker-controlled, so their presence is at least an unvalidated
// code-loading surface.
var ruleFunction = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-FUNCTION",
	Title:      "ONNX model carries model-local function bodies",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceMedium,
	CWE:        []string{"CWE-829"},
	Class:      "code",
	Description: "ModelProto.functions is non-empty, or a node carries an 'overload' value. A model-local " +
		"function is a subgraph supplied by the file rather than an operator schema from the " +
		"specification, and an overload binds a node to one by name. The functions are resolved and " +
		"executed by the runtime, so they are attacker-controlled code paths that a reviewer must read; " +
		"they are not covered by the standard operator review.",
	Refs: []string{"https://onnx.ai/onnx/repo-docs/IR.html#functions"},
	Tags: []string{"onnx", "native-code"},
})

// ruleStruct reports a structural contradiction in the protobuf.
//
// Severity is medium: a file that contradicts its own declared structure is not
// necessarily malicious, but it is not what the reference implementation would
// accept either, and a parser that silently ignores the contradiction is how a
// payload hides behind framing the loader and the scanner disagree about.
var ruleStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-ONNX-STRUCT",
	Title:      "ONNX model is structurally inconsistent",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "structure",
	Description: "The protobuf structure contradicts the ONNX specification: a missing ir_version, graph " +
		"or opset_import, a field whose wire type cannot be the declared ONNX type, a negative dimension, " +
		"a data_type of UNDEFINED, raw_data whose length does not equal product(dims) x element size, " +
		"external_data that is not marked with data_location=EXTERNAL, or both raw_data and external_data " +
		"set. The reference loader validates these; a file that fails them is not what it claims to be, " +
		"and a scanner and a loader that disagree here see different bytes.",
	Refs: []string{"https://onnx.ai/onnx/repo-docs/IR.html"},
	Tags: []string{"onnx", "structure"},
})

// rulePathEscape reports a whitelisted path that cannot be opened without
// escaping the scan root.
//
// It is a rule every path-resolving layer shares (ONNX external data, hf-cache
// blob links, SavedModel assets, .mlpackage members), so it is defined here only
// when no other package has registered it: report.DefineRule panics on a
// duplicate ID, and the packages are developed independently. Whoever registers
// it first owns the metadata; the others adopt it by ID.
var rulePathEscape = definePathEscape()

func definePathEscape() *report.Rule {
	if r, ok := report.RuleByID("SC4N-PATH-ESCAPE"); ok {
		return r
	}
	return report.DefineRule(report.Rule{
		ID:         "SC4N-PATH-ESCAPE",
		Title:      "Reference resolves outside the scan root",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-22", "CWE-59"},
		Class:      "path",
		Description: "A path-shaped value was resolved with os.Root and rejected because it leaves the " +
			"containment root (through '..', an absolute name, or a symlink whose target is outside). sc4n " +
			"never opens the file in that case; the finding tells the reviewer that the artifact asked for " +
			"a path it is not allowed to read, which is the same request an arbitrary-file-read exploit " +
			"makes.",
		Refs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-25882"},
		Tags: []string{"path"},
	})
}
