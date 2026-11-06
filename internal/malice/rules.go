package malice

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The grade ladder, and why there are exactly two rules here.
//
// Every critical sc4n already emits is a *capability* statement: the artifact
// can reach a sink. A reviewer holding 216 of them (the unsafe corpus) still
// cannot answer "does this one run code, or is it merely powerful?" without
// reading the artifact by hand. These two rules are the behaviour grades above
// capability, and each is emitted only where the existing critical states
// capability rather than behaviour:
//
//	constructed  the loader's own load path executes artifact-supplied code and
//	             the payload is inside the artifact (RuleConstructed).
//	demonstrated the artifact was loaded in a disposable container and the
//	             recorded effects are attributed to its digest (RuleDemonstrated).
//
// The third grade, capability, emits nothing: absence of a MALICE finding is the
// grade, and docs/architecture.md states that so it is documented rather than
// silent. SC4N-KERAS-LAMBDA and SC4N-REPO-PTH get no second finding because they
// already assert the load path executes the artifact's contents - restating that
// as MALICE-CONSTRUCTED would add a rule, not an answer.

// RuleConstructed is the static grade.
var RuleConstructed = report.DefineRule(report.Rule{
	ID:         "SC4N-MALICE-CONSTRUCTED",
	Title:      "Loader runs artifact-supplied code on its own load path",
	Severity:   report.SeverityCritical,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-502", "CWE-94", "CWE-78"},
	Class:      "malice",
	Description: "The artifact's bytes are code that the loader executes while loading it, and the payload " +
		"comes from the artifact itself: a pickle REDUCE hands a string to a code or process sink, a module " +
		"imported through trust_remote_code calls a sink in its import-time body, or a chat template invokes a " +
		"Python object that is reachable from the template context. This is the behaviour grade above the " +
		"capability criticals: the same artifact's SC4N-PICKLE-GLOBAL-CRITICAL, SC4N-CONFIG-AUTO-MAP or " +
		"SC4N-JINJA-PY-OBJECT finding says a sink is reachable, and this finding says which sink runs, with " +
		"which payload, on the loader's own path. It does not assert intent - code that runs on load can still " +
		"be benign, and the payload is quoted so a reviewer can judge it - and its absence is not a clean " +
		"bill: it means the reach is structural, for example a plain attribute name on a named class, or a " +
		"module that only defines classes. That third case is the capability grade and it is stated in " +
		"docs/architecture.md.",
})

// RuleDemonstrated is the dynamic grade.
var RuleDemonstrated = report.DefineRule(report.Rule{
	ID:         "SC4N-MALICE-DEMONSTRATED",
	Title:      "Artifact executed on load in isolation and produced effects",
	Severity:   report.SeverityCritical,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-502", "CWE-94", "CWE-78", "CWE-506"},
	Class:      "malice",
	Description: "An attestation produced by tools/sc4nconfirm recorded what happened when these exact bytes " +
		"were loaded in a disposable container with no network interface and a read-only root: the process " +
		"executed a program, attempted a socket connection, opened a path outside the artifact's directory, or " +
		"wrote a file. The finding names the loader and the effects, and it is attributed to the artifact's " +
		"SHA-256, so identical bytes scanned anywhere carry the identical verdict. sc4n never executes " +
		"artifact bytes itself: this finding consumes an attestation the operator generated with a separate " +
		"tool, and a scan without -attestation cannot emit it. A load that failed on an import is not a " +
		"demonstration and emits nothing; the attestation records the missing module instead, so 'we could " +
		"not load it' is never read as 'it did nothing'.",
})

// Families name where a constructed grade came from. They are stable strings:
// they appear in Finding.Extra and in the corpus tables of the verification
// rounds, so changing one silently breaks a query.
const (
	// FamilyPickleReduce is a pickle REDUCE that hands an artifact-supplied
	// payload to a code or process sink.
	FamilyPickleReduce = "pickle-reduce"
	// FamilyImportScope is a module imported by trust_remote_code whose
	// import-time body calls a sink.
	FamilyImportScope = "import-scope"
	// FamilyTemplateCall is a chat template that calls through a Python object.
	FamilyTemplateCall = "template-call"
)
