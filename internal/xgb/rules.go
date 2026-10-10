// The XGBoost/UBJSON rule set.
//
// Only two rules are defined here, because only two things can go wrong with a
// UBJSON model file once the pickle shapes have been routed away:
//
//   - the byte stream is not the structure it claims to be, or it is padded with
//     a container sc4n cannot bound; and
//   - there are bytes after the root value, which the XGBoost reader stops before
//     and therefore never sees. That is the smuggling shape: an appended native
//     image, a second container, or a pickle that a different reader would pick up.
//
// What is deliberately NOT here is a "model looks suspicious" heuristic. A `.ubj`
// or `.json` XGBoost model is data; the code-bearing surfaces of this family are
// the pickle forms, and those are the pickle engine's to report.
package xgb

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleStruct reports a UBJSON stream that violates its own framing, or that hits
// sc4n's bounded-parse caps.
var RuleStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-XGB-UBJ-STRUCT",
	Title:      "UBJSON stream is structurally invalid or exceeds the walk budget",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "format",
	Description: "The XGBoost UBJSON value stream could not be walked: an unknown marker, a length or " +
		"count that is negative or exceeds the bytes actually remaining, a typed container without the " +
		"mandatory count, an unsupported typed element, nesting beyond the walk cap, or more elements than " +
		"MaxEntries. The parse stops at the first unrecoverable point and the walk is bounded throughout, " +
		"so an attacker-controlled length is never allocated. A malformed model means an XGBoost reader " +
		"and sc4n disagree about where the document ends, which is how appended data hides.",
	Refs: []string{
		"https://ubjson.org/type-reference/",
		"https://github.com/dmlc/xgboost/blob/master/src/common/json.cc",
	},
	Tags: []string{"xgboost", "format", "malformed"},
})

// RuleTrailing reports bytes after the root UBJSON value.
var RuleTrailing = report.DefineRule(report.Rule{
	ID:         "SC4N-XGB-UBJ-TRAILING",
	Title:      "Bytes follow the root UBJSON value",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "polyglot",
	Description: "The UBJSON parse completed a root value and then found more bytes. XGBoost's reader " +
		"decodes exactly one root value and ignores whatever follows, so the trailing region is invisible " +
		"to the legitimate loader while remaining visible to any other reader that is handed the file. " +
		"That is the polyglot/smuggling shape: an appended executable, a second container, or a serialised " +
		"object. The XGBoost documentation itself states the in-memory snapshot is not secure, so do not " +
		"assume the trailing bytes are benign just because the model part parsed.",
	Refs: []string{
		"https://ubjson.org/type-reference/",
		"https://github.com/dmlc/xgboost/blob/master/doc/tutorials/saving_model.rst",
	},
	Tags: []string{"xgboost", "polyglot", "smuggling"},
})
