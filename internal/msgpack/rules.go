package msgpack

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The MessagePack rule set.
//
// MessagePack is a data-only format with no code field. The two shapes that
// matter are therefore structural — a truncated or lying length that makes a
// loader read past a buffer, or a payload smuggled in a float/int bit pattern —
// plus the fact that a blob value can itself be a pickle or a native image,
// which is handled by dispatching the blob rather than by a rule here.
var (
	// RuleStruct covers malformed and truncated MessagePack: an unknown type
	// byte, a length that runs past the end of the file, and a trailing byte
	// after the top-level value. Flax/JAX/MLX write a single top-level map, so
	// any of these is a file no reference decoder accepts. The nesting and
	// element budgets are not part of this rule: the walker reports those through
	// limits.Emit as SC4N-LIMIT-DEPTH and SC4N-LIMIT-ENTRIES.
	RuleStruct = report.DefineRule(report.Rule{
		ID:         "SC4N-MSGPACK-STRUCT",
		Title:      "MessagePack value violates the format",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20", "CWE-502"},
		Class:      "structure",
		Description: "A MessagePack type byte the parser does not know, a declared string/binary/ext/array/" +
			"map length that runs past the end of the file, or bytes after the single top-level value. " +
			"The walker is bounded and never " +
			"allocates from a declared length before checking it against the bytes remaining, so a " +
			"crafted length cannot make the scan itself read out of bounds.",
		Refs: []string{
			"https://github.com/msgpack/msgpack/blob/master/spec.md",
			"https://cwe.mitre.org/data/definitions/20.html",
		},
	})

	// RuleNaNPayload reports a run of NaN-shaped float bit patterns inside binary
	// data, the classic way to smuggle a stream in a weight blob.
	RuleNaNPayload = report.DefineRule(report.Rule{
		ID:         "SC4N-MSGPACK-NAN-PAYLOAD",
		Title:      "Run of NaN float patterns in a MessagePack binary blob",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-506"},
		Class:      "msgpack",
		Description: "A binary blob contains four or more repeated NaN-shaped byte pairs (0x7f 0xf8 or " +
			"0xff 0xf8, the exponent-and-top-mantissa bytes of a double-precision NaN). One NaN is ordinary " +
			"data; a run is a common carrier for an encoded payload because a NaN passes through numeric " +
			"code without being touched. Informational only: a run has benign explanations (padding, a " +
			"mask tensor), so it is a pointer for a reviewer, never a gate.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	})
)
