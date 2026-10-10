// Package tokenizer analyses the tokenizer half of a model repository: the
// regular expressions embedded in tokenizer.json and the special-token strings
// in a tokenizer_config.json / special_tokens_map.json.
//
// The regular expressions are the interesting part. A tokenizer's
// pre_tokenizer/normalizer pattern is executed against every input string the
// serving process tokenises, and the runtime that executes it is not
// deterministic across stacks: the Rust `tokenizers` crate uses an RE2-family
// engine, while Python implementations hand the same pattern to the
// backtracking `re`/`regex` module. A pattern that is merely unsupported in RE2
// (a backreference, a lookaround, a possessive quantifier) becomes, in Python,
// a catastrophic-backtracking hazard — or a compile error, depending on which
// site loads it. That split is the CVE-2024-12720 / CVE-2025-2099 /
// CVE-2025-3263 / CVE-2025-5197 family, and it is why this package reports the
// construct it saw and states which runtime the severity assumes.
package tokenizer

import "github.com/fr0g-66723067-io/sc4n/internal/report"

var (
	// ruleRedos is medium rather than high because the same construct is
	// legitimate in a published tokenizer that only ever runs under RE2. The
	// evidence names the construct and the pattern so a reviewer can decide;
	// the rule text states that the severity assumes Python-regex semantics.
	ruleRedos = report.DefineRule(report.Rule{
		ID:         "SC4N-TOKENIZER-REDOS",
		Title:      "Tokenizer regex is not expressible in RE2 and can backtrack catastrophically",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-1333"},
		Class:      "tokenizer",
		Description: "A regular expression inside tokenizer.json uses a construct that RE2 does not " +
			"support and that a backtracking engine can make super-linear: a backreference (\\1, \\k<>, " +
			"(?P=name)), a lookaround ((?=), (?!), (?<=), (?<!)), an atomic group ((?>)), a recursion or " +
			"subroutine call ((?R), (?0), (?&name), (?P>name)), a conditional group ((?(...))), a " +
			"possessive quantifier (*+, ++, ?+), or a quantified group that already contains a " +
			"quantifier ((\\w+)+, (a*)*). The Rust `tokenizers` crate runs these through an RE2-family " +
			"engine where the pattern is simply an error, but the Python implementations hand the same " +
			"pattern to `re`/`regex`, where it is a denial-of-service hazard on attacker-influenced " +
			"input (the CVE-2024-12720 / CVE-2025-2099 / CVE-2025-3263 / CVE-2025-5197 family). " +
			"Severity is medium and the construct is named: the pattern is legitimate in some " +
			"distributions, and the finding assumes Python-regex semantics.",
		Refs: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-12720",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-2099",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-3263",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-5197",
			"https://cwe.mitre.org/data/definitions/1333.html",
		},
		Tags: []string{"tokenizer", "redos"},
	})

	// ruleUnknownClass is informational: an unrecognised tokenizer_class is a
	// reason to look at which library the repo expects, not a finding on its own.
	ruleUnknownClass = report.DefineRule(report.Rule{
		ID:         "SC4N-TOKENIZER-UNKNOWN-CLASS",
		Title:      "tokenizer_class is outside the known Transformers tokenizer set",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-1357"},
		Class:      "tokenizer",
		Description: "A tokenizer_class is not one of the classes Transformers ships. That is often " +
			"an entirely ordinary custom tokenizer, but a class name the local library does not know " +
			"is also how a repository routes loading through code the user did not intend to run " +
			"(the same shape as an auto_map entry). Informational: the name is recorded so a reviewer " +
			"can check whether the named class resolves to a library the user already has.",
		Refs: []string{"https://huggingface.co/docs/transformers/main_classes/tokenizer"},
		Tags: []string{"tokenizer"},
	})
)
