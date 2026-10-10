// Package cards analyses model and dataset cards, HF metadata documents and
// arbitrary metadata text for prompt injection and for content that is hidden
// from a human reviewer.
//
// A model card is read by two audiences with opposite capabilities. A person
// reads the rendered Markdown; an agent or a loader reads every byte, including
// the HTML comments a renderer discards and the zero-width characters a terminal
// does not draw. Prompt injection in this channel is OWASP LLM01 and it needs no
// executable artifact at all: the payload is the text. The detectors here are
// deliberately literal — a phrase table and a character-class check — because a
// heuristic scorer would be neither reproducible nor reviewable.
//
// The shared string indicators (webhooks, credential paths, unicode anomalies,
// the chat pseudo-tags) are NOT redefined here; ScanText calls
// stringscan.EmitString so there is exactly one table and one rule per
// indicator across the whole scanner.
package cards

import "github.com/fr0g-66723067-io/sc4n/internal/report"

var (
	// ruleCardInjection covers the directive shapes the shared indicator table
	// does not: imperative sentences aimed at a model, tool/function-call JSON
	// directives, and an instruction buried in an HTML comment. It is medium
	// because a document *about* prompt injection quotes the same text.
	ruleCardInjection = report.DefineRule(report.Rule{
		ID:         "SC4N-CARD-INJECTION",
		Title:      "Card or metadata carries an instruction aimed at a model",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-1426"},
		Class:      "card",
		Description: "A model card, dataset card or metadata value contains a directive aimed at a " +
			"model rather than at a reader: an imperative (\"you must\", \"always respond\", \"never " +
			"reveal\"), a tool/function-call JSON directive (\"tool_calls\", \"function_call\", " +
			"\"recipient_name\", <tool_call>), or instruction-like text hidden inside an HTML comment. " +
			"Cards and metadata are pasted into prompts by agents and by RAG pipelines, so text in them " +
			"is an input channel with no executable artifact required (OWASP LLM01). Medium because a " +
			"document that discusses prompt injection, and a legitimate README that says \"you must " +
			"install the dependencies\", contain similar words; read the evidence.",
		Refs: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/1426.html",
		},
		Tags: []string{"prompt-injection", "card"},
	})

	// ruleCardHidden is the hidden-channel rule. It is high because a card is a
	// document whose whole purpose is to be read, and both HTML comments and the
	// zero-width/bidi set are unreadable to the human the card is for.
	ruleCardHidden = report.DefineRule(report.Rule{
		ID:         "SC4N-CARD-HIDDEN",
		Title:      "Card hides text in an HTML comment or with invisible characters",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1007", "CWE-1426"},
		Class:      "card",
		Description: "A model card, dataset card or metadata value contains an HTML comment or a run of " +
			"zero-width/bidi control characters. Every Markdown renderer drops HTML comments, so " +
			"instruction text in one is present for the model and absent for the person reviewing the " +
			"card; the zero-width/bidi set is the same idea at the character level, and the bidirectional " +
			"overrides additionally reorder what a reader sees (Trojan Source). High because the only " +
			"reason to put instruction text in a comment is to hide it from review. Note the honest " +
			"false-positive direction: a build or lint directive (`<!-- markdownlint-disable -->`) also " +
			"trips this, so read the evidence before acting.",
		Refs: []string{
			"https://trojansource.codes/",
			"https://cwe.mitre.org/data/definitions/1007.html",
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		},
		Tags: []string{"card", "hidden", "prompt-injection"},
	})

	// ruleCardParse is low: an unparseable frontmatter block is a reason to fall
	// back to raw-text scanning, not a finding about intent.
	ruleCardParse = report.DefineRule(report.Rule{
		ID:         "SC4N-CARD-PARSE",
		Title:      "Card frontmatter could not be parsed and was scanned as raw text",
		Severity:   report.SeverityLow,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20"},
		Class:      "card",
		Description: "A card's YAML frontmatter block does not match the scalar/list subset sc4n reads, " +
			"so its fields could not be resolved by name. sc4n does not link a YAML library and does not " +
			"need one to scan text, so the document is still scanned in full as raw text; this finding " +
			"records that the structured view is missing, which matters when a reviewer is comparing the " +
			"frontmatter fields against what the scanner saw.",
		Refs: []string{"https://huggingface.co/docs/hub/model-cards"},
		Tags: []string{"card"},
	})
)
