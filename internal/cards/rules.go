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
			"install the dependencies\", contain similar words; read the evidence. This rule is medium " +
			"where SC4N-TEMPLATE-INJECTION is high for the same phrasing: a card is read once, by whoever " +
			"opens it, while a chat template is rendered around every conversation the model serves.",
		Refs: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/1426.html",
		},
		Tags: []string{"prompt-injection", "card"},
	})

	// ruleCardHidden is the hidden-channel rule. It is high because a card is a
	// document whose whole purpose is to be read, and both HTML comments and the
	// order-affecting control characters are unreadable to the human the card is
	// for.
	ruleCardHidden = report.DefineRule(report.Rule{
		ID:         "SC4N-CARD-HIDDEN",
		Title:      "Card hides instruction text in an HTML comment or reorders text with control characters",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1007", "CWE-1426"},
		Class:      "card",
		Description: "A model card, dataset card or metadata value carries instruction-shaped text inside " +
			"an HTML comment, or a run of order-affecting control characters (the bidirectional " +
			"overrides and directional marks — Trojan Source). Every Markdown renderer drops HTML " +
			"comments, so an instruction in one is present for the model and absent for the person " +
			"reviewing the card, and a bidirectional override reorders what that person reads. High " +
			"because text shaped like an instruction, or a character that rewrites the reading order, " +
			"has no editorial purpose in a card. A comment *without* instruction-shaped text is " +
			"SC4N-CARD-COMMENT (info) and a zero-width run that reorders nothing is " +
			"SC4N-CARD-INVISIBLE (medium): the split is what keeps this rule's severity meaningful " +
			"on the 450 comments and invisible runs of the 273-model HF campaign, every one of which " +
			"carried no instruction at all.",
		Refs: []string{
			"https://trojansource.codes/",
			"https://cwe.mitre.org/data/definitions/1007.html",
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		},
		Tags: []string{"card", "hidden", "prompt-injection"},
	})

	// ruleCardComment is the editorial case of the hidden channel: a comment is
	// invisible to every renderer, so it is reported, but a comment with no
	// instruction in it is how a card carries a commented-out heading, a lint
	// directive or an uploader's section markers.
	ruleCardComment = report.DefineRule(report.Rule{
		ID:         "SC4N-CARD-COMMENT",
		Title:      "Card carries an HTML comment with no instruction in it",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1007"},
		Class:      "card",
		Description: "A model card, dataset card or metadata value contains an HTML comment whose body " +
			"carries no instruction-shaped text. A Markdown renderer drops the comment, so the reader " +
			"never sees it, which is why it is reported at all; it is informational because a " +
			"commented-out heading, a `<!-- markdownlint-disable -->` directive and an uploader's " +
			"`<!-- RVN_FILE_SELECTION_GUIDE_START -->` markers are ordinary editorial practice — 419 " +
			"of the 450 comments in the 273-model HF campaign. A comment that does carry " +
			"instruction-shaped text is SC4N-CARD-HIDDEN (high).",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/1007.html",
			"https://huggingface.co/docs/hub/model-cards",
		},
		Tags: []string{"card"},
	})

	// ruleCardInvisible is the copy-paste case of the invisible-character channel:
	// a zero-width or soft-hyphen run hides text from a reader without reordering
	// it, which happens by accident whenever text is pasted from a rendered page.
	ruleCardInvisible = report.DefineRule(report.Rule{
		ID:         "SC4N-CARD-INVISIBLE",
		Title:      "Card carries an invisible character that reorders nothing",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1007"},
		Class:      "card",
		Description: "A model card, dataset card or metadata value contains a run of zero-width or " +
			"soft-hyphen characters: characters a reader does not see, but that do not reorder the " +
			"text either. Medium because copy-paste from a rendered page carries them by accident — " +
			"they are also legitimate data in a tokenizer vocabulary — where an order-affecting " +
			"control character is never accidental and is reported as SC4N-CARD-HIDDEN (high).",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/1007.html",
		},
		Tags: []string{"card", "hidden"},
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
