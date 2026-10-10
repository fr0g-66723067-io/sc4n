package gguf

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The GGUF rule set.
//
// Severity calibration follows the plan: `critical` is a code-execution surface
// reachable from the file's normal load path, `high` is an exploitable
// file-access/executable-content shape, `medium` is a structural violation that
// makes the file not what its own header claims, and `info` is a fact a reader
// needs in order not to misread the verdict.
//
// The structural rules mirror the exact checks the llama.cpp GGUF reader performs
// and the parser bugs its CVEs fired on: CVE-2024-21802, CVE-2024-23496,
// CVE-2024-23605, CVE-2025-53630 (cumulative-size integer overflow),
// CVE-2026-33298 (`ggml_nbytes` overflow) and GHSA-8wwf-w4qm-gpqr. A violation
// does not abort the scan; where parsing can continue it does, and every cap that
// fires is reported rather than silently truncating.
var (
	// RuleStruct is any way the declared structure contradicts the bytes: absent
	// magic, an unsupported version, counts beyond the file, an illegal key/name
	// length, a duplicate key, a retired or out-of-range ggml type, more than
	// four dimensions, a zero dimension, a misaligned/unsorted/overlapping tensor
	// offset, or an extent that runs past EOF.
	RuleStruct = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-STRUCT",
		Title:      "GGUF structure violates the format's own header",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20"},
		Class:      "structure",
		Description: "The file's declared counts, key or tensor metadata contradict the bytes actually " +
			"present: absent magic, a version outside {2,3}, a count larger than the file, an illegal key or " +
			"tensor-name length, a duplicate metadata key, a retired or out-of-range ggml type, more than four " +
			"dimensions, a zero dimension, a tensor offset that is misaligned, out of declaration order or " +
			"overlapping its predecessor, or a tensor extent that runs past EOF. These are exactly the checks " +
			"the llama.cpp GGUF reader performs, and the parser bugs that reached CVEs (CVE-2024-21802, " +
			"CVE-2024-23496, CVE-2024-23605, CVE-2025-53630 cumulative-size overflow, CVE-2026-33298 " +
			"ggml_nbytes overflow, GHSA-8wwf-w4qm-gpqr) were triggered by count/offset arithmetic on values " +
			"like these. A reader that accepts this file is reading a different byte layout than the one the " +
			"header describes.",
		Refs: []string{
			"https://github.com/ggml-org/ggml/blob/master/docs/gguf.md",
			"https://nvd.nist.gov/vuln/detail/CVE-2024-21802",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-53630",
			"https://nvd.nist.gov/vuln/detail/CVE-2026-33298",
			"https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-8wwf-w4qm-gpqr",
		},
		Tags: []string{"format-validation"},
	})

	// RuleTrailing is undeclared data after the last tensor.
	RuleTrailing = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-TRAILING-DATA",
		Title:      "GGUF has undeclared trailing data after the last tensor",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "structure",
		Description: "The file is longer than 8 + metadata + aligned tensor region + the last tensor's " +
			"extent, so bytes exist that no tensor describes. The GGUF reader never looks at them, which is " +
			"what makes the shape useful for smuggling: a second artifact can live there and every GGUF-only " +
			"tool reports a normal model. The evidence carries the residual length, its byte entropy and any " +
			"validated native magic found in it.",
		Refs: []string{
			"https://github.com/ggml-org/ggml/blob/master/docs/gguf.md",
		},
		Tags: []string{"evasion", "polyglot"},
	})

	// RulePolyglot is the llamafile/APE and embedded-executable shape.
	RulePolyglot = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-POLYGLOT",
		Title:      "GGUF carries an APE/llamafile sigil or an embedded native executable",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "structure",
		Description: "An APE sigil (MZqFpD=' or jartsr=') or a validated ELF/PE/Mach-O header appears in " +
			"the first 8 KiB or the last 1 MiB of the file. This is the llamafile single-file-executable " +
			"shape: one file that is both a model and a runnable program, so a tool that treats it as weights " +
			"and a person who runs it as a binary see different things. Executables are validated with the " +
			"standard library's debug/elf, debug/macho and debug/pe header parsers; a bare magic match without " +
			"a valid header is left to the format-independent polyglot layer at info.",
		Refs: []string{
			"https://github.com/Mozilla-Ocho/llamafile",
			"https://justine.lol/ape.html",
		},
		Tags: []string{"polyglot", "evasion"},
	})

	// RuleEndianAmbiguous reports that the byte order had to be chosen.
	RuleEndianAmbiguous = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-ENDIAN-AMBIGUOUS",
		Title:      "GGUF version 3 byte order is ambiguous; one was chosen",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-20"},
		Class:      "structure",
		Description: "GGUF version 3 added a big-endian variant and the format carries no flag that names " +
			"the byte order, so a reader has to infer it. sc4n tested the declared counts (and the first " +
			"metadata key length) under both orders; when both are plausible, or only big-endian is, it " +
			"reports this finding and states which order it used rather than guessing silently. A file whose " +
			"counts are plausible in both orders cannot be interpreted unambiguously by sc4n, so the tensor " +
			"geometry below this finding is the little-endian reading.",
		Refs: []string{"https://github.com/ggml-org/ggml/blob/master/docs/gguf.md"},
		Tags: []string{"format-validation"},
	})

	// RuleExtentUnverified reports a tensor whose extent could not be computed.
	RuleExtentUnverified = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-EXTENT-UNVERIFIED",
		Title:      "GGUF tensor extent could not be computed; geometry checks skipped",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        nil,
		Class:      "structure",
		Description: "A tensor names a ggml type whose block size sc4n cannot confirm, or an element count " +
			"that is not a whole number of blocks, so its byte extent is unknown. sc4n deliberately skips " +
			"the overlap, alignment-of-end and trailing-data checks for it: a wrong block size would " +
			"fabricate an overlap or a trailing payload, and a false \"trailing data\" finding is worse than " +
			"an honest \"not verified\". The tensor's own offset alignment is still checked.",
		Refs: []string{"https://github.com/ggml-org/ggml/blob/master/docs/gguf.md"},
		Tags: []string{"format-validation"},
	})

	// RuleTemplateSSTI is python-object introspection inside a chat template.
	RuleTemplateSSTI = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-TEMPLATE-SSTI",
		Title:      "GGUF chat template reaches Python object internals (template SSTI)",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1336"},
		Class:      "template",
		Description: "A tokenizer.chat_template value contains a Python-object introspection construct " +
			"(__class__, __mro__, __subclasses__, __globals__, __builtins__, __import__, __code__, " +
			"__reduce__, ... or an |attr filter over an underscore-prefixed name). An unsandboxed Jinja2 " +
			"engine that renders this template can walk from any object to its class hierarchy and reach the " +
			"import machinery, which is remote code execution on the inference host — the CVE-2026-5760 / " +
			"CERT VU#915947 class (SGLang's unsandboxed Jinja2 via /v1/rerank). A model whose chat template " +
			"does this is not a model file, it is a payload for whatever serves it.",
		Refs: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2026-5760",
			"https://kb.cert.org/vuls/id/915947",
		},
		Tags: []string{"rce", "template-injection"},
	})

	// RuleTemplateBackdoor is a hidden directive inside a chat template.
	RuleTemplateBackdoor = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-TEMPLATE-BACKDOOR",
		Title:      "GGUF chat template embeds an instruction-override backdoor",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-74"},
		Class:      "template",
		Description: "A tokenizer.chat_template value contains an instruction-override or hidden-directive " +
			"phrase (\"ignore previous instructions\", \"do not tell the user\", \"system prompt:\", a " +
			"literal <system> tag, ...). The template is rendered around every conversation, so text in it " +
			"reaches the model as if it came from the application — the Pillar chat-template-backdoor shape " +
			"and the OWASP LLM01 prompt-injection class. It is reported even when the Jinja is syntactically " +
			"ordinary, because the payload is the prose, not the syntax. The phrasing is short, so a template " +
			"that legitimately documents an attack can trip it; read the matched directive before concluding.",
		Refs: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://github.com/ggml-org/ggml/blob/master/docs/gguf.md",
		},
		Tags: []string{"prompt-injection", "backdoor"},
	})

	// RuleTemplateBackdoorWeak is a concealment-class phrase with nothing else in
	// the template to corroborate it.
	RuleTemplateBackdoorWeak = report.DefineRule(report.Rule{
		ID:         "SC4N-GGUF-TEMPLATE-BACKDOOR-WEAK",
		Title:      "GGUF chat template contains model-directed instruction text (no channel corroborates it)",
		Severity:   report.SeverityLow,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-74"},
		Class:      "template",
		Description: "A tokenizer.chat_template value contains a concealment-class phrase (\"do not tell the " +
			"user\", \"do not mention this\") or a chat pseudo-tag, and no override directive, endpoint or " +
			"other corroboration. Reported at low severity because a legitimate tool-use instruction reads " +
			"the same way — three of llama.cpp's shipped templates say \"do not tell the user about " +
			"function calls\" — and because a template that emits <|system|> is doing its job. The " +
			"high-severity SC4N-GGUF-TEMPLATE-BACKDOOR is the form that carries an override directive.",
		Refs: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		},
		Tags: []string{"prompt-injection", "backdoor"},
	})
)
