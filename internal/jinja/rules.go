// Package jinja analyses Jinja2 templates — chat templates above all — for
// server-side template injection and for hidden directives.
//
// A chat template is code that runs on the inference host. The Transformers
// renderer hands the template to Jinja2, and Jinja2 is not a sandbox: an
// attribute walk from any value to `__class__.__mro__[1].__subclasses__()`
// reaches an arbitrary callable, and the `attr` filter reaches the same names
// through a string so that a lexer which only looks at `.name` misses it. That
// path is the CVE-2026-5760 (SGLang `/v1/rerank`, CVSS 9.8) and CERT VU#915947
// class, and a template shipped inside a GGUF or a `tokenizer_config.json` is
// exactly how an attacker gets one onto a host they do not otherwise control.
//
// The second half is quieter: a template may be syntactically benign and still
// prepend a hidden directive to every conversation (the Pillar "chat-template
// backdoor"). That is what SC4N-TEMPLATE-INJECTION is for, and the phrase table
// is deliberately *not* the chat pseudo-tag table the shared engine carries:
// `[INST]`, `<|im_start|>` and `<|user|>` appear in legitimate templates and
// must not be reported here.
package jinja

import "github.com/fr0g-66723067-io/sc4n/internal/report"

var (
	// rulePyObject is the introspection primitive. Reaching any dunder attribute
	// or name from a template value is the first step of every published Jinja2
	// SSTI chain, so the severity is critical even though the second step is what
	// executes: by the time `__globals__` or `__subclasses__` is named, the
	// template author's intent is not in question.
	rulePyObject = report.DefineRule(report.Rule{
		ID:         "SC4N-JINJA-PY-OBJECT",
		Title:      "Template reaches a Python object through a dunder attribute or name",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1336", "CWE-94"},
		Class:      "template",
		Description: "A Jinja2 template contains an attribute, subscript or name from the Python " +
			"introspection set: __class__, __mro__, __subclasses__, __globals__, __builtins__, " +
			"__import__, __init__, __reduce__, __getattribute__, __dict__, __code__ or __loader__. " +
			"Jinja2 is not sandboxed, so walking from any value to one of these reaches an arbitrary " +
			"callable: __class__.__mro__[1].__subclasses__()[i](...) is the standard chain, and the " +
			"`attr` filter (|attr('__globals__')) reaches the same names through a string. This is the " +
			"class behind CVE-2026-5760 (SGLang /v1/rerank, CVSS 9.8) and CERT VU#915947. A chat " +
			"template has no legitimate reason to name any of them.",
		Refs: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2026-5760",
			"https://kb.cert.org/vuls/id/915947",
			"https://portswigger.net/web-security/server-side-template-injection",
		},
		Tags: []string{"template", "ssti", "execution"},
	})

	// ruleDangerousGlobal is the gadget half: the globals Jinja2 exposes that
	// reach `__globals__` when their attributes are walked. It fires only when one
	// of them is the receiver of an attribute/subscript access, or when `attr`
	// selects a leading-underscore name, so `{% set ns = namespace(found=false) %}`
	// — the ordinary way a template carries a loop-scoped variable — stays clean.
	ruleDangerousGlobal = report.DefineRule(report.Rule{
		ID:         "SC4N-JINJA-DANGEROUS-GLOBAL",
		Title:      "Template walks an attribute off a Jinja2 global that reaches __globals__",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-1336"},
		Class:      "template",
		Description: "A Jinja2 template uses one of the globals that immediately reaches an " +
			"interesting object as the receiver of an attribute or subscript access: lipsum, cycler, " +
			"joiner, namespace, dict or range, or it applies the `attr` filter to a name that starts " +
			"with an underscore. lipsum.__globals__['os'].popen(…) and cycler.__init__.__globals__ " +
			"are the canonical chains, and they exist because these globals are real Python objects " +
			"whose __globals__ is the template module's namespace. The bare constructors themselves " +
			"(namespace(a=1), dict(...), range(3)) are ordinary template style and are not reported " +
			"by this rule; the finding is the attribute access out of them. (A computed " +
			"{% set ns = namespace(...) %} is separately a low-confidence SC4N-JINJA-DYNAMIC-NAME, " +
			"not a gadget.)",
		Refs: []string{
			"https://portswigger.net/web-security/server-side-template-injection",
			"https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/",
		},
		Tags: []string{"template", "ssti"},
	})

	// ruleDynamicName is the evasion half: a dunder name assembled at render time
	// is invisible to a scanner that matches literal names, and a computed value
	// assignment hides what is being constructed. Both are heuristics, so the
	// confidence is low and the severity stays at medium — the honest reading is
	// "something is being built rather than written down", not "this executes".
	ruleDynamicName = report.DefineRule(report.Rule{
		ID:         "SC4N-JINJA-DYNAMIC-NAME",
		Title:      "Template assembles a name or value instead of writing it literally",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-1336", "CWE-506"},
		Class:      "template",
		Description: "A Jinja2 template builds a string by concatenation (the classic " +
			"'__g' + 'lobals__' that defeats a name denylist), applies the `attr` filter to a " +
			"computed name, or assigns a value with {% set %} whose right-hand side is computed rather " +
			"than a literal, a name or a filter chain. None of these is proof of intent on its own, " +
			"which is why the confidence is low; the constructive form is reported because obfuscating " +
			"an introspection name is the first thing a template-injection payload has to do.",
		Refs: []string{
			"https://owasp.org/www-community/attacks/Code_Injection",
			"https://cwe.mitre.org/data/definitions/1336.html",
		},
		Tags: []string{"template", "obfuscation"},
	})

	// ruleInclude is the file-access surface: include/import/extends/from make the
	// template read another file at render time.
	ruleInclude = report.DefineRule(report.Rule{
		ID:         "SC4N-JINJA-INCLUDE",
		Title:      "Template loads another template or module file",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1336"},
		Class:      "template",
		Description: "A Jinja2 template uses {% include %}, {% import %}, {% extends %} or " +
			"{% from %}, so rendering it reads another file that the loader resolves (and, in " +
			"Jinja's own examples, can build the name from a variable). A chat template shipped with " +
			"a model has no reason to pull in a sibling file; when one does, the sibling is part of " +
			"the artifact's executable surface and is only safe if it was scanned too.",
		Refs: []string{
			"https://jinja.palletsprojects.com/en/stable/templates/#import",
			"https://cwe.mitre.org/data/definitions/1336.html",
		},
		Tags: []string{"template", "file-access"},
	})

	// ruleRaw is low severity on purpose: {% raw %} exists to stop Jinja from
	// interpreting {{ }}, so a scanner that only looks at {{ }} sees nothing.
	// Legitimate templates almost never need it.
	ruleRaw = report.DefineRule(report.Rule{
		ID:         "SC4N-JINJA-RAW",
		Title:      "Template hides a region inside a {% raw %} block",
		Severity:   report.SeverityLow,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1336"},
		Class:      "template",
		Description: "A Jinja2 template contains a {% raw %} (or {% verbatim %}) block. Everything " +
			"inside is emitted literally, so a scanner that tokenises {{ }} and {% %} sees the " +
			"delimiters but not the content. A real chat template rarely needs one, and a payload " +
			"that wants its own delimiters to survive into the prompt uses exactly this. Low severity " +
			"because the technique is also used legitimately to show template syntax in documentation.",
		Refs: []string{"https://jinja.palletsprojects.com/en/stable/templates/#escaping"},
		Tags: []string{"template"},
	})

	// ruleTemplateInjection is the hidden-directive half. The phrase table is
	// narrow on purpose and is not the shared chat pseudo-tag table.
	ruleTemplateInjection = report.DefineRule(report.Rule{
		ID:         "SC4N-TEMPLATE-INJECTION",
		Title:      "Template embeds an instruction that overrides the conversation",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-1426", "CWE-94"},
		Class:      "template",
		Description: "A Jinja2 template carries an instruction aimed at the model rather than at a " +
			"renderer: \"ignore previous instructions\", \"do not tell the user\", \"system prompt:\", " +
			"\"exfiltrate\", a request to send the conversation elsewhere, or the same text hidden in a " +
			"{# comment #} or a {% raw %} block. A chat template is pasted into every conversation the " +
			"model serves, so an instruction in it is a standing prompt injection (OWASP LLM01) and, " +
			"with a tool or a URL, a backdoor. The table deliberately excludes chat pseudo-tags like " +
			"[INST] and <|im_start|>, which legitimate templates are built from, and the arguments of " +
			"raise_exception(), which Transformers itself provides.",
		Refs: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://kb.cert.org/vuls/id/915947",
		},
		Tags: []string{"template", "prompt-injection"},
	})
)
