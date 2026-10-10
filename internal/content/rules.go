// Package content routes the text-ish files of a model repository to the right
// library and owns the Hugging Face metadata rules.
//
// A repository is mostly metadata: config.json, tokenizer.json, adapter_config.json,
// modules.json, README.md, chat_template.jinja, .gitattributes. Each of those
// files is a different attack surface, and every one of them is a *text* file, so
// the format dispatch in internal/artifact classifies them all as JSON, Markdown,
// Jinja or plain text. This package is the layer that turns "a text artifact" into
// "run the card detector", "run the tokenizer regex analyser", "run the Jinja2
// analyser" or "run the HF metadata rules", using the artifact's own name to
// decide. Without it a .md, .json or .jinja fixture is read by nothing and the
// scanner reports the repository as clean.
//
// Every rule here is a *named* trigger documented in its own description: the
// point of SC4N-CONFIG-AUTO-MAP existing as a rule rather than a silent branch is
// that `sc4n rules` lists it and `sc4n scan -format sarif` carries its help text.
package content

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// define registers r unless its ID already exists, in which case the existing
// rule is returned. The rule IDs above are shared contract; another package may
// legitimately define one first (the tree loads packages in init order), and
// DefineRule panics on a duplicate, so this is the safe form the plan asks for.
func define(r report.Rule) *report.Rule {
	if existing, ok := report.RuleByID(r.ID); ok {
		return existing
	}
	return report.DefineRule(r)
}

var (
	// ruleAutoMap is critical: an auto_map entry is a class name that the loader
	// imports and executes with the user's privileges when trust_remote_code is
	// set (or, in older Transformers, by default for some code paths). It is the
	// standard delivery mechanism for a malicious repo, and it is exactly why
	// transformers added the trust_remote_code gate (VU#456290, CVE-2026-4372).
	ruleAutoMap = define(report.Rule{
		ID:         "SC4N-CONFIG-AUTO-MAP",
		Title:      "config.json selects a local module to import and execute",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-94"},
		Class:      "config",
		Description: "A Hugging Face config carries an `auto_map`, which maps an Auto* class " +
			"(AutoConfig, AutoModel, AutoTokenizer, …) to a Python module and class name inside the " +
			"repository. With trust_remote_code enabled the loader imports that module and executes " +
			"it, so the model file itself is code. The finding names each referenced module and states " +
			"whether sc4n found the matching .py file in the scanned tree (a local module is code that " +
			"will run; a module that is absent still fails the same way at load time). This is the " +
			"VU#456290 / CVE-2026-4372 surface. Critical because an auto_map is code execution on the " +
			"artifact's normal load path.",
		Refs: []string{
			"https://huggingface.co/docs/transformers/main/en/main_classes/model#models-hosted-on-the-hub",
			"https://kb.cert.org/vuls/id/456290",
			"https://nvd.nist.gov/vuln/detail/CVE-2026-4372",
		},
		Tags: []string{"config", "remote-code", "code-execution"},
	})

	// ruleUnknownArchitecture is informational: a name outside the Transformers
	// set is a reason to check which library the repo expects, not a finding on
	// its own.
	ruleUnknownArchitecture = define(report.Rule{
		ID:         "SC4N-CONFIG-ARCHITECTURE-UNKNOWN",
		Title:      "config.json names an architecture outside the known Transformers set",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-1357"},
		Class:      "config",
		Description: "A `config.json` `architectures` entry is not one of the model classes Transformers " +
			"ships. That is frequently an ordinary custom or brand-new architecture, but a class name " +
			"the local library does not know is also what routes loading through a repository-provided " +
			"module (see SC4N-CONFIG-AUTO-MAP). Informational: the name is recorded so a reviewer can " +
			"check whether it resolves to a library the user already has.",
		Refs: []string{"https://huggingface.co/docs/transformers/main/en/main_classes/model"},
		Tags: []string{"config", "provenance"},
	})

	// ruleTrustRemoteCode is high: it is the explicit switch that turns every
	// other remote-code surface (auto_map) on, and it is almost never needed for
	// a checkpoint the user already has the library for.
	ruleTrustRemoteCode = define(report.Rule{
		ID:         "SC4N-CONFIG-TRUST-REMOTE-CODE",
		Title:      "config.json enables trust_remote_code",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-94"},
		Class:      "config",
		Description: "A Hugging Face config sets `trust_remote_code` to a truthful value. That flag is " +
			"an explicit instruction to the loader to import and execute Python from the repository " +
			"(the `auto_map` modules, custom tokenizers, custom configuration classes), so setting it " +
			"is a decision to run untrusted code. High rather than critical because the flag alone only " +
			"permits code execution; it needs a co-located module to actually run, and sc4n reports the " +
			"`auto_map` separately with SC4N-CONFIG-AUTO-MAP.",
		Refs: []string{
			"https://huggingface.co/docs/transformers/main/en/security",
			"https://kb.cert.org/vuls/id/456290",
		},
		Tags: []string{"config", "remote-code", "code-execution"},
	})

	// ruleConfigChatTemplate is informational: it records that a config carried
	// a chat_template and that every entry of it was routed to the Jinja2
	// analyser. It is the proof, in the report, that a list-shaped template was
	// fully walked rather than only its first entry.
	ruleConfigChatTemplate = define(report.Rule{
		ID:         "SC4N-CONFIG-CHAT-TEMPLATE",
		Title:      "config carries a chat template, which the Jinja2 rules analysed",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1336"},
		Class:      "config",
		Description: "A config.json or tokenizer_config.json carries a `chat_template`. The field may be " +
			"a single string, a list of {name, template} objects, or an object keyed by name; sc4n " +
			"extracts every entry and hands each one to the Jinja2 analyser (SC4N-JINJA-* and " +
			"SC4N-TEMPLATE-INJECTION), because a scanner that reads only the first list entry misses a " +
			"malicious second one. Informational: it exists so the report shows how many templates were " +
			"seen and under which names. The template itself is the attack surface for chat-template " +
			"SSTI (CVE-2026-5760 / CERT VU#915947).",
		Refs: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2026-5760",
			"https://kb.cert.org/vuls/id/915947",
		},
		Tags: []string{"config", "template", "ssti"},
	})

	// ruleAdapterExternalBase is high: an adapter repo that resolves its base
	// model to another hub repository makes the user fetch and load a second,
	// separately-reviewed-as-unknown artifact.
	ruleAdapterExternalBase = define(report.Rule{
		ID:         "SC4N-ADAPTER-EXTERNAL-BASE",
		Title:      "PEFT adapter resolves its base model to another repository",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-829"},
		Class:      "adapter",
		Description: "A PEFT `adapter_config.json` sets `base_model_name_or_path` to a value that does " +
			"not resolve to a directory in the scanned tree — a Hub repository id or a URL. Loading " +
			"the adapter therefore downloads and loads a *second* artifact whose contents are not in " +
			"this scan, so an adapter that looks benign can pull in a base model the user never " +
			"reviewed. High because the indirection is the point: the scan's verdict is incomplete " +
			"without the referenced repository, and the name is the only thing sc4n can check.",
		Refs: []string{
			"https://huggingface.co/docs/peft/main/en/package_reference/config",
			"https://huggingface.co/docs/hub/security",
		},
		Tags: []string{"adapter", "supply-chain", "provenance"},
	})

	// ruleModulesRemoteModule is medium/low: a sentence-transformers modules.json
	// routinely names a remote base model (an empty path means "fetch from the
	// hub"), so the finding records the remote stack rather than asserting
	// malice.
	ruleModulesRemoteModule = define(report.Rule{
		ID:         "SC4N-MODULES-REMOTE-MODULE",
		Title:      "sentence-transformers modules.json reconstructs a remote module stack",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-829"},
		Class:      "modules",
		Description: "A sentence-transformers `modules.json` has an entry whose `path` is empty or names " +
			"an external repository, so loading the model fetches a module from the Hub and composes " +
			"it with the local ones. An empty path for the Transformer module is ordinary and appears " +
			"in most published sentence-transformers repositories, which is why the severity is medium " +
			"and the confidence low: the finding's value is that it tells a reviewer the scan does not " +
			"cover the whole load path, and names which module type is remote.",
		Refs: []string{
			"https://sbert.net/docs/package_reference/sentence_transformer/models.html",
			"https://huggingface.co/docs/hub/security",
		},
		Tags: []string{"modules", "supply-chain", "provenance"},
	})

	// ruleGitattributesLFS is medium: a filter=lfs line means the real blob
	// lives in LFS and the file on disk is a pointer, so sc4n did not read the
	// bytes it appears to be scanning.
	ruleGitattributesLFS = define(report.Rule{
		ID:         "SC4N-GITATTRIBUTES-LFS",
		Title:      ".gitattributes routes files through Git LFS",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-829"},
		Class:      "gitattributes",
		Description: "A `.gitattributes` line assigns `filter=lfs` to a path pattern. Every matching " +
			"file is then a small LFS *pointer* in the working tree, and the real content is fetched " +
			"from the LFS server at checkout with no scanning by sc4n. Medium: it does not make an " +
			"artifact malicious, but it is the reason a scan of a checkout can report a clean, tiny " +
			"file that is not the artifact the loader will use. A repository whose weights are LFS " +
			"pointers must be scanned from a fully materialised checkout or from the Hub blobs.",
		Refs: []string{"https://git-lfs.com/", "https://huggingface.co/docs/hub/security"},
		Tags: []string{"gitattributes", "lfs", "provenance"},
	})

	// ruleGitattributesFilter is high: a non-LFS clean/smudge filter or a custom
	// diff driver names an external command that Git runs on checkout or diff,
	// i.e. command execution driven by a file inside the artifact.
	ruleGitattributesFilter = define(report.Rule{
		ID:         "SC4N-GITATTRIBUTES-FILTER",
		Title:      ".gitattributes names a non-LFS filter or diff driver",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-78", "CWE-829"},
		Class:      "gitattributes",
		Description: "A `.gitattributes` line assigns `filter=<driver>` or `diff=<driver>` for a driver " +
			"other than LFS. A filter driver is configured in Git config with `clean`/`smudge` " +
			"commands that Git executes when the file is checked out or staged, and a diff driver can " +
			"name a `textconv` command executed on diff; the `.gitattributes` file only names the " +
			"driver, so the command lives in the (attacker-influenced) local Git configuration. High " +
			"because naming an unknown driver in a model repository is a request to run a program when " +
			"the repository is cloned or diffed, and the known built-in diff drivers are allowlisted " +
			"to keep syntax-highlighting conventions from firing the rule.",
		Refs: []string{
			"https://git-scm.com/docs/gitattributes",
			"https://git-scm.com/docs/git-config#Documentation/git-config.txt-filterltdrivergtsmudge",
		},
		Tags: []string{"gitattributes", "command-execution"},
	})
)
