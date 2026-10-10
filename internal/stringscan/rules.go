package stringscan

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The shared indicator rules.
//
// Every one of these is about a *data string*: a metadata value, a tensor name, a
// tokenizer entry, a chat template, a card, a reconstructed pickle constant. None
// of them proves intent on its own — a README may legitimately discuss webhooks —
// which is why they are calibrated at medium and high rather than critical, and
// why the evidence names the exact literal that matched.

var (
	ruleC2 = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-C2",
		Title:      "Data string names a command-and-control or exfiltration endpoint",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "content",
		Description: "A string in the artifact contains a webhook, paste, tunnel or overlay endpoint: " +
			"discord.com/api/webhooks, api.telegram.org, hooks.slack.com, webhook.site, requestbin, " +
			"pipedream, canarytokens, interact.sh and the other oast domains, transfer.sh, ngrok, " +
			"trycloudflare, serveo, or a .onion address. These are how a payload that runs inside a loader " +
			"gets its instructions or sends what it found out. The indicator is a literal match, so a " +
			"document that *discusses* webhook abuse trips it too; read the offset before concluding.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/506.html",
			"https://attack.mitre.org/techniques/T1071/001/",
		},
		Tags: []string{"exfiltration", "c2"},
	})

	ruleCredential = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-CREDENTIAL",
		Title:      "Data string names credential material or a credential path",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-522", "CWE-200"},
		Class:      "content",
		Description: "A string in the artifact references a credential store or *reads* a credential " +
			"from the environment: ~/.ssh and id_rsa, ~/.aws/credentials, the Hugging Face token cache, " +
			"/etc/shadow, /proc/self/environ, .netrc, .git-credentials, .docker/config.json, " +
			".kube/config, wallet.dat, service-account.json, or a shell/batch expansion or environment " +
			"lookup of AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, HF_TOKEN and their relatives. A model " +
			"artifact has no functional reason to reach for any of these. The bare *name* of a credential " +
			"environment variable is deliberately not an indicator: a tool schema or a deployment note " +
			"naming GITHUB_TOKEN is describing which variables exist, not reading one.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/522.html"},
		Tags: []string{"credential-access"},
	})

	ruleSecretValue = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-SECRET-VALUE",
		Title:      "Data string contains what looks like a hard-coded secret",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-798", "CWE-540"},
		Class:      "content",
		Description: "A string in the artifact assigns a value to a credential variable " +
			"(AWS_SECRET_ACCESS_KEY=, GITHUB_TOKEN=, OPENAI_API_KEY=, HF_TOKEN=, …) or contains a PEM " +
			"private-key header. The matched value is masked: the finding records that a secret-shaped " +
			"string is present and where, without reproducing it into a log, a SARIF upload or a baseline " +
			"file. Note the direction of the risk this does not cover: a secret committed by an honest " +
			"author is a leak, while a secret read by a malicious one is exfiltration, and this rule " +
			"cannot tell them apart.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/798.html"},
		Tags: []string{"secret"},
	})

	ruleShell = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-SHELL",
		Title:      "Data string contains a shell or process payload",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-78"},
		Class:      "content",
		Description: "A string in the artifact contains a shell payload fragment: an interactive shell " +
			"(bash -i, /bin/sh -c), a pipe into an interpreter (| sh, curl | sh, base64 -d | sh), a " +
			"reverse shell (nc -e, /dev/tcp/, socat exec:), a PowerShell or cmd encoder invocation, or a " +
			"download-and-run chain. Inside a model or its metadata there is no benign reason for one.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/78.html"},
		Tags: []string{"execution"},
	})

	ruleDecoder = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-DECODER",
		Title:      "Data string names a decoder or a second-stage loader",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "content",
		Description: "A string in the artifact names a decoding or second-stage-loading call: base64 and " +
			"hex decoders, the compression decompressors, marshal.loads, compile/exec/eval, __import__, " +
			"os.system, subprocess.Popen, or a second pickle/dill/cloudpickle load. Any one of these in a " +
			"metadata value is an obfuscation or second-stage indicator; the combination of a long opaque " +
			"literal and a decoder in the same string is what SC4N-STRING-OBFUSCATION reports.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"obfuscation"},
	})

	ruleLoaderFlag = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-LOADER-FLAG",
		Title:      "Data string sets a flag that turns off a loader's safety",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "content",
		Description: "A string in the artifact contains trust_remote_code, allow_pickle=True, " +
			"weights_only=False, safe_mode=False, yaml.unsafe_load, or an auto_map reference. Each of " +
			"these is a documented way to make a loader execute code that the artifact supplies, and a " +
			"model card or config that carries one is telling the user to disable the check that would " +
			"have stopped it.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://huggingface.co/docs/hub/security",
		},
		Tags: []string{"misconfiguration"},
	})

	ruleInjection = report.DefineRule(report.Rule{
		ID:         "SC4N-METADATA-INJECTION",
		Title:      "Data string contains prompt-injection phrasing or a chat pseudo-tag",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-1426"},
		Class:      "metadata",
		Description: "A string in the artifact contains instruction-like text aimed at a model rather than " +
			"at a reader: \"ignore previous instructions\", \"do not tell the user\", " +
			"\"override your instructions\", an exfiltration instruction, or a chat pseudo-tag " +
			"([INST], <|im_start|>, <system>, ### Instruction:). Model cards, dataset cards and metadata " +
			"are read by agents and are pasted into prompts, so text in them is an input channel into " +
			"whatever consumes the artifact (OWASP LLM01). The rule is medium because a document that " +
			"quotes an injection, or a legitimate chat template, contains the same literals.",
		Refs: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/1426.html",
		},
		Tags: []string{"prompt-injection"},
	})

	ruleMetadataCode = report.DefineRule(report.Rule{
		ID:         "SC4N-METADATA-CODE",
		Title:      "Metadata value contains code-execution keywords",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-94", "CWE-506"},
		Class:      "metadata",
		Description: "A metadata value — a tensor name, a __metadata__ entry, a GGUF key, an ONNX " +
			"doc_string or a config field — contains code-execution keywords: os.system, subprocess, " +
			"__import__, exec, eval, pickle.load, marshal.loads, socket.socket, urllib.request, " +
			"requests.post or a base64 decode. Metadata is read (and sometimes printed, templated or " +
			"executed) by tooling, so a value that is source code is a different kind of object than the " +
			"field it occupies claims to be.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
		Tags: []string{"metadata"},
	})

	ruleObfuscation = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-OBFUSCATION",
		Title:      "Data string hides a long opaque literal beside a decoder",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "content",
		Description: "A string in the artifact contains a long base64 or hexadecimal literal (at least 48 " +
			"characters) and, in the same string or an adjacent one, a decoder call. The combination is " +
			"the standard way to carry a second-stage payload past a scanner that looks for readable " +
			"commands: the literal alone is ordinary data, and the decoder alone is ordinary library " +
			"usage. The rule reports the literal's length and offset, not its contents.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"obfuscation"},
	})

	ruleRawIPURL = report.DefineRule(report.Rule{
		ID:         "SC4N-STRING-RAW-IP-URL",
		Title:      "Data string contains a URL with a raw IP address",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "content",
		Description: "A string in the artifact contains an http/https URL whose host is a literal IP " +
			"address rather than a name (http://192.0.2.10:8080/payload). Legitimate model metadata " +
			"points at named hosts: a raw IP in a data file means either an ad-hoc server or an attempt " +
			"to bypass name-based blocking, and it is one of the few endpoint shapes a domain " +
			"denylist cannot cover.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"exfiltration"},
	})

	ruleUnicode = report.DefineRule(report.Rule{
		ID:         "SC4N-UNICODE-ANOMALY",
		Title:      "Text contains zero-width, bidi-control or homoglyph characters",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1007", "CWE-838"},
		Class:      "content",
		Description: "A string in the artifact contains characters that are invisible or that reverse text " +
			"order: zero-width space/joiner/non-joiner, the bidi control set, or a homoglyph mix of " +
			"scripts in one identifier. These are how a card hides an instruction from a reader while a " +
			"tokeniser still sees it, and how an identifier is made to look like an allowlisted one. " +
			"Confidence is high because the characters are unambiguous; the severity is medium because " +
			"the intent is not.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/1007.html",
			"https://trojansource.codes/",
		},
		Tags: []string{"unicode"},
	})
)
