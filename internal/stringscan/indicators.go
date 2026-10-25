// Package stringscan is the shared indicator engine: one Aho–Corasick automaton
// over a table of literals, applied to every string any parser materialises.
//
// It exists because the alternative does not scale and does not stay consistent.
// Running N patterns as N scans over a byte buffer costs N passes over every
// artifact, and letting each format define its own "looks malicious" strings means
// a webhook URL is reported for a GGUF but not for a safetensors file. One
// automaton, one table, one set of rules, one pass.
//
// The engine is deliberately literal-based: no regular expressions on the hot
// path (the structural checks that do need them are separate and use RE2), and no
// allocation proportional to the input. Case folding is folded into the automaton
// rather than done by lowercasing a copy of the buffer, because copying a
// multi-gigabyte artifact to make it lowercase is exactly the kind of "helpful"
// step that turns a scan into an OOM.
package stringscan

import (
	"sort"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/pickle"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func init() {
	// The pickle engine reconstructs str/bytes constants and hands them here, so
	// that a payload hidden in a pickle string is reported by the same rules that
	// report it in a metadata value. The dependency runs one way: stringscan knows
	// about pickle's hook, and pickle knows nothing about this package.
	pickle.StringScan = EmitString
	pickle.BytesScan = emitBytes
	pickle.StringUse = EmitUse
}

// Hit is one indicator match.
type Hit struct {
	Rule *report.Rule
	// Off is the byte offset of the match inside the scanned buffer.
	Off int64
	// Match is the matched literal (preserving the input's case) or, for a
	// synthetic match such as a raw-IP URL, a short window around it.
	Match string
	// Redacted marks a match that contains a secret value.
	Redacted bool
	// Extra carries machine-readable context (the indicator kind, a length).
	Extra map[string]string
	// codeOnly marks a hit that is a word rather than a use and is kept only when
	// the buffer also names a decoder or second-stage callable. It is internal:
	// callers see the filtered result.
	codeOnly bool
}

// Kind selects which of the shared indicator rules apply to a buffer.
//
// The engine is context-free by construction — one automaton, one table — but its
// rules are calibrated for *prose that a model reads*: a metadata value, a config
// string, a model card, source code. Applied to a symbol table, a tokenizer
// vocabulary or a flatbuffer segment, the shape rules match ordinary data, and
// the scanner reports a benign file as hostile. The tier is how a caller says
// which context it is in without the engine having to guess.
type Kind uint8

const (
	// KindText applies every rule. It is the default, and it is right for
	// metadata values, config, source code and cards.
	KindText Kind = iota
	// KindSecrets applies only the rules that are about a *reachable* secret or
	// endpoint: C2/webhook URLs, raw-IP URLs, credentials and secret values. It
	// is what a region that is not prose gets — a symbol table, a tokenizer
	// vocabulary, a flatbuffer segment — where a shell fragment or a decoder name
	// is just a string in a table.
	KindSecrets
	// KindTemplate applies every rule except the injection-phrase indicator. A
	// chat template is a program that emits text, and "do not tell the user about
	// function calls" is a tool-use instruction. Judging that phrasing is the job
	// of the template analyser (SC4N-TEMPLATE-INJECTION, SC4N-JINJA-*), which
	// knows it is reading a template; the generic metadata rule cannot tell it
	// from an injection, and reporting both is a duplicate with a worse verdict.
	KindTemplate
)

// tier is which family a rule belongs to, for the Kind filter.
type tier uint8

const (
	// tierShape is a shape that is only interesting in prose.
	tierShape tier = iota
	// tierSecret is a reachable secret or endpoint.
	tierSecret
)

// ruleTiers names the rules that survive every Kind. Everything else is a shape.
//
// The Unicode-anomaly rule is deliberately not here: a tokenizer vocabulary or a
// symbol table is a KindSecrets region, and such a table legitimately contains
// zero-width and private-use characters as *data* (64 of llama.cpp's 19 GGUF
// vocabularies do). A text artifact that is not valid UTF-8 still gets the pass
// through EmitUnicodeAnomalies, which is where the byte-safe tier needs it.
var ruleTiers = map[*report.Rule]tier{
	ruleC2:          tierSecret,
	ruleRawIPURL:    tierSecret,
	ruleCredential:  tierSecret,
	ruleSecretValue: tierSecret,
	ruleEICAR:       tierSecret,
}

func tierOf(r *report.Rule) tier {
	if t, ok := ruleTiers[r]; ok {
		return t
	}
	return tierShape
}

// allows reports whether a hit is in scope for the kind.
//
// It takes the hit rather than the rule because a rule can carry more than one
// indicator family; the filter is on the family, which is already on the hit
// (`Extra["kind"]`).
func (k Kind) allows(h Hit) bool {
	switch k {
	case KindSecrets:
		return tierOf(h.Rule) == tierSecret
	case KindTemplate:
		return h.Rule != ruleInjection
	default:
		return true
	}
}

// emitBytes runs the byte-safe tier over a bytes constant. The pickle engine
// reaches it only for a constant it has already judged binary (its own
// mostlyText test); reading such a buffer as prose manufactures findings out of a
// tensor's mantissas and out of a pickled multilingual label list. The tier keeps
// the literal table, the endpoint hunt, the credential and secret assignments and
// the EICAR marker, which are correct on any bytes.
func emitBytes(sink *report.Sink, base int64, b []byte) {
	EmitKind(sink, base, b, KindSecrets)
}

// EmitUnicodeAnomalies reports the invisible, order-changing and mixed-script hits
// in b. It is separate from EmitKind because that pass is byte-safe: it decodes
// runes and skips an invalid byte rather than standing down, so a caller holding a
// buffer it will not scan as text — a text artifact that is not valid UTF-8 — still
// runs this one.
func EmitUnicodeAnomalies(sink *report.Sink, base int64, b []byte) {
	for _, h := range scanUnicodeAnomalies(b, nil) {
		emit(sink, base, h)
	}
}

// Scan returns the indicator hits in b, ordered by offset and then rule ID so that
// the result is a total order for a given input.
func Scan(b []byte) []Hit { return scan(b) }

// ScanString is Scan for a string, without copying it.
func ScanString(s string) []Hit { return scan(unsafeBytes(s)) }

// Emit scans b and reports every hit through the sink at absolute offsets derived
// from base.
func Emit(sink *report.Sink, base int64, b []byte) { EmitKind(sink, base, b, KindText) }

// EmitString is Emit for a string.
func EmitString(sink *report.Sink, base int64, s string) {
	EmitStringKind(sink, base, s, KindText)
}

// EmitKind is Emit with an explicit context tier.
func EmitKind(sink *report.Sink, base int64, b []byte, k Kind) {
	for _, h := range Scan(b) {
		if k.allows(h) {
			emit(sink, base, h)
		}
	}
}

// EmitStringKind is EmitKind for a string.
func EmitStringKind(sink *report.Sink, base int64, s string, k Kind) {
	for _, h := range ScanString(s) {
		if k.allows(h) {
			emit(sink, base, h)
		}
	}
}

// HasSecretHit reports whether s contains a reachable secret or endpoint — the
// KindSecrets family: a C2/webhook URL, a raw-IP URL, a credential path or a
// secret assignment.
//
// It exists so a caller that has to decide *how strongly* to report something
// else (the template analyser, deciding between a directive and an ordinary
// tool-use sentence) can ask this table rather than keeping a second copy of it.
func HasSecretHit(s string) bool {
	for _, h := range ScanString(s) {
		if tierOf(h.Rule) == tierSecret {
			return true
		}
	}
	return false
}

func emit(sink *report.Sink, base int64, h Hit) {
	ev := h.Match
	if h.Rule.Class == "metadata" || h.Rule.Class == "content" {
		ev = "indicator " + strconv.Quote(report.TruncateEvidence(h.Match, 120)) + " in a data string"
		// A raw-IP URL carries the notation its host was written in ("0x7f000001"
		// is a hex integer, "2130706433" a decimal one). The URL is in the
		// evidence above, but reading it as an address needs the notation, so the
		// finding names it.
		if form := h.Extra["form"]; form != "" {
			ev += " (" + formPhrase(form) + " host)"
		}
	}
	if h.Redacted {
		sink.EmitRedacted(h.Rule, base+h.Off,
			"a value matching the "+h.Extra["shape"]+" shape is present and has been masked", h.Extra)
		return
	}
	sink.EmitExtra(h.Rule, base+h.Off, ev, h.Extra)
}

// formPhrase renders a host notation for evidence, with its article: the
// notations are "hex", "octal", "integer" and "dotted-decimal", so a plain
// concatenation produced "a octal host".
func formPhrase(form string) string {
	switch form {
	case "octal", "integer":
		return "an " + form
	}
	return "a " + form
}

// sortedHits orders hits deterministically.
//
// The insertion sort for short slices is not a micro-optimisation for its own sake:
// sort.SliceStable allocates a swapper, and a buffer with no indicators must cost
// no allocation at all (TestScanIntoCostsNothingWhenThereIsNothingToReport).
func sortedHits(hits []Hit) []Hit {
	if len(hits) < 2 {
		return hits
	}
	less := func(i, j int) bool {
		if hits[i].Off != hits[j].Off {
			return hits[i].Off < hits[j].Off
		}
		return hits[i].Rule.ID < hits[j].Rule.ID
	}
	if len(hits) < 16 {
		for i := 1; i < len(hits); i++ {
			for j := i; j > 0 && less(j, j-1); j-- {
				hits[j], hits[j-1] = hits[j-1], hits[j]
			}
		}
		return hits
	}
	sort.SliceStable(hits, less)
	return hits
}

// indicatorTable is the flat literal list the automaton is built from. Each entry
// names the rule it reports and the exact literal to look for.
//
// The table is data rather than code so that adding an indicator is a one-line
// change with a reviewable diff, and TestIndicatorsAreWellFormed checks every entry.
var indicatorTable = buildIndicatorTable()

type indicator struct {
	literal string
	rule    *report.Rule
	kind    string
	// redact marks an indicator whose match must not be reproduced.
	redact bool
	// codeOnly marks an indicator that is a word rather than a use: a
	// `chmod +x`, a `python -c`, a bare credential file name. It is reported only
	// when the same buffer also names a decoder or second-stage callable, which is
	// the decoder-chain context the fragment is diagnostic in. A README that
	// mentions the word, or an install document that shows a command, is not.
	codeOnly bool
}

func buildIndicatorTable() []indicator {
	var out []indicator
	add := func(rule *report.Rule, kind string, redact bool, literals ...string) {
		for _, l := range literals {
			out = append(out, indicator{literal: l, rule: rule, kind: kind, redact: redact})
		}
	}
	// addCode registers a literal that is a word rather than a use: reported only
	// when a decoder-chain context is present in the same buffer (see
	// dropUncorroborated). It is how the prose-shaped shell fragments and bare
	// credential names are kept out of ordinary documentation.
	addCode := func(rule *report.Rule, kind string, literals ...string) {
		for _, l := range literals {
			out = append(out, indicator{literal: l, rule: rule, kind: kind, codeOnly: true})
		}
	}

	// Command-and-control and exfiltration endpoints. These are the URLs a payload
	// actually posts to; a model artifact has no business containing one.
	add(
		ruleC2, "c2-webhook", false,
		"discord.com/api/webhooks", "discordapp.com/api/webhooks",
		"api.telegram.org", "hooks.slack.com", "slack.com/api/chat.postMessage",
		"webhook.site", "requestbin.net", "pipedream.net", "canarytokens.com",
		"interact.sh", "oast.fun", "oast.me", "burpcollaborator.net",
		"dnslog.cn", "ceye.io", "transfer.sh", "anonfiles.com", "0x0.st",
		"temp.sh", "gofile.io", "file.io", "ngrok-free.app", "ngrok.io",
		"trycloudflare.com", "serveo.net", "localhost.run", "termbin.com",
		"pastebin.com/raw", "ghostbin.co",
	)

	// Tor and other overlay endpoints. Reported separately from the webhook set
	// because a legitimate dataset description has no reason to name one either.
	add(ruleC2, "c2-overlay", false, ".onion", ".i2p", "onion.ws", "onion.pet", "onion.ly")

	// Credential material and the paths that hold it. A *path* is reported
	// wherever it appears: a directory component is the use. A bare file *name*
	// (id_rsa, known_hosts, credentials.json, …) is a word a document can mention
	// without reaching for it — a GCP guide names credentials.json, an SSH guide
	// names known_hosts — so it is code-only and needs the decoder-chain context.
	// The path-anchored forms still catch the real reach: ~/.ssh covers
	// ~/.ssh/id_rsa, ~/.ssh/known_hosts and ~/.ssh/authorized_keys.
	add(
		ruleCredential, "credential-path", false,
		"~/.ssh", "/.ssh/id_rsa", "/.ssh/id_ed25519", "~/.aws", "/.aws/credentials",
		"~/.cache/huggingface/token", "/.cache/huggingface/token",
		"/etc/shadow", "/etc/passwd", "/proc/self/environ", "/proc/self/mem",
		".netrc", ".git-credentials", ".docker/config.json", ".kube/config",
		".npmrc", ".pypirc",
	)
	addCode(
		ruleCredential, "credential-path",
		"id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
		"wallet.dat", "login.keychain", "credentials.json",
		"service-account.json", "macaroons", "cookies.sqlite",
	)
	// A credential environment variable is reported when it is *read*, not when it
	// is merely named. The name alone is what a tool schema, an agent prompt or a
	// deployment document contains: on llama.cpp's 71 real chat templates the only
	// high finding was "GITHUB_TOKEN" listed as a tool's parameter, which is the
	// template telling the model which variables exist. The shapes below all take
	// the value: a shell or batch expansion of the name, and an environment lookup
	// of it. A literal `NAME=value` is covered separately by
	// SC4N-STRING-SECRET-VALUE, which redacts the match.
	credentialEnv := []string{
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
		"SLACK_TOKEN", "DOCKER_AUTH", "KUBECONFIG", "NPM_TOKEN", "PYPI_TOKEN",
	}
	for _, n := range credentialEnv {
		add(
			ruleCredential, "credential-env-access", false,
			"$"+n, "${"+n+"}", "%"+n+"%",
			`environ["`+n+`"]`, "environ['"+n+"']",
			`environ.get("`+n+`")`, "environ.get('"+n+"')",
			// The default-argument idiom: os.environ.get("NAME", ""). The trailing
			// comma is part of the literal so that a longer name that merely starts
			// with a vendor name (GITHUB_TOKEN_EXTRA) does not match.
			`environ.get("`+n+`",`, "environ.get('"+n+"',",
			`getenv("`+n+`")`, "getenv('"+n+"')",
		)
	}

	// The EICAR self-test is a marker, not a shape: it is long enough and specific
	// enough that a false positive is not a realistic outcome. The literal is the
	// folded form (the automaton lowercases), and it is a raw string because the
	// real marker carries one backslash.
	add(
		ruleEICAR, "eicar-test-file", false,
		`x5o!p%@ap[4\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*`,
	)

	// A literal `NAME=` followed by a value is the shape a hard-coded secret takes.
	// These are the redacting indicators: the match itself is secret material.
	// The generic names at the end cover a hard-coded credential that is not one
	// of the vendor variables above — a JSON field, an INI line, a shell script
	// — and are the shape that carries `password=hunter2` or `client_secret=`.
	add(
		ruleSecretValue, "secret-assignment", true,
		"AWS_SECRET_ACCESS_KEY=", "AWS_ACCESS_KEY_ID=", "GITHUB_TOKEN=",
		"OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "HF_TOKEN=",
		"SLACK_TOKEN=", "NPM_TOKEN=", "PYPI_TOKEN=", "PRIVATE KEY-----",
		"password=", "passwd=", "secret=", "api_key=",
	)

	// Shell and process payloads. The chains carry their own context — `curl | sh`
	// and `wget -qO-` include the pipe — so they are reported wherever they
	// appear. The interpreter-invocation fragments below are words an install
	// document uses ("Run chmod +x run.sh"), so they are code-only: reported when
	// the same buffer also names a decoder or second-stage callable. The bare
	// `| sh` spellings are gone entirely: "| shape" in a Markdown table is not a
	// pipe into a shell, and the real chains above already carry the pipe.
	add(
		ruleShell, "shell-payload", false,
		"bash -i", "sh -i", "/bin/sh -c", "/bin/bash -c", "bash -c",
		"curl | sh", "wget -qO-",
		"nc -e", "ncat -e", "socat exec:", "/dev/tcp/",
		"powershell -e", "powershell -enc", "cmd.exe /c", "certutil -urlcache",
		"reverse shell",
	)
	addCode(
		ruleShell, "shell-payload",
		"mkfifo", "chmod +x", "base64 -d", "base64 --decode", "whoami",
		"python -c", "perl -e", "ruby -e",
	)

	// Decoder calls: a data string that names one is a step in an obfuscation
	// chain, which is what the pickle and metadata contexts make interesting.
	add(
		ruleDecoder, "decoder", false,
		"b64decode", "b85decode", "a85decode", "unhexlify", "fromhex",
		"codecs.decode", "zlib.decompress", "gzip.decompress", "bz2.decompress",
		"lzma.decompress", "marshal.loads", "compile(", "exec(", "eval(",
		"__import__", "subprocess.Popen", "os.system", "os.popen",
		"pickle.load", "dill.loads", "cloudpickle.loads",
	)

	// Loader flags that turn a data file into a code-loading path.
	add(
		ruleLoaderFlag, "loader-flag", false,
		"trust_remote_code", "allow_pickle=true", "allow_pickle=True",
		"weights_only=false", "weights_only=False", "safe_mode=false",
		"yaml.unsafe_load", "yaml.load(", "auto_map", "load_in_8bit",
	)

	// Prompt-injection phrasing. The literals are the ones that appear in the
	// published model-card and dataset-card attacks; the phrasing is short enough
	// that a false positive is possible in a document *about* prompt injection,
	// which is why the rule is medium and says so.
	add(
		ruleInjection, "injection-phrase", false,
		"ignore previous instructions", "ignore all previous instructions",
		"ignore the previous instructions", "disregard previous instructions",
		"disregard all previous", "do not tell the user", "don't tell the user",
		"do not inform the user", "do not mention this", "never mention this",
		"you must not reveal", "do not reveal this", "without telling the user",
		"override your instructions", "ignore your instructions",
		"new instructions:", "system prompt:", "exfiltrate",
		// The above-anaphora family: the instruction points at the text before
		// it instead of naming what it overrides, so these literals are what a
		// card gains when its body is prepended to another prompt. The shared
		// table and internal/cards carry the same phrases, so one card reports
		// both the metadata and the card verdict.
		"ignore the above", "ignore all previous", "disregard the above",
		"forget the above", "forget all previous",
		// A bare imperative with no object. It is phrasing, not a delimiter, so it
		// stays; the chat-format delimiters (`[INST]`, `<|im_start|>`,
		// `### Instruction:`) are deliberately absent: they are the syntax a chat
		// template emits, and a card that documents a template contains them
		// without asking a model to do anything. They were literals until round 7,
		// and 157 of the 172 SC4N-METADATA-INJECTION findings on the 273-model
		// campaign were exactly that — model cards documenting a template.
		"act as if",
	)

	// Code-execution keywords inside metadata values, which is the tensorguard
	// TG06-TG10 shape.
	add(
		ruleMetadataCode, "metadata-code", false,
		"os.system", "subprocess", "__import__", "exec(", "eval(",
		"trust_remote_code", "pickle.load", "marshal.loads", "socket.socket",
		"urllib.request", "requests.post", "base64.b64decode",
	)
	return out
}

// kindCount is a sanity assertion used by the tests: a table that shrank by
// accident is a detector that silently stopped working.
func kindCount() int { return len(indicatorTable) }

// rulesForKind returns the rules a kind can produce, for the tests.
func rulesForKind(kind string) []*report.Rule {
	seen := map[*report.Rule]bool{}
	var out []*report.Rule
	for _, ind := range indicatorTable {
		if ind.kind == kind && !seen[ind.rule] {
			seen[ind.rule] = true
			out = append(out, ind.rule)
		}
	}
	return out
}

// ruleIDsFor lists every rule the table can report, sorted.
func ruleIDsFor() []string {
	seen := map[string]bool{}
	for _, ind := range indicatorTable {
		seen[ind.rule.ID] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// titleContains is a test helper.
func titleContains(sub string) bool {
	for _, r := range report.Rules() {
		if strings.Contains(r.Title, sub) {
			return true
		}
	}
	return false
}
