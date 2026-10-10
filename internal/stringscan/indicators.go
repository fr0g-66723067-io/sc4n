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
	pickle.BytesScan = Emit
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
	// KindTemplate applies every rule except the instruction/pseudo-tag
	// indicator. A chat template is a program that emits text: `<|im_start|>` is
	// the delimiter it exists to emit, and "do not tell the user about function
	// calls" is a tool-use instruction. Judging that phrasing is the job of the
	// template analyser (SC4N-TEMPLATE-INJECTION, SC4N-JINJA-*), which knows it
	// is reading a template; the generic metadata rule cannot tell either apart
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
var ruleTiers = map[*report.Rule]tier{
	ruleC2:          tierSecret,
	ruleRawIPURL:    tierSecret,
	ruleCredential:  tierSecret,
	ruleSecretValue: tierSecret,
}

func tierOf(r *report.Rule) tier {
	if t, ok := ruleTiers[r]; ok {
		return t
	}
	return tierShape
}

// allows reports whether a hit is in scope for the kind.
func (k Kind) allows(r *report.Rule) bool {
	switch k {
	case KindSecrets:
		return tierOf(r) == tierSecret
	case KindTemplate:
		return r != ruleInjection
	default:
		return true
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
		if k.allows(h.Rule) {
			emit(sink, base, h)
		}
	}
}

// EmitStringKind is EmitKind for a string.
func EmitStringKind(sink *report.Sink, base int64, s string, k Kind) {
	for _, h := range ScanString(s) {
		if k.allows(h.Rule) {
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
		ev = "indicator " + strconv.Quote(truncate(h.Match, 120)) + " in a data string"
	}
	if h.Redacted {
		sink.EmitRedacted(h.Rule, base+h.Off, "a value that matches the "+h.Rule.Title+" shape is present and has been masked", h.Extra)
		return
	}
	sink.EmitExtra(h.Rule, base+h.Off, ev, h.Extra)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
}

func buildIndicatorTable() []indicator {
	var out []indicator
	add := func(rule *report.Rule, kind string, redact bool, literals ...string) {
		for _, l := range literals {
			out = append(out, indicator{literal: l, rule: rule, kind: kind, redact: redact})
		}
	}

	// Command-and-control and exfiltration endpoints. These are the URLs a payload
	// actually posts to; a model artifact has no business containing one.
	add(ruleC2, "c2-webhook", false,
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

	// Credential material and the paths that hold it.
	add(ruleCredential, "credential-path", false,
		"~/.ssh", "/.ssh/id_rsa", "/.ssh/id_ed25519", "id_rsa", "id_ed25519",
		"authorized_keys", "known_hosts", "~/.aws", "/.aws/credentials",
		"~/.cache/huggingface/token", "/.cache/huggingface/token",
		"/etc/shadow", "/etc/passwd", "/proc/self/environ", "/proc/self/mem",
		".netrc", ".git-credentials", ".docker/config.json", ".kube/config",
		".npmrc", ".pypirc", "wallet.dat", "login.keychain", "credentials.json",
		"service-account.json", "macaroons", "cookies.sqlite",
	)
	add(ruleCredential, "credential-env", false,
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
		"SLACK_TOKEN", "DOCKER_AUTH", "KUBECONFIG", "NPM_TOKEN", "PYPI_TOKEN",
	)

	// A literal `NAME=` followed by a value is the shape a hard-coded secret takes.
	// These are the redacting indicators: the match itself is secret material.
	add(ruleSecretValue, "secret-assignment", true,
		"AWS_SECRET_ACCESS_KEY=", "AWS_ACCESS_KEY_ID=", "GITHUB_TOKEN=",
		"OPENAI_API_KEY=", "ANTHROPIC_API_KEY=", "HF_TOKEN=",
		"SLACK_TOKEN=", "NPM_TOKEN=", "PYPI_TOKEN=", "PRIVATE KEY-----",
	)

	// Shell and process payloads.
	add(ruleShell, "shell-payload", false,
		"bash -i", "sh -i", "/bin/sh -c", "/bin/bash -c", "bash -c",
		"| sh", "|sh", "| bash", "|bash", "curl | sh", "wget -qO-",
		"nc -e", "ncat -e", "socat exec:", "/dev/tcp/", "mkfifo",
		"powershell -e", "powershell -enc", "cmd.exe /c", "certutil -urlcache",
		"chmod +x", "base64 -d", "base64 --decode", "whoami", "reverse shell",
		"python -c", "perl -e", "ruby -e",
	)

	// Decoder calls: a data string that names one is a step in an obfuscation
	// chain, which is what the pickle and metadata contexts make interesting.
	add(ruleDecoder, "decoder", false,
		"b64decode", "b85decode", "a85decode", "unhexlify", "fromhex",
		"codecs.decode", "zlib.decompress", "gzip.decompress", "bz2.decompress",
		"lzma.decompress", "marshal.loads", "compile(", "exec(", "eval(",
		"__import__", "subprocess.Popen", "os.system", "os.popen",
		"pickle.load", "dill.loads", "cloudpickle.loads",
	)

	// Loader flags that turn a data file into a code-loading path.
	add(ruleLoaderFlag, "loader-flag", false,
		"trust_remote_code", "allow_pickle=true", "allow_pickle=True",
		"weights_only=false", "weights_only=False", "safe_mode=false",
		"yaml.unsafe_load", "yaml.load(", "auto_map", "load_in_8bit",
	)

	// Prompt-injection phrasing. The literals are the ones that appear in the
	// published model-card and dataset-card attacks; the phrasing is short enough
	// that a false positive is possible in a document *about* prompt injection,
	// which is why the rule is medium and says so.
	add(ruleInjection, "injection-phrase", false,
		"ignore previous instructions", "ignore all previous instructions",
		"ignore the previous instructions", "disregard previous instructions",
		"disregard all previous", "do not tell the user", "don't tell the user",
		"do not inform the user", "do not mention this", "never mention this",
		"you must not reveal", "do not reveal this", "without telling the user",
		"override your instructions", "ignore your instructions",
		"new instructions:", "system prompt:", "exfiltrate",
	)
	add(ruleInjection, "injection-tag", false,
		"[INST]", "[/INST]", "<|im_start|>", "<|im_end|>", "<|system|>",
		"<|user|>", "<|assistant|>", "<system>", "</system>", "### Instruction:",
		"### System:", "### Human:", "ACT AS IF", "act as if",
	)

	// Code-execution keywords inside metadata values, which is the tensorguard
	// TG06-TG10 shape.
	add(ruleMetadataCode, "metadata-code", false,
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
