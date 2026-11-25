package stringscan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// unsafeBytes views a string's bytes without copying. The result MUST NOT be
// written to: strings are immutable and the compiler may place this one in read-only
// memory. Every caller in this package only reads.
func unsafeBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// ScanInto is Scan with a caller-provided destination, so that a hot loop can
// reuse one slice and allocate nothing. It returns the slice to reuse; the caller
// owns it afterwards.
func ScanInto(b []byte, dst []Hit) []Hit {
	if len(b) == 0 {
		return dst[:0]
	}
	return scanInto(b, dst[:0])
}

// scan runs every detector over b and returns the ordered, deduplicated hits.
func scan(b []byte) []Hit {
	if len(b) == 0 {
		return nil
	}
	return scanInto(b, make([]Hit, 0, 4))
}

func scanInto(b []byte, hits []Hit) []Hit {
	hits = automaton.scanLiterals(b, hits)
	hits = dropUncomposedPipes(b, hits)
	hits = dropUncorroborated(hits)
	hits = dropPlaceholderAssignments(b, hits)
	hits = scanRawIPURLs(b, hits)
	hits = scanSecretTokens(b, hits)
	hits = scanJSONSecretProps(b, hits)
	hits = scanOpaqueLiterals(b, hits)
	hits = scanUnicodeAnomalies(b, hits)
	return dedupeRepeatedURLs(dedupe(sortedHits(hits)))
}

// downloadSources are the tokens that turn "| sh" from a table cell into a
// download-and-run. Each is a download *command* or a URL scheme, and the check
// requires it to sit before the pipe in the same buffer: a document that shows a
// URL in one sentence and a shell column in another does not compose into a
// payload, and a pipe that follows a download does.
// The sources are download *commands*, not URLs: the first attempt also accepted
// a bare http(s):// and turned a voice-name table (`| SH |` beside a model card's
// links) into ten high findings on the top25-downloads corpus. A URL is a
// reference; a command piped into an interpreter is a payload.
var downloadSources = [][]byte{
	[]byte("curl "), []byte("curl\t"), []byte("curl-"),
	[]byte("wget "), []byte("wget\t"), []byte("wget-"),
	[]byte("fetch "), []byte("busybox "), []byte("/dev/tcp/"),
}

// dropUncomposedPipes removes a pipe-to-interpreter hit whose buffer has no
// download source before it.
func dropUncomposedPipes(b []byte, hits []Hit) []Hit {
	out := hits[:0]
	for _, h := range hits {
		if h.Extra["kind"] == "pipe-to-shell" && !hasDownloadSource(b[:h.Off]) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// hasDownloadSource reports whether a download command precedes the pipe on the
// same logical shell line (honouring `\` line continuations and matching
// commands case-insensitively). The line bound is what keeps a card that shows
// a curl example in one paragraph and a shell table in another from composing
// into a payload.
func hasDownloadSource(prefix []byte) bool {
	start := len(prefix)
	for start > 0 {
		nl := bytes.LastIndexByte(prefix[:start], '\n')
		if nl < 0 {
			start = 0
			break
		}
		esc := nl - 1
		if esc >= 0 && prefix[esc] == '\r' {
			esc--
		}
		if esc >= 0 && prefix[esc] == '\\' {
			start = esc
			continue
		}
		start = nl + 1
		break
	}
	line := prefix[start:]
	for _, s := range downloadSources {
		if containsFold(line, s) {
			return true
		}
	}
	return false
}

// containsFold reports whether haystack contains needle (an already-lowercased
// ASCII slice) case-insensitively without allocating.
func containsFold(haystack, needle []byte) bool {
	nlen := len(needle)
	if nlen == 0 || len(haystack) < nlen {
		return false
	}
	first := needle[0]
	for i := 0; i <= len(haystack)-nlen; i++ {
		if lowerASCII(haystack[i]) != first {
			continue
		}
		match := true
		for j := 1; j < nlen; j++ {
			if lowerASCII(haystack[i+j]) != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// dropUncorroborated removes the hits that are words rather than uses unless the
// buffer carries their context.
//
// A `chmod +x` or a bare `id_rsa` is reported only when the same buffer also names
// a decoder or second-stage callable — the decoder-chain shape (`os.system`,
// `base64.b64decode`, `eval(`, …). That is the difference between an install
// document that shows a command and a payload that is about to run one. The
// decoder set is the same one the obfuscation pairing uses, so it is exactly the
// hit kind "decoder" already in the slice, which keeps the two features consistent
// by construction.
func dropUncorroborated(hits []Hit) []Hit {
	hasDecoder := false
	for i := range hits {
		if hits[i].Extra["kind"] == "decoder" {
			hasDecoder = true
			break
		}
	}
	if hasDecoder {
		return hits
	}
	out := hits[:0]
	for _, h := range hits {
		if h.codeOnly {
			continue
		}
		out = append(out, h)
	}
	return out
}

// scanIntoBody keeps the body of the old scan() separate so that ScanInto's
// zero-allocation promise is visible at the call sites: nothing in here allocates
// unless a detector found something.

// dedupe collapses hits that name the same rule at the same offset. Several
// literals belong to one rule and can end at the same offset (for example a
// fragment whose shorter spelling is a suffix of its longer one), and reporting
// the same rule twice at one offset is noise a reviewer has to filter by hand.
func dedupe(hits []Hit) []Hit {
	out := hits[:0]
	lastRule := ""
	lastOff := int64(-1)
	for _, h := range hits {
		if h.Rule.ID == lastRule && h.Off == lastOff {
			continue
		}
		lastRule, lastOff = h.Rule.ID, h.Off
		out = append(out, h)
	}
	return out
}

// dedupeRepeatedURLs keeps one raw-IP URL finding per distinct URL string in a
// buffer.
//
// The rule reports an address instead of a name, and the same address written
// twenty times is one decision to point at it: sglang's bundled flexkv card wrote
// `http://127.0.0.1:8000` in every usage snippet and produced the same medium
// finding repeatedly. A different notation of the same address is a different
// string and stays a separate finding, because the notation is what the evidence
// explains (0x7f000001 is not the same reading as 127.0.0.1 to a reviewer who has
// to check it).
func dedupeRepeatedURLs(hits []Hit) []Hit {
	seen := make(map[string]bool, 4)
	out := hits[:0]
	for _, h := range hits {
		if h.Rule == ruleRawIPURL {
			if seen[h.Match] {
				continue
			}
			seen[h.Match] = true
		}
		out = append(out, h)
	}
	return out
}

// scanRawIPURLs reports an http/https URL whose host is a literal IPv4 address.
func scanRawIPURLs(b []byte, hits []Hit) []Hit {
	// Two single-anchor memchr passes. One pass per case of the anchor byte keeps
	// the search linear: bytes.IndexByte stops at the next occurrence, so each pass
	// scans the buffer once no matter how many candidates it finds. (A single pass
	// that searched for both cases would rescan the tail for every 'h', which on
	// ordinary prose — where 'h' is about a tenth of the bytes — is quadratic.)
	hits = scanURLsAnchored(b, 'h', hits)
	hits = scanURLsAnchored(b, 'H', hits)
	return hits
}

func scanURLsAnchored(b []byte, anchor byte, hits []Hit) []Hit {
	i := 0
	for {
		j := bytes.IndexByte(b[i:], anchor)
		if j < 0 || i+j+8 >= len(b) {
			return hits
		}
		i += j
		rest := b[i:]
		var after int
		switch {
		case hasPrefixFold(rest, "http://"):
			after = 7
		case hasPrefixFold(rest, "https://"):
			after = 8
		default:
			i++
			continue
		}
		hostOffset := after
		host := rest[hostOffset:]
		// Skip URL userinfo (`user:pass@host`) within the authority component so
		// `http://user:pass@192.0.2.1/x` and `http://example.com@198.51.100.1/x`
		// inspect the actual host literal.
		authEnd := indexAny(host, "/?# \t\r\n\"'`,;)")
		if authEnd < 0 {
			authEnd = len(host)
		}
		if at := bytes.LastIndexByte(host[:authEnd], '@'); at >= 0 {
			hostOffset += at + 1
			host = rest[hostOffset:]
		}
		var hostEnd int
		bracket := len(host) > 0 && host[0] == '['
		if bracket {
			// A bracketed IPv6 literal: the host ends at ']', and the colons
			// inside it are not the delimiters the unbracketed scan looks for.
			close := bytes.IndexByte(host, ']')
			if close < 0 {
				i++
				continue
			}
			hostEnd = close + 1
		} else {
			hostEnd = indexAny(host, "/:?# \t\r\n\"'`,;)")
			if hostEnd < 0 {
				hostEnd = len(host)
			}
		}
		hostLit := host[:hostEnd]
		inner := hostLit
		if bracket {
			inner = hostLit[1 : len(hostLit)-1]
		}
		// A host literal is a bracketed IPv6 literal or one of the IPv4
		// notations; anything else is a name and no finding. Both checks must run
		// before anything is allocated, because this path runs once per URL
		// candidate in the buffer and the engine's cost contract is that a
		// candidate that is not a host costs nothing.
		var (
			form          string
			value         uint32
			documentation bool
		)
		if bracket {
			if !isIPv6Literal(inner) {
				i++
				continue
			}
			// RFC 3849 reserves the 2001:db8::/32 block for documentation, and
			// saying so in the evidence saves a reviewer the lookup.
			documentation = isDocumentationIPv6(inner)
		} else {
			ok := false
			form, value, ok = parseIPv4Literal(inner)
			if !ok {
				i++
				continue
			}
			// RFC 5737 reserves 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
			// The label is decided on the address the host resolves to, so a hex
			// or integer spelling of a documentation address is labelled too.
			documentation = isDocumentationIP(value)
		}
		extra := map[string]string{"kind": "raw-ip-url", "host": string(hostLit)}
		// The notation the host was written in is part of the finding: the URL
		// reads as a name unless the reader is told "0x7f000001" is a hex integer
		// and "2130706433" a decimal one.
		if form != "" {
			extra["form"] = form
		}
		if documentation {
			extra["reserved"] = "documentation"
		}
		hits = append(hits, Hit{
			Rule:  ruleRawIPURL,
			Off:   int64(i),
			Match: string(rest[:hostOffset+hostEnd]),
			Extra: extra,
		})
		i += hostOffset + hostEnd
	}
}

// isIPv6Literal reports whether b is the inside of a bracketed IPv6 literal: at
// least one colon and nothing but hex digits, colons, dots (an IPv4-mapped
// address) or a zone separator. It is deliberately a shape test rather than a full
// address parser: the rule's signal is "a URL whose host is a literal address",
// and refusing a technically invalid literal would only lose that signal.
func isIPv6Literal(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	colons := 0
	for i := range b {
		switch c := b[i]; {
		case c == ':':
			colons++
		case c == '.' || c == '%': // IPv4-mapped, zone id
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return colons > 0
}

// isDocumentationIPv6 reports whether a bracketed IPv6 literal is in the range
// reserved for documentation (2001:db8::/32, RFC 3849) or is the unspecified or
// loopback address, which is the IPv6 counterpart of isDocumentationIP's labels.
func isDocumentationIPv6(b []byte) bool {
	s := strings.ToLower(string(b))
	return strings.HasPrefix(s, "2001:db8:") || s == "2001:db8::" || s == "::1" || s == "::"
}

func hasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerASCII(b[i]) != prefix[i] {
			return false
		}
	}
	return true
}

func indexAny(b []byte, set string) int {
	for i := 0; i < len(b); i++ {
		for j := 0; j < len(set); j++ {
			if b[i] == set[j] {
				return i
			}
		}
	}
	return -1
}

// parseIPv4Literal reports whether b is an IPv4 literal in one of the notations
// a curl-class client resolves, and returns the notation and the address.
//
// The dotted quad of decimal octets is one spelling among six. inet_aton — and
// therefore curl, and anything else that accepts the numeric-host form — also
// reads hex octets ("0x7f.0.0.1"), octal octets written with a leading zero
// ("0177.0.0.1"), and a single 32-bit number in decimal ("2130706433"), octal
// ("017700000001") or hex ("0x7f000001"). Every one of them reaches the same
// host, and a detector that knows only the dotted-decimal spelling reads
// "http://0x7f000001/x" as a URL whose host is a name.
//
// The notation is returned rather than only a verdict because the finding has to
// say what it saw: "the host is 0x7f000001" is not something a reviewer can check
// without being told it is a hex integer.
//
// Each octet of a dotted form is bounded at 255 (the accumulation is bounded
// too, so "999.999.999.999" is not an address and reporting it as a raw-IP URL
// would be a finding a reviewer cannot act on), and a dotted form must have
// exactly four components: "http://1.2.3/" is a version path, not an address.
func parseIPv4Literal(b []byte) (form string, value uint32, ok bool) {
	if len(b) == 0 {
		return "", 0, false
	}
	if bytes.IndexByte(b, '.') < 0 {
		// A single number: the whole 32-bit address in one field.
		v, notation, ok := ipv4Number(b)
		if !ok {
			return "", 0, false
		}
		if notation == "decimal" {
			notation = "integer"
		}
		return notation, uint32(v), true
	}
	parts := 0
	form = "dotted-decimal"
	for {
		dot := bytes.IndexByte(b, '.')
		part := b
		if dot >= 0 {
			part = b[:dot]
		}
		v, notation, ok := ipv4Number(part)
		if !ok || v > 255 || parts == 4 {
			return "", 0, false
		}
		value = value<<8 | uint32(v)
		switch {
		case notation == "hex":
			form = "hex"
		case notation == "octal" && form == "dotted-decimal":
			form = "octal"
		}
		parts++
		if dot < 0 {
			break
		}
		b = b[dot+1:]
	}
	if parts != 4 {
		return "", 0, false
	}
	return form, value, true
}

// ipv4Number parses one field of an IPv4 literal: a decimal number, an octal
// one (a leading zero, which is how inet_aton and the C library read "0177") or
// a hexadecimal one ("0x7f"). It returns the value and the notation it was
// written in, so that the caller can name a host that is not plain decimal.
func ipv4Number(s []byte) (value uint64, notation string, ok bool) {
	if len(s) == 0 {
		return 0, "", false
	}
	notation, base, digits := "decimal", uint64(10), s
	switch {
	case len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'):
		notation, base, digits = "hex", 16, s[2:]
	case len(s) > 1 && s[0] == '0':
		notation, base, digits = "octal", 8, s[1:]
	}
	if len(digits) == 0 {
		return 0, "", false
	}
	var v uint64
	for _, c := range digits {
		d := hexValue(c)
		if d < 0 || uint64(d) >= base {
			return 0, "", false
		}
		v = v*base + uint64(d)
		if v > 0xFFFFFFFF {
			return 0, "", false
		}
	}
	return v, notation, true
}

// hexValue is the numeric value of a hex digit, or -1.
func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// isDocumentationIP reports whether the address is in a range reserved for
// documentation or for private use, where a scanner should say so rather than
// leave the reader wondering whether the target is real. It takes the parsed
// address rather than its spelling, so a documentation address written in hex or
// as a single integer is labelled the same way as the dotted quad.
func isDocumentationIP(v uint32) bool {
	switch v >> 24 {
	case 192:
		// 192.0.2.0/24 (TEST-NET-1) and 192.168.0.0/16 (private). The TEST-NET-1
		// match must name the third octet: 192.0.0.0/16 is ordinary address space
		// (192.0.5.7 is a real host), and labelling the whole of it "documentation"
		// is a label a reviewer uses to dismiss a finding.
		return v>>16&0xff == 0 && v>>8&0xff == 2 || v>>16&0xff == 168
	case 198:
		// 198.51.100.0/24 (TEST-NET-2).
		return v>>16&0xff == 51 && v>>8&0xff == 100
	case 203:
		// 203.0.113.0/24 (TEST-NET-3).
		return v>>16&0xff == 0 && v>>8&0xff == 113
	case 127, 10:
		return true
	case 172:
		second := v >> 16 & 0xff
		return second >= 16 && second <= 31
	}
	return false
}

// tokenAlphabet is the character class a vendor issues a token in.
type tokenAlphabet uint8

const (
	// alphaUpper is the AWS access-key class: uppercase letters and digits.
	alphaUpper tokenAlphabet = iota
	// alphaToken is the GitHub, OpenAI, Google and Slack class: letters,
	// digits, underscore and hyphen.
	alphaToken
	// alphaURL is the base64url class a JWT segment is drawn from.
	alphaURL
	// alphaAlnum is the Hugging Face class: letters and digits only. The vendor
	// issues no punctuation, and allowing an underscore would make every
	// hf_-prefixed Python identifier a candidate.
	alphaAlnum
)

func inAlphabet(c byte, a tokenAlphabet) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return a != alphaUpper
	case c == '-' || c == '_':
		return a == alphaToken || a == alphaURL
	}
	return false
}

// isTokenByte reports whether c is a byte of an opaque token, which is what the
// left boundary of a prefixed token must not be: "skill-base" contains "sk-",
// and "disk-1" does too.
func isTokenByte(c byte) bool {
	return inAlphabet(c, alphaToken)
}

// secretTokenShapes are the provider credential shapes the literal table cannot
// carry: a token whose own prefix announces the vendor, which is how a
// credential appears in a JSON document ("token":"ghp_…") and how one appears
// under a name the table does not list.
//
// Every prefix here is public — it is printed in the vendor's own documentation
// — and the run after it is the secret. Each shape is matched with a left
// boundary and a minimum run of the alphabet the vendor issues, because the bare
// prefixes are far too short and too common to be literals in the automaton:
// "sk-" occurs inside "risk-based", "task-", "disk-"; "AKIA", "ASIA" and "AIza"
// are letter runs of the word "Asia"; and every base64 blob of a JSON document
// begins with "eyJ".
//
// The prefix is a byte slice rather than a string because the scan runs
// bytes.Index over it: converting a string at every call allocated once per
// shape per buffer, which broke the engine's cost contract on a clean buffer.
var secretTokenShapes = []struct {
	prefix   []byte
	shape    string
	alphabet tokenAlphabet
	minRun   int
}{
	{[]byte("ghp_"), "ghp_", alphaToken, 20},
	{[]byte("github_pat_"), "github_pat_", alphaToken, 20},
	{[]byte("hf_"), "hf_", alphaAlnum, 30},
	{[]byte("sk-"), "sk-", alphaToken, 20},
	{[]byte("AKIA"), "AKIA", alphaUpper, 16},
	{[]byte("ASIA"), "ASIA", alphaUpper, 16},
	{[]byte("AIza"), "AIza", alphaToken, 30},
	{[]byte("xoxb-"), "xoxb-", alphaToken, 20},
}

// jwtPrefix is the first three characters of a JWT header: the base64 of "{" and
// the first byte of the first claim, which every JSON Web Token begins with.
const (
	jwtPrefix     = "eyJ"
	jwtSegmentMin = 8
)

var jwtPrefixBytes = []byte(jwtPrefix)

// scanSecretTokens reports the credential shapes that carry their own vendor
// prefix. A NAME= assignment is the shape SC4N-STRING-SECRET-VALUE has always
// covered; this is the value shape, which the name-based table cannot see.
//
// The hits are redacted exactly as an assignment is: the value never reaches the
// evidence, and the finding's `shape` extra names the prefix that matched.
// scanSecretTokens appends a hit for every provider token shape in b.
//
// The scan is one pass over the buffer that stops only at offsets where a shape
// could begin (a first-byte set), rather than one bytes.Index pass per shape: the
// per-shape version cost eight full traversals of every buffer scanned, which showed
// up as a 30% regression on a clean 1 MiB buffer where no shape occurs at all.
func scanSecretTokens(b []byte, hits []Hit) []Hit {
	var first [256]bool
	for _, s := range secretTokenShapes {
		first[s.prefix[0]] = true
	}
	first[jwtPrefixBytes[0]] = true

	for at := 0; at < len(b); at++ {
		if !first[b[at]] {
			continue
		}
		// A shape has to start at a token boundary, not in the middle of a longer
		// run of token bytes (`risk-based` contains sk-, `Asia` contains AKIA).
		if at > 0 && isTokenByte(b[at-1]) {
			continue
		}
		rest := b[at:]
		for _, s := range secretTokenShapes {
			if !bytes.HasPrefix(rest, s.prefix) {
				continue
			}
			run := tokenRun(rest[len(s.prefix):], s.alphabet)
			if run < s.minRun {
				continue
			}
			// Reject lowercase-hyphenated prose such as `sk-learn-classification-model`.
			if s.alphabet == alphaToken && isLowerHyphenatedBytes(rest[len(s.prefix):len(s.prefix)+run]) {
				continue
			}
			hits = append(hits, secretTokenHit(int64(at), s.shape))
		}
		if bytes.HasPrefix(rest, jwtPrefixBytes) && jwtShape(rest) {
			hits = append(hits, secretTokenHit(int64(at), jwtPrefix+"… (JWT)"))
		}
	}
	return hits
}

// jwtShape reports whether b begins a JSON Web Token: the "eyJ" header segment,
// then two more base64url segments of at least jwtSegmentMin characters each,
// separated by dots. The prefix alone is not enough to report — a base64 blob of
// a JSON document begins with those three characters — so all three segments are
// required.
func jwtShape(b []byte) bool {
	i := len(jwtPrefixBytes) + tokenRun(b[len(jwtPrefixBytes):], alphaURL)
	if i < len(jwtPrefixBytes)+jwtSegmentMin {
		return false
	}
	for range 2 {
		if i >= len(b) || b[i] != '.' {
			return false
		}
		i++
		n := tokenRun(b[i:], alphaURL)
		if n < jwtSegmentMin {
			return false
		}
		i += n
	}
	return true
}

// tokenRun is the length of the run of alphabet bytes starting at b.
func tokenRun(b []byte, a tokenAlphabet) int {
	n := 0
	for n < len(b) && inAlphabet(b[n], a) {
		n++
	}
	return n
}

// dropPlaceholderAssignments removes the `NAME=` hits whose value is a documented
// placeholder rather than secret material.
//
// The literal table cannot see the value, so `api_key=` fires on
// `api_key="EMPTY"` and `password=password` alike. Measured on the Hugging Face
// corpus: widening the assignment shapes to api_key/password/secret added 15 high
// findings, and every one of them was a local-server example in a README
// (`api_key="EMPTY"`, `api_key="none"`, `api_key="not-needed"`,
// `api_key='your-api-key'`, `password=password`) — a documentation convention, not
// a hard-coded credential. The rule keeps its severity for values that could be a
// credential and drops only the ones a reader can see are not.
func dropPlaceholderAssignments(b []byte, hits []Hit) []Hit {
	out := hits[:0]
	for _, h := range hits {
		if h.Extra["kind"] != "secret-assignment" || !h.Redacted {
			out = append(out, h)
			continue
		}
		if assignmentValueIsPlaceholder(b, h) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// assignmentValueIsPlaceholder reports whether the value that follows the matched
// assignment is a placeholder.
//
// The value is read the way every consumer of the file would read it: leading
// space and one opening quote are skipped, and the run ends at anything that
// cannot be inside a bare credential (space, quote, comma, bracket, comment).
func assignmentValueIsPlaceholder(b []byte, h Hit) bool {
	at := int(h.Off) + len(h.Match)
	if at >= len(b) {
		return true
	}
	for at < len(b) && (b[at] == ' ' || b[at] == '\t' || b[at] == '"' || b[at] == '\'') {
		at++
	}
	end := at
	for end < len(b) && isCredentialByte(b[end]) {
		end++
	}
	value := string(b[at:end])
	name := strings.TrimSuffix(h.Match, "=")
	if value == "" || len(value) < 4 {
		return true
	}
	// An expansion or a bracketed stand-in is a template, not a value.
	switch value[0] {
	case '<', '$', '{', '%', '@', '*', '.':
		return true
	}
	// A lower-case hyphenated phrase is a name, not a secret:
	// `AIBRIX_KV_CACHE_OL_PRIS_PASSWORD="kvcache-redis"` is a default a reader
	// replaces. A value that mixes case, digits or symbols is a credential shape.
	if isLowerHyphenated(value) {
		return true
	}
	nv := normaliseCredential(value)
	nn := normaliseCredential(name)
	if nv == nn {
		// `password=password`, `api_key=api_key`: the name standing in for a value.
		return true
	}
	switch {
	case strings.HasPrefix(nv, "your"):
		return true
	case credentialPlaceholders[nv]:
		return true
	}
	// A value that *names* a credential is a reference, not a secret:
	// api_key=openai_api_key in a card's code block, api_key=args.key in a script,
	// token=cfg.token. mistralai/Mistral-Large-4-1T-A52B's README produced three
	// high SC4N-STRING-SECRET-VALUE findings for the first. A bare value such as
	// password=hunter2 does not name a credential and is still reported.
	for _, suffix := range credentialNameSuffixes {
		if len(nv) > len(suffix) && strings.HasSuffix(nv, suffix) {
			return true
		}
	}
	return false
}

// credentialNameSuffixes end the names of credentials, so a value carrying one is
// naming a credential rather than being one.
var credentialNameSuffixes = []string{
	"apikey", "apisecret", "secretkey", "accesstoken", "authtoken",
	"password", "passwd", "passphrase", "credential", "credentials", "token", "secret",
}

// isLowerHyphenated reports whether s is one or more lower-case words joined by
// hyphens ("kvcache-redis", "my-super-secret"). Such a value names a thing; a
// hard-coded secret carries case, digits or symbols.
func isLowerHyphenated(s string) bool {
	if !strings.Contains(s, "-") || len(s) < 3 || strings.Contains(s, "--") || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func isLowerHyphenatedBytes(b []byte) bool {
	if len(b) < 3 || b[0] == '-' || b[len(b)-1] == '-' {
		return false
	}
	hasHyphen := false
	prevHyphen := false
	for _, c := range b {
		if c == '-' {
			if prevHyphen {
				return false
			}
			hasHyphen = true
			prevHyphen = true
			continue
		}
		if c < 'a' || c > 'z' {
			return false
		}
		prevHyphen = false
	}
	return hasHyphen
}

// isCredentialByte reports whether c can appear inside an unquoted credential
// value.
func isCredentialByte(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '"', '\'', ',', ';', '(', ')', '[', ']', '{', '}',
		'#', '<', '>', '\\', '`':
		return false
	}
	return c >= 0x21 && c < 0x7f
}

// normaliseCredential lowercases a name or value and drops the separators that
// spellings vary in, so `your-api-key`, `your_api_key` and `YOURAPIKEY` compare
// equal.
func normaliseCredential(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			out = append(out, c)
		}
	}
	return string(out)
}

// credentialPlaceholders is the vocabulary of values that are visibly not a
// credential. It is deliberately short and specific: every entry is a word a
// document uses in place of a value.
var credentialPlaceholders = map[string]bool{
	"empty": true, "none": true, "null": true, "nil": true, "nada": true,
	"notneeded": true, "notrequired": true, "changeme": true, "replaceme": true,
	"placeholder": true, "redacted": true, "dummy": true, "fake": true,
	"example": true, "sample": true, "test": true, "testing": true, "todo": true,
	"unknown": true, "undefined": true, "default": true, "unset": true,
	"secret": true, "password": true, "passwd": true, "token": true,
	"apikey": true, "key": true, "value": true, "string": true, "xxx": true,
	"xxxx": true, "xxxxx": true, "xxxxxxxx": true, "abc": true, "abcdef": true,
	"1234": true, "12345": true, "123456": true, "1234567": true, "12345678": true,
	"localhost": true, "local": true,
	// Measured on the trending campaign (2026-10-28): a README's OpenAI example
	// says api_key="unused", which was the one high finding on RecursiveSI/flint.
	"unused": true, "unusedtoken": true, "nokey": true, "noauth": true,
	"whatever": true, "anything": true, "foo": true, "bar": true, "baz": true,
}

// secretTokenHit builds the redacted hit for a token shape. Match carries the
// shape name rather than the bytes of the stream, so that a token value cannot
// reach the evidence even if the redacted branch of emit is ever changed: the
// bytes of the buffer are the half that must not be reproduced.
func secretTokenHit(off int64, shape string) Hit {
	return Hit{
		Rule:     ruleSecretValue,
		Off:      off,
		Match:    shape,
		Redacted: true,
		Extra:    map[string]string{"kind": "secret-token", "shape": shape},
	}
}

// minOpaqueRun is the length at which a base64 or hex literal stops looking like a
// hash or an id and starts looking like a payload.
const minOpaqueRun = 48

// decoderCallables are the qualified names of the callables that make a long
// opaque argument interesting. It is the context half of SC4N-STRING-OBFUSCATION:
// the rule cannot fire on the literal alone, and it cannot fire on the callable
// alone either, so EmitUse is what pairs them.
var decoderCallables = map[string]bool{
	"builtins.exec":       true,
	"builtins.eval":       true,
	"builtins.compile":    true,
	"base64.b64decode":    true,
	"base64.b85decode":    true,
	"base64.b32decode":    true,
	"base64.b16decode":    true,
	"codecs.decode":       true,
	"binascii.unhexlify":  true,
	"binascii.a2b_base64": true,
	"zlib.decompress":     true,
	"gzip.decompress":     true,
	"bz2.decompress":      true,
	"lzma.decompress":     true,
	"marshal.loads":       true,
	"pickle.loads":        true,
	"pickle.load":         true,
	"dill.loads":          true,
	"cloudpickle.loads":   true,
	"torch.load":          true,
	"functools.reduce":    true,
}

// isDecoderCallable reports whether a qualified callable name is one that turns an
// opaque argument into something else.
func isDecoderCallable(q string) bool {
	if decoderCallables[q] {
		return true
	}
	// A decoder reached through a module subtree is still a decoder: the reference
	// mistake this guards against is the exact-name check that let
	// asyncio.subprocess slip past picklescan (CVE-2025-10157).
	for name := range decoderCallables {
		if strings.HasPrefix(q, name+".") {
			return true
		}
	}
	return false
}

// EmitUse reports a string that was passed to a named callable. It pairs the
// literal with the decoder, which is the only way the obfuscation shape is visible:
// a long base64 string on its own is a hash or a blob id, and base64.b64decode on
// its own is ordinary library usage.
func EmitUse(sink *report.Sink, off int64, text, callable string) {
	EmitString(sink, off, text)
	if !isDecoderCallable(callable) {
		return
	}
	kind, start, run := classifyRun(unsafeBytes(text), 0)
	if run < minOpaqueRun {
		return
	}
	sink.EmitExtra(ruleObfuscation, off+int64(start),
		"a "+strconv.Itoa(run)+"-character "+kind+" literal is passed to "+callable+", which decodes or executes its argument: neither half is suspicious alone, and together they are the standard second-stage shape",
		map[string]string{"kind": kind, "length": strconv.Itoa(run), "callable": callable})
}

// opaqueDecoderWindow is how far a decoder call may sit from a literal for the
// pairing to count: the same statement, or the line next to it. A decoder
// anywhere in the buffer used to corroborate every long run in it, which is how a
// model card's URL fragment became "an opaque literal passed to a decoder"
// because the card's own usage snippet says model.eval().
const opaqueDecoderWindow = 200

// scanOpaqueLiterals reports a long opaque literal that a decoder call reads.
//
// The pairing is the point: a 64-character base64 string is a checksum, a git blob
// id, a token or a payload, and the only thing that separates the last of those
// from the others is whether something decodes it. Four conditions, each with its
// own reason, all needed:
//
//   - the run is long enough (minOpaqueRun) that it is not a hash or an id;
//   - it is a *quoted* string literal, because the rule is about the argument a
//     decoder reads — a path or a dataset id in prose is not an argument;
//   - it is a real encoding (validOpaqueRun);
//   - the decoder is next to it (decoderWithin), because a decoder anywhere in
//     the buffer used to corroborate every long run in it.
//
// The last two and the first are what the 273-model HF campaign's 224 false
// positives needed: a card's "com/FlagOpen/FlagEmbedding/tree/master/examples/
// finetune" was corroborated by the card's own usage snippet, and a dataset id
// like "mteb/sprintduplicatequestions-pairclassification" is not base64 at all.
// scanJSONSecretProps reports `"password": "value"` shapes. The assignment
// automaton matches `password=` but not the quoted-key JSON spelling, so a config
// object was invisible to the secret-value rule.
var jsonSecretNames = map[string]bool{
	"password": true, "passwd": true, "secret": true,
	"apikey": true, "clientsecret": true, "accesstoken": true,
	"authtoken": true, "privatekey": true,
}

func scanJSONSecretProps(b []byte, hits []Hit) []Hit {
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		keyEnd := i + 1
		for keyEnd < len(b) && b[keyEnd] != '"' {
			if b[keyEnd] == '\\' {
				keyEnd++
			}
			keyEnd++
		}
		if keyEnd >= len(b) {
			break
		}
		key := string(b[i+1 : keyEnd])
		// The key is matched through the same normalisation as an assignment
		// name, so `apiKey` and `API_KEY` reach the same policy as `api_key`.
		// The finding still names the spelling the document used.
		if !jsonSecretNames[normaliseCredential(key)] {
			i = keyEnd
			continue
		}
		j := keyEnd + 1
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
			j++
		}
		if j >= len(b) || b[j] != ':' {
			i = keyEnd
			continue
		}
		j++
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
			j++
		}
		if j >= len(b) || b[j] != '"' {
			i = keyEnd
			continue
		}
		valStart := j + 1
		valEnd := valStart
		for valEnd < len(b) && b[valEnd] != '"' {
			if b[valEnd] == '\\' {
				valEnd++
			}
			valEnd++
		}
		if valEnd >= len(b) {
			break
		}
		value := string(b[valStart:valEnd])
		if len(value) < 8 {
			i = valEnd
			continue
		}
		probe := append(append([]byte(key), '='), value...)
		if assignmentValueIsPlaceholder(probe, Hit{Off: 0, Match: key + "="}) {
			i = valEnd
			continue
		}
		hits = append(hits, Hit{
			Rule: ruleSecretValue, Off: int64(valStart), Redacted: true,
			Extra: map[string]string{"shape": key + ":", "kind": "secret-json"},
		})
		i = valEnd
	}
	return hits
}

// minJSONSecretValue is the shortest decoded property value the secret rule
// treats as a credential. Eight bytes is the raw scanner's floor for the same
// shape: below it a value is a placeholder or a word, and reporting it would
// make `"password": "changeme"` (a documented default a reader replaces) a
// finding.
const minJSONSecretValue = 8

// EmitJSONSecretValue reports `"name": "value"` when name is a credential
// property and value is not a placeholder, at off (the value's offset).
//
// The raw scanner sees the byte form through scanJSONSecretProps. A decoded
// metadata document (config.json, model_index.json) hands each key and value to
// the string engine separately, so the property-to-value pairing does not exist
// in any single buffer it scans: without this call a generic credential in a
// config was invisible to SC4N-STRING-SECRET-VALUE while the same bytes in a
// plain .json produced the high finding. The masking contract is the raw
// scanner's: the finding names the shape and never the value.
func EmitJSONSecretValue(sink *report.Sink, off int64, name, value string) {
	if !jsonSecretNames[normaliseCredential(name)] || len(value) < minJSONSecretValue {
		return
	}
	probe := make([]byte, 0, len(name)+1+len(value))
	probe = append(append(append(probe, name...), '='), value...)
	if assignmentValueIsPlaceholder(probe, Hit{Off: 0, Match: name + "="}) {
		return
	}
	sink.EmitRedacted(ruleSecretValue, off,
		"a value matching the "+name+": shape is present and has been masked",
		map[string]string{"shape": name + ":", "kind": "secret-json"})
}

func scanOpaqueLiterals(b []byte, hits []Hit) []Hit {
	var decoders []int64
	for _, h := range hits {
		if h.Extra["kind"] == "decoder" {
			decoders = append(decoders, h.Off)
		}
	}
	if len(decoders) == 0 {
		return hits
	}
	kind, start, run := classifyRun(b, 0)
	for start < len(b) {
		if run >= minOpaqueRun && quotedAt(b, start, run) &&
			validOpaqueRun(kind, b[start:start+run]) &&
			decoderWithin(decoders, int64(start), int64(run)) {
			hits = append(hits, Hit{
				Rule:  ruleObfuscation,
				Off:   int64(start),
				Match: "",
				Extra: map[string]string{
					"kind":   kind,
					"length": strconv.Itoa(run),
				},
			})
		}
		start += run
		if start >= len(b) {
			break
		}
		kind, start, run = classifyRun(b, start)
	}
	return hits
}

// quotedAt reports whether the run is a quoted string literal: a quote
// immediately before it and the same quote immediately after it. The rule is
// about the argument a decoder reads, and in every real encoding — Python source,
// JSON, YAML, TOML — that argument is a quoted string. Prose that mentions a path
// is not one, which is the difference between a payload and a README's URL.
func quotedAt(b []byte, start, run int) bool {
	if start == 0 || start+run >= len(b) {
		return false
	}
	q := b[start-1]
	if q != '"' && q != '\'' {
		return false
	}
	return b[start+run] == q
}

// decoderWithin reports whether a decoder hit sits within opaqueDecoderWindow
// bytes of the run, counting a hit inside the run as adjacent.
func decoderWithin(offs []int64, start, run int64) bool {
	for _, o := range offs {
		if o >= start && o < start+run {
			return true
		}
		d := start - o
		if o >= start+run {
			d = o - (start + run)
		}
		if d <= opaqueDecoderWindow {
			return true
		}
	}
	return false
}

// validOpaqueRun reports whether a run is an actual base64 or hex literal rather
// than an identifier, a URL path or a dataset id that happens to be 48 characters
// long. A model card's "com/FlagOpen/FlagEmbedding/tree/master/examples/finetune"
// and a dataset id like "mteb/sprintduplicatequestions-pairclassification" are the
// two shapes that made 224 of the campaign's 260 findings: the second cannot be
// base64 at all (a 4n+1 length is not decodable), and the first is only decodable
// as text, which is what the decode-to-at-least-24-bytes test checks.
func validOpaqueRun(kind string, run []byte) bool {
	switch kind {
	case "hex":
		if len(run)%2 != 0 {
			return false
		}
		_, err := hex.DecodeString(string(run))
		return err == nil
	case "base64":
		s := strings.TrimRight(string(run), "=")
		if len(s)%4 == 1 {
			return false
		}
		if dec, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(dec) >= 24 {
			return true
		}
		dec, err := base64.RawURLEncoding.DecodeString(s)
		return err == nil && len(dec) >= 24
	}
	return false
}

// classifyRun returns the class of the run of opaque characters starting at from,
// the index after it, and its length.
func classifyRun(b []byte, from int) (kind string, start, run int) {
	start = from
	for start < len(b) && !isOpaqueByte(b[start]) {
		start++
	}
	run = 0
	base64ish := true
	for start+run < len(b) && isOpaqueByte(b[start+run]) {
		c := b[start+run]
		if !isHexByte(c) {
			kind = "base64"
			base64ish = false
		}
		run++
	}
	if base64ish && run > 0 {
		kind = "hex"
	}
	if kind == "" {
		kind = "opaque"
	}
	return kind, start, run
}

func isOpaqueByte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=', c == '-', c == '_':
		return true
	}
	return false
}

// isWordASCII reports whether c is the kind of byte a zero-width character is
// inserted into to hide a name: a letter, a digit or an underscore.
func isWordASCII(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_':
		return true
	}
	return false
}

// zeroWidthRun counts the consecutive zero-width characters starting at b.
func zeroWidthRun(b []byte) int {
	n := 0
	for offset := 0; offset < len(b); {
		r, size := utf8.DecodeRune(b[offset:])
		switch r {
		case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD:
			n++
			offset += size
			continue
		}
		break
	}
	return n
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// maxMixedScriptBytes bounds the mixed-script check to a *value*: an identifier,
// a token, a metadata string. A longer buffer is a document, and a document that
// contains two scripts is a multilingual document — llama.cpp's tokenizer test
// inputs and a ByteDance chat template are both exactly that, and both were
// reported as homoglyph attacks before this bound.
const maxMixedScriptBytes = 256

// scanUnicodeAnomalies reports invisible, order-changing and mixed-script runs.
//
// The walk decodes runes straight out of the byte slice rather than ranging over a
// string: `range string(b)` copies the whole buffer, and a clean buffer must cost
// no allocation (TestScanIntoCostsNothingWhenThereIsNothingToReport).
//
// An invalid byte does not disable the pass: the walk skips it and keeps going, so
// a bidi override or an invisible character on either side of a stray 0xE9 is still
// reported. The invalid byte splits the valid runs rather than standing the
// detector down; an artifact that is wholly invalid is still covered by the
// byte-safe literal tier and, for a text artifact, by SC4N-CONTENT-NOT-UTF8.
func scanUnicodeAnomalies(b []byte, hits []Hit) []Hit {
	// Fixed-size state rather than maps, for the same reason.
	var (
		// reported[0] zero-width, [1] bidi control, [2] line separator,
		// [3] Unicode Tags. One finding of a kind per buffer: the second
		// zero-width character in a string adds nothing a reviewer does not
		// already know from the first.
		reported    [4]bool
		scriptSeen  [4]bool
		scriptCount [4]int
		scriptKind  byte
		firstMixed  = -1
	)
	// prevWord records whether the rune before this one was an ASCII letter,
	// digit or underscore: the context in which a zero-width character hides
	// something from a reader.
	prevWord := false
	for offset := 0; offset < len(b); {
		// ASCII fast path. No ASCII byte is invisible, bidi or a line separator, and
		// the only script class ASCII can carry is Latin, so the whole rune switch
		// collapses to one branch. The slow path below runs only for non-ASCII, which
		// is rare in the JSON, Python and YAML this engine mostly sees.
		if c := b[offset]; c < utf8.RuneSelf {
			if (c|0x20) >= 'a' && (c|0x20) <= 'z' {
				scriptCount[0]++
				if !scriptSeen[0] {
					scriptSeen[0] = true
					scriptKind++
					if scriptKind > 1 && firstMixed < 0 {
						firstMixed = offset
					}
				}
			}
			prevWord = isWordASCII(c)
			offset++
			continue
		}
		r, size := utf8.DecodeRune(b[offset:])
		if r == utf8.RuneError && size == 1 {
			// An invalid byte: skip it and keep the pass running on the next run.
			prevWord = false
			offset++
			continue
		}
		switch {
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF || r == 0x00AD:
			// Exempt a single leading UTF-8 BOM at byte 0.
			if offset == 0 && r == 0xFEFF && zeroWidthRun(b) == 1 {
				prevWord = false
				offset += size
				continue
			}
			// A zero-width character inside a word hides a name from a reader; the
			// same character between two emoji is a ZWJ grapheme join, which is
			// ordinary text ("😶‍🌫️" is one emoji, not a hidden identifier). A run of
			// them is never legitimate, so it is reported either way.
			nextWord := offset+size < len(b) && b[offset+size] < utf8.RuneSelf && isWordASCII(b[offset+size])
			if (prevWord || nextWord || zeroWidthRun(b[offset:]) >= 2) && !reported[0] {
				reported[0] = true
				hits = append(hits, Hit{
					Rule:  ruleUnicode,
					Off:   int64(offset),
					Match: string(r),
					Extra: map[string]string{"kind": "zero-width", "rune": runeName(r)},
				})
			}
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			if !reported[1] {
				reported[1] = true
				hits = append(hits, Hit{
					Rule:  ruleUnicode,
					Off:   int64(offset),
					Match: string(r),
					Extra: map[string]string{"kind": "bidi-control", "rune": runeName(r)},
				})
			}
		case r == 0x2028, r == 0x2029:
			if !reported[2] {
				reported[2] = true
				hits = append(hits, Hit{
					Rule:  ruleUnicode,
					Off:   int64(offset),
					Match: string(r),
					Extra: map[string]string{"kind": "line-separator", "rune": runeName(r)},
				})
			}
		case r >= 0xE0000 && r <= 0xE007F:
			// The Unicode Tags block — U+E0001 and the deprecated tag
			// characters U+E0020-U+E007F — is the standard invisible
			// prompt-injection channel: the characters draw nothing, every
			// renderer drops them, and a model's tokeniser still reads the
			// instruction they spell. No model artifact, card or template has a
			// legitimate use for one, so the first is reported.
			//
			// The evidence names the range rather than the individual rune: the
			// rune is invisible where the evidence is read, so a reviewer
			// cannot tell a hidden character from an empty string, and the
			// range is what identifies the channel.
			if !reported[3] {
				reported[3] = true
				hits = append(hits, Hit{
					Rule:  ruleUnicode,
					Off:   int64(offset),
					Match: "U+E0000-U+E007F Tags block characters",
					Extra: map[string]string{"kind": "unicode-tag", "range": "U+E0000-U+E007F", "rune": runeName(r)},
				})
			}
		default:
			if s := script(r); s != 0 {
				idx := -1
				switch s {
				case 'L':
					idx = 0
				case 'G':
					idx = 1
				case 'C':
					idx = 2
				case 'H':
					idx = 3
				}
				if idx >= 0 {
					scriptCount[idx]++
				}
				if idx >= 0 && !scriptSeen[idx] {
					scriptSeen[idx] = true
					scriptKind++
				}
				if scriptKind > 1 && firstMixed < 0 {
					firstMixed = offset
				}
			}
		}
		prevWord = false
		offset += size
	}
	// Mixed scripts is a homoglyph claim, and a homoglyph is a lookalike inside
	// otherwise Latin text: "pаypal" with a Cyrillic а. Two scripts in a buffer are
	// not enough — text written *in* another script that happens to contain an
	// ASCII word is not an attack, and the counter-example is measured: an sklearn
	// dataset whose labels are Russian (f64k/pickle/ARCH_traned_LinearSVC_*.pickle
	// in the corpus) produced 3,850 "mixed scripts" findings, every one of them a
	// Cyrillic sentence with an ASCII identifier next to it. The claim therefore
	// requires the Latin count to exceed every other script combined: a homoglyph
	// attack always satisfies it, a Russian sentence never does.
	if scriptKind > 1 && firstMixed >= 0 && len(b) <= maxMixedScriptBytes &&
		scriptCount[0] > scriptCount[1]+scriptCount[2]+scriptCount[3] {
		hits = append(hits, Hit{
			Rule:  ruleUnicode,
			Off:   int64(firstMixed),
			Match: "mixed scripts",
			Extra: map[string]string{"kind": "mixed-script", "scripts": string(rune('0' + scriptKind))},
		})
	}
	return hits
}

// script is a coarse script class for the mixed-script check: Latin, Greek,
// Cyrillic or Han. Anything else returns 0 and takes no part in the check, which
// keeps a legitimate multi-script document (an Arabic model card, a Japanese
// README) from being reported.
func script(r rune) byte {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= 0x00C0 && r <= 0x024F:
		return 'L'
	case r >= 0x0370 && r <= 0x03FF, r >= 0x1F00 && r <= 0x1FFF:
		return 'G'
	case r >= 0x0400 && r <= 0x04FF:
		return 'C'
	case r >= 0x4E00 && r <= 0x9FFF:
		return 'H'
	}
	return 0
}

// runeName renders a rune for evidence without pulling in a Unicode table.
func runeName(r rune) string {
	switch r {
	case 0x200B:
		return "U+200B ZERO WIDTH SPACE"
	case 0x200C:
		return "U+200C ZERO WIDTH NON-JOINER"
	case 0x200D:
		return "U+200D ZERO WIDTH JOINER"
	case 0x2060:
		return "U+2060 WORD JOINER"
	case 0xFEFF:
		return "U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)"
	case 0x00AD:
		return "U+00AD SOFT HYPHEN"
	case 0x202A:
		return "U+202A LEFT-TO-RIGHT EMBEDDING"
	case 0x202B:
		return "U+202B RIGHT-TO-LEFT EMBEDDING"
	case 0x202C:
		return "U+202C POP DIRECTIONAL FORMATTING"
	case 0x202D:
		return "U+202D LEFT-TO-RIGHT OVERRIDE"
	case 0x202E:
		return "U+202E RIGHT-TO-LEFT OVERRIDE"
	case 0x2066:
		return "U+2066 LEFT-TO-RIGHT ISOLATE"
	case 0x2067:
		return "U+2067 RIGHT-TO-LEFT ISOLATE"
	case 0x2068:
		return "U+2068 FIRST STRONG ISOLATE"
	case 0x2069:
		return "U+2069 POP DIRECTIONAL ISOLATE"
	case 0x2028:
		return "U+2028 LINE SEPARATOR"
	case 0x2029:
		return "U+2029 PARAGRAPH SEPARATOR"
	}
	return "U+" + strings.ToUpper(strconv.FormatInt(int64(r), 16))
}

// min keeps the package dependency-free of generics.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
