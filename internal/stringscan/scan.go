package stringscan

import (
	"bytes"
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
	hits = scanRawIPURLs(b, hits)
	hits = scanOpaqueLiterals(b, hits)
	hits = scanUnicodeAnomalies(b, hits)
	return dedupe(sortedHits(hits))
}

// scanIntoBody keeps the body of the old scan() separate so that ScanInto's
// zero-allocation promise is visible at the call sites: nothing in here allocates
// unless a detector found something.

// dedupe collapses hits that name the same rule at the same offset. Several
// literals belong to one rule and can end at the same offset (for example
// "|sh" and "| sh"), and reporting the same rule twice at one offset is noise a
// reviewer has to filter by hand.
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
		host := rest[after:]
		hostEnd := indexAny(host, "/:?# \t\r\n\"'`,;)")
		if hostEnd < 0 {
			hostEnd = len(host)
		}
		host = host[:hostEnd]
		if !isIPv4Literal(host) {
			i++
			continue
		}
		// The URL may be a legitimate documentation example (RFC 5737 reserves the
		// documentation ranges), and saying so in the evidence saves a reviewer the
		// lookup.
		extra := map[string]string{"kind": "raw-ip-url", "host": string(host)}
		if isDocumentationIP(host) {
			extra["reserved"] = "documentation"
		}
		hits = append(hits, Hit{
			Rule:  ruleRawIPURL,
			Off:   int64(i),
			Match: string(rest[:after+hostEnd]),
			Extra: extra,
		})
		i += after + hostEnd
	}
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

// isIPv4Literal reports whether b is a dotted quad of four decimal octets.
func isIPv4Literal(b []byte) bool {
	octets, digits := 0, 0
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] >= '0' && b[i] <= '9':
			if digits >= 3 {
				return false
			}
			digits++
		case b[i] == '.':
			if digits == 0 {
				return false
			}
			octets++
			digits = 0
		default:
			return false
		}
	}
	return octets == 3 && digits > 0
}

// isDocumentationIP reports whether the address is in a range reserved for
// documentation or for private use, where a scanner should say so rather than
// leave the reader wondering whether the target is real.
func isDocumentationIP(b []byte) bool {
	first := 0
	i := 0
	for ; i < len(b) && b[i] != '.'; i++ {
		first = first*10 + int(b[i]-'0')
	}
	switch {
	case first == 192:
		// 192.0.2.0/24 (TEST-NET-1) and 192.168.0.0/16 (private).
		second := 0
		for i++; i < len(b) && b[i] != '.'; i++ {
			second = second*10 + int(b[i]-'0')
		}
		return second == 0 || second == 168
	case first == 198:
		// 198.51.100.0/24 (TEST-NET-2).
		second, third := 0, 0
		for i++; i < len(b) && b[i] != '.'; i++ {
			second = second*10 + int(b[i]-'0')
		}
		for i++; i < len(b) && b[i] != '.'; i++ {
			third = third*10 + int(b[i]-'0')
		}
		return second == 51 && third == 100
	case first == 203:
		// 203.0.113.0/24 (TEST-NET-3).
		second, third := 0, 0
		for i++; i < len(b) && b[i] != '.'; i++ {
			second = second*10 + int(b[i]-'0')
		}
		for i++; i < len(b) && b[i] != '.'; i++ {
			third = third*10 + int(b[i]-'0')
		}
		return second == 0 && third == 113
	case first == 127, first == 10:
		return true
	case first == 172:
		second := 0
		for i++; i < len(b) && b[i] != '.'; i++ {
			second = second*10 + int(b[i]-'0')
		}
		return second >= 16 && second <= 31
	}
	return false
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

// scanOpaqueLiterals reports a long opaque literal in the same buffer as a decoder
// call.
//
// The pairing is the point: a 64-character base64 string is a checksum, a git blob
// id, a token or a payload, and the only thing that separates the last of those
// from the others is whether something in the same string decodes it.
func scanOpaqueLiterals(b []byte, hits []Hit) []Hit {
	hasDecoder := false
	for _, h := range hits {
		if h.Extra["kind"] == "decoder" {
			hasDecoder = true
			break
		}
	}
	if !hasDecoder {
		return hits
	}
	kind, start, run := classifyRun(b, 0)
	for start < len(b) {
		if run >= minOpaqueRun {
			hits = append(hits, Hit{
				Rule:  ruleObfuscation,
				Off:   int64(start),
				Match: string(b[start : start+min(run, 96)]),
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

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// scanUnicodeAnomalies reports invisible, order-changing and mixed-script runs.
//
// The walk decodes runes straight out of the byte slice rather than ranging over a
// string: `range string(b)` copies the whole buffer, and a clean buffer must cost
// no allocation (TestScanIntoCostsNothingWhenThereIsNothingToReport).
func scanUnicodeAnomalies(b []byte, hits []Hit) []Hit {
	if !utf8.Valid(b) {
		return hits
	}
	// Fixed-size state rather than maps, for the same reason.
	var (
		reported   [3]bool
		scriptSeen [4]bool
		scriptKind byte
		firstMixed = -1
	)
	for offset := 0; offset < len(b); {
		// ASCII fast path. No ASCII byte is invisible, bidi or a line separator, and
		// the only script class ASCII can carry is Latin, so the whole rune switch
		// collapses to one branch. The slow path below runs only for non-ASCII, which
		// is rare in the JSON, Python and YAML this engine mostly sees.
		if c := b[offset]; c < utf8.RuneSelf {
			if !scriptSeen[0] && (c|0x20) >= 'a' && (c|0x20) <= 'z' {
				scriptSeen[0] = true
				scriptKind++
				if scriptKind > 1 && firstMixed < 0 {
					firstMixed = offset
				}
			}
			offset++
			continue
		}
		r, size := utf8.DecodeRune(b[offset:])
		switch {
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF || r == 0x00AD:
			if !reported[0] {
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
				if idx >= 0 && !scriptSeen[idx] {
					scriptSeen[idx] = true
					scriptKind++
				}
				if scriptKind > 1 && firstMixed < 0 {
					firstMixed = offset
				}
			}
		}
		offset += size
	}
	if scriptKind > 1 && firstMixed >= 0 {
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

// minInt and min keep the package dependency-free of generics.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
