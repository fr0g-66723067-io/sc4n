package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Parser analyses one artifact.
//
// Contract for every implementation:
//
//   - it reads only through ctx's source and never mutates it;
//   - it never writes to disk, never extracts a member, and never executes the
//     artifact or an external tool (this is what makes sc4n safe to run over a
//     hostile file in CI);
//   - it never panics on malformed input: a parse error becomes a finding plus a
//     returned error, and the caller decides whether the artifact is unreadable;
//   - it reports every finding through ctx.Sink, never directly on the Collector,
//     so the artifact name is always right.
type Parser interface {
	Parse(ctx *Ctx, s source.Source) error
}

var (
	parsersMu sync.Mutex
	parsers   = map[Format]Parser{}
)

// RegisterParser binds a parser to the format it handles. It panics on a
// duplicate binding, because two parsers for one format would make dispatch
// order silently decide coverage.
func RegisterParser(f Format, p Parser) {
	parsersMu.Lock()
	defer parsersMu.Unlock()
	if _, dup := parsers[f]; dup {
		panic(fmt.Sprintf("artifact: parser for %s registered twice", f))
	}
	parsers[f] = p
}

// ParserFor returns the registered parser for f.
func ParserFor(f Format) (Parser, bool) {
	parsersMu.Lock()
	defer parsersMu.Unlock()
	p, ok := parsers[f]
	return p, ok
}

// Session is the shared state of one scan: the collector, the containment root,
// the memory budget and the content-hash memo that keeps a blob reachable through
// several cache revisions from being scanned more than once.
type Session struct {
	Collector *report.Collector
	// Root is the containment root for path-shaped values (ONNX external data,
	// SavedModel assets, symlink resolution). Empty means "the artifact's own
	// directory".
	Root string
	// DeepStats enables the informational weight-statistics rules.
	DeepStats bool
	// TopLimits is the budget as configured, used for nested containers as the
	// starting point.
	TopLimits limits.Limits

	mu   sync.Mutex
	seen map[string]string
}

// NewSession returns a Session with an initialised memo.
func NewSession(c *report.Collector, root string, l limits.Limits) *Session {
	return &Session{
		Collector: c,
		Root:      root,
		TopLimits: l,
		seen:      map[string]string{},
	}
}

// MarkSeen records that content with the given digest has been scanned as name.
// It returns the earlier name and false when the content was already scanned,
// which lets an hf-cache walk report one finding set for a blob referenced from
// twenty revisions.
func (s *Session) MarkSeen(digest, name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.seen[digest]; ok {
		return prev, false
	}
	s.seen[digest] = name
	return name, true
}

// Ctx is the per-artifact, per-nesting-level context. It is created fresh for
// every member, so Depth and Limits are never shared across siblings and the
// budget cannot leak between them.
type Ctx struct {
	Session *Session
	Sink    *report.Sink
	Limits  limits.Limits
	// Depth is the container nesting level of this artifact; 0 at the top.
	Depth int
	// Format is what this level was sniffed as, for diagnostics and for the
	// SC4N-LIMIT-* / SC4N-FORMAT-AMBIGUOUS evidence.
	Format Format
}

// Member returns the child context for a nested member: the sink is re-bound to
// the member's display name, depth increments and the limit budget is reduced by
// one level. ok is false when the depth budget is exhausted, in which case the
// caller MUST emit SC4N-LIMIT-DEPTH and stop.
func (c *Ctx) Member(name string, f Format) (*Ctx, bool) {
	l, ok := c.Limits.Descendant()
	if !ok {
		return nil, false
	}
	return &Ctx{
		Session: c.Session,
		Sink:    c.Sink.Named(name),
		Limits:  l,
		Depth:   c.Depth + 1,
		Format:  f,
	}, true
}

// NewCtx returns a top-level context for an artifact.
func (s *Session) NewCtx(name string, l limits.Limits) *Ctx {
	return &Ctx{
		Session: s,
		Sink:    s.Collector.For(name),
		Limits:  l,
	}
}

// Errors returned by dispatch.
var (
	// ErrUnsupported means no sniffer recognised the content. It is reported as
	// an artifact with format "unknown" and no findings, and it does NOT fail
	// the scan: an unknown file in a repo is ordinary.
	ErrUnsupported = errors.New("artifact: unsupported format")
)

// Dispatch sniffs s and returns the format plus the name of the sniffer that
// matched.
// Scan dispatches s and runs the matching parser, recursively for containers.
// It returns the format that ran and an error only when the parser itself failed.
// A format with no registered parser (recognised but shallow) is not an error:
// the surrounding shallow scanner has already done what it can.
//
// Universal scanners run first, for *every* artifact and every nested member,
// before any format parser. They are where the format-independent layers live:
// polyglot/native-magic detection and the format-versus-extension check. Running
// them before the parser matters because a parser that fails early must not be
// able to suppress the format-independent findings.
func Scan(ctx *Ctx, s source.Source) (Format, error) {
	f, _ := Sniff(s, ctx.Limits)
	ctx.Format = f
	RunUniversal(ctx, s, f)
	if f == FormatUnknown {
		return f, nil
	}
	p, ok := ParserFor(f)
	if !ok {
		return f, nil
	}
	if err := p.Parse(ctx, s); err != nil {
		return f, err
	}
	return f, nil
}

// UniversalFunc is a format-independent scan layer.
type UniversalFunc func(ctx *Ctx, s source.Source, f Format)

var (
	universalMu sync.Mutex
	universal   []struct {
		name string
		fn   UniversalFunc
	}
)

// RegisterUniversal adds a format-independent scan layer. It panics on a
// duplicate name so that the set of layers applied to every artifact is
// enumerable, which is what makes "sc4n scanned everything with X" a true
// statement.
func RegisterUniversal(name string, fn UniversalFunc) {
	universalMu.Lock()
	defer universalMu.Unlock()
	for _, u := range universal {
		if u.name == name {
			panic("artifact: universal scanner " + name + " registered twice")
		}
	}
	universal = append(universal, struct {
		name string
		fn   UniversalFunc
	}{name, fn})
}

// RunUniversal runs every registered universal layer in registration order.
// Registration order is deterministic (package init order within one binary is
// fixed by the import graph), and each layer is required to be order-independent
// of the others: none reads state another wrote.
func RunUniversal(ctx *Ctx, s source.Source, f Format) {
	universalMu.Lock()
	layers := make([]UniversalFunc, len(universal))
	for i, u := range universal {
		layers[i] = u.fn
	}
	universalMu.Unlock()
	for _, fn := range layers {
		fn(ctx, s, f)
	}
}

// ScanMember dispatches and parses a nested member from a Source. It is the entry
// point container parsers use, so that container nesting, naming and depth
// accounting are implemented exactly once.
//
// A parser error is reported here as SC4N-PARSE-FAILED on the member's name, not
// just returned: every container caller (archive, numpy, torch, msgpack, xgb)
// discards the returned error, so an unreported failure leaves a nested member
// invisible — an outer zip whose member inner.zip has a damaged directory yielded
// no finding about inner.zip and never scanned its members, which is exactly the
// fail-open shape the rule exists to prevent. The error is still returned for a
// caller that wants it.
//
// It takes a Source rather than a byte slice because a member can be far larger
// than memory: a stored member is a zero-copy Section over the parent's mapping,
// and a compressed member is decompressed into a private temporary file that is
// mapped (source.Spill). A container parser that has the member's bytes in hand
// uses ScanMemberBytes.
func ScanMember(parent *Ctx, name string, s source.Source) (Format, error) {
	sub, ok := parent.Member(name, FormatUnknown)
	if !ok {
		emitLimitDepth(parent, name)
		return FormatUnknown, nil
	}
	f, err := Scan(sub, s)
	if err != nil {
		parent.Sink.Named(name).EmitExtra(RuleParseFailed, 0, err.Error(), nil)
	}
	return f, err
}

// ScanMemberBytes is ScanMember for a member that is already in memory. The
// Source wraps the caller's slice, which must not be mutated until the call
// returns.
func ScanMemberBytes(parent *Ctx, name string, data []byte) (Format, error) {
	s := source.Mem(parent.Sink.Named(name).Artifact(), data)
	defer s.Close()
	return ScanMember(parent, name, s)
}

func emitLimitDepth(ctx *Ctx, name string) {
	limits.Emit(ctx.Sink, limits.RuleDepth, "MaxDepth", int64(ctx.Depth+1), int64(ctx.Session.TopLimits.MaxDepth), "stopped at "+name)
}

// maxMagicProbe is how many leading bytes the magic table looks at. It is enough
// for every fixed signature in the table (the longest is the 8-byte HDF5 and
// xz magics) plus the TFLite identifier at offset 4.
const maxMagicProbe = 512

var magicSniffer = []struct {
	magic  []byte
	format Format
	// at is the offset the magic must occupy; 0 unless stated.
	at int
}{
	{[]byte("PK\x03\x04"), FormatZip, 0},
	{[]byte("PK\x05\x06"), FormatZip, 0},
	{[]byte("PK\x07\x08"), FormatZip, 0},
	{[]byte("\x93NUMPY"), FormatNPY, 0},
	{[]byte("GGUF"), FormatGGUF, 0},
	{[]byte("\x89HDF\r\n\x1a\n"), FormatHDF5, 0},
	{[]byte("TFL3"), FormatTFLite, 4},
	{[]byte("\x1f\x8b"), FormatGzip, 0},
	{[]byte("BZh"), FormatBzip2, 0},
	{[]byte("\xfd7zXZ\x00"), FormatXz, 0},
	{[]byte("\x04\x22\x4d\x18"), FormatLz4, 0},
	{[]byte("\x28\xb5\x2f\xfd"), FormatZstd, 0},
	{[]byte("7z\xbc\xaf\x27\x1c"), FormatSevenZip, 0},
	{[]byte("Rar!\x1a\x07"), FormatRar, 0},
	{[]byte("\x7fELF"), FormatNative, 0},
	{[]byte("MZ"), FormatNative, 0},
	{[]byte("\xfe\xed\xfa\xce"), FormatNative, 0},
	{[]byte("\xfe\xed\xfa\xcf"), FormatNative, 0},
	{[]byte("\xce\xfa\xed\xfe"), FormatNative, 0},
	{[]byte("\xcf\xfa\xed\xfe"), FormatNative, 0},
	{[]byte("\xca\xfe\xba\xbe"), FormatNative, 0},
	{[]byte("\xd0\xcf\x11\xe0"), FormatNative, 0},
	{[]byte("!<arch>\n"), FormatNative, 0},
	{[]byte("\x78\x01"), FormatZlib, 0},
	{[]byte("\x78\x9c"), FormatZlib, 0},
	{[]byte("\x78\xda"), FormatZlib, 0},
	{[]byte("\x5d\x00\x00"), FormatLzma, 0},
}

func init() {
	RegisterSniffer("magic", 100, sniffMagic)
	RegisterSniffer("tarkind", 90, sniffTar)
	RegisterSniffer("pickle-proto", 80, sniffPickleHeader)
	RegisterSniffer("text", -100, sniffText)

	RegisterFormat(Info{Format: FormatUnknown, Magic: "(none)", Depth: DepthNone,
		Notes: "no sniffer matched; the file is reported as \"unknown\" and only the format-independent layers run — native magic, the format-versus-extension check, a shebang, and the name-driven rules for .pth, .start, .pyc and Dockerfile. No parser runs and no string indicators: a file that reaches \"unknown\" had no text sniff, so an indicator inside it is not reported."})
	RegisterFormat(Info{Format: FormatZip, Magic: "PK\\x03\\x04", Depth: DepthStructural, Container: true,
		Notes: "stored and deflate members (plus zip64) are read; encrypted entries, CRC mismatches, duplicate names, absolute or traversal paths, link members, local-vs-central name disagreements and bomb ratios are reported; members are never extracted to disk."})
	RegisterFormat(Info{Format: FormatTar, Magic: "ustar at offset 257", Depth: DepthStructural, Container: true,
		Notes: "ustar and GNU long-name members are read; absolute, traversal and link members are reported."})
	RegisterFormat(Info{Format: FormatGzip, Magic: "\\x1f\\x8b", Depth: DepthStructural, Container: true,
		Notes: "single-member streams are unwrapped and the payload re-dispatched, up to MaxDepth; the whole-file ratio is bounded by MaxRatio."})
	RegisterFormat(Info{Format: FormatZlib, Magic: "\\x78 01|9c|da", Depth: DepthStructural, Container: true,
		Notes: "zlib streams are unwrapped and re-dispatched; joblib's default compression is zlib, so this is the common path into a joblib payload."})
	RegisterFormat(Info{Format: FormatBzip2, Magic: "BZh", Depth: DepthStructural, Container: true,
		Notes: "bzip2 streams are unwrapped and re-dispatched; gzip(bzip2(pickle)) is the published modelscan double-compression bypass, so this wrapper is supported precisely because it is used that way."})
	RegisterFormat(Info{Format: FormatXz, Magic: "\\xfd7zXZ\\x00", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED: no xz decoder in the Go standard library and sc4n has no third-party dependencies. The presence of xz in a model file is reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION (medium) with the offset, and any pickle or native payload inside it is NOT scanned."})
	RegisterFormat(Info{Format: FormatLzma, Magic: "\\x5d\\x00\\x00", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib lzma decoder). The 2-byte magic is weak and collides with ordinary data, so it is only reported after a header-shape sanity check. Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION."})
	RegisterFormat(Info{Format: FormatLz4, Magic: "\\x04\\x22\\x4d\\x18", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib lz4 decoder; joblib lz4 is a documented joblib compression method). Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION."})
	RegisterFormat(Info{Format: FormatZstd, Magic: "\\x28\\xb5\\x2f\\xfd", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib zstd decoder). Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION."})
	RegisterFormat(Info{Format: FormatSevenZip, Magic: "7z\\xbc\\xaf\\x27\\x1c", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED. A 7z file named .pt is the February 2025 Hugging Face campaign: the loader (patched torch) still deserialised the payload while every extension-driven scanner saw \"not a zip\". Reported as SC4N-TORCH-7Z (critical) when the name suggests a torch checkpoint, plus SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION."})
	RegisterFormat(Info{Format: FormatRar, Magic: "Rar!\\x1a\\x07", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib rar decoder). Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION."})
	RegisterFormat(Info{Format: FormatZlibJoblibLegacy, Magic: "ZF", Depth: DepthNone, Container: false,
		Notes: "joblib's pre-0.10 z-file framing: a 21-byte header — \"ZF\" plus the uncompressed length as a space-padded 0x-prefixed hex string — followed by a stdlib zlib stream. sc4n recognises the frame (both the header shape and the zlib stream must be plausible) but does not unwrap it, so the payload is not scanned; reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION naming the framing."})
	RegisterFormat(Info{Format: FormatNative, Magic: "\\x7fELF | MZ | Mach-O | OLE | !<arch>", Depth: DepthShallow,
		Notes: "header validity is checked with debug/elf, debug/macho and debug/pe; a bare magic match without a valid header is reported at info only. A valid executable inside a model artifact is SC4N-POLYGLOT-NATIVE."})

	RegisterFormat(Info{Format: FormatJSON, Magic: "leading { or [", Depth: DepthStructural,
		Notes: "routing is name-dependent. The Hugging Face metadata names (config.json, adapter_config.json, modules.json, model_index.json, dataset_info.json) and the tokenizer files (tokenizer.json, tokenizer_config.json, special_tokens_map.json) are decoded with encoding/json and the metadata, tokenizer, chat-template and card-injection rule families run over the decoded document — every JSON value in the stream, not just the first. Any other JSON is scanned as raw text by the shared indicator engine."})
	RegisterFormat(Info{Format: FormatJSONLines, Magic: "one JSON value per line", Depth: DepthShallow,
		Notes: "no per-line decoder: the file is scanned as text by the shared indicator engine, so an indicator anywhere in it is found, while a malformed line is not reported and no per-line structure is decoded."})
	RegisterFormat(Info{Format: FormatPython, Magic: "text; extension .py", Depth: DepthStructural,
		Notes: "hand-written Python 3.14 lexer plus a statement-level taint engine over the source/sink pairs listed in internal/pysrc/rules.go (isSourceDotted, isShellSink, isDeserializeSink, isNetworkSink and the standalone-construct predicates); there is no type inference, so taint is intra-statement and intra-function."})
	RegisterFormat(Info{Format: FormatNotebook, Magic: "JSON with a \"cells\" array", Depth: DepthStructural,
		Notes: "code cells are mapped back to their original line numbers in the .ipynb file; IPython magics and shell escapes are reported separately from ordinary Python findings."})
	RegisterFormat(Info{Format: FormatJinja, Magic: "text containing {{ }} or {% %}", Depth: DepthStructural,
		Notes: "Jinja2 lexer plus an introspection/dynamic-name analyzer, applied to .jinja/.j2/.tmpl files, chat_template.jinja, tokenizer_config.json:chat_template, config.json-embedded templates and GGUF tokenizer.chat_template."})
	RegisterFormat(Info{Format: FormatMarkdown, Magic: "text; extension .md", Depth: DepthStructural,
		Notes: "YAML frontmatter (subset reader) plus the prompt-injection and Unicode-anomaly detectors, applied to model and dataset cards."})
	RegisterFormat(Info{Format: FormatYAML, Magic: "text; extension .yml/.yaml", Depth: DepthShallow,
		Notes: "no YAML library is linked, so YAML is scanned as text for string indicators, prompt-injection content and the GitHub Actions pull_request_target pattern; it is not parsed into a document tree."})
	RegisterFormat(Info{Format: FormatText, Magic: "(fallback)", Depth: DepthShallow,
		Notes: "any file with no NUL byte in its first kilobyte and no structural sniffer match is scanned with the string-indicator engine at depth shallow. Extension-specific rules (.pth, .start, .pyc, Dockerfile) still apply."})
}

func sniffMagic(s source.Source, l limits.Limits) (Format, bool) {
	head, err := s.Bytes(0, min64(s.Size(), maxMagicProbe))
	if err != nil && (len(head) < 8) {
		return FormatUnknown, false
	}
	for _, m := range magicSniffer {
		if len(head) < m.at+len(m.magic) {
			continue
		}
		if bytes.HasPrefix(head[m.at:], m.magic) {
			return m.format, true
		}
	}
	return FormatUnknown, false
}

// sniffTar looks for the ustar magic at offset 257, which is where every tar
// variant that Go's archive/tar accepts puts it.
func sniffTar(s source.Source, l limits.Limits) (Format, bool) {
	if s.Size() < 262 {
		return FormatUnknown, false
	}
	b, err := s.Bytes(257, 5)
	if err != nil || len(b) < 5 {
		return FormatUnknown, false
	}
	if bytes.Equal(b, []byte("ustar")) {
		return FormatTar, true
	}
	return FormatUnknown, false
}

// sniffPickleHeader recognises the protocol markers that a pickle *must* start
// with (PROTO for protocol >= 2). It is deliberately a low-priority, shape-only
// check: internal/pickle registers a higher-priority sniffer that walks the whole
// opcode stream, and a stream that fails that walk is not a pickle at all. The
// gap this closes is the reverse case — a file whose first bytes look like a
// pickle but that no walker accepts — so the result here is only ever a hint.
func sniffPickleHeader(s source.Source, l limits.Limits) (Format, bool) {
	b, err := s.Bytes(0, 2)
	if err != nil || len(b) < 2 {
		return FormatUnknown, false
	}
	if b[0] == 0x80 && b[1] >= 1 && b[1] <= 5 {
		return FormatPickle, true
	}
	// Protocol 0/1 pickles have no PROTO prefix, and their first byte is an
	// ordinary ASCII letter -- 'c' for GLOBAL, '(' for MARK, ']' for EMPTY_LIST.
	// A file whose first byte is 'c' is far more likely to be source code than a
	// pickle, so this sniffer deliberately does not claim those: internal/pickle
	// registers a walk-based sniffer above it that accepts a protocol-0/1 stream
	// only after decoding it to a clean STOP.
	return FormatUnknown, false
}

// sniffText is the last-resort classifier. It runs only when no structural
// sniffer matched, and it never claims a binary file: a NUL byte in the first
// kilobyte disqualifies the content.
func sniffText(s source.Source, l limits.Limits) (Format, bool) {
	n := min64(s.Size(), 1024)
	head, err := s.Bytes(0, n)
	if err != nil && len(head) == 0 {
		return FormatUnknown, false
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return FormatUnknown, false
	}
	trimmed := bytes.TrimLeft(head, " \t\r\n\ufeff")
	switch {
	case len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '['):
		if looksLikeJSON(s) {
			return FormatJSON, true
		}
	case bytes.HasPrefix(trimmed, []byte("#!")):
		return FormatText, true
	}
	return FormatText, true
}

// looksLikeJSON reports whether the stream holds exactly one complete JSON value.
// It deliberately does not validate the whole document: a config.json inside a
// multi-gigabyte repository is classified by extension and structure in the repo
// walker, and validating 100 MB of JSON here would cost more than the sniff is
// worth. The bounded reader keeps a single pathological token (a gigabyte string)
// from being buffered, and a value that does not complete inside the window is
// simply not claimed as JSON.
func looksLikeJSON(s source.Source) bool {
	return decodesOneJSONValue(json.NewDecoder(io.LimitReader(s.Reader(0), 64<<10)))
}

// decodesOneJSONValue reports whether the decoder holds exactly one complete JSON
// value: the first Decode succeeds and the next one reaches EOF. One token is not
// enough — a text file whose first byte is '[' or a digit is not JSON.
func decodesOneJSONValue(dec *json.Decoder) bool {
	var v, rest json.RawMessage
	if err := dec.Decode(&v); err != nil {
		return false
	}
	return dec.Decode(&rest) == io.EOF
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
