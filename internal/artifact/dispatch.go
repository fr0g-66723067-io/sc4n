package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
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
	// Partial names artifacts (paths as the report names them, or paths relative
	// to Root) whose bytes are a truncated copy — a header slice of a larger file.
	// A rule that would compare a declared extent against the file on disk must ask
	// before it claims a violation: measured on BAAI/bge-m3, a 724 KB ONNX model
	// whose sibling data file is 2.2 GB and was fetched as a 2 MiB slice produced
	// 389 high findings that said its external_data lengths ran past the end.
	Partial []string
	// TopLimits is the budget as configured, used for nested containers as the
	// starting point.
	TopLimits limits.Limits

	mu      sync.Mutex
	seen    map[string]string
	partial map[string]bool

	spentDecompressed int64
	spentSpill        int64
	decompressedOnce  sync.Once
	spillOnce         sync.Once
}

// IsPartial reports whether the named artifact is a truncated copy.
func (s *Session) IsPartial(name string) bool {
	if s == nil || len(s.partial) == 0 {
		return false
	}
	if s.partial[name] {
		return true
	}
	if s.Root != "" {
		if rel, err := filepath.Rel(s.Root, name); err == nil && s.partial[rel] {
			return true
		}
	}
	return s.partial[filepath.Base(name)]
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

// SetPartial marks artifacts as truncated copies. It is called before the walk
// starts, so a rule can ask about a file it is not itself scanning.
func (s *Session) SetPartial(names []string) {
	if len(names) == 0 {
		return
	}
	s.partial = make(map[string]bool, len(names))
	for _, n := range names {
		s.partial[n] = true
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

// ChargeDecompressed adds n bytes to the scan-wide decompressed budget and
// returns the new total. The budget is scan-wide, not per walker: a nested
// archive that restarted its own cumulative counter multiplied the declared cap
// by the nesting depth.
func (s *Session) ChargeDecompressed(n int64) int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > 0 {
		s.spentDecompressed += n
	}
	return s.spentDecompressed
}

// RemainingDecompressed returns the bytes left in the scan-wide budget, clamped
// at zero. A zero result means the next member must not be opened.
func (s *Session) RemainingDecompressed() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cap := s.TopLimits.MaxDecompressedBytes
	if cap <= 0 {
		cap = limits.Default().MaxDecompressedBytes
	}
	if s.spentDecompressed >= cap {
		return 0
	}
	return cap - s.spentDecompressed
}

// ChargeSpill adds n bytes to the scan-wide materialisation budget.
func (s *Session) ChargeSpill(n int64) int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > 0 {
		s.spentSpill += n
	}
	return s.spentSpill
}

// RemainingSpill returns the bytes left for materialised members, clamped at
// zero.
func (s *Session) RemainingSpill() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cap := s.TopLimits.MaxSpillBytes
	if cap <= 0 {
		cap = limits.Default().MaxSpillBytes
	}
	if s.spentSpill >= cap {
		return 0
	}
	return cap - s.spentSpill
}

// ReportDecompressedLimit emits the one SC4N-LIMIT-DECOMPRESSED for the scan,
// even when a nested container reaches the same exhausted budget from another
// walker.
func (s *Session) ReportDecompressedLimit(sink *report.Sink, value, cap int64) {
	if s == nil || sink == nil {
		return
	}
	s.decompressedOnce.Do(func() {
		if cap <= 0 {
			cap = limits.Default().MaxDecompressedBytes
		}
		limits.Emit(sink, limits.RuleDecompressed, "MaxDecompressedBytes", value, cap,
			"scan-wide decompressed budget")
	})
}

// ReportSpillLimit emits the one SC4N-LIMIT-SPILL for the scan-wide
// materialisation budget.
func (s *Session) ReportSpillLimit(sink *report.Sink, value, cap int64) {
	if s == nil || sink == nil {
		return
	}
	s.spillOnce.Do(func() {
		if cap <= 0 {
			cap = limits.Default().MaxSpillBytes
		}
		limits.Emit(sink, limits.RuleSpill, "MaxSpillBytes", value, cap,
			"scan-wide spill budget")
	})
}

// Ctx wrappers are nil-safe so a parser sees the same API whether it was
// constructed by a scan or by a unit test.

func (c *Ctx) ChargeDecompressed(n int64) int64 {
	if c == nil {
		return 0
	}
	return c.Session.ChargeDecompressed(n)
}

func (c *Ctx) RemainingDecompressed() int64 {
	if c == nil {
		return 0
	}
	return c.Session.RemainingDecompressed()
}

func (c *Ctx) ChargeSpill(n int64) int64 {
	if c == nil {
		return 0
	}
	return c.Session.ChargeSpill(n)
}

func (c *Ctx) RemainingSpill() int64 {
	if c == nil {
		return 0
	}
	return c.Session.RemainingSpill()
}

func (c *Ctx) ReportDecompressedLimit(value, cap int64) {
	if c == nil {
		return
	}
	c.Session.ReportDecompressedLimit(c.Sink, value, cap)
}

func (c *Ctx) ReportSpillLimit(value, cap int64) {
	if c == nil {
		return
	}
	c.Session.ReportSpillLimit(c.Sink, value, cap)
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

// containerMagics are the leading magics whose format is a container the archive
// layer unwraps, in one place because two callers need the same list: the magic
// sniffer (through magicSniffer) and artifact.LeadingContainerMagic.
var containerMagics = []struct {
	magic  []byte
	format Format
	at     int
}{
	{[]byte("PK\x03\x04"), FormatZip, 0},
	{[]byte("PK\x05\x06"), FormatZip, 0},
	{[]byte("PK\x07\x08"), FormatZip, 0},
	{[]byte("\x1f\x8b"), FormatGzip, 0},
	{[]byte("BZh"), FormatBzip2, 0},
	{[]byte("\x78\x01"), FormatZlib, 0},
	{[]byte("\x78\x9c"), FormatZlib, 0},
	{[]byte("\x78\xda"), FormatZlib, 0},
	{[]byte("\xfd7zXZ\x00"), FormatXz, 0},
	{[]byte("\x5d\x00\x00"), FormatLzma, 0},
	{[]byte("\x04\x22\x4d\x18"), FormatLz4, 0},
	{[]byte("\x28\xb5\x2f\xfd"), FormatZstd, 0},
	{[]byte("7z\xbc\xaf\x27\x1c"), FormatSevenZip, 0},
	{[]byte("Rar!\x1a\x07"), FormatRar, 0},
	// Media containers: their bodies are entropy-coded, so a PROTO byte inside the
	// first 64 bytes is a coincidence, not a payload prefix.
	{[]byte("RIFF"), FormatUnknown, 0}, // WebP, WAV, AVI
	{[]byte("\x89PNG\r\n\x1a\n"), FormatUnknown, 0},
	{[]byte("\xff\xd8\xff"), FormatUnknown, 0}, // JPEG
	{[]byte("GIF8"), FormatUnknown, 0},
	{[]byte("BM"), FormatUnknown, 0},      // BMP
	{[]byte("II*\x00"), FormatUnknown, 0}, // TIFF, little endian
	{[]byte("MM\x00*"), FormatUnknown, 0}, // TIFF, big endian
	{[]byte("%PDF-"), FormatUnknown, 0},
	{[]byte("OggS"), FormatUnknown, 0},
	{[]byte("fLaC"), FormatUnknown, 0},
	{[]byte("ID3"), FormatUnknown, 0},  // MP3
	{[]byte("ftyp"), FormatUnknown, 4}, // MP4/MOV
	{[]byte("WEBP"), FormatUnknown, 8},
}

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
}

// weakMagicSniffer holds the signatures that are too short to be an identity on
// their own: a two-byte zlib header and a three-byte lzma one. They are claimed at
// a priority *below* every structured content sniffer, because a stream that merely
// starts with those bytes is common in files that are something else — a
// safetensors file's first eight bytes are a little-endian header length, the
// official writer pads the header to a multiple of 8, and a header of 376, 40056 or
// 55928 bytes puts 78 01, 78 9c or 78 da at offset 0. Claimed at magic priority, a
// perfectly valid model.safetensors was dispatched as zlib and its own parser never
// ran: two medium findings about a zlib stream that was not there, and no
// SC4N-SAFETENSORS-* at all.
var weakMagicSniffer = []struct {
	magic  []byte
	format Format
	at     int
}{
	{[]byte("\x78\x01"), FormatZlib, 0},
	{[]byte("\x78\x9c"), FormatZlib, 0},
	{[]byte("\x78\xda"), FormatZlib, 0},
	{[]byte("\x5d\x00\x00"), FormatLzma, 0},
}

func init() {
	RegisterSniffer("magic", 100, sniffMagic)
	// Below every structured sniffer (the lowest of those is msgpack at 50) and
	// above the text fallback, so a zlib-shaped prefix cannot outrank a file that
	// is really a model: see weakMagicSniffer.
	RegisterSniffer("magic-weak", 55, sniffWeakMagic)
	RegisterSniffer("tarkind", 90, sniffTar)
	RegisterSniffer(textFallbackSniffer, -100, sniffText)

	RegisterFormat(Info{
		Format: FormatUnknown, Magic: "(none)", Depth: DepthNone,
		Notes: "no sniffer matched; the file is reported as \"unknown\" and only the format-independent layers run — native magic, the format-versus-extension check, a shebang, and the name-driven rules for .pth, .start, .pyc and Dockerfile. No parser runs and no string indicators: a file that reaches \"unknown\" had no text sniff, so an indicator inside it is not reported.",
	})
	RegisterFormat(Info{
		Format: FormatZip, Magic: "PK\\x03\\x04", Depth: DepthStructural, Container: true,
		Notes: "stored and deflate members (plus zip64) are read; encrypted entries, CRC mismatches, duplicate names, absolute or traversal paths, link members, local-vs-central name disagreements and bomb ratios are reported; members are never extracted to disk.",
	})
	RegisterFormat(Info{
		Format: FormatTar, Magic: "ustar at offset 257", Depth: DepthStructural, Container: true,
		Notes: "ustar and GNU long-name members are read; absolute, traversal and link members are reported.",
	})
	RegisterFormat(Info{
		Format: FormatGzip, Magic: "\\x1f\\x8b", Depth: DepthStructural, Container: true,
		Notes: "single-member streams are unwrapped and the payload re-dispatched, up to MaxDepth; the whole-file ratio is bounded by MaxRatio.",
	})
	RegisterFormat(Info{
		Format: FormatZlib, Magic: "\\x78 01|9c|da", Depth: DepthStructural, Container: true,
		Notes: "zlib streams are unwrapped and re-dispatched; joblib's default compression is zlib, so this is the common path into a joblib payload.",
	})
	RegisterFormat(Info{
		Format: FormatBzip2, Magic: "BZh", Depth: DepthStructural, Container: true,
		Notes: "bzip2 streams are unwrapped and re-dispatched; gzip(bzip2(pickle)) is the published modelscan double-compression bypass, so this wrapper is supported precisely because it is used that way.",
	})
	RegisterFormat(Info{
		Format: FormatXz, Magic: "\\xfd7zXZ\\x00", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED: no xz decoder in the Go standard library and sc4n has no third-party dependencies. The presence of xz in a model file is reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION (medium) with the offset, and any pickle or native payload inside it is NOT scanned.",
	})
	RegisterFormat(Info{
		Format: FormatLzma, Magic: "\\x5d\\x00\\x00", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib lzma decoder). The 2-byte magic is weak and collides with ordinary data, so it is only reported after a header-shape sanity check. Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION.",
	})
	RegisterFormat(Info{
		Format: FormatLz4, Magic: "\\x04\\x22\\x4d\\x18", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib lz4 decoder; joblib lz4 is a documented joblib compression method). Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION.",
	})
	RegisterFormat(Info{
		Format: FormatZstd, Magic: "\\x28\\xb5\\x2f\\xfd", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib zstd decoder). Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION.",
	})
	RegisterFormat(Info{
		Format: FormatSevenZip, Magic: "7z\\xbc\\xaf\\x27\\x1c", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED. A 7z file named .pt is the February 2025 Hugging Face campaign: the loader (patched torch) still deserialised the payload while every extension-driven scanner saw \"not a zip\". Reported as SC4N-TORCH-7Z (critical) when the name suggests a torch checkpoint, plus SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION.",
	})
	RegisterFormat(Info{
		Format: FormatRar, Magic: "Rar!\\x1a\\x07", Depth: DepthNone, Container: false,
		Notes: "NOT DECOMPRESSED (no stdlib rar decoder). Reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION.",
	})
	RegisterFormat(Info{
		Format: FormatZlibJoblibLegacy, Magic: "ZF", Depth: DepthNone, Container: false,
		Notes: "joblib's pre-0.10 z-file framing: a 21-byte header — \"ZF\" plus the uncompressed length as a space-padded 0x-prefixed hex string — followed by a stdlib zlib stream. sc4n recognises the frame (both the header shape and the zlib stream must be plausible) but does not unwrap it, so the payload is not scanned; reported as SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION naming the framing.",
	})
	RegisterFormat(Info{
		Format: FormatNative, Magic: "\\x7fELF | MZ | Mach-O | OLE | !<arch>", Depth: DepthShallow,
		Notes: "header validity is checked with debug/elf, debug/macho and debug/pe; a bare magic match without a valid header is reported at info only. A valid executable inside a model artifact is SC4N-POLYGLOT-NATIVE.",
	})

	RegisterFormat(Info{
		Format: FormatJSON, Magic: "leading { or [", Depth: DepthStructural,
		Notes: "routing is name-dependent. The Hugging Face metadata names (config.json, adapter_config.json, modules.json, model_index.json, dataset_info.json) and the tokenizer files (tokenizer.json, tokenizer_config.json, special_tokens_map.json) are decoded with encoding/json and the metadata, tokenizer, chat-template and card-injection rule families run over the decoded document — every JSON value in the stream, not just the first. Any other JSON is scanned as raw text by the shared indicator engine, with any vocabulary it holds (a top-level or model.vocab table, merges, added-token contents) left out of the prose pass: a tokenizer vocabulary is data, and judging it as prose reported code execution on every Qwen tokenizer and a Unicode anomaly on every multilingual one. The markdown note covers the document tier that .txt and .log files share.",
	})
	RegisterFormat(Info{
		Format: FormatJSONLines, Magic: "one JSON value per line", Depth: DepthShallow,
		Notes: "no per-line decoder: the file is scanned as text by the shared indicator engine, so an indicator anywhere in it is found, while a malformed line is not reported and no per-line structure is decoded.",
	})
	RegisterFormat(Info{
		Format: FormatPython, Magic: "text; extension .py", Depth: DepthStructural,
		Notes: "hand-written Python 3.14 lexer plus a statement-level taint engine over the source/sink pairs listed in internal/pysrc/rules.go (isSourceDotted, isShellSink, isDeserializeSink, isNetworkSink and the standalone-construct predicates); there is no type inference, so taint is intra-statement and intra-function.",
	})
	RegisterFormat(Info{
		Format: FormatNotebook, Magic: "JSON with a \"cells\" array", Depth: DepthStructural,
		Notes: "code cells are mapped back to their original line numbers in the .ipynb file; IPython magics and shell escapes are reported separately from ordinary Python findings.",
	})
	RegisterFormat(Info{
		Format: FormatJinja, Magic: "text containing {{ }} or {% %}", Depth: DepthStructural,
		Notes: "Jinja2 lexer plus an introspection/dynamic-name analyzer, applied to .jinja/.j2/.tmpl files, chat_template.jinja, tokenizer_config.json:chat_template, config.json-embedded templates and GGUF tokenizer.chat_template.",
	})
	RegisterFormat(Info{
		Format: FormatMarkdown, Magic: "text; extension .md", Depth: DepthStructural,
		Notes: "YAML frontmatter (subset reader) plus the prompt-injection and Unicode-anomaly detectors, applied to model and dataset cards and to the other prose documents a repository carries (.txt, .text, .log). Those share the card tier: the injection table, the invisible-character detectors and secret values run, while the rules about what a loader or a callable would do with a string do not, because nothing loads a .txt.",
	})
	RegisterFormat(Info{
		Format: FormatYAML, Magic: "text; extension .yml/.yaml", Depth: DepthShallow,
		Notes: "no YAML library is linked, so YAML is scanned as text for string indicators, prompt-injection content and the GitHub Actions pull_request_target pattern; it is not parsed into a document tree.",
	})
	RegisterFormat(Info{
		Format: FormatText, Magic: "(fallback)", Depth: DepthShallow,
		Notes: "any file with no NUL byte in its first kilobyte and no structural sniffer match is scanned with the string-indicator engine at depth shallow. Extension-specific rules (.pth, .start, .pyc, Dockerfile) still apply.",
	})
}

// LeadingContainerMagic reports whether b begins with a magic that another parser
// owns: a compression or archive format this tree unwraps (zip, tar, gzip, zlib,
// bzip2, xz, lz4, zstd, 7z, rar), or a media container whose bytes are compressed
// by definition (RIFF/WebP, PNG, JPEG, GIF, BMP, TIFF, PDF, Ogg, FLAC, MP3, MP4).
//
// It exists for the pickle sniffer's prefix search: a stream that opens with such
// a magic and carries a PROTO byte a few bytes in — zlib's level-0 framing does
// that with a pickle verbatim, and so does any compressed image body by chance —
// would be claimed as a pickle and walked as opcodes, reporting the container's own
// bytes as SC4N-PICKLE-PREFIX and SC4N-PICKLE-TRAILING instead of dispatching the
// file as what it is. Measured on a 196 KB WebP in a real repository: the pickle
// sniffer claimed it, found a 14-byte accidental stream at offset 129551 and
// reported two highs about an image.
func LeadingContainerMagic(b []byte) bool {
	for _, m := range containerMagics {
		if len(b) >= m.at+len(m.magic) && bytes.HasPrefix(b[m.at:], m.magic) {
			return true
		}
	}
	return false
}

func sniffMagic(s source.Source, l limits.Limits) (Format, bool) {
	return sniffTable(s, magicSniffer)
}

// sniffWeakMagic claims the short signatures, at a priority below every structured
// sniffer; see weakMagicSniffer.
func sniffWeakMagic(s source.Source, l limits.Limits) (Format, bool) {
	return sniffTable(s, weakMagicSniffer)
}

// sniffTable runs one magic table against the artifact's head. Both tables hold the
// same struct type, so the scan is written once.
func sniffTable(s source.Source, table []struct {
	magic  []byte
	format Format
	at     int
},
) (Format, bool) {
	head, err := s.Bytes(0, min64(s.Size(), maxMagicProbe))
	if err != nil && (len(head) < 8) {
		return FormatUnknown, false
	}
	for _, m := range table {
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

// sniffText is the last-resort classifier. It runs only when no structural
// sniffer matched, and it never claims a binary file: a NUL byte in the first
// kilobyte disqualifies the content.
func sniffText(s source.Source, l limits.Limits) (Format, bool) {
	n := min64(s.Size(), 1024)
	head, err := s.Bytes(0, n)
	if err != nil && len(head) == 0 {
		return FormatUnknown, false
	}
	if bytes.IndexByte(head, 0) < 0 {
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
	// A NUL in the head means binary, with one exception: when the artifact
	// *opens* as a document — a printable prefix at least minTextPrefix long — it
	// is text with binary appended, and the content layer reports that as
	// SC4N-CONTENT-NOT-UTF8 while still running the byte-safe indicators over the
	// whole buffer. Without the exception, one appended byte silenced the whole
	// scan: a config.json plus a NUL was dispatched "unknown", and "unknown" has no
	// parser and no indicator pass, so its finding list was empty and read exactly
	// like a clean file's.
	if p := textPrefixLen(head); p >= minTextPrefix {
		return FormatText, true
	}
	return FormatUnknown, false
}

// textPrefixLen returns the length of the leading run of bytes a text format can
// hold: ASCII printable plus tab, newline and carriage return. It stops at the
// first control byte or NUL, which is what makes "the artifact opens as text"
// decidable without reading the whole file.
func textPrefixLen(b []byte) int {
	for i, c := range b {
		switch {
		case c >= 0x20 && c < 0x7f:
		case c == '\t' || c == '\n' || c == '\r':
		default:
			return i
		}
	}
	return len(b)
}

// textFallbackSniffer is the name of the last-resort classifier: it claims
// anything that reads as text and nothing more specific did. Sniff treats a claim
// from it as weaker than a bare native magic, which is the one place this name
// matters.
const textFallbackSniffer = "text"

// minTextPrefix is how many bytes of a NUL-free printable prefix make "text with
// binary appended" a reading of the file rather than a coincidence: every byte of
// that prefix must be printable, which one random byte in 256 is not.
const minTextPrefix = 64

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
