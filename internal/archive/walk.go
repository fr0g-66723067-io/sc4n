package archive

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// Member is one archive member's metadata, read from the directory without
// decompressing its content.
type Member struct {
	Name           string
	Size           int64 // declared uncompressed size
	CompressedSize int64
	Mode           uint32
	Method         uint16 // zip compression method, or 0 for tar
	CRC32          uint32
	Encrypted      bool
	IsDir          bool
	// LinkKind is "" for a regular file, else "symlink"/"hardlink"/"device".
	LinkKind string
	Link     string // link target, when LinkKind != ""
	// LocalName is the name in the local header when it disagrees with the
	// central directory, else "".
	LocalName string
	Index     int

	// The unexported fields below are how Open finds the member's bytes. They are
	// populated by Collect; a Member built by hand (with no source position) makes
	// Open return an error rather than read the wrong bytes.
	src      memberSrc
	dataOff  int64 // zip: offset of the member body
	localErr string
}

type memberSrc uint8

const (
	srcUnknown memberSrc = iota
	srcZip
	srcTar
)

// Members is an archive's member directory.
type Members struct {
	Format    artifact.Format
	Members   []Member
	Truncated bool  // the member cap was hit
	Trailing  int64 // bytes between the end-of-central-directory record and EOF
}

// ErrNotArchive is returned by Collect for content that is neither a zip nor a tar.
var ErrNotArchive = errors.New("archive: not a zip or tar archive")

// Collect reads the member directory of a zip or tar source without decompressing
// anything. It never fails on a malformed member; malformed structure is reported
// by Check.
func Collect(s source.Source, l limits.Limits) (Members, error) {
	if s == nil {
		return Members{}, ErrNotArchive
	}
	if looksZip(s, l) {
		entries, info, err := readZipDirectory(s, l)
		if err != nil {
			return Members{}, err
		}
		ms := Members{Format: artifact.FormatZip, Truncated: info.Truncated, Trailing: info.Trailing}
		ms.Members = make([]Member, 0, len(entries))
		for i := range entries {
			e := &entries[i]
			m := Member{
				Name:      e.name,
				Index:     i,
				Method:    e.method,
				CRC32:     e.crc,
				Encrypted: e.flags&0x1 != 0,
				src:       srcZip,
			}
			m.Size = clampU64(e.uncomp)
			m.CompressedSize = clampU64(e.comp)
			m.Mode = e.extAttrs >> 16
			m.IsDir = e.name != "" && strings.HasSuffix(e.name, "/")
			switch m.Mode & 0xF000 {
			case 0xA000:
				m.LinkKind = "symlink"
			case 0x2000, 0x6000, 0x1000:
				m.LinkKind = "device"
			case 0x4000:
				m.IsDir = true
			}
			body, localName, localErr := resolveLocal(s, *e)
			m.dataOff = body
			m.LocalName = localName
			m.localErr = localErr
			ms.Members = append(ms.Members, m)
		}
		return ms, nil
	}
	if isTar(s) {
		return collectTar(s, l)
	}
	return Members{}, ErrNotArchive
}

func clampU64(v uint64) int64 {
	if v > 1<<62 {
		return 1 << 62
	}
	return int64(v)
}

func isTar(s source.Source) bool {
	if s.Size() < 262 {
		return false
	}
	b, err := s.Bytes(257, 5)
	return (err == nil || len(b) >= 5) && len(b) >= 5 && string(b[:5]) == "ustar"
}

// Check emits the archive rules for ms (paths, links, name mismatch, encryption,
// CRC, duplicate names, entry/ratio/depth caps).
func (ms Members) Check(ctx *artifact.Ctx) {
	if ctx == nil || ctx.Sink == nil {
		return
	}
	if ms.Truncated {
		limits.Emit(ctx.Sink, limits.RuleEntries, "MaxEntries", int64(len(ms.Members)), int64(ctx.Limits.MaxEntries), "archive member cap reached")
	}
	if ms.Trailing > 0 {
		ctx.Sink.EmitExtra(ruleArchiveTrailingData, 0,
			strconv.FormatInt(ms.Trailing, 10)+" byte(s) follow the end-of-central-directory record, so the container and the appended region disagree about where it ends",
			map[string]string{"trailingBytes": strconv.FormatInt(ms.Trailing, 10)})
	}
	seen := make(map[string]bool, len(ms.Members))
	for i := range ms.Members {
		m := &ms.Members[i]
		checkMemberName(ctx, m)
		if m.LinkKind != "" {
			extra := map[string]string{"member": m.Name, "kind": m.LinkKind}
			if m.Link != "" {
				extra["target"] = m.Link
			}
			ctx.Sink.EmitExtra(ruleArchiveLink, 0, m.LinkKind+" member "+snippet(m.Name), extra)
		}
		if m.Encrypted {
			ctx.Sink.EmitExtra(ruleArchiveEncrypted, 0, "encrypted member "+snippet(m.Name), map[string]string{"member": m.Name})
		}
		if m.LocalName != "" {
			ctx.Sink.EmitExtra(ruleArchiveNameMismatch, 0,
				"central directory says "+snippet(m.Name)+" but local header says "+snippet(m.LocalName),
				map[string]string{"member": m.Name, "localName": m.LocalName})
		}
		if m.localErr != "" {
			ctx.Sink.EmitExtra(ruleArchiveMemberError, 0, m.localErr+" in member "+snippet(m.Name), map[string]string{"member": m.Name, "error": m.localErr})
		}
		if m.Name != "" {
			if seen[m.Name] {
				ctx.Sink.EmitExtra(ruleArchiveDuplicateName, 0, "duplicate member name "+snippet(m.Name), map[string]string{"member": m.Name})
			}
			seen[m.Name] = true
		}
		checkMemberRatio(ctx, m)
	}
}

// checkMemberName reports a name that would escape the extraction root or is
// otherwise unusable.
func checkMemberName(ctx *artifact.Ctx, m *Member) {
	if m.Name == "" {
		return
	}
	reasons := make([]string, 0, 3)
	if strings.ContainsRune(m.Name, 0) {
		reasons = append(reasons, "NUL byte")
	}
	if strings.HasPrefix(m.Name, "/") || strings.HasPrefix(m.Name, "\\") {
		reasons = append(reasons, "absolute path")
	}
	if len(m.Name) >= 2 && m.Name[1] == ':' {
		reasons = append(reasons, "drive letter")
	}
	if strings.ContainsRune(m.Name, '\\') {
		reasons = append(reasons, "backslash separator")
	}
	if hasDotDot(m.Name) {
		reasons = append(reasons, ".. traversal segment")
	}
	if len(m.Name) > 4096 {
		reasons = append(reasons, "over-long name")
	}
	if len(reasons) == 0 {
		return
	}
	ctx.Sink.EmitExtra(ruleArchivePath, 0, strings.Join(reasons, ", ")+" in member name "+snippet(m.Name),
		map[string]string{"member": m.Name, "reason": strings.Join(reasons, ",")})
}

// hasDotDot reports whether name contains a ".." path segment under either
// separator. It walks segments rather than searching for the substring, so a
// legitimate name like "a..b" is not reported.
func hasDotDot(name string) bool {
	for _, seg := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// checkMemberRatio reports a member whose declared expansion exceeds MaxRatio.
func checkMemberRatio(ctx *artifact.Ctx, m *Member) {
	if ctx.Limits.MaxRatio <= 0 || m.CompressedSize <= 0 || m.Size <= 0 {
		return
	}
	ratioCap := mulCap(m.CompressedSize, ctx.Limits.MaxRatio)
	if m.Size > ratioCap {
		limits.Emit(ctx.Sink, limits.RuleRatio, "MaxRatio", m.Size, ratioCap, "member "+snippet(m.Name))
	}
}

// Open decompresses one member, enforcing the per-member and cumulative caps while
// reading. The caller closes the returned reader.
func Open(s source.Source, l limits.Limits, m Member) (io.ReadCloser, error) {
	switch m.src {
	case srcZip:
		return openZipMember(s, l, m)
	case srcTar:
		return openTarMember(s, l, m)
	default:
		return nil, errors.New("archive: member has no source position; use Collect")
	}
}

// Scan is the generic parser: Collect + Check + dispatch every member through
// artifact.ScanMember. Registered for FormatZip, FormatTar and the supported
// single-stream compressors.
func Scan(ctx *artifact.Ctx, s source.Source) error {
	if ctx == nil || s == nil {
		return nil
	}
	switch ctx.Format {
	case artifact.FormatGzip, artifact.FormatZlib, artifact.FormatBzip2:
		return scanCompressed(ctx, s)
	case artifact.FormatXz, artifact.FormatLzma, artifact.FormatLz4, artifact.FormatZstd,
		artifact.FormatSevenZip, artifact.FormatRar, artifact.FormatZlibJoblibLegacy:
		emitUnsupportedFormat(ctx, s, ctx.Format)
		return nil
	}

	ms, err := Collect(s, ctx.Limits)
	if err != nil {
		return err
	}
	ms.Check(ctx)
	switch ms.Format {
	case artifact.FormatZip:
		scanZipMembers(ctx, s, ms)
	case artifact.FormatTar:
		scanTarMembers(ctx, s)
	}
	return nil
}

// ZipNames returns up to max zip member names, reading only the end-of-central-
// directory and the central directory. Format sniffers use it to discriminate
// torch/keras/npz/pt2 from a generic zip.
func ZipNames(s source.Source, l limits.Limits, max int) ([]string, error) {
	entries, _, err := readZipDirectory(s, l)
	if err != nil {
		return nil, err
	}
	n := len(entries)
	if max > 0 && n > max {
		n = max
	}
	out := make([]string, n)
	for i := range n {
		out[i] = entries[i].name
	}
	return out, nil
}

// scanZipMembers walks every member of a zip, opening it on demand. A large
// *stored* member is handed to the parser as a zero-copy Section of the parent
// mapping; a large *compressed* member is spilled to a private temp file.
func scanZipMembers(ctx *artifact.Ctx, s source.Source, ms Members) {
	max := maxBlob(ctx.Limits)
	var cumulative int64
	for i := range ms.Members {
		m := ms.Members[i]
		if m.IsDir || m.LinkKind != "" || m.Encrypted {
			continue
		}
		if m.Method == 0 && m.Size > max {
			src, err := source.Section(s, m.dataOff, m.CompressedSize, m.Name)
			if err != nil {
				emitOpenError(ctx, m.Name, err)
				continue
			}
			checkNativeShebang(ctx, m.Name, sourcePrefix(src))
			// The section is handed over through crcSource: the parser may read
			// only the header, so the container's one integrity check is performed
			// when the parser is done rather than not at all. ScanMember does not
			// close the source it is given, so the wrapper is closed here — the
			// Close *is* the check.
			cs := &crcSource{Source: src, sink: ctx.Sink, name: m.Name, want: m.CRC32}
			artifact.ScanMember(ctx, m.Name, cs)
			n := src.Size()
			_ = cs.Close()
			cumulative += n
			if exceededDecompressed(ctx, cumulative) {
				return
			}
			continue
		}
		rc, err := Open(s, ctx.Limits, m)
		if err != nil {
			emitOpenError(ctx, m.Name, err)
			continue
		}
		cumulative += processReader(ctx, m.Name, m.Size, rc, nil)
		_ = rc.Close()
		if exceededDecompressed(ctx, cumulative) {
			return
		}
	}
}

// scanTarMembers walks a tar in one pass, so a tar with many members is O(n).
func scanTarMembers(ctx *artifact.Ctx, s source.Source) {
	tr := newTarReader(s)
	max := ctx.Limits.MaxEntries
	if max <= 0 {
		max = limits.Default().MaxEntries
	}
	var cumulative int64
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			ctx.Sink.EmitExtra(ruleArchiveMemberError, 0, err.Error(), map[string]string{"error": err.Error()})
			return
		}
		if i >= max {
			return
		}
		if hdr.Typeflag != tarTypeReg && hdr.Typeflag != tarTypeRegA {
			continue
		}
		if hdr.Name == "" {
			continue
		}
		cumulative += processReader(ctx, hdr.Name, hdr.Size, tr, nil)
		if exceededDecompressed(ctx, cumulative) {
			return
		}
	}
}

func exceededDecompressed(ctx *artifact.Ctx, cumulative int64) bool {
	if ctx.Limits.MaxDecompressedBytes <= 0 || cumulative <= ctx.Limits.MaxDecompressedBytes {
		return false
	}
	limits.Emit(ctx.Sink, limits.RuleDecompressed, "MaxDecompressedBytes", cumulative, ctx.Limits.MaxDecompressedBytes, "archive")
	return true
}

// processReader reads one member from a forward reader and dispatches it. A member
// at or below MaxStringBlob is read into memory (the pooled path); a larger one is
// spilled to a private temp file and parsed through the normal Source machinery,
// so a member far larger than memory still has its content analysed. declared is
// the member's declared uncompressed size, or -1 when unknown, and is used only for
// the SC4N-LIMIT-SPILL evidence. onPrefix, when non-nil, sees the member's leading
// bytes before dispatch (the compression layer uses it to detect a nested wrapper).
// It returns the number of member bytes consumed, for the cumulative cap.
func processReader(ctx *artifact.Ctx, name string, declared int64, r io.Reader, onPrefix func([]byte)) int64 {
	max := maxBlob(ctx.Limits)
	probe, rerr := io.ReadAll(io.LimitReader(r, max+1))
	n := int64(len(probe))

	if onPrefix != nil {
		onPrefix(probe)
	}
	checkNativeShebang(ctx, name, probe)

	if n > max {
		capBytes := spillCap(ctx.Limits)
		src, err := source.Spill(name, io.MultiReader(bytes.NewReader(probe), r), capBytes)
		if err != nil {
			emitSpillError(ctx, name, declared, capBytes, err)
			scanPrefix(ctx, name, probe)
			return n
		}
		artifact.ScanMember(ctx, name, src)
		sn := src.Size()
		_ = src.Close()
		return sn
	}

	switch {
	case rerr == nil:
		artifact.ScanMemberBytes(ctx, name, probe)
	case errors.Is(rerr, errCRC):
		ctx.Sink.EmitExtra(ruleArchiveCRC, 0, "crc32 mismatch in member "+snippet(name), map[string]string{"member": name})
		// The data itself is complete; only the checksum disagrees, so scanning
		// it is still meaningful.
		artifact.ScanMemberBytes(ctx, name, probe)
	default:
		emitOpenError(ctx, name, rerr)
		scanPrefix(ctx, name, probe)
	}
	return n
}

// minScanBytes is the shortest prefix worth dispatching. Below it the content
// rules see a fragment of a header and report noise.
const minScanBytes = 16

// scanPrefix dispatches the bytes already read from a member whose read ended in
// a cap or a spill failure. Discarding them would lose every finding in the part
// of the member that was read, and the first bytes are exactly where an attacker
// puts the payload: the sibling CRC branch has always scanned them for that
// reason.
func scanPrefix(ctx *artifact.Ctx, name string, probe []byte) {
	if len(probe) >= minScanBytes {
		artifact.ScanMemberBytes(ctx, name, probe)
	}
}

// crcSource validates a stored member's CRC-32 when the parser is finished with
// it.
//
// The Section path exists so that a large member is never buffered, which means
// the CRC cannot be folded into the read: the parser is free to read a header and
// nothing else. Skipping the check would leave the container's only integrity
// signal silently unperformed for exactly the members that are too large to
// buffer, so it is done at Close by streaming the member once through crc32. The
// cost is one sequential pass over page-cache-resident bytes; the alternative is
// a scanner that reports a corrupt archive as clean.
type crcSource struct {
	source.Source
	sink *report.Sink
	name string
	want uint32
	done bool
}

var crcBufPool = sync.Pool{New: func() any { b := make([]byte, 1<<20); return &b }}

func (c *crcSource) Close() error {
	if !c.done {
		c.done = true
		// Every stored member is verified, including one whose declared CRC is 0:
		// crc32 of the empty string is 0, so the guard that used to skip that case
		// disabled the check for a legitimately empty member rather than avoiding
		// a false positive.
		sum := crc32.NewIEEE()
		bufp := crcBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(sum, c.Source.Reader(0), *bufp)
		crcBufPool.Put(bufp)
		if err == nil && sum.Sum32() != c.want {
			c.sink.EmitExtra(ruleArchiveCRC, 0, "crc32 mismatch in member "+snippet(c.name),
				map[string]string{"member": c.name})
		}
	}
	return c.Source.Close()
}

// emitSpillError classifies a failure to materialise a large member.
func emitSpillError(ctx *artifact.Ctx, name string, declared, capBytes int64, err error) {
	var st *source.SpillTooLargeError
	var le *LimitError
	switch {
	case errors.As(err, &st):
		value := declared
		if value <= st.Limit {
			value = st.Limit + 1
		}
		limits.Emit(ctx.Sink, limits.RuleSpill, "MaxSpillBytes", value, st.Limit, "member "+snippet(name))
	case errors.As(err, &le):
		limits.Emit(ctx.Sink, le.Rule, le.Limit, le.Value, le.Cap, le.Detail)
	case errors.Is(err, errCRC):
		ctx.Sink.EmitExtra(ruleArchiveCRC, 0, "crc32 mismatch in member "+snippet(name), map[string]string{"member": name})
	default:
		_ = capBytes
		ctx.Sink.EmitExtra(ruleArchiveMemberError, 0, err.Error()+" in member "+snippet(name),
			map[string]string{"member": name, "error": err.Error()})
	}
}

// checkNativeShebang reports a member that is a native executable or a script.
func checkNativeShebang(ctx *artifact.Ctx, name string, b []byte) {
	if kind, ok := bytescan.ValidNative(b); ok {
		ctx.Sink.EmitExtra(ruleArchiveNativeMember, 0, kind.String()+" executable in member "+snippet(name),
			map[string]string{"member": name, "kind": kind.String()})
	}
	if interp, ok := bytescan.ShebangAt(b); ok {
		ctx.Sink.EmitExtra(ruleArchiveShebang, 0, "#!"+interp+" script in member "+snippet(name),
			map[string]string{"member": name, "interpreter": interp})
	}
}

// sourcePrefix returns up to 1 MiB of a Source for the native/shebang check, which
// only needs the header region but tolerates a larger slice.
func sourcePrefix(s source.Source) []byte {
	n := s.Size()
	if n > 1<<20 {
		n = 1 << 20
	}
	b, err := s.Bytes(0, n)
	if err != nil && len(b) < int(n) {
		return b
	}
	return b[:n]
}

// emitOpenError classifies a failure to open/read a member.
func emitOpenError(ctx *artifact.Ctx, name string, err error) {
	var le *LimitError
	var um *unsupportedMethodError
	switch {
	case errors.As(err, &le):
		limits.Emit(ctx.Sink, le.Rule, le.Limit, le.Value, le.Cap, le.Detail)
	case errors.As(err, &um):
		ctx.Sink.EmitExtra(ruleArchiveUnsupportedCompression, 0,
			"zip member "+snippet(name)+" uses "+algorithmFor(um)+"; NOT DECOMPRESSED",
			map[string]string{"member": name, "algorithm": algorithmFor(um)})
	default:
		ctx.Sink.EmitExtra(ruleArchiveMemberError, 0, err.Error()+" in member "+snippet(name),
			map[string]string{"member": name, "error": err.Error()})
	}
}

// scanCompressed unwraps one supported compression layer and re-dispatches it,
// spilling to a temp file when the payload is larger than MaxStringBlob.
func scanCompressed(ctx *artifact.Ctx, s source.Source) error {
	c, ok := compressorForFormat(ctx.Format)
	if !ok {
		return nil
	}
	if !Supported(c) {
		emitUnsupportedFormat(ctx, s, ctx.Format)
		return nil
	}
	r, closer, err := decompressor(s, ctx.Limits, c)
	if err != nil {
		emitOpenError(ctx, ctx.Sink.Artifact(), err)
		return nil
	}
	if closer != nil {
		defer closer.Close()
	}
	processReader(ctx, decompressedName(ctx), -1, r, func(probe []byte) {
		if inner, ok := DetectCompressor(source.Mem("payload", probe), ctx.Limits); ok {
			ctx.Sink.EmitExtra(ruleArchiveNestedCompression, 0,
				c.String()+" payload is itself "+inner.String(),
				map[string]string{"outer": c.String(), "inner": inner.String()})
		}
	})
	return nil
}

// decompressor opens a supported single-stream compressor, applying the same
// MaxDecompressedBytes/MaxRatio caps while it is read.
func decompressor(s source.Source, l limits.Limits, c Compressor) (io.Reader, io.Closer, error) {
	switch c {
	case CompressorGzip:
		zr, err := gzip.NewReader(s.Reader(0))
		if err != nil {
			return nil, nil, err
		}
		return capReader(zr, l, s.Size(), "gzip layer"), zr, nil
	case CompressorZlib:
		zr, err := zlib.NewReader(s.Reader(0))
		if err != nil {
			return nil, nil, err
		}
		return capReader(zr, l, s.Size(), "zlib layer"), zr, nil
	case CompressorBzip2:
		return capReader(bzip2.NewReader(s.Reader(0)), l, s.Size(), "bzip2 layer"), nil, nil
	default:
		return nil, nil, ErrUnsupportedCompression
	}
}

func capReader(r io.Reader, l limits.Limits, compressed int64, detail string) io.Reader {
	capBytes, rule := decompressionCap(compressed, l)
	return &limitReader{r: r, remaining: capBytes, rule: rule, limit: limitName(rule), cap: capBytes, detail: detail}
}

func maxBlob(l limits.Limits) int64 {
	if l.MaxStringBlob > 0 {
		return l.MaxStringBlob
	}
	return limits.Default().MaxStringBlob
}

func spillCap(l limits.Limits) int64 {
	if l.MaxSpillBytes > 0 {
		return l.MaxSpillBytes
	}
	return limits.Default().MaxSpillBytes
}

// emitUnsupportedFormat reports a recognised-but-undecodable wrapper.
func emitUnsupportedFormat(ctx *artifact.Ctx, s source.Source, f artifact.Format) {
	c, _ := compressorForFormat(f)
	alg := c.String()
	if alg == "none" {
		alg = f.String()
	}
	ctx.Sink.EmitExtra(ruleArchiveUnsupportedCompression, 0,
		alg+" at offset 0; NOT DECOMPRESSED (no standard-library decoder)",
		map[string]string{"algorithm": alg, "format": f.String(), "offset": "0"})
}

// decompressedName strips a compression suffix from the artifact name so a nested
// finding reads "model.pkl" rather than "model.pkl.gz".
func decompressedName(ctx *artifact.Ctx) string {
	base := ctx.Sink.Artifact()
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	lower := strings.ToLower(base)
	for _, ext := range []string{".bzip2", ".bzip", ".gz", ".gzip", ".zlib", ".zz", ".bz2"} {
		if strings.HasSuffix(lower, ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	if base == "" {
		base = "payload"
	}
	return base
}

func snippet(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// parser is the registered Parser for every archive/compression format.
type parser struct{}

func (parser) Parse(ctx *artifact.Ctx, s source.Source) error { return Scan(ctx, s) }

// sniffZip recognises a zip archive, including one with a prefix.
func sniffZip(s source.Source, l limits.Limits) (artifact.Format, bool) {
	if looksZip(s, l) {
		return artifact.FormatZip, true
	}
	return artifact.FormatUnknown, false
}

func init() {
	// Priority 60 sits below the built-in magic/tarkind/pickle sniffers, so a
	// zip whose members identify it as torch/keras/npz/pt2 is claimed by a
	// higher-priority sniffer from those packages, and this one catches only a
	// still-generic zip (including a prefixed archive the magic table misses).
	artifact.RegisterSniffer("archive-zip", 60, sniffZip)

	p := parser{}
	for _, f := range []artifact.Format{
		artifact.FormatZip, artifact.FormatTar,
		artifact.FormatGzip, artifact.FormatZlib, artifact.FormatBzip2,
		artifact.FormatXz, artifact.FormatLzma, artifact.FormatLz4, artifact.FormatZstd,
		artifact.FormatSevenZip, artifact.FormatRar, artifact.FormatZlibJoblibLegacy,
	} {
		if _, ok := artifact.ParserFor(f); !ok {
			artifact.RegisterParser(f, p)
		}
	}

	// Capability rows for the container/compression formats already exist in
	// internal/artifact's magic table; register one only if it is absent so this
	// package cannot collide with them.
	for _, info := range []artifact.Info{
		{Format: artifact.FormatZip, Magic: "PK\\x03\\x04", Depth: artifact.DepthStructural, Container: true,
			Notes: "stored and deflate members (plus zip64) are read; encrypted entries, CRC mismatches, duplicate names, absolute or traversal paths, link members, local-vs-central name disagreements and bomb ratios are reported; members are never extracted to disk."},
		{Format: artifact.FormatTar, Magic: "ustar at offset 257", Depth: artifact.DepthStructural, Container: true,
			Notes: "ustar and GNU long-name members are read; absolute, traversal and link members are reported."},
		{Format: artifact.FormatGzip, Magic: "\\x1f\\x8b", Depth: artifact.DepthStructural, Container: true,
			Notes: "single-member streams are unwrapped and the payload re-dispatched, up to MaxDepth; the whole-file ratio is bounded by MaxRatio."},
		{Format: artifact.FormatZlib, Magic: "\\x78 01|9c|da", Depth: artifact.DepthStructural, Container: true,
			Notes: "zlib streams are unwrapped and re-dispatched; joblib's default compression is zlib, so this is the common path into a joblib payload."},
		{Format: artifact.FormatBzip2, Magic: "BZh", Depth: artifact.DepthStructural, Container: true,
			Notes: "bzip2 streams are unwrapped and re-dispatched; gzip(bzip2(pickle)) is the published modelscan double-compression bypass, so this wrapper is supported precisely because it is used that way."},
	} {
		if _, ok := artifact.FormatInfo(info.Format); !ok {
			artifact.RegisterFormat(info)
		}
	}
}
