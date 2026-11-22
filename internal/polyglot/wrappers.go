package polyglot

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"io"
	"sort"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// WindowBytes bounds every magic scan this layer performs.
//
// The bound is not an optimisation, it is a correctness requirement: sc4n must
// scan a 13 GB F16 safetensors file in bounded memory and in time proportional to
// the file's *header*, not its size. The two regions where a second format can
// realistically hide are the head (a prefixed/leading payload, or a header that is
// itself another format) and the tail (an appended payload after the model's own
// STOP/EOCD). Reading the first and last 1 MiB costs at most 2 MiB per artifact,
// no matter how large the artifact is, and never scans the whole file.
//
// The tradeoff is stated in the rule docs: a native header buried strictly in the
// middle of a 13 GB tensor body is not found. That is deliberate — recovering it
// would require a whole-file pass, which is exactly the cost this bound exists to
// avoid, and a payload at a page-aligned interior offset is not reachable by the
// loaders sc4n models.
const WindowBytes = 1 << 20

// Window is one bounded byte range read from the artifact.
type Window struct {
	// Base is the absolute offset of Data inside the artifact.
	Base int64
	Data []byte
}

// readWindow returns the bytes at [off, off+n) clamped to the artifact. A short
// slice (the artifact ends before off+n) is returned as-is; the caller only ever
// uses it for magic matching, where a short read simply means "nothing found".
func readWindow(s source.Source, off, n int64) Window {
	if off < 0 {
		off = 0
	}
	if n <= 0 {
		return Window{Base: off}
	}
	b, err := s.Bytes(off, n)
	if err != nil && len(b) == 0 {
		return Window{Base: off}
	}
	return Window{Base: off, Data: b}
}

// MagicWindows returns the head and tail windows. The tail is emitted only when
// it does not overlap the head: the tail range is [size-WindowBytes, size) and
// the head's is [0, WindowBytes), so below two windows the tail is a subset of
// the head, and emitting it would scan those bytes twice and report every
// indicator in them once per window at the same offset. At exactly two windows
// the two are disjoint and both are needed — the second window is not covered by
// the head. It is exported for internal/native, which applies the same bound to a
// native artifact.
func MagicWindows(s source.Source, size int64) []Window {
	head := readWindow(s, 0, WindowBytes)
	out := []Window{head}
	if size >= 2*WindowBytes {
		out = append(out, readWindow(s, size-WindowBytes, WindowBytes))
	}
	return out
}

// containerMagic is a signature that identifies a container only at its own
// canonical anchor. Scanning for these at arbitrary interior offsets would make
// every zip that stores a tar (byte 257 of a stored member's data) a false
// polyglot, so the anchor is part of the signature.
type containerMagic struct {
	magic  []byte
	format artifact.Format
}

// leadingContainers are the container signatures that must occupy offset 0.
var leadingContainers = []containerMagic{
	{[]byte("PK\x03\x04"), artifact.FormatZip},
	{[]byte("PK\x05\x06"), artifact.FormatZip},
	{[]byte("PK\x07\x08"), artifact.FormatZip},
	{[]byte("7z\xbc\xaf\x27\x1c"), artifact.FormatSevenZip},
	{[]byte("Rar!\x1a\x07"), artifact.FormatRar},
	{[]byte("\x1f\x8b"), artifact.FormatGzip},
	{[]byte("BZh"), artifact.FormatBzip2},
	{[]byte("\xfd7zXZ\x00"), artifact.FormatXz},
	{[]byte("\x04\x22\x4d\x18"), artifact.FormatLz4},
	{[]byte("\x28\xb5\x2f\xfd"), artifact.FormatZstd},
	{[]byte("\x89HDF\r\n\x1a\n"), artifact.FormatHDF5},
}

// tarMagicAnchor is where the tar "ustar" magic lives: 257 bytes into a tar
// header, which for a container polyglot is 257 bytes into the file.
const tarMagicAnchor = 257

// leadingContainer returns the container format whose signature starts b, or
// FormatUnknown.
func leadingContainer(b []byte) artifact.Format {
	for _, c := range leadingContainers {
		if bytes.HasPrefix(b, c.magic) {
			return c.format
		}
	}
	return artifact.FormatUnknown
}

// hasTarAnchor reports whether b carries the tar ustar magic at the canonical
// offset. The tar header's checksum is not verified: the coexistence of the two
// anchors is the signal the rule claims, and the rule text says so.
func hasTarAnchor(b []byte) bool {
	return len(b) >= tarMagicAnchor+5 && bytes.HasPrefix(b[tarMagicAnchor:], []byte("ustar"))
}

// textFormats are the formats where a leading "#!" is idiomatic rather than a
// contradiction. The shebang rule is suppressed for all of them so that a normal
// Python file, notebook or Markdown card is never reported.
var textFormats = map[artifact.Format]bool{
	artifact.FormatText:      true,
	artifact.FormatPython:    true,
	artifact.FormatNotebook:  true,
	artifact.FormatJinja:     true,
	artifact.FormatMarkdown:  true,
	artifact.FormatYAML:      true,
	artifact.FormatJSON:      true,
	artifact.FormatJSONLines: true,
}

// ValidateNativeHeader validates the native header that begins at off.
//
// ELF, PE and Mach-O are validated by handing the standard library's own header
// parser a view of the *whole* artifact from off, so a large executable whose
// section table sits at the end still validates. ar and OLE have no stdlib parser,
// so they use bytescan.ValidNative's structural check over a bounded slice.
//
// It is exported so that internal/native validates a native artifact's own header
// with the same code the universal layer uses: the two must never disagree about
// whether a header is real, because one of them reports it at high severity and
// the other at info.
func ValidateNativeHeader(s source.Source, size, off int64) (bytescan.NativeKind, bool) {
	if off < 0 || off >= size {
		return bytescan.NativeNone, false
	}
	hdr, _ := s.Bytes(off, min(size-off, 64))
	kind := bytescan.MagicAt(hdr)
	if kind == bytescan.NativeNone {
		return kind, false
	}
	switch kind {
	case bytescan.NativeArchive, bytescan.NativeOLE:
		b, _ := s.Bytes(off, min(size-off, WindowBytes))
		_, ok := bytescan.ValidNative(b)
		return kind, ok
	}
	sr := io.NewSectionReader(s, off, size-off)
	switch kind {
	case bytescan.NativeELF:
		f, err := elf.NewFile(sr)
		if err != nil {
			return kind, false
		}
		_ = f.Close()
		return kind, true
	case bytescan.NativePE, bytescan.NativeAPE:
		f, err := pe.NewFile(sr)
		if err != nil {
			return kind, false
		}
		_ = f.Close()
		return kind, true
	case bytescan.NativeMachO:
		// The universal (fat) container has its own parser; the thin magics —
		// including the byte-swapped pair — are read by macho.NewFile, which
		// detects the endianness itself. debug/macho reads FAT_MAGIC only, so the
		// fat variants it rejects never reach here as a validated header.
		if bytes.HasPrefix(hdr, []byte("\xca\xfe\xba\xbe")) {
			if !bytescan.FatArchCountPlausible(hdr) || !fatMachHeadersPlausible(s, size, off) {
				return kind, false
			}
			f, err := macho.NewFatFile(sr)
			if err != nil {
				return kind, false
			}
			_ = f.Close()
			return kind, true
		}
		if !bytescan.MachLoadCommandsPlausible(hdr) {
			return kind, false
		}
		f, err := macho.NewFile(sr)
		if err != nil {
			return kind, false
		}
		_ = f.Close()
		return kind, true
	}
	return kind, false
}

// fatMachHeadersPlausible validates every arch's inner Mach header before
// debug/macho can allocate a table from the fat header. The source is read
// rather than a 64-byte view because the arch headers can be anywhere in the
// artifact, and at most MaxFatArches entries are touched.
func fatMachHeadersPlausible(s source.Source, size, off int64) bool {
	hdr, err := s.Bytes(off, 8)
	if err != nil && len(hdr) < 8 {
		return false
	}
	if !bytescan.FatArchCountPlausible(hdr) {
		return false
	}
	is64 := bytes.HasPrefix(hdr, []byte("\xca\xfe\xba\xbf")) ||
		bytes.HasPrefix(hdr, []byte("\xbf\xba\xfe\xca"))
	big := bytes.HasPrefix(hdr, []byte("\xca\xfe\xba\xbe")) ||
		bytes.HasPrefix(hdr, []byte("\xca\xfe\xba\xbf"))
	entry := int64(20)
	if is64 {
		entry = 32
	}
	count := int64(binary.BigEndian.Uint32(hdr[4:]))
	if !big {
		count = int64(binary.LittleEndian.Uint32(hdr[4:]))
	}
	if count <= 0 || count > bytescan.MaxFatArches {
		return false
	}
	for i := int64(0); i < count; i++ {
		at := off + 8 + i*entry
		if at+entry > off+size {
			return false
		}
		e, err := s.Bytes(at, entry)
		if err != nil && int64(len(e)) < entry {
			return false
		}
		var archOff uint64
		switch {
		case big && is64:
			archOff = binary.BigEndian.Uint64(e[8:])
		case big:
			archOff = uint64(binary.BigEndian.Uint32(e[8:]))
		case is64:
			archOff = binary.LittleEndian.Uint64(e[8:])
		default:
			archOff = uint64(binary.LittleEndian.Uint32(e[8:]))
		}
		if archOff > uint64(size) || int64(archOff)+24 > size {
			return false
		}
		mh, err := s.Bytes(off+int64(archOff), 24)
		if err != nil && len(mh) < 24 {
			return false
		}
		if !bytescan.MachLoadCommandsPlausible(mh) {
			return false
		}
	}
	return true
}

// ExecImportNames returns the dynamic symbols from the ELF header at off that
// name process-control primitives, sorted and deduplicated, capped at maxExecNames.
//
// It is a symbol-table walk, not a disassembly: the names are what the dynamic
// loader will bind when the binary is loaded, so the finding is a statement about
// the loader, not about the code. debug/elf needs only SHT_DYNSYM and its linked
// string table, both of which are in the section headers of any stripped binary.
//
// An error (or a non-ELF artifact) returns nil: an artifact that does not
// validate as an executable is SC4N-POLYGLOT-MAGIC-ONLY's job, and a rule that
// fired on a broken header would be reporting the parse, not the imports.
func ExecImportNames(s source.Source, size, off int64) []string {
	if off < 0 || off >= size {
		return nil
	}
	f, err := elf.NewFile(io.NewSectionReader(s, off, size-off))
	if err != nil {
		return nil
	}
	defer f.Close()
	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool, len(syms))
	var out []string
	for _, sym := range syms {
		name := sym.Name
		// Versioned names read "system@GLIBC_2.2.5"; the version is a dynamic
		// linker detail, the symbol is what matters.
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		if !execImports[name] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
		if len(out) >= maxExecNames {
			break
		}
	}
	sort.Strings(out)
	return out
}

// maxExecNames bounds how many symbol names reach a finding. A statically linked
// binary can import dozens; the first eight sorted are enough to identify the
// shape and keep the evidence readable.
const maxExecNames = 8

// execImports is the set of imported symbols that make a native binary dangerous
// to load in a process that trusts it. It is deliberately about *process
// control*: allocation, math and I/O symbols say nothing, while spawning a
// shell, executing a file or reading another process's memory are the primitives
// a loader-time payload needs.
var execImports = map[string]bool{
	"system": true, "popen": true,
	"execl": true, "execle": true, "execlp": true,
	"execv": true, "execve": true, "execvp": true,
	"fork": true, "vfork": true,
	"dlopen": true, "ptrace": true,
}

// EachValidatedNative calls fn for every *validated* native header in b, with the
// offset relative to b. It is exported for internal/native, which looks for a
// second executable inside a native artifact.
//
// The walk is a single pass: every byte is visited once, and bytescan.ValidNative
// (the standard library's own header parser, via bytescan) runs only at a
// candidate magic, so a window full of data costs one linear scan and a window
// carrying many headers does not cost a re-scan per header.
//
// A header whose section table extends past the end of the bounded window does
// not validate here — that is the documented "shallow" limit of this layer.
func EachValidatedNative(b []byte, fn func(bytescan.NativeKind, int)) {
	for i := 0; i+8 <= len(b); i++ {
		switch b[i] {
		case 0x7f, 'M', 'j', '\xfe', '\xce', '\xcf', '\xca', '\xd0', '!':
		default:
			continue
		}
		kind := bytescan.MagicAt(b[i:])
		if kind == bytescan.NativeNone {
			continue
		}
		if _, ok := bytescan.ValidNative(b[i:]); ok {
			fn(kind, i)
		}
	}
}
