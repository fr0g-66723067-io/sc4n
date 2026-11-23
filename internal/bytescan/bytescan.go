// Package bytescan holds the small byte-level primitives that several parsers
// need: Shannon entropy, native-executable magic recognition and shebang
// detection.
//
// They live here rather than in each parser so that a finding that quotes "the
// trailing bytes have entropy 7.9" and a finding that quotes "native ELF at
// offset 0x40" are computed the same way everywhere, and so that the polyglot
// layer, the pickle walker and the archive walker cannot drift apart.
package bytescan

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"math"
)

// Entropy returns the Shannon entropy of b in bits per byte (0..8). A value above
// roughly 7.5 says the bytes look compressed, encrypted or randomly padded; a
// value near 0 says they are uniform (padding, zeros, a single repeated byte).
// Both are useful evidence next to an unexplained byte region.
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	total := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// NativeKind is the kind of native executable a magic belongs to.
type NativeKind uint8

const (
	NativeNone NativeKind = iota
	NativeELF
	NativePE
	NativeMachO
	NativeArchive
	NativeOLE
	NativeAPE
)

func (k NativeKind) String() string {
	switch k {
	case NativeELF:
		return "ELF"
	case NativePE:
		return "PE/DOS"
	case NativeMachO:
		return "Mach-O"
	case NativeArchive:
		return "ar archive"
	case NativeOLE:
		return "OLE/CFB"
	case NativeAPE:
		return "APE (Actually Portable Executable)"
	default:
		return "none"
	}
}

// apeSigils are the two APE magic strings. An APE file starts with "MZ" (it is a
// valid DOS/PE image as well), and the shell stub that follows checks one of these
// sigils to decide it is an APE.
var apeSigils = [][]byte{
	[]byte("MZqFpD='"),
	[]byte("jartsr='"),
}

// MagicAt reports the native format recognised at the start of b, if any. It
// recognises the *bare* magic only; callers that want a validated header use
// ValidNative.
func MagicAt(b []byte) NativeKind {
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return NativeELF
	case bytes.HasPrefix(b, []byte("MZ")):
		for _, sig := range apeSigils {
			if bytes.HasPrefix(b, sig) {
				return NativeAPE
			}
		}
		return NativePE
	case bytes.HasPrefix(b, []byte("\xfe\xed\xfa\xce")), bytes.HasPrefix(b, []byte("\xfe\xed\xfa\xcf")),
		bytes.HasPrefix(b, []byte("\xce\xfa\xed\xfe")), bytes.HasPrefix(b, []byte("\xcf\xfa\xed\xfe")),
		// The universal (fat) container, FAT_MAGIC. It is shared with the Java
		// class-file magic and with the two fat variants Go's debug/macho cannot
		// read (FAT_CIGAM, FAT_MAGIC_64), so a claim on it means "a header of this
		// shape starts here", never "this is a program": the validator separates a
		// universal binary from a .class file, and a fat variant the standard
		// library refuses simply falls through to the content sniffers.
		bytes.HasPrefix(b, []byte("\xca\xfe\xba\xbe")):
		return NativeMachO
	case bytes.HasPrefix(b, []byte("!<arch>\n")):
		return NativeArchive
	case bytes.HasPrefix(b, []byte("\xd0\xcf\x11\xe0")):
		return NativeOLE
	case bytes.HasPrefix(b, []byte("MZqFpD='")), bytes.HasPrefix(b, []byte("jartsr='")):
		return NativeAPE
	}
	return NativeNone
}

// MaxFatArches bounds the universal-binary arch count before debug/macho can
// allocate a table from an attacker-chosen number.
const MaxFatArches = 64

// FatArchCountPlausible reports whether b begins with a fat Mach-O header whose
// arch count is nonzero and at most MaxFatArches.
func FatArchCountPlausible(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	var n uint32
	switch {
	case bytes.HasPrefix(b, []byte("\xca\xfe\xba\xbe")),
		bytes.HasPrefix(b, []byte("\xca\xfe\xba\xbf")):
		n = binary.BigEndian.Uint32(b[4:])
	case bytes.HasPrefix(b, []byte("\xbe\xba\xfe\xca")),
		bytes.HasPrefix(b, []byte("\xbf\xba\xfe\xca")):
		n = binary.LittleEndian.Uint32(b[4:])
	default:
		return false
	}
	return n > 0 && n <= MaxFatArches
}

// MachLoadCommandsPlausible validates the two header fields debug/macho uses to
// size its load-command table: 0 < ncmds <= 1<<16 and
// 8*ncmds <= sizeofcmds <= 16 MiB.
func MachLoadCommandsPlausible(b []byte) bool {
	if len(b) < 24 {
		return false
	}
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(b, []byte("\xfe\xed\xfa\xce")), bytes.HasPrefix(b, []byte("\xfe\xed\xfa\xcf")):
		order = binary.BigEndian
	case bytes.HasPrefix(b, []byte("\xce\xfa\xed\xfe")), bytes.HasPrefix(b, []byte("\xcf\xfa\xed\xfe")):
		order = binary.LittleEndian
	default:
		return false
	}
	ncmd := order.Uint32(b[16:])
	cmdsz := order.Uint32(b[20:])
	return ncmd > 0 && ncmd <= 1<<16 && cmdsz <= 16<<20 && cmdsz >= 8*ncmd
}

// FatArchHeadersPlausible validates every arch's inner Mach header in a bounded
// byte slice. A fat file whose arch table is not fully present is refused rather
// than handed to debug/macho.
func FatArchHeadersPlausible(b []byte) bool {
	if !FatArchCountPlausible(b) {
		return false
	}
	is64 := bytes.HasPrefix(b, []byte("\xca\xfe\xba\xbf")) ||
		bytes.HasPrefix(b, []byte("\xbf\xba\xfe\xca"))
	big := bytes.HasPrefix(b, []byte("\xca\xfe\xba\xbe")) ||
		bytes.HasPrefix(b, []byte("\xca\xfe\xba\xbf"))
	entry := 20
	if is64 {
		entry = 32
	}
	count := int(binary.BigEndian.Uint32(b[4:]))
	if !big {
		count = int(binary.LittleEndian.Uint32(b[4:]))
	}
	for i := 0; i < count; i++ {
		at := 8 + i*entry
		if at+entry > len(b) {
			return false
		}
		var off uint64
		if big {
			if is64 {
				off = binary.BigEndian.Uint64(b[at+8:])
			} else {
				off = uint64(binary.BigEndian.Uint32(b[at+8:]))
			}
		} else if is64 {
			off = binary.LittleEndian.Uint64(b[at+8:])
		} else {
			off = uint64(binary.LittleEndian.Uint32(b[at+8:]))
		}
		if off > uint64(len(b)) || int64(off)+24 > int64(len(b)) {
			return false
		}
		if !MachLoadCommandsPlausible(b[off:]) {
			return false
		}
	}
	return true
}

// ValidNative reports whether b is a *valid* native executable of its magic's
// kind, by handing it to the standard library's header parser.
//
// The distinction between a valid header and a bare magic matters for severity: a
// magic match alone is ordinary data that happens to look like a header (a tensor
// of bytes can contain 0x7f E L F in three of its 16-bit lanes), while a header
// the linker's own parser accepts is a real executable. The universal layer
// reports the bare match at info and the validated match at high.
func ValidNative(b []byte) (NativeKind, bool) {
	switch MagicAt(b) {
	case NativeELF:
		if f, err := elf.NewFile(bytes.NewReader(b)); err == nil {
			_ = f.Close()
			return NativeELF, true
		}
		return NativeELF, false
	case NativePE:
		if f, err := pe.NewFile(bytes.NewReader(b)); err == nil {
			_ = f.Close()
			return NativePE, true
		}
		return NativePE, false
	case NativeMachO:
		switch {
		case bytes.HasPrefix(b, []byte("\xfe\xed\xfa\xce")), bytes.HasPrefix(b, []byte("\xfe\xed\xfa\xcf")),
			bytes.HasPrefix(b, []byte("\xce\xfa\xed\xfe")), bytes.HasPrefix(b, []byte("\xcf\xfa\xed\xfe")):
			if !MachLoadCommandsPlausible(b) {
				return NativeMachO, false
			}
			if f, err := macho.NewFile(bytes.NewReader(b)); err == nil {
				_ = f.Close()
				return NativeMachO, true
			}
		default:
			// FAT_MAGIC: the universal container. debug/macho reads this one and
			// rejects FAT_CIGAM and FAT_MAGIC_64, so those stay unclaimed rather
			// than being called a program without a header the linker would take.
			if !FatArchHeadersPlausible(b) {
				return NativeMachO, false
			}
			f, err := macho.NewFatFile(bytes.NewReader(b))
			if err == nil {
				_ = f.Close()
				return NativeMachO, true
			}
		}
		return NativeMachO, false
	case NativeArchive:
		// archive/tar and archive/zip do not read ar archives; the 8-byte magic
		// plus a plausible first member name is enough to call it an object
		// archive rather than random bytes.
		return NativeArchive, len(b) > 68 && b[58] == '`' && b[59] == '\n'
	case NativeAPE:
		// An APE is a valid PE by construction; validate the PE header.
		if f, err := pe.NewFile(bytes.NewReader(b)); err == nil {
			_ = f.Close()
			return NativeAPE, true
		}
		return NativeAPE, false
	case NativeOLE:
		// An OLE compound file's header declares 512-byte sectors and a small
		// sector shift of 9 or 12; checking the shift is enough to separate a real
		// header from four bytes that happen to match.
		return NativeOLE, len(b) >= 32 && (b[30] == 9 || b[30] == 12)
	default:
		return NativeNone, false
	}
}

// FindNative scans b for the first *validated* native header and returns its kind
// and offset. It exists for the "there is an executable somewhere in these bytes"
// question, which is what a polyglot or an appended-payload check is asking; the
// search is O(n) and allocation-free.
func FindNative(b []byte) (NativeKind, int, bool) {
	for i := 0; i+8 <= len(b); i++ {
		if b[i] != 0x7f && b[i] != 'M' && b[i] != '\xfe' && b[i] != '\xce' && b[i] != '\xcf' && b[i] != '\xca' && b[i] != 0xd0 && b[i] != '!' {
			continue
		}
		if kind := MagicAt(b[i:]); kind != NativeNone {
			if _, ok := ValidNative(b[i:]); ok {
				return kind, i, true
			}
		}
	}
	return NativeNone, 0, false
}

// ShebangAt reports whether b starts with a `#!` interpreter line, returning the
// interpreter name. A shell shebang inside a model artifact or an archive member
// is a direct statement of intent.
func ShebangAt(b []byte) (string, bool) {
	if !bytes.HasPrefix(b, []byte("#!")) {
		return "", false
	}
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	if len(line) > 512 {
		line = line[:512]
	}
	rest := bytes.TrimSpace(line[2:])
	if i := bytes.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	if len(rest) == 0 {
		return "", false
	}
	return string(rest), true
}
