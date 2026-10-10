package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
)

// polyglotFixtures writes the generic/universal-layer fixtures: the shapes the
// polyglot and native layers detect. Every byte array is built here; nothing is
// read from the host.
func polyglotFixtures(f *fixtureSet) {
	// A bare native magic with no valid header: "\x7fELF" then zeros. A magic
	// match alone must be informational, because four bytes that look like a
	// header are ordinary tensor data.
	f.add("polyglot_magic_only.bin", append([]byte("\x7fELF"), make([]byte, 200)...))

	// A real zip whose 232-byte member name places the tar ustar magic at offset
	// 257. archive/zip reads it as a zip; a tar reader sees a header at offset 0.
	// Two container signatures at their canonical anchors is the container
	// polyglot shape (CWE-436 interpretation conflict).
	f.add("polyglot_zip_tar.zip", zipWithTarAnchor())

	// A tiny but genuinely valid ELF (hand-built header + one program header, no
	// host file) with a second valid ELF appended: the self-extracting/embedded
	// payload shape. Both headers are accepted by debug/elf, which is what
	// separates this from polyglot_magic_only.bin.
	f.add("native_embedded.so", append(tinyELF(), tinyELF()...))

	// A ZIP named .safetensors. safetensors is a JSON header followed by a tensor
	// buffer, so a file whose bytes are a zip contradicts its name; this is the
	// documented evasion of extension-driven scanners.
	f.add("extension_mismatch.safetensors", plainZip())

	// Benign: deterministic pseudo-random bytes with no magic anywhere. It must
	// produce nothing, which is how the "a random .bin is not a finding"
	// property is enforced.
	f.add("benign/random.bin", deterministicNoise(2048))
}

// tinyELF builds the smallest ELF64 header plus one program header that Go's
// debug/elf accepts. Fixed bytes only, so the fixture is identical on every host.
func tinyELF() []byte {
	b := make([]byte, 64+56)
	copy(b, "\x7fELF")
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // ELFDATA2LSB
	b[6] = 1 // EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], 3)    // e_type ET_DYN
	le.PutUint16(b[18:], 0x3e) // e_machine x86-64
	le.PutUint32(b[20:], 1)    // e_version
	le.PutUint64(b[32:], 64)   // e_phoff
	le.PutUint16(b[52:], 64)   // e_ehsize
	le.PutUint16(b[54:], 56)   // e_phentsize
	le.PutUint16(b[56:], 1)    // e_phnum
	le.PutUint16(b[58:], 64)   // e_shentsize
	ph := b[64:]
	le.PutUint32(ph[0:], 1)               // p_type PT_LOAD
	le.PutUint32(ph[4:], 5)               // p_flags
	le.PutUint64(ph[32:], uint64(len(b))) // p_filesz
	le.PutUint64(ph[40:], uint64(len(b))) // p_memsz
	le.PutUint64(ph[48:], 0x1000)         // p_align
	return b
}

// zipWithTarAnchor writes a valid zip whose member name carries "ustar" at
// absolute offset 257.
func zipWithTarAnchor() []byte {
	const nameLen = 232
	name := make([]byte, nameLen)
	for i := range name {
		name[i] = 'a'
	}
	// Local header is 30 bytes, then the name, so name[227] is file offset 257.
	copy(name[227:], "ustar")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: string(name), Method: zip.Store})
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte("sc4n polyglot zip+tar fixture")); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// plainZip writes a small, ordinary store-method zip used as the ZIP-content
// fixture for the extension check.
func plainZip() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "x.bin", Method: zip.Store})
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// deterministicNoise is a fixed-seed LCG stream: pseudo-random bytes, no magic.
func deterministicNoise(n int) []byte {
	b := make([]byte, n)
	state := uint32(0x1234567)
	for i := range b {
		state = state*1664525 + 1013904223
		b[i] = byte(state >> 24)
	}
	return b
}

func init() {
	register(contributor{
		name:     "polyglot",
		fixtures: polyglotFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return map[string]expectation{
				"polyglot_magic_only.bin": {
					Expect: []string{"SC4N-POLYGLOT-MAGIC-ONLY"},
					// The whole point: a four-byte magic is not an executable.
					Forbid: []string{"SC4N-POLYGLOT-NATIVE", "SC4N-NATIVE-VALID"},
					Notes: "a bare \\x7fELF with no valid header: the magic is data that looks like a " +
						"header, so it is reported at info and never as a validated native executable.",
				},
				"polyglot_zip_tar.zip": {
					Expect: []string{"SC4N-POLYGLOT-CONTAINER"},
					Forbid: []string{"SC4N-POLYGLOT-NATIVE"},
					Notes: "a real zip whose member name puts the tar ustar magic at offset 257, so two " +
						"container readers open the same bytes two different ways (CWE-436, container " +
						"polyglot).",
				},
				"native_embedded.so": {
					Expect: []string{"SC4N-NATIVE-VALID", "SC4N-NATIVE-EMBEDDED-PAYLOAD"},
					Notes: "a hand-built valid ELF with a second valid ELF appended: the self-extracting " +
						"payload shape. debug/elf accepts both headers, so this is a dropped executable, " +
						"not a magic coincidence.",
				},
				"extension_mismatch.safetensors": {
					Expect: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
					Forbid: []string{"SC4N-POLYGLOT-NATIVE"},
					Notes: "a zip named .safetensors. safetensors is a JSON header plus a tensor buffer, " +
						"so the bytes contradict the name; extension-driven tooling (and the human " +
						"reading the file name) sees the safe-sounding extension first.",
				},
			}, map[string]expectation{
				"benign/random.bin": {
					Notes: "fixed-seed pseudo-random bytes with no magic at any anchor: the universal " +
						"layer must stay silent on it, so no magic scan may be driven by a byte pattern " +
						"that ordinary data satisfies.",
				},
			}
		},
	})
}
