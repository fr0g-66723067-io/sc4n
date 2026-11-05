package main

import "encoding/binary"

// nativeImportsFixtures writes the ELF pair for SC4N-NATIVE-EXEC-IMPORTS.
//
// Both files are minimal ELF64 shared objects whose only interesting property is
// the dynamic symbol table: one imports system/popen, the other imports
// zlibVersion. The pair is what keeps the rule honest against the direction that
// matters — a C extension that does arithmetic imports none of the exec family,
// so a rule that fired on "any undefined symbol" would fail the benign gate here.
func init() {
	register(contributor{
		name:     "native-imports",
		fixtures: nativeImportsFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"native_imports_system.so": {
					Expect: []string{"SC4N-NATIVE-EXEC-IMPORTS"},
					Notes: "An ELF64 shared object whose .dynsym has two undefined imports, system and " +
						"popen. debug/elf reads them without disassembling anything, and they are exactly " +
						"what the dynamic loader binds at load time: a member that can spawn a shell.",
				},
			}, map[string]expectation{
				"benign/native_imports_benign.so": {
					Forbid: []string{"SC4N-NATIVE-EXEC-IMPORTS", "SC4N-POLYGLOT-MAGIC-ONLY"},
					Notes: "The same ELF shape importing zlibVersion: a numerical extension's ordinary " +
						"dependency. It must validate (no POLYGLOT-MAGIC-ONLY) and must not be called a " +
						"process-control importer.",
				},
			}
		},
	})
}

func nativeImportsFixtures(f *fixtureSet) {
	f.add("native_imports_system.so", elfDynsym("system", "popen"))
	f.add("benign/native_imports_benign.so", elfDynsym("zlibVersion"))
}

// elfDynsym builds a minimal ELF64 little-endian shared object with four
// sections — NULL, .dynstr, .dynsym and .shstrtab — where every name is an
// undefined (SHN_UNDEF) dynamic symbol, which is what an import is.
//
// The layout is the smallest one debug/elf accepts: a header with a section
// header table, a symbol table whose sh_link names its string table, and
// sh_entsize = 24 so the stdlib's size assertion holds. No program headers and no
// section contents beyond those three, because the rule reads the symbol table
// and nothing else.
func elfDynsym(names ...string) []byte {
	// .dynstr: a leading NUL, then each name NUL-terminated.
	var dynstr []byte
	dynstr = append(dynstr, 0)
	offs := make([]uint32, len(names))
	for i, n := range names {
		offs[i] = uint32(len(dynstr))
		dynstr = append(dynstr, n...)
		dynstr = append(dynstr, 0)
	}

	// .dynsym: a zeroed entry 0, then one Elf64_Sym per name with
	// st_info = 0x12 (GLOBAL|FUNC) and st_shndx = SHN_UNDEF.
	dynsym := make([]byte, 24*(len(names)+1))
	for i := range names {
		base := 24 * (i + 1)
		binary.LittleEndian.PutUint32(dynsym[base:], offs[i])
		dynsym[base+4] = 0x12
		binary.LittleEndian.PutUint16(dynsym[base+6:], 0) // SHN_UNDEF
	}

	shstr := []byte("\x00.dynstr\x00.dynsym\x00.shstrtab\x00")
	const (
		nameDynstr   = 1
		nameDynsym   = 9
		nameShstrtab = 17
	)
	const ehsize = 64
	const shentsize = 64

	offDynstr := uint64(ehsize)
	offDynsym := align8(offDynstr + uint64(len(dynstr)))
	offShstr := offDynsym + uint64(len(dynsym))
	offShdr := align8(offShstr + uint64(len(shstr)))

	buf := make([]byte, offShdr+4*shentsize)
	// e_ident
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2 /*ELFCLASS64*/, 1 /*ELFDATA2LSB*/, 1 /*EV_CURRENT*/})
	binary.LittleEndian.PutUint16(buf[16:], 3)       // e_type = ET_DYN
	binary.LittleEndian.PutUint16(buf[18:], 0x3e)    // e_machine = EM_X86_64
	binary.LittleEndian.PutUint32(buf[20:], 1)       // e_version
	binary.LittleEndian.PutUint64(buf[40:], offShdr) // e_shoff
	binary.LittleEndian.PutUint16(buf[52:], ehsize)  // e_ehsize
	binary.LittleEndian.PutUint16(buf[58:], shentsize)
	binary.LittleEndian.PutUint16(buf[60:], 4) // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 3) // e_shstrndx

	copy(buf[offDynstr:], dynstr)
	copy(buf[offDynsym:], dynsym)
	copy(buf[offShstr:], shstr)

	sh := func(i int, name, typ uint32, off, size uint64, link, info uint32, align, entsize uint64) {
		b := buf[offShdr+uint64(i)*shentsize:]
		binary.LittleEndian.PutUint32(b[0:], name)
		binary.LittleEndian.PutUint32(b[4:], typ)
		// Elfa64_Shdr: name 0, type 4, flags 8, addr 16, offset 24, size 32,
		// link 40, info 44, addralign 48, entsize 56.
		binary.LittleEndian.PutUint64(b[24:], off)
		binary.LittleEndian.PutUint64(b[32:], size)
		binary.LittleEndian.PutUint32(b[40:], link)
		binary.LittleEndian.PutUint32(b[44:], info)
		binary.LittleEndian.PutUint64(b[48:], align)
		binary.LittleEndian.PutUint64(b[56:], entsize)
	}
	const (
		shtNull   = 0
		shtStrtab = 3
		shtDynsym = 11
	)
	sh(0, 0, shtNull, 0, 0, 0, 0, 0, 0)
	sh(1, nameDynstr, shtStrtab, offDynstr, uint64(len(dynstr)), 0, 0, 1, 0)
	sh(2, nameDynsym, shtDynsym, offDynsym, uint64(len(dynsym)), 1, 1, 8, 24)
	sh(3, nameShstrtab, shtStrtab, offShstr, uint64(len(shstr)), 0, 0, 1, 0)
	return buf
}

func align8(v uint64) uint64 { return (v + 7) &^ 7 }
