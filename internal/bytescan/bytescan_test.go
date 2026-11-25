package bytescan

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func minimalELF64() []byte {
	b := make([]byte, 64+56)
	copy(b, "\x7fELF")
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // ELFDATA2LSB
	b[6] = 1 // EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], 3)
	le.PutUint16(b[18:], 0x3e)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], 64)
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 1)
	le.PutUint16(b[58:], 64)
	ph := b[64:]
	le.PutUint32(ph[0:], 1)
	le.PutUint32(ph[4:], 5)
	le.PutUint64(ph[32:], uint64(len(b)))
	le.PutUint64(ph[40:], uint64(len(b)))
	le.PutUint64(ph[48:], 0x1000)
	return b
}

func minimalPE64(magic []byte) []byte {
	b := make([]byte, 0x80)
	copy(b, magic)
	le := binary.LittleEndian
	le.PutUint32(b[0x3c:], 0x40) // e_lfanew
	copy(b[0x40:], "PE\x00\x00")
	le.PutUint16(b[0x44:], 0x8664) // IMAGE_FILE_MACHINE_AMD64
	le.PutUint16(b[0x46:], 0)      // NumberOfSections
	le.PutUint16(b[0x54:], 0)      // SizeOfOptionalHeader
	le.PutUint16(b[0x56:], 0x0002) // IMAGE_FILE_EXECUTABLE_IMAGE
	return b
}

func minimalThinMachO64() []byte {
	// 32-byte 64-bit little-endian Mach-O header + 16-byte LC_UUID load command.
	b := make([]byte, 32+16)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(b[4:], 0x01000007) // CPU_TYPE_X86_64
	le.PutUint32(b[8:], 3)          // CPU_SUBTYPE_X86_64_ALL
	le.PutUint32(b[12:], 2)         // MH_EXECUTE
	le.PutUint32(b[16:], 1)         // ncmds
	le.PutUint32(b[20:], 16)        // sizeofcmds
	le.PutUint32(b[32:], 0x1b)      // LC_UUID
	le.PutUint32(b[36:], 16)        // cmdsize
	return b
}

func minimalFatMachO() []byte {
	thin := minimalThinMachO64()
	const archOff = 32
	b := make([]byte, archOff+len(thin))
	be := binary.BigEndian
	be.PutUint32(b[0:], 0xcafebabe)
	be.PutUint32(b[4:], 1)
	be.PutUint32(b[8:], 0x01000007)
	be.PutUint32(b[12:], 3)
	be.PutUint32(b[16:], archOff)
	be.PutUint32(b[20:], uint32(len(thin)))
	be.PutUint32(b[24:], 3)
	copy(b[archOff:], thin)
	return b
}

func minimalArArchive() []byte {
	b := make([]byte, 68)
	copy(b[0:], "!<arch>\n")
	copy(b[8:], "foo.o/          0           0     0     100644  0         ")
	b[66] = '`'
	b[67] = '\n'
	return b
}

func minimalOLE(shift byte) []byte {
	b := make([]byte, 64)
	copy(b[0:], "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
	b[28] = 0xfe
	b[29] = 0xff
	b[30] = shift
	b[31] = 0
	return b
}

func minimalJartsrAPE() []byte {
	return []byte("jartsr='\x00\x00\x00\x00'\n#!/bin/sh\nexec /bin/sh -c 'echo ape'\n")
}

func TestMagicAt(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want NativeKind
	}{
		{"elf", []byte("\x7fELF\x02"), NativeELF},
		{"pe", []byte("MZ\x90\x00"), NativePE},
		{"ape-mz", []byte("MZqFpD='stub'"), NativeAPE},
		{"ape-jartsr", []byte("jartsr='stub'"), NativeAPE},
		{"macho-be32", []byte("\xfe\xed\xfa\xce"), NativeMachO},
		{"macho-be64", []byte("\xfe\xed\xfa\xcf"), NativeMachO},
		{"macho-le32", []byte("\xce\xfa\xed\xfe"), NativeMachO},
		{"macho-le64", []byte("\xcf\xfa\xed\xfe"), NativeMachO},
		{"macho-fat", []byte("\xca\xfe\xba\xbe"), NativeMachO},
		{"ar", []byte("!<arch>\n"), NativeArchive},
		{"ole", []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), NativeOLE},
		{"none", []byte("hello world"), NativeNone},
		{"empty", nil, NativeNone},
	}
	for _, tc := range cases {
		if got := MagicAt(tc.in); got != tc.want {
			t.Errorf("MagicAt(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestValidNative(t *testing.T) {
	validCases := []struct {
		name string
		in   []byte
		want NativeKind
	}{
		{"elf", minimalELF64(), NativeELF},
		{"pe", minimalPE64([]byte("MZ")), NativePE},
		{"ape-mz", minimalPE64([]byte("MZqFpD='")), NativeAPE},
		{"ape-jartsr", minimalJartsrAPE(), NativeAPE},
		{"macho-thin", minimalThinMachO64(), NativeMachO},
		{"macho-fat", minimalFatMachO(), NativeMachO},
		{"ar-exact-68", minimalArArchive(), NativeArchive},
		{"ole-shift-9", minimalOLE(9), NativeOLE},
		{"ole-shift-12", minimalOLE(12), NativeOLE},
	}
	for _, tc := range validCases {
		kind, ok := ValidNative(tc.in)
		if kind != tc.want || !ok {
			t.Errorf("ValidNative(%s) = (%v, %v), want (%v, true)", tc.name, kind, ok, tc.want)
		}
	}

	// Ar archive with "`\n" at the old buggy offsets 58..59 must be rejected.
	badArOffset := make([]byte, 80)
	copy(badArOffset[0:], "!<arch>\n")
	badArOffset[58] = '`'
	badArOffset[59] = '\n'

	// OLE negative variants.
	badOLEMagic := minimalOLE(9)
	badOLEMagic[4] = 0x00
	badOLEOrder := minimalOLE(9)
	badOLEOrder[28] = 0xff
	badOLEHighByte := minimalOLE(9)
	badOLEHighByte[31] = 1
	badOLEShift := minimalOLE(10)

	invalidCases := []struct {
		name string
		in   []byte
		want NativeKind
	}{
		{"bare-elf", append([]byte("\x7fELF"), make([]byte, 64)...), NativeELF},
		{"bare-pe", append([]byte("MZ"), make([]byte, 64)...), NativePE},
		{"bare-ape-mz", append([]byte("MZqFpD='"), make([]byte, 64)...), NativeAPE},
		{"bare-ape-jartsr", []byte("jartsr='only"), NativeAPE},
		{"non-shell-ape-jartsr", []byte("jartsr='foo'\nplain prose without shell\n"), NativeAPE},
		{"binary-after-jartsr", []byte("jartsr='x'\n\x00\xff\xfe\x01\x02\x03\x04\x05\x06"), NativeAPE},
		{"ar-short-67", minimalArArchive()[:67], NativeArchive},
		{"ar-wrong-offset-58", badArOffset, NativeArchive},
		{"ole-bad-magic", badOLEMagic, NativeOLE},
		{"ole-bad-order", badOLEOrder, NativeOLE},
		{"ole-bad-high-byte", badOLEHighByte, NativeOLE},
		{"ole-bad-shift", badOLEShift, NativeOLE},
		{"ole-short", minimalOLE(9)[:31], NativeOLE},
		{"macho-bad-fat", []byte("\xca\xfe\xba\xbe\x00\x00\x00\x41"), NativeMachO},
		{"none", []byte("not a binary"), NativeNone},
	}
	for _, tc := range invalidCases {
		kind, ok := ValidNative(tc.in)
		if kind != tc.want || ok {
			t.Errorf("ValidNative(%s) = (%v, %v), want (%v, false)", tc.name, kind, ok, tc.want)
		}
	}
}

func TestFindNative(t *testing.T) {
	pad := bytes.Repeat([]byte{'A'}, 37)
	cases := []struct {
		name    string
		payload []byte
		want    NativeKind
	}{
		{"elf", minimalELF64(), NativeELF},
		{"pe", minimalPE64([]byte("MZ")), NativePE},
		{"macho", minimalThinMachO64(), NativeMachO},
		{"ar", minimalArArchive(), NativeArchive},
		{"ole", minimalOLE(9), NativeOLE},
		{"ape-jartsr", minimalJartsrAPE(), NativeAPE},
	}
	for _, tc := range cases {
		buf := append(append([]byte{}, pad...), tc.payload...)
		kind, off, ok := FindNative(buf)
		if !ok || kind != tc.want || off != len(pad) {
			t.Errorf("FindNative(%s) = (%v, %d, %v), want (%v, %d, true)",
				tc.name, kind, off, ok, tc.want, len(pad))
		}
	}

	if kind, off, ok := FindNative([]byte("no native header here at all")); ok {
		t.Fatalf("FindNative on plain text returned (%v, %d, true)", kind, off)
	}
}

func TestShebangAt(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"#!/bin/sh\necho hi\n", "/bin/sh", true},
		{"#!/bin/bash -eu\n", "/bin/bash", true},
		{"#!/usr/bin/env\tpython3\n", "/usr/bin/env", true},
		{"#! \t /usr/bin/python3\t-u\r\n", "/usr/bin/python3", true},
		{"#!/bin/sh", "/bin/sh", true},
		{"#!   \t \n", "", false},
		{"# not a shebang\n", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := ShebangAt([]byte(tc.in))
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("ShebangAt(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
