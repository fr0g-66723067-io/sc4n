package main

// Pickle opcodes, repeated here so that a fixture's bytes can be read against the
// name of the opcode that produced them. The values are the same as
// internal/pickle's generated table; TestOpcodeConstantsMatchTable there is what
// keeps the two honest.
const (
	bPROTO          = 0x80
	bFRAME          = 0x95
	bSTOP           = 0x2e
	bMARK           = 0x28
	bPOP            = 0x30
	bPOP_MARK       = 0x31
	bDUP            = 0x32
	bEMPTY_TUPLE    = 0x29
	bEMPTY_LIST     = 0x5d
	bEMPTY_DICT     = 0x7d
	bEMPTY_SET      = 0x8f
	bBININT         = 0x4a
	bBININT1        = 0x4b
	bBININT2        = 0x4d
	bNEWTRUE        = 0x88
	bNEWFALSE       = 0x89
	bNONE           = 0x4e
	bGLOBAL         = 0x63
	bSTACK_GLOBAL   = 0x93
	bREDUCE         = 0x52
	bBUILD          = 0x62
	bTUPLE          = 0x74
	bTUPLE1         = 0x85
	bTUPLE2         = 0x86
	bTUPLE3         = 0x87
	bLIST           = 0x6c
	bDICT           = 0x64
	bSETITEM        = 0x73
	bSETITEMS       = 0x75
	bAPPEND         = 0x61
	bAPPENDS        = 0x65
	bBINPUT         = 0x71
	bBINGET         = 0x68
	bLONG_BINPUT    = 0x72
	bMEMOIZE        = 0x94
	bPUT            = 0x70
	bGET            = 0x67
	bBINUNICODE     = 0x58
	bSHORT_BINUNI   = 0x8c
	bSHORT_BINSTR   = 0x55
	bBINSTRING      = 0x54
	bSTRING         = 0x53
	bUNICODE        = 0x56
	bBINBYTES       = 0x42
	bSHORT_BINBYTES = 0x43
	bBINPERSID      = 0x51
	bPERSID         = 0x50
	bINST           = 0x69
	bOBJ            = 0x6f
	bNEWOBJ         = 0x81
	bNEWOBJ_EX      = 0x92
	bEXT1           = 0x82
	bEXT2           = 0x83
	bLONG1          = 0x8a
	bLONG4          = 0x8b
	bBINFLOAT       = 0x47
	bREADONLY       = 0x98
)

func cat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func proto(n byte) []byte { return []byte{bPROTO, n} }

// u1, u2, u4 encode a little-endian unsigned integer.
func u1(n byte) []byte { return []byte{n} }
func u2(n uint16) []byte {
	return []byte{byte(n), byte(n >> 8)}
}
func u4(n uint32) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}

// binUnicode is BINUNICODE: a 4-byte unsigned length followed by UTF-8 bytes.
func binUnicode(s string) []byte {
	return cat([]byte{bBINUNICODE}, u4(uint32(len(s))), []byte(s))
}

// shortBinUnicode is SHORT_BINUNICODE: a 1-byte length. It is a protocol-4 opcode,
// so it also exercises SC4N-PICKLE-REQUIRES-UNSAFE-LOADER.
func shortBinUnicode(s string) []byte {
	if len(s) > 255 {
		panic("shortBinUnicode: string too long")
	}
	return cat([]byte{bSHORT_BINUNI, byte(len(s))}, []byte(s))
}

// globalText is the text-form GLOBAL: two newline-terminated names.
func globalText(module, name string) []byte {
	return []byte("c" + module + "\n" + name + "\n")
}

// stackGlobal pushes a name through STACK_GLOBAL, which means the name never
// appears as a literal "module name" pair in the file: this is the obfuscation
// that defeats scanners which grep for "os.system" in the bytes.
func stackGlobal(module, name string) []byte {
	return cat(shortBinUnicode(module), shortBinUnicode(name), []byte{bSTACK_GLOBAL})
}

func stop() []byte { return []byte{bSTOP} }
