package pickle

// Opcode byte constants.
//
// These are named so the walker reads like the opcode list rather than like a
// hex dump. TestOpcodeConstantsMatchTable asserts every constant against the
// generated table, so a mistake here is caught at test time rather than becoming
// a silently mis-decoded stream.
const (
	opMARK             = 0x28
	opEMPTY_TUPLE      = 0x29
	opSTOP             = 0x2e
	opPOP              = 0x30
	opPOP_MARK         = 0x31
	opDUP              = 0x32
	opBINBYTES         = 0x42
	opSHORT_BINBYTES   = 0x43
	opFLOAT            = 0x46
	opBINFLOAT         = 0x47
	opINT              = 0x49
	opBININT           = 0x4a
	opBININT1          = 0x4b
	opLONG             = 0x4c
	opBININT2          = 0x4d
	opNONE             = 0x4e
	opPERSID           = 0x50
	opBINPERSID        = 0x51
	opREDUCE           = 0x52
	opSTRING           = 0x53
	opBINSTRING        = 0x54
	opSHORT_BINSTRING  = 0x55
	opUNICODE          = 0x56
	opBINUNICODE       = 0x58
	opEMPTY_LIST       = 0x5d
	opAPPEND           = 0x61
	opBUILD            = 0x62
	opGLOBAL           = 0x63
	opDICT             = 0x64
	opAPPENDS          = 0x65
	opGET              = 0x67
	opBINGET           = 0x68
	opINST             = 0x69
	opLONG_BINGET      = 0x6a
	opLIST             = 0x6c
	opOBJ              = 0x6f
	opPUT              = 0x70
	opBINPUT           = 0x71
	opLONG_BINPUT      = 0x72
	opSETITEM          = 0x73
	opTUPLE            = 0x74
	opSETITEMS         = 0x75
	opEMPTY_DICT       = 0x7d
	opPROTO            = 0x80
	opNEWOBJ           = 0x81
	opEXT1             = 0x82
	opEXT2             = 0x83
	opEXT4             = 0x84
	opTUPLE1           = 0x85
	opTUPLE2           = 0x86
	opTUPLE3           = 0x87
	opNEWTRUE          = 0x88
	opNEWFALSE         = 0x89
	opLONG1            = 0x8a
	opLONG4            = 0x8b
	opSHORT_BINUNICODE = 0x8c
	opBINUNICODE8      = 0x8d
	opBINBYTES8        = 0x8e
	opEMPTY_SET        = 0x8f
	opADDITEMS         = 0x90
	opFROZENSET        = 0x91
	opNEWOBJ_EX        = 0x92
	opSTACK_GLOBAL     = 0x93
	opMEMOIZE          = 0x94
	opFRAME            = 0x95
	opBYTEARRAY8       = 0x96
	opNEXT_BUFFER      = 0x97
	opREADONLY_BUFFER  = 0x98
)

// opcodeConstants maps every constant above to its expected name so the table and
// the constants cannot drift apart.
var opcodeConstants = map[byte]string{
	opMARK:             "MARK",
	opEMPTY_TUPLE:      "EMPTY_TUPLE",
	opSTOP:             "STOP",
	opPOP:              "POP",
	opPOP_MARK:         "POP_MARK",
	opDUP:              "DUP",
	opBINBYTES:         "BINBYTES",
	opSHORT_BINBYTES:   "SHORT_BINBYTES",
	opFLOAT:            "FLOAT",
	opBINFLOAT:         "BINFLOAT",
	opINT:              "INT",
	opBININT:           "BININT",
	opBININT1:          "BININT1",
	opLONG:             "LONG",
	opBININT2:          "BININT2",
	opNONE:             "NONE",
	opPERSID:           "PERSID",
	opBINPERSID:        "BINPERSID",
	opREDUCE:           "REDUCE",
	opSTRING:           "STRING",
	opBINSTRING:        "BINSTRING",
	opSHORT_BINSTRING:  "SHORT_BINSTRING",
	opUNICODE:          "UNICODE",
	opBINUNICODE:       "BINUNICODE",
	opEMPTY_LIST:       "EMPTY_LIST",
	opAPPEND:           "APPEND",
	opBUILD:            "BUILD",
	opGLOBAL:           "GLOBAL",
	opDICT:             "DICT",
	opAPPENDS:          "APPENDS",
	opGET:              "GET",
	opBINGET:           "BINGET",
	opINST:             "INST",
	opLONG_BINGET:      "LONG_BINGET",
	opLIST:             "LIST",
	opOBJ:              "OBJ",
	opPUT:              "PUT",
	opBINPUT:           "BINPUT",
	opLONG_BINPUT:      "LONG_BINPUT",
	opSETITEM:          "SETITEM",
	opTUPLE:            "TUPLE",
	opSETITEMS:         "SETITEMS",
	opEMPTY_DICT:       "EMPTY_DICT",
	opPROTO:            "PROTO",
	opNEWOBJ:           "NEWOBJ",
	opEXT1:             "EXT1",
	opEXT2:             "EXT2",
	opEXT4:             "EXT4",
	opTUPLE1:           "TUPLE1",
	opTUPLE2:           "TUPLE2",
	opTUPLE3:           "TUPLE3",
	opNEWTRUE:          "NEWTRUE",
	opNEWFALSE:         "NEWFALSE",
	opLONG1:            "LONG1",
	opLONG4:            "LONG4",
	opSHORT_BINUNICODE: "SHORT_BINUNICODE",
	opBINUNICODE8:      "BINUNICODE8",
	opBINBYTES8:        "BINBYTES8",
	opEMPTY_SET:        "EMPTY_SET",
	opADDITEMS:         "ADDITEMS",
	opFROZENSET:        "FROZENSET",
	opNEWOBJ_EX:        "NEWOBJ_EX",
	opSTACK_GLOBAL:     "STACK_GLOBAL",
	opMEMOIZE:          "MEMOIZE",
	opFRAME:            "FRAME",
	opBYTEARRAY8:       "BYTEARRAY8",
	opNEXT_BUFFER:      "NEXT_BUFFER",
	opREADONLY_BUFFER:  "READONLY_BUFFER",
}

// weightsOnlyAccepted is the set of opcodes the reference weights-only unpickler
// implements, derived from the handler list in
// pytorch/torch/_weights_only_unpickler.py at tag v2.7.0 (its Unpickler.load body):
// every opcode it names in an `elif key[0] == ...` branch is here, and every opcode
// in the generated table that is *not* here makes the loader raise
// "Unsupported operand".
//
// This is a derived set rather than the illustrative list in the design notes, and
// the difference is worth knowing: STRING/BINSTRING/FLOAT/INT/LONG (the protocol-0
// text forms), PUT/GET/POP/DUP (the memo and stack-manipulation opcodes),
// STACK_GLOBAL, SHORT_BINUNICODE, MEMOIZE and FRAME are all unhandled too. That is
// why a protocol-4 or protocol-5 pickle cannot load weights-only at all — the
// loader is protocol-2-shaped — and why SC4N-PICKLE-REQUIRES-UNSAFE-LOADER is a
// low-confidence finding rather than an accusation.
var weightsOnlyAccepted = map[byte]bool{
	opGLOBAL:          true,
	opNEWOBJ:          true,
	opREDUCE:          true,
	opBUILD:           true,
	opAPPEND:          true,
	opAPPENDS:         true,
	opSETITEM:         true,
	opSETITEMS:        true,
	opMARK:            true,
	opTUPLE:           true,
	opTUPLE1:          true,
	opTUPLE2:          true,
	opTUPLE3:          true,
	opNONE:            true,
	opNEWFALSE:        true,
	opNEWTRUE:         true,
	opEMPTY_TUPLE:     true,
	opEMPTY_LIST:      true,
	opEMPTY_DICT:      true,
	opEMPTY_SET:       true,
	opBININT:          true,
	opBININT1:         true,
	opBININT2:         true,
	opBINFLOAT:        true,
	opBINUNICODE:      true,
	opSHORT_BINSTRING: true,
	opBINPERSID:       true,
	opBINGET:          true,
	opLONG_BINGET:     true,
	opBINPUT:          true,
	opLONG_BINPUT:     true,
	opLONG1:           true,
	opPROTO:           true,
	opSTOP:            true,
}

// requiresUnsafeLoader reports whether an opcode forces the caller into the
// unsafe unpickler.
func requiresUnsafeLoader(code byte) bool {
	if opTable[code].name == "" {
		return false
	}
	return !weightsOnlyAccepted[code]
}

// callableOpcodes are the opcodes that turn a name from the stream into an actual
// call: they are where a gadget becomes execution, so the gadget table is
// consulted at every one of them.
var callableOpcodes = map[byte]bool{
	opREDUCE:    true,
	opBUILD:     true,
	opINST:      true,
	opOBJ:       true,
	opNEWOBJ:    true,
	opNEWOBJ_EX: true,
}
