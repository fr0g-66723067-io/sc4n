package gguf

import "math"

// GGML tensor type table.
//
// Transcribed from ggml-org/ggml @ a05c9922613c6a2230dbb1d0de679519ecafb4f0,
// include/ggml.h lines 390-433 (the `enum ggml_type` member list), cross-checked
// against the per-block `static_assert(sizeof(block_*) == ...)` lines in
// src/ggml-common.h and the runtime `type_traits[]` blck_size/type_size table in
// src/ggml.c at the same commit. The cited lines:
//
//	include/ggml.h:429-433   MXFP4 = 39, NVFP4 = 40, Q1_0 = 41, Q2_0 = 42,
//	                         GGML_TYPE_COUNT = 43
//	src/ggml-common.h:199    static_assert(sizeof(block_q4_0)  == sizeof(ggml_half) + QK4_0 / 2, ...);
//	src/ggml-common.h:309    static_assert(sizeof(block_q2_K)  == 2*sizeof(ggml_half) + QK_K/16 + QK_K/4, ...);
//	src/ggml-common.h:185    static_assert(sizeof(block_q1_0)  == sizeof(ggml_half) + QK1_0 / 8, ...);     QK1_0 = 128
//	src/ggml-common.h:192    static_assert(sizeof(block_q2_0)  == sizeof(ggml_half) + QK2_0 / 4, ...);     QK2_0 = 64
//	src/ggml-common.h:219    static_assert(sizeof(block_mxfp4) == sizeof(uint8_t) + QK_MXFP4/2, ...);      QK_MXFP4 = 32
//	src/ggml-common.h:227    static_assert(sizeof(block_nvfp4) == sizeof(uint8_t)*(QK_NVFP4/QK_NVFP4_SUB)
//	                                                                     + QK_NVFP4/2, ...);              QK_NVFP4 = 64, QK_NVFP4_SUB = 16
//	src/ggml.c:688,696,763,771  [GGML_TYPE_Q1_0] = { .blck_size = QK1_0, .type_size = sizeof(block_q1_0) }, ...
//
// with QK_K = 256, K_SCALE_SIZE = 12 and IQ3S_N_SCALE = QK_K/64 = 4 from the same
// file. The table was originally pinned at GGML_TYPE_COUNT = 40 with MXFP4 as the
// last entry (ggml-org/ggml @ ffa4e8b80930029a35991f94e7c8a93cd67730ab); upstream
// has since grown to COUNT = 43, so a table that stopped at 39 reported the three
// current types — NVFP4, Q1_0, Q2_0 — as out-of-range on files llama.cpp writes
// today. Ids >= ggmlTypeCount are unknown and are reported as SC4N-GGUF-STRUCT. A
// wrong entry here would fabricate overlap/trailing-data findings, which is why an
// entry whose size we cannot confirm is marked verified=false and its extent check
// is skipped with SC4N-GGUF-EXTENT-UNVERIFIED instead of guessed.
//
// The unit of a block is `blockSize` elements encoded in `typeSize` bytes, so a
// tensor with N elements occupies (N / blockSize) * typeSize bytes and N must be
// a multiple of blockSize for that to be an integer.
type ggmlTypeInfo struct {
	name string
	// blockSize is the number of tensor elements one block encodes.
	blockSize uint64
	// typeSize is the on-disk size of one block in bytes.
	typeSize uint64
	// verified is false when blockSize/typeSize could not be confirmed against
	// the pinned header; the extent check is skipped for such types.
	verified bool
}

// ggmlTypeCount is GGML_TYPE_COUNT at the cited commit (include/ggml.h:433).
// Ids >= this are unknown.
const ggmlTypeCount = 43

// typeTable is indexed by ggml_type id; retired ids hold the zero value.
var typeTable = [ggmlTypeCount]ggmlTypeInfo{
	0: {"F32", 1, 4, true},
	1: {"F16", 1, 2, true},
	2: {"Q4_0", 32, 18, true},
	3: {"Q4_1", 32, 20, true},
	// 4 (Q4_2) and 5 (Q4_3) were removed from ggml and MUST be rejected.
	6:  {"Q5_0", 32, 22, true},
	7:  {"Q5_1", 32, 24, true},
	8:  {"Q8_0", 32, 34, true},
	9:  {"Q8_1", 32, 36, true},
	10: {"Q2_K", 256, 84, true},
	11: {"Q3_K", 256, 110, true},
	12: {"Q4_K", 256, 144, true},
	13: {"Q5_K", 256, 176, true},
	14: {"Q6_K", 256, 210, true},
	15: {"Q8_K", 256, 292, true},
	16: {"IQ2_XXS", 256, 66, true},
	17: {"IQ2_XS", 256, 74, true},
	18: {"IQ3_XXS", 256, 98, true},
	19: {"IQ1_S", 256, 50, true},
	20: {"IQ4_NL", 32, 18, true},
	21: {"IQ3_S", 256, 110, true},
	22: {"IQ2_S", 256, 82, true},
	23: {"IQ4_XS", 256, 136, true},
	24: {"I8", 1, 1, true},
	25: {"I16", 1, 2, true},
	26: {"I32", 1, 4, true},
	27: {"I64", 1, 8, true},
	28: {"F64", 1, 8, true},
	29: {"IQ1_M", 256, 56, true},
	30: {"BF16", 1, 2, true},
	// 31 (Q4_0_4_4), 32 (Q4_0_4_8) and 33 (Q4_0_8_8) were removed from gguf.
	34: {"TQ1_0", 256, 54, true},
	35: {"TQ2_0", 256, 66, true},
	// 36 (IQ4_NL_4_4), 37 (IQ4_NL_4_8) and 38 (IQ4_NL_8_8) were removed.
	39: {"MXFP4", 32, 17, true},
	// 40-42 are current upstream types, not out-of-range ones: NVFP4 (4 UE4M3
	// scales + 64/2 packed E2M1 per 64 elements = 36 bytes, src/ggml-common.h:221-227),
	// Q1_0 (QK1_0 = 128 elements, ggml_half + 128/8 bits = 18 bytes,
	// src/ggml-common.h:180-185) and Q2_0 (QK2_0 = 64 elements, ggml_half +
	// 64/4 bytes of 2-bit quants = 18 bytes, src/ggml-common.h:187-192). Each
	// block size is confirmed by the static_assert on the same line and by the
	// type_traits[] blck_size/type_size entries in src/ggml.c.
	40: {"NVFP4", 64, 36, true},
	41: {"Q1_0", 128, 18, true},
	42: {"Q2_0", 64, 18, true},
}

// retiredType reports whether id is one of the ids the pinned enum documents as
// removed: 4, 5, 31, 32, 33, 36, 37, 38.
func retiredType(id uint32) bool {
	switch id {
	case 4, 5, 31, 32, 33, 36, 37, 38:
		return true
	}
	return false
}

// TypeInfo returns the table row for a ggml_type id. ok is false when the id is
// unknown (>= ggmlTypeCount) or retired. verified is false when the type is known
// but its block size could not be confirmed, in which case callers MUST skip the
// extent check rather than guess.
//
// It is exported for the fixture-backed table test, which fails on a wrong entry.
func TypeInfo(id uint32) (name string, blockSize, typeSize uint64, verified, ok bool) {
	if id >= ggmlTypeCount || retiredType(id) {
		return "", 0, 0, false, false
	}
	ti := typeTable[id]
	if ti.name == "" {
		return "", 0, 0, false, false
	}
	return ti.name, ti.blockSize, ti.typeSize, ti.verified, true
}

// tensorBytes returns the byte length of a tensor of nelem elements of type id.
// ok is false when the extent cannot be computed — unknown/retired type, an
// unverified table entry, a product overflow, or an element count that is not a
// whole number of blocks — in which case the caller records
// SC4N-GGUF-EXTENT-UNVERIFIED and does NOT treat the tensor as evidence for
// overlap or trailing data.
func tensorBytes(id uint32, nelem uint64) (uint64, bool) {
	_, blockSize, typeSize, verified, ok := TypeInfo(id)
	if !ok || !verified || blockSize == 0 || typeSize == 0 {
		return 0, false
	}
	if nelem%blockSize != 0 {
		return 0, false
	}
	blocks := nelem / blockSize
	if blocks > math.MaxUint64/typeSize {
		return 0, false
	}
	return blocks * typeSize, true
}

// product returns the product of dims and false on uint64 overflow.
func product(dims []uint64) (uint64, bool) {
	p := uint64(1)
	for _, d := range dims {
		if d != 0 && p > math.MaxUint64/d {
			return 0, false
		}
		p *= d
	}
	return p, true
}
