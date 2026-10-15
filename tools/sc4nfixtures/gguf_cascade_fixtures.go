package main

// GGUF truncation and current-type fixtures (FP-2a / FP-2b).
//
// FP-2b: one truncation is one fact. A GGUF whose tensors run past the end of the
// file used to emit one medium SC4N-GGUF-STRUCT per tensor — 847 per shard over
// the 256 header slices of the HF campaign corpus, 86% of that campaign's whole
// finding set — so one truncated download read as hundreds of distinct
// violations. The truncated fixture here has exactly that shape: correctly
// aligned, in-declaration-order tensors whose extents need 512 bytes of data
// section with only 32 present. It must report the structural rule, and since the
// file is complete in every other respect it must report nothing else.
//
// FP-2a: the benign control is a complete, valid model that uses the ggml types
// upstream grew after the table was pinned at GGML_TYPE_COUNT = 40 (NVFP4 = 40,
// Q1_0 = 41, Q2_0 = 42; ggml-org/ggml @ a05c9922613c6a2230dbb1d0de679519ecafb4f0,
// cited in full in internal/gguf/types.go). A stale table reports each of them as
// out-of-range, which is a medium finding on a model with nothing else wrong with
// it, so this control pins the table against the current upstream enum.
//
// cascadeTypeSizes is a second, independent transcription of that block layout,
// limited to the ids these fixtures use, so the fixture bytes are laid out from
// an independent copy rather than from the parser's own table. See
// tools/sc4nfixtures/gguf_fixtures.go for the same discipline.

var cascadeTypeSizes = map[uint32]struct{ block, size uint64 }{
	0:  {1, 4},    // F32
	1:  {1, 2},    // F16
	40: {64, 36},  // NVFP4: 4 UE4M3 scales + 64/2 packed E2M1 (QK_NVFP4 = 64)
	41: {128, 18}, // Q1_0: ggml_half + 128/8 (QK1_0 = 128)
	42: {64, 18},  // Q2_0: ggml_half + 64/4 (QK2_0 = 64)
}

// cascadeBytes is ggufTensorBytes for the ids cascadeTypeSizes covers.
func cascadeBytes(t ggufTensor) uint64 {
	ts, ok := cascadeTypeSizes[t.typ]
	if !ok || ts.block == 0 {
		return 0
	}
	n := uint64(1)
	for _, d := range t.dims {
		n *= d
	}
	if n%ts.block != 0 {
		return 0
	}
	return (n / ts.block) * ts.size
}

// cascadeLayout is layout for the type table above.
func cascadeLayout(align uint64, tensors ...ggufTensor) ([]ggufTensor, uint64) {
	var cur uint64
	for i := range tensors {
		cur = alignUpU64(cur, align)
		tensors[i].offset = cur
		cur += cascadeBytes(tensors[i])
	}
	return tensors, cur
}

func init() {
	register(contributor{
		name: "gguf_cascade",
		fixtures: func(f *fixtureSet) {
			// A truncated shard: four aligned, in-order F32 tensors (128 bytes
			// each, 512 in total) with 32 bytes of data section present. Every
			// tensor therefore starts inside the file and ends past EOF, which is
			// what a partial download and a header slice both look like.
			f.add("gguf_truncated_cascade.gguf", buildGGUF(ggufSpec{
				version: 3,
				kvs:     []ggufKV{{key: "general.architecture", valType: 8, val: ggufStr("qwen3")}},
				tensors: []ggufTensor{
					{name: "blk.0.attn_q.weight", dims: []uint64{32}, typ: 0, offset: 0},
					{name: "blk.0.attn_k.weight", dims: []uint64{32}, typ: 0, offset: 128},
					{name: "blk.0.attn_v.weight", dims: []uint64{32}, typ: 0, offset: 256},
					{name: "blk.0.attn_output.weight", dims: []uint64{32}, typ: 0, offset: 384},
				},
				dataLen: 32,
			}))

			// The benign control: a complete, valid model that uses the current
			// upstream types (NVFP4, Q1_0, Q2_0) alongside F32, with an exact
			// data section, correct alignment and correct declaration order.
			complete, completeLen := cascadeLayout(
				32,
				ggufTensor{name: "token_embd.weight", dims: []uint64{64}, typ: 40},           // NVFP4
				ggufTensor{name: "blk.0.attn_k.weight", dims: []uint64{128}, typ: 41},        // Q1_0
				ggufTensor{name: "blk.0.ffn_down_exps.weight", dims: []uint64{128}, typ: 42}, // Q2_0
				ggufTensor{name: "output_norm.weight", dims: []uint64{16}, typ: 0},           // F32
			)
			f.add("benign/gguf_complete.gguf", buildGGUF(ggufSpec{
				version: 3,
				kvs: []ggufKV{
					{key: "general.architecture", valType: 8, val: ggufStr("qwen3")},
					{key: "general.name", valType: 8, val: ggufStr("sc4n benign qwen3 with current ggml types")},
				},
				tensors: complete,
				dataLen: completeLen,
			}))
		},
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"gguf_truncated_cascade.gguf": {
					Expect: []string{"SC4N-GGUF-STRUCT"},
					Notes: "Four aligned, in-declaration-order F32 tensors whose extents (512 bytes) " +
						"run past the 32-byte data section. One truncation, one fact: the parser " +
						"reports the first tensor individually and the remaining three as a single " +
						"aggregate, so this fixture pins the cascade collapse and would catch a " +
						"regression that emits one finding per tensor (847 per shard over 256 " +
						"shards in the HF campaign corpus).",
				},
			}, map[string]expectation{
				"benign/gguf_complete.gguf": {
					Forbid: []string{
						"SC4N-GGUF-STRUCT", "SC4N-GGUF-TRAILING-DATA", "SC4N-GGUF-POLYGLOT",
						"SC4N-GGUF-ENDIAN-AMBIGUOUS", "SC4N-GGUF-EXTENT-UNVERIFIED",
					},
					Notes: "A complete model that uses NVFP4 (40), Q1_0 (41) and Q2_0 (42) — the ggml " +
						"types upstream added after the table was pinned at GGML_TYPE_COUNT = 40 — " +
						"with exact extents, correct alignment and correct declaration order. A stale " +
						"type table reports each of them as out-of-range, which is a medium finding on " +
						"a legitimate current model.",
				},
			}
		},
	})
}
