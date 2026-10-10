package onnx

// This file is the transcribed ONNX schema the walkers are built on. Every field
// number, wire shape and enum value below was read from onnx.proto3 at tag
// v1.21.0:
//
//	https://github.com/onnx/onnx/blob/v1.21.0/onnx/onnx.proto3
//
// The one thing this file must never do is guess. A proto field number is only
// as good as the schema it came from, and a wrong entry silently reinterprets an
// attacker-controlled message (a "tensor name" read out of a binary blob, a
// length taken from the wrong field). TestFieldTables therefore pins the numbers
// against the schema text quoted in these comments, so a drift is a test
// failure rather than a missing detector.

import "google.golang.org/protobuf/encoding/protowire"

// fieldKind is the wire shape an ONNX field is declared with. It decides both
// which wire type is accepted for the field and how its value is consumed.
type fieldKind uint8

const (
	kindVarint        fieldKind = iota // int32 / int64 / bool / enum
	kindFixed32                        // float
	kindFixed64                        // double
	kindString                         // string
	kindBytes                          // bytes
	kindMessage                        // nested message
	kindPackedVarint                   // repeated numeric, packed or unpacked
	kindPackedFixed32                  // repeated float
	kindPackedFixed64                  // repeated double
)

// accepts reports whether typ is a legal wire type for a field of this kind.
// Packed numeric fields accept both the packed (a single length-delimited run)
// and the unpacked (one element per field record) encodings: both are legal
// protobuf and both appear in published models.
func (k fieldKind) accepts(typ protowire.Type) bool {
	switch k {
	case kindVarint:
		return typ == protowire.VarintType
	case kindFixed32:
		return typ == protowire.Fixed32Type
	case kindFixed64:
		return typ == protowire.Fixed64Type
	case kindString, kindBytes, kindMessage:
		return typ == protowire.BytesType
	case kindPackedVarint:
		return typ == protowire.VarintType || typ == protowire.BytesType
	case kindPackedFixed32:
		return typ == protowire.Fixed32Type || typ == protowire.BytesType
	case kindPackedFixed64:
		return typ == protowire.Fixed64Type || typ == protowire.BytesType
	}
	return false
}

// fieldSpec names one field of one ONNX message.
type fieldSpec struct {
	name string
	kind fieldKind
}

// modelFields is ModelProto (onnx.proto3 v1.21.0 lines 449-526).
var modelFields = map[protowire.Number]fieldSpec{
	1:  {"ir_version", kindVarint},
	2:  {"producer_name", kindString},
	3:  {"producer_version", kindString},
	4:  {"domain", kindString},
	5:  {"model_version", kindVarint},
	6:  {"doc_string", kindString},
	7:  {"graph", kindMessage},
	8:  {"opset_import", kindMessage},
	14: {"metadata_props", kindMessage},
	20: {"training_info", kindMessage},
	25: {"functions", kindMessage},
	26: {"configuration", kindMessage},
}

// graphFields is GraphProto (v1.21.0 lines 562-600; 3, 4 and 6-9 are reserved).
var graphFields = map[protowire.Number]fieldSpec{
	1:  {"node", kindMessage},
	2:  {"name", kindString},
	5:  {"initializer", kindMessage},
	10: {"doc_string", kindString},
	11: {"input", kindMessage},
	12: {"output", kindMessage},
	13: {"value_info", kindMessage},
	14: {"quantization_annotation", kindMessage},
	15: {"sparse_initializer", kindMessage},
	16: {"metadata_props", kindMessage},
}

// nodeFields is NodeProto (v1.21.0 lines 217-250).
var nodeFields = map[protowire.Number]fieldSpec{
	1:  {"input", kindString},
	2:  {"output", kindString},
	3:  {"name", kindString},
	4:  {"op_type", kindString},
	5:  {"attribute", kindMessage},
	6:  {"doc_string", kindString},
	7:  {"domain", kindString},
	8:  {"overload", kindString},
	9:  {"metadata_props", kindMessage},
	10: {"device_configurations", kindMessage},
}

// tensorFields is TensorProto (v1.21.0 lines 605-787).
var tensorFields = map[protowire.Number]fieldSpec{
	1:  {"dims", kindPackedVarint},
	2:  {"data_type", kindVarint},
	3:  {"segment", kindMessage},
	4:  {"float_data", kindPackedFixed32},
	5:  {"int32_data", kindPackedVarint},
	6:  {"string_data", kindBytes},
	7:  {"int64_data", kindPackedVarint},
	8:  {"name", kindString},
	9:  {"raw_data", kindBytes},
	10: {"double_data", kindPackedFixed64},
	11: {"uint64_data", kindPackedVarint},
	12: {"doc_string", kindString},
	13: {"external_data", kindMessage},
	14: {"data_location", kindVarint},
	16: {"metadata_props", kindMessage},
}

// segmentFields is TensorProto.Segment (v1.21.0 lines 673-676).
var segmentFields = map[protowire.Number]fieldSpec{
	1: {"begin", kindVarint},
	2: {"end", kindVarint},
}

// attributeFields is AttributeProto (v1.21.0 lines 138-197; 12 and 16-19 are
// reserved).
var attributeFields = map[protowire.Number]fieldSpec{
	1:  {"name", kindString},
	2:  {"f", kindFixed32},
	3:  {"i", kindVarint},
	4:  {"s", kindBytes},
	5:  {"t", kindMessage},
	6:  {"g", kindMessage},
	7:  {"floats", kindPackedFixed32},
	8:  {"ints", kindPackedVarint},
	9:  {"strings", kindBytes},
	10: {"tensors", kindMessage},
	11: {"graphs", kindMessage},
	13: {"doc_string", kindString},
	14: {"tp", kindMessage},
	15: {"type_protos", kindMessage},
	20: {"type", kindVarint},
	21: {"ref_attr_name", kindString},
	22: {"sparse_tensor", kindMessage},
	23: {"sparse_tensors", kindMessage},
}

// valueInfoFields is ValueInfoProto (v1.21.0 lines 202-213).
var valueInfoFields = map[protowire.Number]fieldSpec{
	1: {"name", kindString},
	2: {"type", kindMessage},
	3: {"doc_string", kindString},
	4: {"metadata_props", kindMessage},
}

// sparseFields is SparseTensorProto (v1.21.0 lines 790-811).
var sparseFields = map[protowire.Number]fieldSpec{
	1: {"values", kindMessage},
	2: {"indices", kindMessage},
	3: {"dims", kindPackedVarint},
}

// opsetFields is OperatorSetIdProto (v1.21.0 lines 911-921).
var opsetFields = map[protowire.Number]fieldSpec{
	1: {"domain", kindString},
	2: {"version", kindVarint},
}

// functionFields is FunctionProto (v1.21.0 lines 929-994; 2 and 3 are reserved).
var functionFields = map[protowire.Number]fieldSpec{
	1:  {"name", kindString},
	4:  {"input", kindString},
	5:  {"output", kindString},
	6:  {"attribute", kindString},
	7:  {"node", kindMessage},
	8:  {"doc_string", kindString},
	9:  {"opset_import", kindMessage},
	10: {"domain", kindString},
	11: {"attribute_proto", kindMessage},
	12: {"value_info", kindMessage},
	13: {"overload", kindString},
	14: {"metadata_props", kindMessage},
}

// entryFields is StringStringEntryProto (v1.21.0 lines 542-545).
var entryFields = map[protowire.Number]fieldSpec{
	1: {"key", kindString},
	2: {"value", kindString},
}

// trainingInfoFields is TrainingInfoProto (v1.21.0 lines 344-417). Its two
// graphs are run during training, so they are walked exactly like the inference
// graph: a non-standard operator domain or an external tensor reference hidden
// in a training algorithm is the same primitive as one in the main graph.
var trainingInfoFields = map[protowire.Number]fieldSpec{
	1: {"initialization", kindMessage},
	2: {"algorithm", kindMessage},
	3: {"initialization_binding", kindMessage},
	4: {"update_binding", kindMessage},
}

// dataTypeBits maps TensorProto.DataType to its element width in bits
// (v1.21.0 lines 606-661). STRING is absent: its elements are variable length
// and are never carried in raw_data, so there is no width to check against.
// UINT2/INT2 are 2 bits and UINT4/INT4/FLOAT4E2M1 are 4 bits, which is why the
// raw_data check in parser.go is expressed in bits rather than bytes: ONNX packs
// sub-byte elements two or four to a byte.
var dataTypeBits = map[int64]uint64{
	1:  32,  // FLOAT
	2:  8,   // UINT8
	3:  8,   // INT8
	4:  16,  // UINT16
	5:  16,  // INT16
	6:  32,  // INT32
	7:  64,  // INT64
	9:  8,   // BOOL (one byte per element)
	10: 16,  // FLOAT16
	11: 64,  // DOUBLE
	12: 32,  // UINT32
	13: 64,  // UINT64
	14: 64,  // COMPLEX64 (two float32)
	15: 128, // COMPLEX128 (two float64)
	16: 16,  // BFLOAT16
	17: 8,   // FLOAT8E4M3FN
	18: 8,   // FLOAT8E4M3FNUZ
	19: 8,   // FLOAT8E5M2
	20: 8,   // FLOAT8E5M2FNUZ
	21: 4,   // UINT4
	22: 4,   // INT4
	23: 4,   // FLOAT4E2M1
	24: 8,   // FLOAT8E8M0
	25: 2,   // UINT2
	26: 2,   // INT2
}

// dataTypeString is TensorProto.DataType.STRING, the one type whose elements are
// not a fixed width.
const dataTypeString int64 = 8

// dataTypeUndefined is TensorProto.DataType.UNDEFINED: never legal on a tensor
// that carries data.
const dataTypeUndefined int64 = 0

// externalDataKeys is the set of external_data keys the hardened ONNX loader
// accepts. Anything else reaches a setattr-shaped sink in the unpatched loader
// (see ruleExternalKey), so the whitelist is deliberately tiny.
var externalDataKeys = map[string]bool{
	"location": true,
	"offset":   true,
	"length":   true,
	"checksum": true,
	"basepath": true,
}

// standardDomains are the operator-set domains the ONNX specification defines.
// A node or opset import outside this set requires a native operator
// implementation from the runtime, which is the CWE-829 surface sc4n reports.
var standardDomains = map[string]bool{
	"":                         true,
	"ai.onnx":                  true,
	"ai.onnx.ml":               true,
	"ai.onnx.preview.training": true,
	"ai.onnx.training":         true,
}

// maxExternalBytes is the largest external_data `length` sc4n treats as a
// plausible model size. The value is 1 PiB: no published model reaches it, while
// the loader bugs in this family are about lengths large enough to overflow an
// allocation (see ruleExternalBounds).
const maxExternalBytes = uint64(1) << 50

// maxRank caps how many dims sc4n will collect from one TensorProto before it
// stops collecting and reports the tensor as structurally anomalous. 64 is far
// above any published tensor rank and far below a list-length DoS.
const maxRank = 64

// maxSniffFields caps the top-level field records the sniffer walks. A
// ModelProto has a dozen; the cap exists so that a crafted stream of millions of
// one-byte fields cannot make sniffing (which runs before every parse) the most
// expensive part of a scan.
const maxSniffFields = 4096

// maxStructDepth caps recursion inside one message tree. It is a defense in
// depth behind the graph-depth budget: every walker here descends through
// length-delimited fields, and a self-referential chain of empty messages must
// not be able to exhaust the Go stack.
const maxStructDepth = 32
