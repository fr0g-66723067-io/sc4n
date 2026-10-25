package tfmodel

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// pbField encodes one length-delimited field.
func pbField(num int, body []byte) []byte {
	out := append([]byte{byte(num<<3 | 2)}, pbVarint(len(body))...)
	return append(out, body...)
}

// pbVarintField encodes one varint field.
func pbVarintField(num, v int) []byte {
	out := append([]byte{byte(num << 3)}, pbVarint(v)...)
	return out
}

// pbWrapped builds the shape tensorflow's own exporter writes: a SavedModel
// wrapper whose field 1 is saved_model_schema_version (a varint) and whose field
// 2 is a MetaGraphDef holding a GraphDef of NodeDefs. An attacker-controlled op
// name is the last node, so the graph walk has something to report.
func pbWrapped(opName string) []byte {
	graph := pbField(1, pbNodeDef("input", "Placeholder"))
	graph = append(graph, pbField(1, pbNodeDef("payload", opName))...)
	metaGraph := pbField(2, graph) // MetaGraphDef.graph_def = 2
	out := pbVarintField(1, 1)     // saved_model_schema_version
	return append(out, pbField(2, metaGraph)...)
}

// TestWrappedSavedModelIsDispatchedAndParsed pins the round-3 defect: the
// sniffer probed top-level field 1 only, so the exporter layout (field 1 varint,
// field 2 MetaGraphDef) was never claimed by TensorFlow and fell to whichever
// sniffer ran first — CoreML on three Hub-unsafe artifacts named saved_model.pb,
// ONNX on a fourth. The payload op was therefore never reached.
func TestWrappedSavedModelIsDispatchedAndParsed(t *testing.T) {
	data := pbWrapped("EagerPyFunc")
	src := source.Mem("saved_model.pb", data)
	defer src.Close()
	if f, ok := sniffSavedModel(src, limits.Default()); !ok || f != artifact.FormatTFSavedModel {
		t.Fatalf("sniff = %v,%v; want tf-savedmodel,true", f, ok)
	}
	got := ids(parseBytes(t, savedModelParser{}, "saved_model.pb", data))
	if !got["SC4N-TF-PYFUNC"] {
		t.Fatalf("graph walk did not reach the payload op: %v", got)
	}
}

// TestWrappedSavedModelDoesNotStealCoreMLOrONNX pins the discriminators the
// wider field probe must not lose. Both measured shapes satisfy the looser
// name+op node probe:
//
//   - CoreML: specificationVersion varint + ModelDescription in field 2, whose
//     first fields are plain strings (testdata/fixtures/benign/tiny.mlmodel
//     satisfies probeNode at field 2).
//   - ONNX: GraphProto in field 7, whose NodeProto also satisfies probeNode
//     (testdata/fixtures/onnx_custom_domain.onnx does at field 7).
//
// So field 2 must be a MetaGraphDef and no field other than 1 and 2 is probed.
func TestWrappedSavedModelDoesNotStealCoreMLOrONNX(t *testing.T) {
	// CoreML: two adjacent printable strings in field 2.
	modelDescription := pbField(1, []byte("sc4n benign"))
	modelDescription = append(modelDescription, pbField(2, []byte("1"))...)
	coreml := append(pbVarintField(1, 1), pbField(2, modelDescription)...)
	// ONNX: a NodeProto that satisfies the node probe, at field 7.
	onnx := append(pbVarintField(1, 7), pbField(7, pbField(1, pbNodeDef("x", "y")))...)

	for name, data := range map[string][]byte{"model.mlmodel": coreml, "model.onnx": onnx} {
		src := source.Mem(name, data)
		f, ok := sniffSavedModel(src, limits.Default())
		src.Close()
		if ok {
			t.Errorf("%s claimed as %v; the TensorFlow probe must not take it", name, f)
		}
	}
}
