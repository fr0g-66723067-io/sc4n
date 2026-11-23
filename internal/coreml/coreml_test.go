package coreml

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"google.golang.org/protobuf/encoding/protowire"
)

func pvar(field protowire.Number, v uint64) []byte {
	b := protowire.AppendTag(nil, field, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func pbytes(field protowire.Number, v []byte) []byte {
	b := protowire.AppendTag(nil, field, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func pstr(field protowire.Number, s string) []byte { return pbytes(field, []byte(s)) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func parse(t *testing.T, name string, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", limits.Default())
	ctx := sess.NewCtx(name, limits.Default())
	s := source.Mem(name, data)
	defer s.Close()
	if err := (parser{}).Parse(ctx, s); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return c.Findings()
}

func hasRule(fs []report.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestCustomModelReported(t *testing.T) {
	model := cat(
		pvar(fieldSpecVersion, 1),
		pbytes(fieldDescription, pstr(1, "m")),
		pbytes(fieldCustomModel, cat(pstr(customFieldClass, "EvilModel"))),
	)
	fs := parse(t, "m.mlmodel", model)
	if !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("expected %s, got %v", RuleCustomLayer.ID, ids(fs))
	}
}

func TestCustomLayerReported(t *testing.T) {
	layer := cat(pstr(1, "layer0"), pbytes(layerFieldCustom, pstr(customFieldClass, "EvilLayer")))
	model := cat(
		pvar(fieldSpecVersion, 1),
		pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, layer)),
	)
	fs := parse(t, "l.mlmodel", model)
	if !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("expected %s, got %v", RuleCustomLayer.ID, ids(fs))
	}
}

func TestCleanModelSilent(t *testing.T) {
	layer := cat(pstr(1, "conv0"), pbytes(100, pvar(1, 3)))
	model := cat(
		pvar(fieldSpecVersion, 1),
		pbytes(fieldDescription, cat(pstr(1, "m"), pstr(2, "1.0"))),
		pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, layer)),
	)
	fs := parse(t, "clean.mlmodel", model)
	if hasRule(fs, RuleCustomLayer.ID) || hasRule(fs, RuleStruct.ID) {
		t.Fatalf("clean model produced %v", ids(fs))
	}
}

func TestMLProgramReported(t *testing.T) {
	model := cat(pvar(fieldSpecVersion, 1), pbytes(fieldMLProgram, pstr(1, "prog")))
	fs := parse(t, "p.mlmodel", model)
	if !hasRule(fs, RuleProgramUnverified.ID) {
		t.Fatalf("expected %s, got %v", RuleProgramUnverified.ID, ids(fs))
	}
}

func TestMalformedReported(t *testing.T) {
	// A length-delimited field whose declared length runs past the buffer.
	tag := protowire.AppendTag(nil, 500, protowire.BytesType)
	tag = protowire.AppendVarint(tag, 1<<20)
	model := cat(pvar(fieldSpecVersion, 1), tag)
	fs := parse(t, "bad.mlmodel", model)
	if !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("expected %s, got %v", RuleStruct.ID, ids(fs))
	}
}

func TestSniffDiscriminates(t *testing.T) {
	coreml := cat(
		pvar(fieldSpecVersion, 1),
		pbytes(fieldCustomModel, pstr(customFieldClass, "X")),
	)
	if _, ok := sniff(source.Mem("m.mlmodel", coreml), limits.Default()); !ok {
		t.Fatal("CoreML model not recognised")
	}
	// A model whose weights live in a sibling file carries no Model.type field at
	// all, only the specificationVersion and the ModelDescription. The ONNX
	// sniffer accepts the field-1 varint alone, so this shape is what decides
	// whether a CoreML file is parsed as CoreML or reported as a broken ONNX.
	described := cat(
		pvar(fieldSpecVersion, 7),
		pbytes(fieldDescription, cat(pstr(1, "AudioEncoder"), pstr(2, "1.0"))),
	)
	if _, ok := sniff(source.Mem("m.mlmodel", described), limits.Default()); !ok {
		t.Fatal("CoreML model with no type field not recognised")
	}
	// The other side of the same field: ONNX's producer_name is a string, and a
	// string is not a nested message.
	if _, ok := sniff(source.Mem("m.onnx", cat(pvar(1, 7), pstr(2, "pytorch"))), limits.Default()); ok {
		t.Fatal("ONNX producer_name string claimed as CoreML")
	}
	// An ONNX-shaped model has no Model.type field >= 200.
	onnxLike := cat(pvar(1, 8), pbytes(8, pvar(1, 17)), pbytes(7, pstr(2, "g")))
	if _, ok := sniff(source.Mem("m.onnx", onnxLike), limits.Default()); ok {
		t.Fatal("ONNX-shaped model claimed as CoreML")
	}
}

func ids(fs []report.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func FuzzCoreMLWalk(f *testing.F) {
	f.Add([]byte{})
	f.Add(cat(pvar(fieldSpecVersion, 1), pbytes(fieldCustomModel, pstr(customFieldClass, "A"))))
	f.Add(cat(pvar(fieldSpecVersion, 1), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers,
		pbytes(layerFieldCustom, pstr(customFieldClass, "B"))))))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		c := report.NewCollector(1000)
		sess := artifact.NewSession(c, "", limits.Default())
		ctx := sess.NewCtx("f.mlmodel", limits.Default())
		s := source.Mem("f.mlmodel", b)
		defer s.Close()
		_ = (parser{}).Parse(ctx, s)
	})
}

func TestSniffDoesNotClaimOnnxWithProtoShapedProducerName(t *testing.T) {
	// ONNX ir_version, a producer_name whose bytes happen to parse as a
	// protobuf message, and a graph field: the ONNX-specific field wins.
	data := cat(
		pvar(1, 7),
		pbytes(2, pstr(1, "pytorch")),
		pbytes(7, nil),
	)
	if f, ok := sniff(source.Mem("o.onnx", data), limits.Default()); ok || f != artifact.FormatUnknown {
		t.Fatalf("ONNX-shaped bytes sniffed as %v, %v", f, ok)
	}
}

func TestPipelineCustomModelIsReported(t *testing.T) {
	inner := cat(pvar(fieldSpecVersion, 1), pbytes(fieldCustomModel, pstr(customFieldClass, "EvilModel")))
	model := cat(pvar(fieldSpecVersion, 1), pbytes(fieldPipeline, pbytes(pipelineFieldModels, inner)))
	fs := parse(t, "p.mlmodel", model)
	if !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("pipeline custom model was hidden; findings=%v", ids(fs))
	}
}

func TestDeepPipelineNestingIsReported(t *testing.T) {
	inner := pbytes(fieldCustomModel, pstr(customFieldClass, "EvilModel"))
	for range maxPipelineDepth + 1 {
		inner = pbytes(fieldPipeline, pbytes(pipelineFieldModels, inner))
	}
	model := cat(pvar(fieldSpecVersion, 1), inner)
	if fs := parse(t, "deep.mlmodel", model); !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("deep pipeline nesting was silent; findings=%v", ids(fs))
	}
}

func TestGroupWireTypeDoesNotHideACustomLayer(t *testing.T) {
	group := protowire.AppendTag(nil, 1, protowire.StartGroupType)
	group = protowire.AppendTag(group, 1, protowire.EndGroupType)
	layer := cat(group, pbytes(layerFieldCustom, pstr(customFieldClass, "EvilLayer")))
	model := cat(pvar(fieldSpecVersion, 1), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, layer)))
	if fs := parse(t, "g.mlmodel", model); !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("a group field hid the custom layer; findings=%v", ids(fs))
	}
}

func TestTruncatedLayerRecordIsReported(t *testing.T) {
	// A length-delimited layer whose declared length runs past the message.
	bad := protowire.AppendTag(nil, nnFieldLayers, protowire.BytesType)
	bad = protowire.AppendVarint(bad, 100)
	bad = append(bad, 1, 2, 3)
	model := cat(pvar(fieldSpecVersion, 1), pbytes(fieldNeuralNetwork, bad))
	if fs := parse(t, "trunc.mlmodel", model); !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("truncated layer was silent; findings=%v", ids(fs))
	}
}

func TestOversizedCustomClassNameIsCappedAndReported(t *testing.T) {
	name := strings.Repeat("A", 100)
	model := cat(pvar(fieldSpecVersion, 1), pbytes(fieldCustomModel, pstr(customFieldClass, name)))
	l := limits.Default()
	l.MaxStringBlob = 16
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	ctx := sess.NewCtx("big.mlmodel", l)
	s := source.Mem("big.mlmodel", model)
	defer s.Close()
	if err := (parser{}).Parse(ctx, s); err != nil {
		t.Fatal(err)
	}
	if !hasRule(c.Findings(), "SC4N-LIMIT-STRING") {
		t.Fatalf("class name cap was silent; findings=%v", ids(c.Findings()))
	}
}

// TestMalformedNestedLayerRecordIsReported pins the fail-closed contract for a
// nested record the walker cannot parse. The wire-valid group reproducer was
// fixed by consuming the group, but a group that never terminates still stopped
// findBytesField, and its nil return read as "the layer has no custom block": the
// layer produced no custom-layer finding and no structural one either.
func TestMalformedNestedLayerRecordIsReported(t *testing.T) {
	layer := protowire.AppendTag(nil, 1, protowire.StartGroupType) // never closed
	model := cat(pvar(fieldSpecVersion, 1), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, layer)))
	fs := parse(t, "bad.mlmodel", model)
	if !hasRule(fs, RuleStruct.ID) {
		t.Fatalf("an unterminated group in a layer was silent; findings=%v", ids(fs))
	}
}
