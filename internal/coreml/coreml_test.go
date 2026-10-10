package coreml

import (
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
