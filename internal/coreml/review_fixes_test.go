package coreml

import (
	"io"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestSniffAcceptsLargeModelOver64KiB(t *testing.T) {
	// A real .mlmodel whose NeuralNetwork payload exceeds 64 KiB.
	bigLayer := cat(pstr(1, "conv0"), pbytes(100, make([]byte, 128<<10)))
	model := cat(
		pvar(fieldSpecVersion, 4),
		pbytes(fieldDescription, cat(pstr(1, "BigNet"), pstr(2, "1.0"))),
		pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, bigLayer)),
	)
	if f, ok := sniff(source.Mem("big.mlmodel", model), limits.Default()); !ok || f != artifact.FormatCoreML {
		t.Fatalf("sniff(>64KiB .mlmodel) = %v, %v; want CoreML, true", f, ok)
	}
}

// sparseSource serves a virtual >64 MiB CoreML protobuf without allocating 65 MiB.
type sparseSource struct {
	name   string
	prefix []byte
	gapLen int64
	suffix []byte
}

func (s *sparseSource) Name() string { return s.name }
func (s *sparseSource) Size() int64  { return int64(len(s.prefix)) + s.gapLen + int64(len(s.suffix)) }
func (s *sparseSource) Reader(off int64) io.Reader {
	if off < 0 {
		off = 0
	}
	if off > s.Size() {
		off = s.Size()
	}
	return io.NewSectionReader(s, off, s.Size()-off)
}
func (s *sparseSource) Close() error { return nil }
func (s *sparseSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= s.Size() {
		return 0, io.EOF
	}
	end := off + int64(len(p))
	var retErr error
	if end > s.Size() {
		end = s.Size()
		retErr = io.EOF
	}
	n := int(end - off)
	pLen := int64(len(s.prefix))
	gapEnd := pLen + s.gapLen
	for i := 0; i < n; i++ {
		pos := off + int64(i)
		switch {
		case pos < pLen:
			p[i] = s.prefix[pos]
		case pos < gapEnd:
			p[i] = 0
		default:
			p[i] = s.suffix[pos-gapEnd]
		}
	}
	return n, retErr
}
func (s *sparseSource) Bytes(off, n int64) ([]byte, error) {
	if off < 0 || off >= s.Size() || n <= 0 {
		return nil, io.EOF
	}
	if off+n > s.Size() {
		n = s.Size() - off
	}
	buf := make([]byte, n)
	k, err := s.ReadAt(buf, off)
	return buf[:k], err
}

func TestParseStreamsBeyond64MiB(t *testing.T) {
	const bigWeightLen = int64(66 << 20) // > 64 MiB
	layer1Prefix := protowire.AppendTag(nil, 100, protowire.BytesType)
	layer1Prefix = protowire.AppendVarint(layer1Prefix, uint64(bigWeightLen))
	layer1Len := uint64(len(layer1Prefix)) + uint64(bigWeightLen)

	layer2 := pbytes(layerFieldCustom, pstr(customFieldClass, "LateEvilLayer"))
	layer2Rec := pbytes(nnFieldLayers, layer2)

	layer1RecPrefix := protowire.AppendTag(nil, nnFieldLayers, protowire.BytesType)
	layer1RecPrefix = protowire.AppendVarint(layer1RecPrefix, layer1Len)

	nnTotalLen := uint64(len(layer1RecPrefix)) + layer1Len + uint64(len(layer2Rec))
	nnPrefix := protowire.AppendTag(nil, fieldNeuralNetwork, protowire.BytesType)
	nnPrefix = protowire.AppendVarint(nnPrefix, nnTotalLen)

	src := &sparseSource{
		name:   "huge.mlmodel",
		prefix: cat(pvar(fieldSpecVersion, 4), nnPrefix, layer1RecPrefix, layer1Prefix),
		gapLen: bigWeightLen,
		suffix: layer2Rec,
	}

	if f, ok := sniff(src, limits.Default()); !ok || f != artifact.FormatCoreML {
		t.Fatalf("sniff(66MiB) = %v, %v; want CoreML, true", f, ok)
	}
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", limits.Default())
	ctx := sess.NewCtx(src.Name(), limits.Default())
	if err := (parser{}).Parse(ctx, src); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !hasRule(c.Findings(), RuleCustomLayer.ID) {
		t.Fatalf("custom layer past 64 MiB was missed; findings=%v", ids(c.Findings()))
	}
	if hasRule(c.Findings(), RuleStruct.ID) {
		t.Fatalf("valid >64 MiB model emitted SC4N-COREML-STRUCT; findings=%v", ids(c.Findings()))
	}
}

func TestNeuralNetworkClassifierAndRegressorDirectLayers(t *testing.T) {
	layer0 := cat(pstr(1, "conv0"), pbytes(100, pvar(1, 3)))
	layer1 := cat(pstr(1, "custom1"), pbytes(layerFieldCustom, pstr(customFieldClass, "EvilClassifierLayer")))
	for _, tc := range []struct {
		name  string
		field protowire.Number
	}{
		{"classifier", fieldNeuralClass},
		{"regressor", fieldNeuralRegr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := cat(
				pvar(fieldSpecVersion, 3),
				pbytes(tc.field, cat(pbytes(nnFieldLayers, layer0), pbytes(nnFieldLayers, layer1))),
			)
			fs := parse(t, tc.name+".mlmodel", model)
			if !hasRule(fs, RuleCustomLayer.ID) {
				t.Fatalf("%s custom layer missed; findings=%v", tc.name, ids(fs))
			}
		})
	}
}

func TestCustomLayerParamsFieldNumbers(t *testing.T) {
	paramVal := pstr(paramValueStrField, "https://discord.com/api/webhooks/1/param")
	paramEntry := cat(pstr(1, "hook"), pbytes(2, paramVal))
	custom := cat(
		pstr(customFieldClass, "PluginOp"),
		pbytes(customFieldWeights, []byte{1, 2, 3, 4}),
		pbytes(customFieldParams, paramEntry),
		pstr(customFieldDescr, "https://hooks.slack.com/services/T/B/X"),
	)
	layer := pbytes(layerFieldCustom, custom)
	model := cat(pvar(fieldSpecVersion, 4), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, layer)))
	fs := parse(t, "custom_fields.mlmodel", model)
	if !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("missing %s; got %v", RuleCustomLayer.ID, ids(fs))
	}
	c2Count := 0
	for _, f := range fs {
		if f.RuleID == "SC4N-STRING-C2" {
			c2Count++
		}
	}
	if c2Count < 2 {
		t.Fatalf("expected C2 findings from both field 30 (parameters) and field 40 (description), got %d: %v", c2Count, fs)
	}
}

func TestSingularFieldMergeBypassAndBranchLoopSubgraphs(t *testing.T) {
	// 1. Singular-field merge: first field 500 has empty class, second has EvilMerged.
	mergedLayer := cat(
		pbytes(layerFieldCustom, pstr(customFieldDescr, "benign")),
		pbytes(layerFieldCustom, cat(pstr(customFieldClass, ""), pstr(customFieldClass, "EvilMerged"))),
	)
	m1 := cat(pvar(fieldSpecVersion, 4), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, mergedLayer)))
	fs1 := parse(t, "merged.mlmodel", m1)
	foundMerged := false
	for _, f := range fs1 {
		if f.RuleID == RuleCustomLayer.ID && strings.Contains(f.Evidence, "EvilMerged") {
			foundMerged = true
		}
	}
	if !foundMerged {
		t.Fatalf("singular-field merge hid EvilMerged; findings=%v", fs1)
	}

	// 2. BranchLayerParams (1360) -> elseBranch (field 2) -> CustomLayerParams.
	evilSubNet := pbytes(nnFieldLayers, pbytes(layerFieldCustom, pstr(customFieldClass, "BranchEvil")))
	branchLayer := pbytes(layerFieldBranch, pbytes(branchElseField, evilSubNet))
	m2 := cat(pvar(fieldSpecVersion, 4), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, branchLayer)))
	if fs := parse(t, "branch.mlmodel", m2); !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("BranchLayerParams subgraph custom layer missed; findings=%v", ids(fs))
	}

	// 3. LoopLayerParams (1370) -> bodyNetwork (field 4) -> CustomLayerParams.
	loopSubNet := pbytes(nnFieldLayers, pbytes(layerFieldCustom, pstr(customFieldClass, "LoopEvil")))
	loopLayer := pbytes(layerFieldLoop, pbytes(loopBodyField, loopSubNet))
	m3 := cat(pvar(fieldSpecVersion, 4), pbytes(fieldNeuralNetwork, pbytes(nnFieldLayers, loopLayer)))
	if fs := parse(t, "loop.mlmodel", m3); !hasRule(fs, RuleCustomLayer.ID) {
		t.Fatalf("LoopLayerParams subgraph custom layer missed; findings=%v", ids(fs))
	}
}
