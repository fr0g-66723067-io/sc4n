// Package coreml parses Apple Core ML model packages.
//
// Core ML's security-relevant surface is not the tensor math: it is the *class
// name*. A `CustomModel` (ModelProto field 555 in the current schema) and a
// `CustomLayerParams` (NeuralNetworkLayer.custom, field 500) both name a class
// that the *host application* must provide and register. The model file does not
// contain that class; it only asks for it by name. A poisoned `.mlmodel`/
// `.mlpackage` therefore does not need to smuggle code into the file at all -- it
// pairs with whatever host plugin the name resolves to, and the file itself looks
// like ordinary weights. That pairing is what SC4N-COREML-CUSTOM-LAYER reports.
//
// The protobuf is walked in place over source.Source with a windowed protowire
// reader. The walk is targeted -- Model.description for metadata strings, field
// 555 for a custom model, field 500 (and the regressor/classifier variants, plus
// Branch/Loop subgraphs) for the neural network's layers -- so it never descends
// into `WeightParams` payloads, streams models of any size without a 64 MiB cut,
// and bounds-checks every length before use.
//
// A `.mlpackage` is a *directory*: the scan engine sees its member files
// individually, and `model.mlmodel` inside it is dispatched here by content. The
// package's other members (a `Manifest.json`, any native binary that has been
// dropped alongside) are handled by their own engines, including the universal
// polyglot layer, which is where "native magic inside the package" is reported.
package coreml

import (
	"unicode/utf8"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
	"google.golang.org/protobuf/encoding/protowire"
)

// CoreML ModelProto field numbers (apple/coremltools mlmodel/format/Model.proto).
const (
	fieldSpecVersion        = 1  // int32 specificationVersion
	fieldDescription        = 2  // ModelDescription
	fieldIsUpdatable        = 10 // bool
	fieldCustomModel        = 555
	fieldNeuralNetwork      = 500 // NeuralNetwork
	fieldNeuralRegr         = 303 // NeuralNetworkRegressor { repeated NeuralNetworkLayer layers = 1 }
	fieldNeuralClass        = 403 // NeuralNetworkClassifier { repeated NeuralNetworkLayer layers = 1 }
	fieldMLProgram          = 502 // MILSpec.Program
	fieldPipelineClassifier = 200
	fieldPipelineRegressor  = 201
	fieldPipeline           = 202
	pipelineFieldModels     = 1
	maxPipelineDepth        = 8
	maxSubgraphDepth        = 16
)

// NeuralNetwork / NeuralNetworkLayer / CustomLayerParams field numbers
// (apple/coremltools mlmodel/format/NeuralNetwork.proto).
const (
	nnFieldLayers       = 1    // repeated NeuralNetworkLayer
	layerFieldCustom    = 500  // CustomLayerParams
	layerFieldBranch    = 1360 // BranchLayerParams
	layerFieldLoop      = 1370 // LoopLayerParams
	branchIfField       = 1    // NeuralNetwork ifBranch
	branchElseField     = 2    // NeuralNetwork elseBranch
	loopCondField       = 3    // NeuralNetwork conditionNetwork
	loopBodyField       = 4    // NeuralNetwork bodyNetwork
	customFieldClass    = 10   // string className
	customFieldWeights  = 20   // repeated WeightParams weights
	customFieldParams   = 30   // map<string, CustomLayerParamValue> / CustomModelParamValue
	customFieldDescr    = 40   // string description
	paramValueStrField  = 20   // CustomModelParamValue/CustomLayerParamValue.stringValue
	paramValueByteField = 60   // CustomModelParamValue.bytesValue
)

// maxProbe bounds the full-message probe for ModelDescription.
const maxProbe = 64 << 10

// maxTextDepth bounds the recursive metadata-string walk.
const maxTextDepth = 6

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatCoreML,
		Magic:  "protobuf: specificationVersion(1) then a Model.type field >= 200 (NeuralNetwork 500, customModel 555)",
		Depth:  artifact.DepthStructural,
		Notes: "the ModelProto is walked with protowire for a CustomModel (field 555) or a NeuralNetwork " +
			"layer's CustomLayerParams (field 500), each of which names a class the HOST must supply; " +
			"metadata strings (ModelDescription, class descriptions, parameter maps) are run through the " +
			"shared indicator engine. A `.mlpackage` is a directory and the walker sees its members " +
			"individually, so `model.mlmodel` is dispatched here by content and any native member is " +
			"reported by the universal polyglot layer. SHALLOW PATH, stated explicitly: a MILSpec/ML " +
			"Program model (`mlProgram`, field 502) is recognised and reported as not deeply parsed; its " +
			"weight blobs and operator graph are not decoded.",
	})
	// Priority 65: above the generic ONNX protobuf discriminator (60), whose
	// "first field is a plausible ir_version" test a CoreML model also satisfies
	// (specificationVersion is field 1 too), and below the Python/notebook
	// sniffers. The shape check requires a Model.type field (>= 200), which no ONNX
	// ModelProto has, so ONNX files are not swallowed.
	artifact.RegisterSniffer("coreml", 65, sniff)
	artifact.RegisterParser(artifact.FormatCoreML, parser{})
}

type parser struct{}

func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	w := &walker{s: s, sink: ctx.Sink, l: defaultLimits(ctx.Limits)}
	w.walkModel(newPBReader(s, 0, s.Size()))
	return nil
}

func defaultLimits(l limits.Limits) limits.Limits {
	d := limits.Default()
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxStringBlob <= 0 {
		l.MaxStringBlob = d.MaxStringBlob
	}
	return l
}

type walker struct {
	s    source.Source
	sink *report.Sink
	l    limits.Limits

	elems         int64
	elemsHi       bool
	structHi      bool
	pipelineDepth int
	subgraphDepth int
}

func (w *walker) count() bool {
	w.elems++
	if w.elems > int64(w.l.MaxEntries) {
		if !w.elemsHi {
			w.elemsHi = true
			limits.Emit(w.sink, limits.RuleEntries, "MaxEntries", w.elems, int64(w.l.MaxEntries), "coreml protobuf fields")
		}
		return false
	}
	return true
}

func (w *walker) bad(msg string) {
	if w.structHi {
		return
	}
	w.structHi = true
	w.sink.Emit(RuleStruct, 0, msg)
}

// walkModel walks the top-level ModelProto in place over source.Source.
func (w *walker) walkModel(r *pbReader) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("ModelProto field tag is malformed or truncated")
			return
		}
		switch typ {
		case protowire.VarintType:
			if _, ok := r.varintValue(); !ok {
				w.bad("ModelProto varint field is truncated")
				return
			}
		case protowire.BytesType:
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("ModelProto length-delimited field is truncated")
				return
			}
			w.modelField(num, off, n)
		case protowire.Fixed32Type:
			if !r.fixedValue(4) {
				w.bad("ModelProto fixed32 field is truncated")
				return
			}
		case protowire.Fixed64Type:
			if !r.fixedValue(8) {
				w.bad("ModelProto fixed64 field is truncated")
				return
			}
		default:
			w.bad("ModelProto uses a protobuf group wire type, which is not valid here")
			return
		}
	}
}

func (w *walker) modelField(num protowire.Number, off, n int64) {
	switch num {
	case fieldDescription:
		w.walkStrings(newPBReader(w.s, off, off+n), 0)
	case fieldPipelineClassifier, fieldPipelineRegressor:
		w.eachBytesField(newPBReader(w.s, off, off+n), pipelineFieldModels, "pipeline wrapper", func(po, pn int64) {
			w.walkPipeline(newPBReader(w.s, po, po+pn), 0)
		})
	case fieldPipeline:
		w.walkPipeline(newPBReader(w.s, off, off+n), 0)
	case fieldCustomModel:
		w.walkCustomModel(newPBReader(w.s, off, off+n))
	case fieldNeuralNetwork:
		w.walkNeuralNetwork(newPBReader(w.s, off, off+n), false)
	case fieldNeuralRegr, fieldNeuralClass:
		// NeuralNetworkClassifier and NeuralNetworkRegressor carry
		// `repeated NeuralNetworkLayer layers = 1` directly alongside
		// classifier/regressor metadata fields.
		w.walkNeuralNetwork(newPBReader(w.s, off, off+n), true)
	case fieldMLProgram:
		w.sink.Emit(RuleProgramUnverified, 0,
			"Model.type is mlProgram (field 502): the MIL operator graph and its weight blobs are not "+
				"decoded by sc4n v1, so this model is recognised but only shallowly analysed")
	default:
		// Every other model-type field (trees, GLM, SVM, ...) names no
		// host-provided class and carries no code; its strings are still worth
		// scanning for indicators.
		if num >= 200 {
			w.walkStrings(newPBReader(w.s, off, off+n), 0)
		}
	}
}

func (w *walker) walkNeuralNetwork(r *pbReader, scanMeta bool) {
	if w.subgraphDepth >= maxSubgraphDepth {
		w.bad("Core ML neural network subgraph nests deeper than the internal cap")
		return
	}
	w.subgraphDepth++
	defer func() { w.subgraphDepth-- }()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML NeuralNetwork.layers field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML NeuralNetwork.layers length-delimited field is truncated")
				return
			}
			if num == nnFieldLayers {
				w.walkLayer(newPBReader(w.s, off, off+n))
			} else if scanMeta {
				w.scanBytesOrStrings(off, n, 0)
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML NeuralNetwork.layers field is malformed or truncated")
			return
		}
	}
}

// walkLayer walks all fields of one NeuralNetworkLayer in a single pass so
// protobuf singular-field merging cannot hide a second custom/branch/loop field.
func (w *walker) walkLayer(r *pbReader) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML NeuralNetworkLayer field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML NeuralNetworkLayer length-delimited field is truncated")
				return
			}
			switch num {
			case layerFieldCustom:
				w.walkCustomLayer(newPBReader(w.s, off, off+n))
			case layerFieldBranch:
				w.walkBranchLayer(newPBReader(w.s, off, off+n))
			case layerFieldLoop:
				w.walkLoopLayer(newPBReader(w.s, off, off+n))
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML NeuralNetworkLayer field is malformed or truncated")
			return
		}
	}
}

func (w *walker) walkBranchLayer(r *pbReader) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML BranchLayerParams field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML BranchLayerParams length-delimited field is truncated")
				return
			}
			if num == branchIfField || num == branchElseField {
				w.walkNeuralNetwork(newPBReader(w.s, off, off+n), false)
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML BranchLayerParams field is malformed or truncated")
			return
		}
	}
}

func (w *walker) walkLoopLayer(r *pbReader) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML LoopLayerParams field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML LoopLayerParams length-delimited field is truncated")
				return
			}
			if num == loopCondField || num == loopBodyField {
				w.walkNeuralNetwork(newPBReader(w.s, off, off+n), false)
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML LoopLayerParams field is malformed or truncated")
			return
		}
	}
}

// walkCustomLayer walks CustomLayerParams:
//
//	10: string className
//	20: repeated WeightParams weights (skipped by length)
//	30: map<string, CustomLayerParamValue> parameters
//	40: string description
func (w *walker) walkCustomLayer(r *pbReader) {
	w.walkCustom(r, "custom layer")
}

// walkCustomModel walks CustomModel:
//
//	10: string className
//	30: map<string, CustomModelParamValue> parameters
//	40: string description
func (w *walker) walkCustomModel(r *pbReader) {
	w.walkCustom(r, "custom model")
}

func (w *walker) walkCustom(r *pbReader, what string) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML " + what + " field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML " + what + " length-delimited field is truncated")
				return
			}
			switch num {
			case customFieldClass:
				w.emitCustomRange(what, off, n)
			case customFieldWeights:
				// WeightParams payloads are skipped by length.
			case customFieldParams:
				w.scanParamEntry(newPBReader(w.s, off, off+n))
			case customFieldDescr:
				w.scanTextRange(off, n)
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML " + what + " field is malformed or truncated")
			return
		}
	}
}

// walkPipeline walks a Pipeline model wrapper. The depth is carried on the
// walker so a nested pipeline inside one of its models also charges the cap.
func (w *walker) walkPipeline(r *pbReader, depth int) {
	if depth >= maxPipelineDepth || w.pipelineDepth >= maxPipelineDepth {
		w.bad("Core ML pipeline nests deeper than the internal cap")
		return
	}
	w.pipelineDepth++
	defer func() { w.pipelineDepth-- }()
	w.eachBytesField(r, pipelineFieldModels, "Pipeline.models", func(off, n int64) {
		w.walkModel(newPBReader(w.s, off, off+n))
	})
}

func (w *walker) emitCustomRange(what string, off, n int64) {
	cap := w.l.MaxStringBlob
	if cap <= 0 {
		cap = limits.Default().MaxStringBlob
	}
	readLen := n
	if readLen > cap {
		limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", n, cap, "Core ML "+what+" class name")
		readLen = cap
	}
	var className []byte
	if readLen > 0 {
		b, err := w.s.Bytes(off, readLen)
		if err == nil || len(b) > 0 {
			className = b
		}
	}
	name := string(className)
	w.sink.EmitExtra(RuleCustomLayer, 0,
		"the model declares a "+what+" named "+report.TruncateEvidence(name, 256)+"; the implementation is supplied by the host "+
			"application, not by this file",
		map[string]string{"kind": what, "class": report.TruncateEvidence(name, 256)})
	if len(className) > 0 {
		stringscan.EmitString(w.sink, 0, name)
	}
}

// scanParamEntry walks a CustomLayer/CustomModel parameters entry
// (key=1, value=2 message); the value's string/bytes members (20/60) are
// scanned across every occurrence.
func (w *walker) scanParamEntry(r *pbReader) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML param entry field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML param entry length-delimited field is truncated")
				return
			}
			switch num {
			case 1:
				w.scanTextRange(off, n)
			case 2:
				w.scanParamValue(newPBReader(w.s, off, off+n))
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML param entry field is malformed or truncated")
			return
		}
	}
}

func (w *walker) scanParamValue(r *pbReader) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML CustomParamValue field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML CustomParamValue length-delimited field is truncated")
				return
			}
			if num == paramValueStrField || num == paramValueByteField {
				w.scanTextRange(off, n)
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML CustomParamValue field is malformed or truncated")
			return
		}
	}
}

// walkStrings recursively scans length-delimited leaves that look like text.
func (w *walker) walkStrings(r *pbReader, depth int) {
	if depth > maxTextDepth {
		return
	}
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				return
			}
			w.scanBytesOrStrings(off, n, depth)
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			return
		}
	}
}

func (w *walker) scanBytesOrStrings(off, n int64, depth int) {
	if n <= 0 {
		return
	}
	if n <= w.l.MaxStringBlob {
		b, err := w.s.Bytes(off, n)
		if err != nil && int64(len(b)) < n {
			return
		}
		if w.isText(b) {
			w.scanText(b)
			return
		}
	}
	w.walkStrings(newPBReader(w.s, off, off+n), depth+1)
}

func (w *walker) scanTextRange(off, n int64) {
	if n <= 0 {
		return
	}
	if n > w.l.MaxStringBlob {
		limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", n, w.l.MaxStringBlob, "coreml string")
		return
	}
	b, err := w.s.Bytes(off, n)
	if err != nil && len(b) == 0 {
		return
	}
	w.scanText(b)
}

// scanText runs the indicator engine over a string/blob, bounded by MaxStringBlob.
func (w *walker) scanText(v []byte) {
	if len(v) == 0 {
		return
	}
	if int64(len(v)) > w.l.MaxStringBlob {
		limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", int64(len(v)), w.l.MaxStringBlob, "coreml string")
		return
	}
	stringscan.EmitString(w.sink, 0, string(v))
}

// isText reports whether v looks like a UTF-8 text leaf rather than a nested
// message or a weight blob. NUL bytes are the tell for binary; a low
// control-character ratio keeps a few embedded escapes from disqualifying a real
// description.
func (w *walker) isText(v []byte) bool {
	if len(v) == 0 || int64(len(v)) > w.l.MaxStringBlob {
		return false
	}
	if !utf8.Valid(v) {
		return false
	}
	control := 0
	for _, c := range v {
		switch c {
		case '\t', '\n', '\r':
		default:
			if c < 0x20 || c == 0x7f {
				control++
			}
		}
	}
	return float64(control) < 0.10*float64(len(v))
}

// eachBytesField invokes fn for every length-delimited value of field want,
// streaming in place over r.
func (w *walker) eachBytesField(r *pbReader, want protowire.Number, what string, fn func(off, n int64)) {
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, _, ok := r.next()
		if !ok {
			w.bad("Core ML " + what + " field tag is malformed or truncated")
			return
		}
		if typ == protowire.BytesType {
			off, n, ok := r.bytesValue()
			if !ok {
				w.bad("Core ML " + what + " length-delimited field is truncated")
				return
			}
			if num == want {
				fn(off, n)
			}
			continue
		}
		if !r.skipFieldValue(num, typ, 0) {
			w.bad("Core ML " + what + " field is malformed or truncated")
			return
		}
	}
}

// isProtoMessage reports whether b is a sequence of well-formed protobuf field
// records that consumes exactly b. It separates CoreML's nested ModelDescription
// (field 2) from ONNX's producer_name (also field 2), which is a UTF-8 string:
// "pytorch" parses as tag 14 wire type 0 and then fails on the next byte.
func isProtoMessage(b []byte) bool {
	fields := 0
	for len(b) > 0 {
		num, _, n := protowire.ConsumeField(b)
		if n <= 0 || num < 1 {
			return false
		}
		b = b[n:]
		fields++
	}
	return fields > 0
}

// sniff recognises a CoreML ModelProto of any size by streaming top-level field
// headers over source.Source: field 1 must be a plausible specificationVersion
// varint, and either a Model.type field (number >= 200, bytes wire type whose
// declared length fits within s.Size()) or a field-2 ModelDescription that is a
// plausible protobuf message must appear.
func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 4 {
		return artifact.FormatUnknown, false
	}
	r := newPBReader(s, 0, size)
	num, typ, _, ok := r.next()
	if !ok || num != fieldSpecVersion || typ != protowire.VarintType {
		return artifact.FormatUnknown, false
	}
	ver, ok := r.varintValue()
	if !ok || ver == 0 || ver > 1000 {
		return artifact.FormatUnknown, false
	}
	sawType, sawDesc, sawONNX := false, false, false
	for range maxSniffFields {
		if r.remaining() <= 0 {
			break
		}
		fnum, ftyp, _, ok := r.next()
		if !ok {
			return artifact.FormatUnknown, false
		}
		switch ftyp {
		case protowire.VarintType:
			if _, ok := r.varintValue(); !ok {
				return artifact.FormatUnknown, false
			}
		case protowire.BytesType:
			off, n, ok := r.bytesValue()
			if !ok {
				return artifact.FormatUnknown, false
			}
			if fnum >= 200 && n > 0 {
				sawType = true
			}
			if fnum == fieldDescription && n > 0 && probeProtoMessage(s, off, n) {
				sawDesc = true
			}
			switch fnum {
			case 7, 8, 14, 20, 25, 26:
				sawONNX = true
			}
		case protowire.Fixed32Type:
			if !r.fixedValue(4) {
				return artifact.FormatUnknown, false
			}
		case protowire.Fixed64Type:
			if !r.fixedValue(8) {
				return artifact.FormatUnknown, false
			}
		default:
			return artifact.FormatUnknown, false
		}
	}
	if sawONNX {
		return artifact.FormatUnknown, false
	}
	if sawType || sawDesc {
		return artifact.FormatCoreML, true
	}
	return artifact.FormatUnknown, false
}
