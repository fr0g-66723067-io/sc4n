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
// The protobuf is walked with google.golang.org/protobuf/encoding/protowire. The
// walk is targeted -- Model.description for metadata strings, field 555 for a
// custom model, field 500 (and the regressor/classifier wrappers) for the neural
// network's layers -- so it never descends into `WeightParams` payloads, and every
// length is bounds-checked by protowire before use.
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
	fieldSpecVersion   = 1  // int32 specificationVersion
	fieldDescription   = 2  // ModelDescription
	fieldIsUpdatable   = 10 // bool
	fieldCustomModel   = 555
	fieldNeuralNetwork = 500 // NeuralNetwork
	fieldNeuralRegr    = 303 // NeuralNetworkRegressor { NeuralNetwork = 1 }
	fieldNeuralClass   = 403 // NeuralNetworkClassifier  { NeuralNetwork = 1 }
	fieldMLProgram     = 502 // MILSpec.Program
)

// NeuralNetwork / NeuralNetworkLayer / CustomLayerParams field numbers
// (apple/coremltools mlmodel/format/NeuralNetwork.proto).
const (
	nnFieldLayers       = 1   // repeated NeuralNetworkLayer
	layerFieldCustom    = 500 // CustomLayerParams
	customFieldClass    = 10  // string className
	customFieldParams   = 20  // map<string, WeightParams> (layer)
	customModelParams   = 30  // map<string, CustomModelParamValue> (custom model)
	customFieldDescr    = 30  // string description (layer custom)
	modelCustomDescr    = 40  // string description (CustomModel)
	paramValueStrField  = 20  // CustomModelParamValue.stringValue
	paramValueByteField = 60  // CustomModelParamValue.bytesValue
)

// maxProbe is how much of the head the sniffer reads to find a CoreML model-type
// field. A ModelDescription is small in every real package; the bound exists so a
// crafted prefix cannot make sniffing expensive.
const maxProbe = 64 << 10

// maxWalkBytes caps the in-memory walk. Core ML packages are small; a model
// larger than this is reported as only partly inspected rather than read whole.
const maxWalkBytes = 64 << 20

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
	size := s.Size()
	n := size
	if n > maxWalkBytes {
		n = maxWalkBytes
	}
	data, err := s.Bytes(0, n)
	if err != nil && len(data) == 0 {
		return err
	}
	w := &walker{sink: ctx.Sink, l: ctx.Limits}
	if size > maxWalkBytes {
		w.sink.Emit(RuleStruct, 0,
			"Core ML model is larger than the bounded walk window; only its first 64 MiB were inspected")
	}
	w.walkModel(data)
	return nil
}

type walker struct {
	sink *report.Sink
	l    limits.Limits

	elems    int64
	elemsHi  bool
	structHi bool
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

// walkModel walks the top-level ModelProto.
func (w *walker) walkModel(b []byte) {
	for len(b) > 0 {
		if !w.count() {
			return
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			w.bad("ModelProto field tag is malformed or truncated")
			return
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			if _, m := protowire.ConsumeVarint(b); m < 0 {
				w.bad("ModelProto varint field is truncated")
				return
			} else {
				b = b[m:]
			}
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				w.bad("ModelProto length-delimited field is truncated")
				return
			}
			b = b[m:]
			w.modelField(num, v)
		case protowire.Fixed32Type:
			if m := consumeFixed32(b); m < 0 {
				w.bad("ModelProto fixed32 field is truncated")
				return
			} else {
				b = b[m:]
			}
		case protowire.Fixed64Type:
			if m := consumeFixed64(b); m < 0 {
				w.bad("ModelProto fixed64 field is truncated")
				return
			} else {
				b = b[m:]
			}
		default:
			w.bad("ModelProto uses a protobuf group wire type, which is not valid here")
			return
		}
	}
}

func (w *walker) modelField(num protowire.Number, v []byte) {
	switch num {
	case fieldDescription:
		w.walkStrings(v, 0)
	case fieldCustomModel:
		w.walkCustomModel(v)
	case fieldNeuralNetwork:
		w.walkNeuralNetwork(v)
	case fieldNeuralRegr, fieldNeuralClass:
		// These wrappers carry the NeuralNetwork in field 1.
		w.walkStrings(v, 0)
		if inner := findBytesField(v, 1); inner != nil {
			w.walkNeuralNetwork(inner)
		}
	case fieldMLProgram:
		w.sink.Emit(RuleProgramUnverified, 0,
			"Model.type is mlProgram (field 502): the MIL operator graph and its weight blobs are not "+
				"decoded by sc4n v1, so this model is recognised but only shallowly analysed")
	default:
		// Every other model-type field (trees, GLM, SVM, pipeline, ...) names no
		// host-provided class and carries no code; its strings are still worth
		// scanning for indicators.
		if num >= 200 {
			w.walkStrings(v, 0)
		}
	}
}

func (w *walker) walkNeuralNetwork(b []byte) {
	w.eachBytesField(b, nnFieldLayers, w.walkLayer)
}

func (w *walker) walkLayer(b []byte) {
	if v := findBytesField(b, layerFieldCustom); v != nil {
		w.walkCustomLayer(v)
	}
}

func (w *walker) walkCustomLayer(b []byte) {
	if v := findBytesField(b, customFieldClass); v != nil {
		w.emitCustom("custom layer", v)
	}
	if v := findBytesField(b, customFieldDescr); v != nil {
		w.walkStrings(v, 0)
	}
	w.eachBytesField(b, customFieldParams, w.scanMapEntry)
}

func (w *walker) walkCustomModel(b []byte) {
	if v := findBytesField(b, customFieldClass); v != nil {
		w.emitCustom("custom model", v)
	}
	if v := findBytesField(b, modelCustomDescr); v != nil {
		w.walkStrings(v, 0)
	}
	// CustomModel parameters are map<string, CustomModelParamValue>; the value is a
	// message whose string/bytes members may carry data.
	w.eachBytesField(b, customModelParams, w.scanParamEntry)
}

func (w *walker) emitCustom(what string, className []byte) {
	name := string(className)
	w.sink.EmitExtra(RuleCustomLayer, 0,
		"the model declares a "+what+" named "+name+"; the implementation is supplied by the host "+
			"application, not by this file",
		map[string]string{"kind": what, "class": name})
	if len(className) > 0 {
		stringscan.EmitString(w.sink, 0, name)
	}
}

// scanMapEntry walks a map<string,string> entry (key=1, value=2).
func (w *walker) scanMapEntry(b []byte) {
	w.eachBytesField(b, 1, w.scanText)
	w.eachBytesField(b, 2, w.scanText)
}

// scanParamEntry walks a CustomModel parameters entry (key=1, value=2 message);
// the value's string/bytes members (20/60) are scanned.
func (w *walker) scanParamEntry(b []byte) {
	w.eachBytesField(b, 1, w.scanText)
	w.eachBytesField(b, 2, func(v []byte) {
		if s := findBytesField(v, paramValueStrField); s != nil {
			w.scanText(s)
		}
		if s := findBytesField(v, paramValueByteField); s != nil {
			w.scanText(s)
		}
	})
}

// walkStrings recursively scans length-delimited leaves that look like text.
func (w *walker) walkStrings(b []byte, depth int) {
	if depth > maxTextDepth {
		return
	}
	for len(b) > 0 {
		if !w.count() {
			return
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			if _, m := protowire.ConsumeVarint(b); m < 0 {
				return
			} else {
				b = b[m:]
			}
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			if w.isText(v) {
				w.scanText(v)
			} else {
				w.walkStrings(v, depth+1)
			}
		case protowire.Fixed32Type:
			if m := consumeFixed32(b); m < 0 {
				return
			} else {
				b = b[m:]
			}
		case protowire.Fixed64Type:
			if m := consumeFixed64(b); m < 0 {
				return
			} else {
				b = b[m:]
			}
		default:
			_ = num
			return
		}
	}
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

// eachBytesField invokes fn for every length-delimited value of the given field
// number, without materialising a slice of them. Element counting is shared with
// the rest of the walk so a crafted message with a million repeated fields stops at
// MaxEntries rather than allocating a slice per field.
func (w *walker) eachBytesField(b []byte, want protowire.Number, fn func([]byte)) {
	for len(b) > 0 {
		if !w.count() {
			return
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			_, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return
			}
			b = b[m:]
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			if num == want {
				fn(v)
			}
		case protowire.Fixed32Type:
			m := consumeFixed32(b)
			if m < 0 {
				return
			}
			b = b[m:]
		case protowire.Fixed64Type:
			m := consumeFixed64(b)
			if m < 0 {
				return
			}
			b = b[m:]
		default:
			return
		}
	}
}

// findBytesField returns the first length-delimited value of field want, or nil.
func findBytesField(b []byte, want protowire.Number) []byte {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			_, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return nil
			}
			b = b[m:]
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil
			}
			if num == want {
				return v
			}
			b = b[m:]
		case protowire.Fixed32Type:
			m := consumeFixed32(b)
			if m < 0 {
				return nil
			}
			b = b[m:]
		case protowire.Fixed64Type:
			m := consumeFixed64(b)
			if m < 0 {
				return nil
			}
			b = b[m:]
		default:
			return nil
		}
	}
	return nil
}

func consumeFixed32(b []byte) int {
	_, n := protowire.ConsumeFixed32(b)
	return n
}

func consumeFixed64(b []byte) int {
	_, n := protowire.ConsumeFixed64(b)
	return n
}

// isProtoMessage reports whether b is a sequence of well-formed protobuf field
// records that consumes exactly b. It separates CoreML's nested ModelDescription
// (field 2) from ONNX's producer_name (also field 2), which is a UTF-8 string:
// "pytorch" parses as tag 14 wire type 0 and then fails on the next byte.
//
// protowire.ConsumeField returns (number, wire type, length) and a negative
// length on error; it validates the outer field structure, not a nested payload.
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

// sniff recognises a CoreML ModelProto by its shape: field 1 must be a plausible
// specificationVersion varint, and either a Model.type field (number >= 200,
// bytes wire type) or a field-2 description that is itself a well-formed
// protobuf message must appear within the probe window. The second shape is what
// a CoreML model whose weights live in a sibling file looks like.
func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	size := s.Size()
	if size < 4 {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, minInt64(size, maxProbe))
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	num, typ, n := protowire.ConsumeTag(head)
	if n < 0 || num != fieldSpecVersion || typ != protowire.VarintType {
		return artifact.FormatUnknown, false
	}
	ver, m := protowire.ConsumeVarint(head[n:])
	if m < 0 || ver == 0 || ver > 1000 {
		return artifact.FormatUnknown, false
	}
	b := head[n+m:]
	for len(b) > 0 {
		fnum, ftyp, k := protowire.ConsumeTag(b)
		if k < 0 {
			return artifact.FormatUnknown, false
		}
		b = b[k:]
		switch ftyp {
		case protowire.VarintType:
			if _, z := protowire.ConsumeVarint(b); z < 0 {
				return artifact.FormatUnknown, false
			} else {
				b = b[z:]
			}
		case protowire.BytesType:
			v, z := protowire.ConsumeBytes(b)
			if z < 0 {
				return artifact.FormatUnknown, false
			}
			b = b[z:]
			if fnum >= 200 && len(v) > 0 {
				return artifact.FormatCoreML, true
			}
			// A CoreML Model carries its description in field 2 as a nested
			// ModelDescription; ONNX's ModelProto carries producer_name in the
			// same field as a string. Accepting the description is what keeps a
			// CoreML model whose weights live outside the file (whisperkit's
			// .mlmodelc bundles) from being claimed by the ONNX sniffer, which
			// only requires a plausible ir_version in field 1 — CoreML's
			// specificationVersion satisfies it.
			if fnum == fieldDescription && len(v) > 0 && isProtoMessage(v) {
				return artifact.FormatCoreML, true
			}
		case protowire.Fixed32Type:
			if z := consumeFixed32(b); z < 0 {
				return artifact.FormatUnknown, false
			} else {
				b = b[z:]
			}
		case protowire.Fixed64Type:
			if z := consumeFixed64(b); z < 0 {
				return artifact.FormatUnknown, false
			} else {
				b = b[z:]
			}
		default:
			return artifact.FormatUnknown, false
		}
	}
	return artifact.FormatUnknown, false
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
