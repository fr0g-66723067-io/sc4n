package tfmodel

// savedmodel.go covers the three TensorFlow graph artifacts:
//
//   - SavedModel protobuf (`saved_model.pb`): SavedModel -> MetaGraphDef ->
//     GraphDef -> NodeDef, walked with the shared windowed protobuf reader.
//   - The TF-JS / GraphDef JSON shape (`model.json` + weightsManifest): the same
//     graph as JSON, walked for op names and manifest paths.
//   - A bare TF checkpoint (`variables.index` + `.data-*` shards): structure only,
//     because a checkpoint stores variables and no graph and therefore has no
//     inline code. It is called out with an informational note so "no findings"
//     is not read as "verified safe".
//
// The graph walk is where a model stops being pure data: PyFunc/EagerPyFunc call
// back into Python, and the file-IO ops carry a path the loader opens when the
// graph runs. Neither executes anything here; both are reported with the node and
// path in the evidence.

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// errUnexpectedGroup reports a protobuf group field. The TensorFlow protos never
// use them, and every parser that has tried to support them has shipped a bug.
var errUnexpectedGroup = errors.New("tfmodel: protobuf group wire type is not used by the TensorFlow protos")

const (
	// maxSniffFields bounds the top-level peek the SavedModel sniffer performs.
	maxSniffFields = 64
	// probeNodeBytes is how much of a candidate node body the probe reads.
	probeNodeBytes = 512
	// maxNodeStrings caps the strings collected from one node's attributes, so a
	// const tensor with a giant list cannot drive unbounded work.
	maxNodeStrings = 64
	// maxScanString caps a string the walker will materialise for rule matching.
	maxScanString = 4096
)

// fileIOOps are the TensorFlow ops whose string attributes name a path the graph
// reads or writes.
var fileIOOps = map[string]bool{
	"ReadFile": true, "WriteFile": true, "SaveV2": true, "RestoreV2": true,
	"Save": true, "Restore": true, "RestoreSlice": true, "SaveSlices": true,
	"MergeV2Checkpoints": true, "ReaderReadV2": true, "ReaderReadUpToV2": true,
	"MatchingFiles": true, "FileName": true, "ReadFileOp": true,
}

// savedModelParser is the registered parser for FormatTFSavedModel.
type savedModelParser struct{}

// sniffSavedModel recognises a SavedModel, a bare GraphDef, or a TF-JS model.json.
//
// Priority is below the ONNX sniffer: a SavedModel's first field is field 1 as a
// length-delimited message, which ONNX's own shape probe rejects, and the plan's
// stated posture is to let the more decisive sniffer go first and record the
// ambiguity rather than guess.
func sniffSavedModel(s source.Source, l limits.Limits) (artifact.Format, bool) {
	if isJSONHead(s) {
		// TF-JS JSON is handled by the dedicated tfjs-model sniffer at its own
		// priority (64), below the Python/notebook sniffers.
		return artifact.FormatUnknown, false
	}
	if s.Size() < 4 {
		return artifact.FormatUnknown, false
	}
	r := newPBReader(s, 0, s.Size())
	for range maxSniffFields {
		num, typ, _, ok := r.next()
		if !ok {
			return artifact.FormatUnknown, false
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				return artifact.FormatUnknown, false
			}
			continue
		}
		off, n, ok := r.bytesValue()
		if !ok {
			return artifact.FormatUnknown, false
		}
		// A SavedModel wrapper carries its MetaGraphDef in field 2 (meta_graphs); a
		// legacy wrapper or a bare GraphDef carries a graph in field 1. Only those
		// two fields are probed, and field 2 must satisfy probeMetaGraph
		// specifically. Measured counter-examples: CoreML puts ModelDescription in
		// field 2 and its ModelDescription satisfies probeNode (two adjacent
		// printable strings), and ONNX puts GraphProto in field 7 whose NodeProto
		// also satisfies probeNode — so either a probe of every field or the looser
		// node probe on field 2 steals both formats.
		switch num {
		case 1:
			if probeMetaGraph(s, off, n) || probeGraph(s, off, n) || probeNode(s, off, n) {
				return artifact.FormatTFSavedModel, true
			}
		case 2:
			if probeMetaGraph(s, off, n) {
				return artifact.FormatTFSavedModel, true
			}
		}
	}
	return artifact.FormatUnknown, false
}

// protowireBytes mirrors protowire.BytesType without importing it here.
const protowireBytes = 2

// Parse walks a SavedModel/GraphDef protobuf or a TF-JS JSON document.
func (savedModelParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	if isJSONHead(s) {
		parseTFJS(ctx, s)
		return nil
	}
	w := &graphWalker{ctx: ctx, s: s}
	scope := w.pushGraphScope()
	defer w.popGraphScope(scope)

	r := newPBReader(s, 0, s.Size())
	var isSavedModel, isBareGraph bool
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "top-level protobuf tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if num == 1 && typ == protowire.VarintType {
				isSavedModel = true
			}
			if !r.skipValue(typ) {
				w.structAt(off, "top-level field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		o, n, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "top-level field "+itoa(int(num))+" declares a length past the end of the file")
			break
		}
		switch num {
		case 1:
			if !isBareGraph && w.walkMetaGraph(o, n) {
				isSavedModel = true
			} else {
				// A bare GraphDef puts NodeDef directly at the top level; a
				// MetaGraphDef always has a graph_def we would have found.
				isBareGraph = true
				w.walkNode(o, n)
			}
		case 2:
			switch {
			case isBareGraph:
				// Bare GraphDef: field 2 is FunctionDefLibrary (library).
				w.walkFunctionLibrary(o, n)
			case isSavedModel:
				// SavedModel wrapper: field 2 is MetaGraphDef (meta_graphs).
				if !w.walkMetaGraph(o, n) {
					w.structAt(off, "top-level field 2 does not decode as a MetaGraphDef")
				}
			default:
				if probeMetaGraph(s, o, n) {
					isSavedModel = true
					w.walkMetaGraph(o, n)
				} else if probeFunctionLibrary(s, o, n) {
					isBareGraph = true
					w.walkFunctionLibrary(o, n)
				} else if !w.walkMetaGraph(o, n) {
					w.structAt(off, "top-level field 2 does not decode as a MetaGraphDef")
				}
			}
		}
	}
	return nil
}

const maxScopeEntries = 65536

type pendingFileIO struct {
	off    int64
	name   string
	op     string
	inputs []string
}

type graphScope struct {
	consts  map[string][]string
	fileIOs []pendingFileIO
}

// graphWalker carries the per-artifact walker state.
type graphWalker struct {
	ctx   *artifact.Ctx
	s     source.Source
	nodes int
	// nodeCapReported guards the one limit finding the node cap emits.
	nodeCapReported bool
	scopes          []*graphScope
}

func (w *graphWalker) pushGraphScope() *graphScope {
	sc := &graphScope{}
	w.scopes = append(w.scopes, sc)
	return sc
}

func (w *graphWalker) currentScope() *graphScope {
	if len(w.scopes) == 0 {
		return nil
	}
	return w.scopes[len(w.scopes)-1]
}

func (w *graphWalker) popGraphScope(sc *graphScope) {
	if len(w.scopes) > 0 && w.scopes[len(w.scopes)-1] == sc {
		w.scopes = w.scopes[:len(w.scopes)-1]
	}
	if sc == nil || len(sc.fileIOs) == 0 || len(sc.consts) == 0 {
		return
	}
	for _, fio := range sc.fileIOs {
		for _, in := range fio.inputs {
			norm := normalizeInputNode(in)
			vals := sc.consts[norm]
			for _, v := range vals {
				w.reportPath(fio.off, "node "+clip(fio.name, 60)+" op "+fio.op+" input "+clip(in, 60), v)
			}
		}
	}
}

func normalizeInputNode(in string) string {
	in = strings.TrimPrefix(in, "^")
	if i := strings.IndexByte(in, ':'); i >= 0 {
		in = in[:i]
	}
	return in
}

func (w *graphWalker) structAt(off int64, msg string) {
	w.ctx.Sink.Emit(ruleTFStruct, off, msg)
}

// walkMetaGraph walks a MetaGraphDef, returning true when it found a graph_def.
func (w *graphWalker) walkMetaGraph(o, n int64) bool {
	r := newPBReader(w.s, o, o+n)
	found := false
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "MetaGraphDef tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				w.structAt(off, "MetaGraphDef field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "MetaGraphDef field "+itoa(int(num))+" declares a length past the end")
			break
		}
		switch num {
		case 2:
			if w.walkGraphDef(oo, nn) {
				found = true
			}
		case 6:
			w.walkAssetDef(oo, nn)
		}
	}
	return found
}

// walkGraphDef walks a GraphDef: its nodes and its function library.
func (w *graphWalker) walkGraphDef(o, n int64) bool {
	sc := w.pushGraphScope()
	defer w.popGraphScope(sc)
	r := newPBReader(w.s, o, o+n)
	found := false
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "GraphDef tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				w.structAt(off, "GraphDef field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "GraphDef field "+itoa(int(num))+" declares a length past the end")
			break
		}
		switch num {
		case 1:
			w.walkNode(oo, nn)
			found = true
		case 2:
			w.walkFunctionLibrary(oo, nn)
		}
	}
	return found
}

// walkFunctionLibrary walks a FunctionDefLibrary: every FunctionDef body is a
// graph the runtime can execute, so its nodes are walked exactly like the main
// graph's.
func (w *graphWalker) walkFunctionLibrary(o, n int64) {
	r := newPBReader(w.s, o, o+n)
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "FunctionDefLibrary tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				w.structAt(off, "FunctionDefLibrary field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "FunctionDefLibrary field declares a length past the end")
			break
		}
		if num == 1 {
			w.walkFunctionDef(oo, nn)
		}
	}
}

// walkFunctionDef walks one FunctionDef; node_def is field 3.
func (w *graphWalker) walkFunctionDef(o, n int64) {
	sc := w.pushGraphScope()
	defer w.popGraphScope(sc)
	r := newPBReader(w.s, o, o+n)
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "FunctionDef tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				w.structAt(off, "FunctionDef field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "FunctionDef field declares a length past the end")
			break
		}
		if num == 3 {
			w.walkNode(oo, nn)
		}
	}
}

// walkAssetDef walks an AssetFileDef: filename is field 2.
func (w *graphWalker) walkAssetDef(o, n int64) {
	r := newPBReader(w.s, o, o+n)
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "AssetFileDef tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				w.structAt(off, "AssetFileDef field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "AssetFileDef field declares a length past the end")
			break
		}
		if num == 2 && nn <= maxScanString {
			b := r.view(oo, nn)
			if printableASCII(b) {
				w.reportPath(off, "asset file", string(b))
			}
		}
	}
}

// maxGraphNodes bounds how many NodeDefs one GraphDef may contribute to the walk.
// It is a memory bound rather than a configured limit: a GraphDef is walked by
// streaming its records, and a file declaring more nodes than this is not a model
// anyone runs.
const maxGraphNodes = 1_000_000

// walkNode walks one NodeDef. name is field 1, op is field 2, input is field 3,
// and the attributes are field 5 (a map<string, AttrValue>).
func (w *graphWalker) walkNode(o, n int64) {
	if w.nodes++; w.nodes > maxGraphNodes {
		// A GraphDef with more than a million nodes is a few MB of declared
		// length, and everything past the cap would otherwise be unscanned in
		// silence: report that the walk stopped rather than letting the absence
		// of findings read as a clean file.
		if !w.nodeCapReported {
			w.nodeCapReported = true
			limits.Emit(w.ctx.Sink, limits.RuleEntries, "MaxGraphNodes", int64(w.nodes), maxGraphNodes,
				"the GraphDef declares more nodes than the walk reads, so the remaining nodes were not analysed")
		}
		return
	}
	r := newPBReader(w.s, o, o+n)
	nodeName, op := "", ""
	var inputs []string
	var attrStrings []string
	var tensorStrings []string
	for r.remaining() > 0 {
		num, typ, off, ok := r.next()
		if !ok {
			if r.remaining() > 0 {
				w.structAt(off, "NodeDef tag is malformed or truncated")
			}
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				w.structAt(off, "NodeDef field "+itoa(int(num))+" has an unreadable value")
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			w.structAt(off, "NodeDef field "+itoa(int(num))+" declares a length past the end")
			break
		}
		switch num {
		case 1:
			if s := smallString(r, oo, nn); s != "" {
				nodeName = s
			}
		case 2:
			if s := smallString(r, oo, nn); s != "" {
				op = s
			}
		case 3:
			if len(inputs) < maxNodeStrings {
				if s := smallString(r, oo, nn); s != "" {
					inputs = append(inputs, s)
				}
			}
		case 5:
			if len(attrStrings) < maxNodeStrings {
				attrStrings = append(attrStrings, w.collectAttrStrings(oo, nn, 0)...)
			}
			if len(tensorStrings) < maxNodeStrings {
				tensorStrings = append(tensorStrings, w.extractAttrTensorStrings(oo, nn)...)
			}
		}
	}
	if sc := w.currentScope(); sc != nil {
		if op == "Const" && nodeName != "" && len(tensorStrings) > 0 {
			if sc.consts == nil {
				sc.consts = make(map[string][]string)
			}
			if len(sc.consts) < maxScopeEntries {
				if len(tensorStrings) > maxNodeStrings {
					tensorStrings = tensorStrings[:maxNodeStrings]
				}
				sc.consts[nodeName] = tensorStrings
			}
		}
		if fileIOOps[op] && len(inputs) > 0 && len(sc.fileIOs) < maxScopeEntries {
			sc.fileIOs = append(sc.fileIOs, pendingFileIO{off: o, name: nodeName, op: op, inputs: inputs})
		}
	}
	w.reportNode(o, nodeName, op, attrStrings, tensorStrings)
}

// extractAttrTensorStrings decodes string tensor values from a NodeDef attr
// map entry (key=1, AttrValue=2 -> TensorProto=8 -> string_val=8 or
// varint-prefixed tensor_content=4 for DT_STRING).
func (w *graphWalker) extractAttrTensorStrings(o, n int64) []string {
	r := newPBReader(w.s, o, o+n)
	var out []string
	for r.remaining() > 0 {
		num, typ, _, ok := r.next()
		if !ok {
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			break
		}
		if num == 2 { // AttrValue
			out = append(out, w.extractAttrValueTensorStrings(oo, nn)...)
		}
	}
	return out
}

func (w *graphWalker) extractAttrValueTensorStrings(o, n int64) []string {
	r := newPBReader(w.s, o, o+n)
	var out []string
	for r.remaining() > 0 {
		num, typ, _, ok := r.next()
		if !ok {
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			break
		}
		if num == 8 { // TensorProto
			out = append(out, w.extractTensorProtoStrings(oo, nn)...)
		}
	}
	return out
}

// dtString is TensorFlow's DataType.DT_STRING enum value.
const dtString = 7

func (w *graphWalker) extractTensorProtoStrings(o, n int64) []string {
	r := newPBReader(w.s, o, o+n)
	var (
		dtype      uint64
		hasDtype   bool
		contentOff int64
		contentLen int64
		hasContent bool
		out        []string
	)
	for r.remaining() > 0 {
		num, typ, _, ok := r.next()
		if !ok {
			break
		}
		if num == 1 && typ == protowire.VarintType {
			v, ok := r.varintValue()
			if !ok {
				break
			}
			dtype, hasDtype = v, true
			continue
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			break
		}
		switch num {
		case 4: // tensor_content
			contentOff, contentLen, hasContent = oo, nn, true
		case 8: // repeated bytes string_val
			if len(out) < maxNodeStrings && nn > 0 && nn <= maxScanString {
				b := r.view(oo, nn)
				if printableASCII(b) {
					out = append(out, string(b))
				}
			}
		}
	}
	if hasContent && (!hasDtype || dtype == dtString) && contentLen > 0 {
		readLen := contentLen
		if readLen > maxScanString*maxNodeStrings {
			readLen = maxScanString * maxNodeStrings
		}
		buf := r.view(contentOff, readLen)
		for len(buf) > 0 && len(out) < maxNodeStrings {
			slen, k := protowire.ConsumeVarint(buf)
			if k < 0 || slen > uint64(len(buf)-k) {
				break
			}
			buf = buf[k:]
			s := buf[:slen]
			buf = buf[slen:]
			if len(s) > 0 && int64(len(s)) <= maxScanString && printableASCII(s) {
				out = append(out, string(s))
			}
		}
	}
	return out
}

// reportNode applies the op-name rules and the indicator engine.
func (w *graphWalker) reportNode(off int64, name, op string, attrStrings, tensorStrings []string) {
	if name != "" {
		scanTextCapped(w.ctx, off, "node name", name)
	}
	switch op {
	case "PyFunc", "EagerPyFunc", "PyFuncStateless":
		w.ctx.Sink.EmitExtra(ruleTFPyFunc, off, "node "+clip(name, 80)+" runs op "+op,
			map[string]string{"op": op, "node": clip(name, 80)})
	}
	fileIO := fileIOOps[op]
	seen := make(map[string]bool, len(attrStrings))
	for i, v := range attrStrings {
		if i >= maxNodeStrings {
			break
		}
		seen[v] = true
		if fileIO {
			w.reportPath(off, "node "+clip(name, 60)+" op "+op, v)
		}
		scanTextCapped(w.ctx, off, "op attribute", v)
	}
	for i, v := range tensorStrings {
		if i >= maxNodeStrings {
			break
		}
		if seen[v] {
			continue
		}
		if fileIO {
			w.reportPath(off, "node "+clip(name, 60)+" op "+op, v)
		}
		scanTextCapped(w.ctx, off, "op tensor", v)
	}
}

// reportPath reports a path constant that escapes the model directory.
func (w *graphWalker) reportPath(off int64, what, v string) {
	if why := pathEscapeReason(v); why != "" {
		w.ctx.Sink.EmitExtra(ruleTFFileIO, off, why+" in "+what+": "+clip(v, 120),
			map[string]string{"reason": why, "value": clip(v, 120)})
	}
}

// collectAttrStrings recovers printable strings from an AttrValue map entry,
// recursing into nested messages (ListValue, TensorProto) up to depth 4.
func (w *graphWalker) collectAttrStrings(o, n int64, depth int) []string {
	if depth > 4 {
		return nil
	}
	r := newPBReader(w.s, o, o+n)
	var out []string
	for range 64 {
		_, typ, _, ok := r.next()
		if !ok {
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			break
		}
		if nn <= 0 {
			continue
		}
		if nn <= maxScanString {
			b := r.view(oo, nn)
			if printableASCII(b) {
				out = append(out, string(b))
				continue
			}
		}
		out = append(out, w.collectAttrStrings(oo, nn, depth+1)...)
		if len(out) >= maxNodeStrings {
			break
		}
	}
	return out
}

// --- probes -------------------------------------------------------------

func probeMetaGraph(s source.Source, o, n int64) bool {
	// The reader spans the whole declared body, clamped to the source, rather than
	// a fixed probe window: bytesValue refuses a nested length that exceeds the
	// reader's end, so a window smaller than a MetaGraphDef's graph_def (which is
	// every real SavedModel — tens of KB to MBs) made the probe fail and the file
	// was dispatched as text. The cost stays bounded because the loop reads at most
	// 16 field *headers*; a body is only descended into by probeGraph/probeNode,
	// whose own readers are windowed.
	r := newPBProbe(s, o, n)
	for range 16 {
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				return false
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			return false
		}
		if num == 2 && probeGraph(s, oo, nn) {
			return true
		}
	}
	return false
}

func probeGraph(s source.Source, o, n int64) bool {
	// Same reason as probeMetaGraph: a GraphDef whose node records exceed a fixed
	// window must still be recognised, or a real SavedModel is not parsed at all.
	r := newPBProbe(s, o, n)
	for range 16 {
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				return false
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			return false
		}
		if num == 1 && probeNode(s, oo, nn) {
			return true
		}
	}
	return false
}

func probeFunctionLibrary(s source.Source, o, n int64) bool {
	r := newPBProbe(s, o, n)
	for range 16 {
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				return false
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			return false
		}
		if num == 1 && probeFunctionDef(s, oo, nn) {
			return true
		}
	}
	return false
}

func probeFunctionDef(s source.Source, o, n int64) bool {
	r := newPBProbe(s, o, n)
	for range 16 {
		num, typ, _, ok := r.next()
		if !ok {
			return false
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				return false
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			return false
		}
		if num == 3 && probeNode(s, oo, nn) {
			return true
		}
	}
	return false
}

// probeNode reports whether [o,o+n) looks like a NodeDef: a name (field 1) and an
// op (field 2), both short printable strings.
func probeNode(s source.Source, o, n int64) bool {
	r := newPBReader(s, o, o+min64(n, probeNodeBytes))
	sawName, sawOp := false, false
	for range 8 {
		num, typ, _, ok := r.next()
		if !ok {
			break
		}
		if typ != protowireBytes {
			if !r.skipValue(typ) {
				break
			}
			continue
		}
		oo, nn, ok := r.bytesValue()
		if !ok {
			break
		}
		if nn <= 0 || nn > maxScanString {
			continue
		}
		if !printableASCII(r.view(oo, nn)) {
			continue
		}
		switch num {
		case 1:
			sawName = true
		case 2:
			sawOp = true
		}
	}
	return sawName && sawOp
}

// smallString reads a bounded printable string field.
func smallString(r *pbReader, o, n int64) string {
	if n <= 0 || n > maxScanString {
		return ""
	}
	b := r.view(o, n)
	if !printableASCII(b) {
		return ""
	}
	return string(b)
}

// printableASCII reports whether b is non-empty printable ASCII.
func printableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// --- TF-JS / GraphDef JSON ---------------------------------------------

// isJSONHead reports whether the artifact begins with a JSON token.
func isJSONHead(s source.Source) bool {
	b, err := s.Bytes(0, 64)
	if err != nil && len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return c == '{' || c == '['
	}
	return false
}

// sniffTFJS recognises a TF-JS model.json: a JSON object whose top-level keys
// include "modelTopology" or "weightsManifest". Requiring JSON head AND parsing
// top-level keys prevents hijacking tokenizer_config.json, config.json, .ipynb,
// or non-JSON source files that merely mention those substrings.
func sniffTFJS(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	if !isJSONHead(s) {
		return artifact.FormatUnknown, false
	}
	head, err := s.Bytes(0, min64(s.Size(), 1<<20))
	if err != nil && len(head) == 0 {
		return artifact.FormatUnknown, false
	}
	if !bytes.Contains(head, []byte("modelTopology")) &&
		!bytes.Contains(head, []byte("weightsManifest")) &&
		!bytes.Contains(head, []byte(`\u`)) {
		return artifact.FormatUnknown, false
	}
	dec := json.NewDecoder(bytes.NewReader(head))
	tok, err := dec.Token()
	if err != nil {
		return artifact.FormatUnknown, false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return artifact.FormatUnknown, false
	}
	const (
		maxTopKeys    = 1024
		maxSkipTokens = 1 << 16
	)
	tokens := 0
	for range maxTopKeys {
		if !dec.More() {
			break
		}
		kt, err := dec.Token()
		if err != nil {
			break
		}
		k, ok := kt.(string)
		if !ok {
			return artifact.FormatUnknown, false
		}
		if k == "modelTopology" || k == "weightsManifest" {
			return artifact.FormatTFSavedModel, true
		}
		if !skipJSONValueBounded(dec, &tokens, maxSkipTokens) {
			break
		}
	}
	return artifact.FormatUnknown, false
}

// skipJSONValueBounded consumes one JSON value from dec, stopping if the token
// budget is exhausted or the stream ends/errors.
func skipJSONValueBounded(dec *json.Decoder, tokens *int, maxTokens int) bool {
	if *tokens >= maxTokens {
		return false
	}
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	*tokens++
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return true
	}
	depth := 1
	for depth > 0 {
		if *tokens >= maxTokens {
			return false
		}
		t, err := dec.Token()
		if err != nil {
			return false
		}
		*tokens++
		if dd, isDelim := t.(json.Delim); isDelim {
			switch dd {
			case '{', '[':
				depth++
			default:
				depth--
			}
		}
	}
	return true
}

// parseTFJS walks a TF-JS model.json: the graph topology's op names and the
// weightsManifest's paths.
func parseTFJS(ctx *artifact.Ctx, s source.Source) {
	cap := ctx.Limits.MaxHeaderBytes
	if cap <= 0 {
		cap = limits.Default().MaxHeaderBytes
	}
	if s.Size() > cap {
		limits.Emit(ctx.Sink, limits.RuleHeader, "MaxHeaderBytes", s.Size(), cap, "TF-JS model.json truncated before analysis")
	}
	n := s.Size()
	if n > cap {
		n = cap
	}
	data, err := s.Bytes(0, n)
	if err != nil && len(data) == 0 {
		ctx.Sink.Emit(ruleTFStruct, 0, "TF-JS model.json is unreadable")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		ctx.Sink.Emit(ruleTFStruct, 0, "TF-JS model.json is not valid JSON: "+err.Error())
		return
	}
	if topo, ok := doc["modelTopology"].(map[string]any); ok {
		if _, isKeras := topo["class_name"]; isKeras {
			analyzeKerasValue(ctx, 0, "modelTopology", topo, 0, &kerasBudget{})
		} else {
			walkTopology(ctx, topo)
		}
	}
	if manifest, ok := doc["weightsManifest"].([]any); ok {
		walkWeightsManifest(ctx, manifest)
	}
}

// walkTopology walks a GraphDef-as-JSON: node[].op and node[].attr strings. The
// walk does not recurse (a node's attr strings are collected by
// jsonStringsBelow), so it carries no depth.
func walkTopology(ctx *artifact.Ctx, topo map[string]any) {
	nodes, _ := topo["node"].([]any)
	for _, nv := range nodes {
		n, ok := nv.(map[string]any)
		if !ok {
			continue
		}
		op, _ := n["op"].(string)
		name, _ := n["name"].(string)
		switch op {
		case "PyFunc", "EagerPyFunc", "PyFuncStateless":
			ctx.Sink.EmitExtra(ruleTFPyFunc, 0, "TF-JS node "+clip(name, 80)+" runs op "+op,
				map[string]string{"op": op, "node": clip(name, 80)})
		}
		if strings.HasPrefix(op, "Flex") {
			ctx.Sink.EmitExtra(ruleTFJSFlexOp, 0, "TF-JS node "+clip(name, 80)+" uses op "+op,
				map[string]string{"op": op, "node": clip(name, 80)})
		}
		if attr, ok := n["attr"].(map[string]any); ok {
			keys := sortedKeys(attr)
			for _, k := range keys {
				for _, v := range jsonStringsBelow(attr[k]) {
					if fileIOOps[op] {
						if why := pathEscapeReason(v); why != "" {
							ctx.Sink.EmitExtra(ruleTFFileIO, 0,
								why+" in TF-JS node "+clip(name, 60)+" op "+op+": "+clip(v, 120),
								map[string]string{"reason": why, "value": clip(v, 120)})
						}
					}
					scanTextCapped(ctx, 0, "TF-JS op attribute", v)
				}
			}
		}
	}
}

// walkWeightsManifest checks the weight shard paths.
func walkWeightsManifest(ctx *artifact.Ctx, manifest []any) {
	for _, gv := range manifest {
		g, ok := gv.(map[string]any)
		if !ok {
			continue
		}
		paths, _ := g["paths"].([]any)
		for _, pv := range paths {
			p, ok := pv.(string)
			if !ok {
				continue
			}
			if why := pathEscapeReason(p); why != "" {
				ctx.Sink.EmitExtra(ruleTFFileIO, 0, why+" in weights manifest path: "+clip(p, 120),
					map[string]string{"reason": why, "value": clip(p, 120)})
			}
			scanTextCapped(ctx, 0, "weights manifest path", p)
		}
	}
}

// jsonStringsBelow returns every string value nested below v (bounded depth).
func jsonStringsBelow(v any) []string {
	var out []string
	var walk func(any, int)
	walk = func(x any, d int) {
		if d > 4 || len(out) >= 32 {
			return
		}
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e, d+1)
			}
		case map[string]any:
			for _, k := range sortedKeys(t) {
				walk(t[k], d+1)
			}
		}
	}
	walk(v, 0)
	return out
}

// sortedKeys returns a map's keys sorted, so a walk over JSON is deterministic.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- bare checkpoint ---------------------------------------------------

// checkpointParser is the registered parser for FormatTFCheckpoint.
type checkpointParser struct{}

// sniffCheckpoint recognises a `.index` checkpoint bundle header. There is no
// magic to dispatch on, so the name is used as the discriminator; the shape check
// (a plausible shard count as the first field) keeps it from claiming arbitrary
// protobufs that happen to end in .index.
func sniffCheckpoint(s source.Source, l limits.Limits) (artifact.Format, bool) {
	if !strings.HasSuffix(s.Name(), ".index") || s.Size() < 4 {
		return artifact.FormatUnknown, false
	}
	r := newPBReader(s, 0, min64(s.Size(), 64))
	num, typ, _, ok := r.next()
	if !ok || num != 1 || typ != 0 { // 0 = varint
		return artifact.FormatUnknown, false
	}
	v, ok := r.varintValue()
	if !ok || v == 0 || v > 1_000_000 {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatTFCheckpoint, true
}

// Parse scans a bare checkpoint: structure and indicators only.
func (checkpointParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	if size < 4 {
		ctx.Sink.Emit(ruleTFCheckpointStruct, 0, "checkpoint index is shorter than a bundle header")
		return nil
	}
	r := newPBReader(s, 0, size)
	num, typ, _, ok := r.next()
	if !ok || num != 1 || typ != 0 {
		ctx.Sink.Emit(ruleTFCheckpointStruct, 0, "bundle header does not begin with a shard count")
		return nil
	}
	if _, ok := r.varintValue(); !ok {
		ctx.Sink.Emit(ruleTFCheckpointStruct, 0, "bundle header shard count is unreadable")
		return nil
	}
	// Walk the remaining fields to prove the framing, without rebuilding the
	// object graph (v1 does not).
	for {
		_, typ, off, ok := r.next()
		if !ok {
			break
		}
		if !r.skipValue(typ) {
			ctx.Sink.Emit(ruleTFCheckpointStruct, off, "checkpoint index field declares a length past the end")
			break
		}
	}
	// Indicators over a bounded prefix: a checkpoint has no inline code, but a
	// name or a shape can still carry a URL or a credential path.
	prefix := min64(size, 1<<20)
	if b, err := s.Bytes(0, prefix); err == nil && len(b) > 0 {
		scanTextCapped(ctx, 0, "checkpoint index", string(b))
	}
	ctx.Sink.Emit(ruleTFCheckpointNoCode, 0, "bare checkpoint: variables only, no graph and no inline code")
	return nil
}

// itoa is a tiny int formatter for evidence strings.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// itoa64 formats a non-negative byte offset for evidence.
func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// itoaF formats a float with two decimals, without pulling fmt into the hot path.
func itoaF(v float64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	whole := int64(v)
	frac := int64((v - float64(whole)) * 100)
	s := itoa64(whole)
	if frac < 10 {
		s += ".0"
	} else {
		s += "."
	}
	s += itoa64(frac)
	if neg {
		s = "-" + s
	}
	return s
}
