// Package onnx parses ONNX models with hand-written protobuf wire walkers.
//
// ONNX is the interchange format nearly every serving stack accepts, and its
// attack surface is not the tensor math: it is the file references and the
// declarations around it. The loader reads external tensor files whose location
// the *artifact* supplies (the traversal and symlink families), assigns
// external_data keys onto an object (the attribute-injection family), sizes an
// allocation from a length string (the OOM family), resolves operators in
// domains the runtime has to provide as native code, and executes model-local
// function bodies. Each of those has a published advisory, cited on the rule.
//
// The walkers here never decode a tensor payload. They walk the message tree
// with google.golang.org/protobuf/encoding/protowire, skip every length-delimited
// body they do not need by its declared length, and validate each length against
// the bytes actually remaining before it is used.
package onnx

import (
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
	"google.golang.org/protobuf/encoding/protowire"
)

// errUnexpectedGroup reports a protobuf group field. onnx.proto3 never uses
// them, and every implementation that has tried to support them has shipped a
// parsing bug, so the value is refused rather than skipped.
var errUnexpectedGroup = errors.New("onnx: protobuf group wire type is not used by onnx.proto3")

// maxIRVersion is the largest ir_version the sniffer treats as plausible. The
// schema is at 14; the bound exists so a random varint cannot qualify a file as
// a ModelProto, not to track the specification.
const maxIRVersion = 100

// dataLocationExternal is TensorProto.DataLocation.EXTERNAL.
const dataLocationExternal = 1

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatONNX,
		Magic:  "protobuf: field 1 varint ir_version, field 7 GraphProto",
		Depth:  artifact.DepthStructural,
		Notes: "the ModelProto/GraphProto/NodeProto/TensorProto structure is walked with protowire: " +
			"external-data references (traversal, whitelist, bounds, symlinks), operator domains, " +
			"model-local functions and the raw_data-versus-dims size relation are checked, and " +
			"doc_string/name/producer_name/metadata_props values are scanned by the shared indicator " +
			"engine. Tensor payloads are not decoded and no weight-level statistics are computed.",
	})
	// Priority 60 is deliberately below every format-specific discriminator: a
	// protobuf-shaped stream is ambiguous between ONNX, TF SavedModel and CoreML,
	// so this sniffer is the generic fallback and the parser records the
	// ambiguity rather than pretending the choice was certain.
	artifact.RegisterSniffer("onnx-proto", 60, sniff)
	artifact.RegisterParser(artifact.FormatONNX, parser{})
}

type parser struct{}

// Parse walks the model and reports every structural, path and metadata finding
// on ctx.Sink. It never returns an error for a malformed artifact: a structure
// violation is a finding, and the walk continues where continuing is meaningful.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	base, contain := resolutionPaths(ctx, s)
	// A header slice of a larger model is not malformed: the campaign fetched a
	// byte prefix under a per-file budget, so a declared extent running past the
	// end is the expected shape. Ask the session before claiming a violation.
	selfPartial := ctx.Session != nil && ctx.Session.IsPartial(ctx.Sink.Artifact())
	w := &walker{
		s:           s,
		l:           ctx.Limits,
		sink:        ctx.Sink,
		root:        base,
		contain:     contain,
		selfPartial: selfPartial,
		partial: func(rel string) bool {
			if ctx.Session == nil {
				return false
			}
			if contain != "" {
				return ctx.Session.IsPartial(filepath.Join(contain, rel))
			}
			return ctx.Session.IsPartial(filepath.Join(base, rel))
		},
	}
	// The sniffer cannot emit, so the honest note about which parser ran on an
	// ambiguous protobuf is made here.
	if sh, ok := sniffShape(newReader(s, 0, s.Size()), s); !ok || !sh.decisive() {
		ctx.Sink.EmitExtra(artifact.RuleAmbiguous, 0,
			"protobuf-shaped artifact parsed as ONNX: "+sh.summary(),
			map[string]string{"parser": "onnx", "reason": "shape is not decisive between ONNX, TF SavedModel and CoreML"})
	}

	st := w.walkModel(newReader(s, 0, s.Size()))
	w.flushDomains()
	if selfPartial {
		// The walk stopped where the bytes did. Report the slice once and skip the
		// required-field checks, which describe a file that claims to be whole.
		w.noteSlice(s.Size())
		return nil
	}
	if !st.hasIRVersion {
		w.structAt(0, "ModelProto has no ir_version field")
	}
	if !st.hasGraph {
		w.structAt(0, "ModelProto has no graph field")
	}
	if !st.hasOpset {
		w.structAt(0, "ModelProto imports no operator set")
	}
	return nil
}

// modelShape is what a top-level protobuf walk revealed about an alleged
// ModelProto.
type modelShape struct {
	ok           bool // the walked prefix was a legal ONNX-shaped field stream
	firstIR      bool // the first field was 1 varint with a plausible ir_version
	hasOpset     bool
	hasFunctions bool
	hasTraining  bool
	hasConfig    bool
	hasMetadata  bool
	graphSeen    bool
	graphShaped  bool
	// truncated records that the walk stopped inside a declared length rather
	// than at an illegal tag: the artifact is a prefix of a larger file.
	truncated bool
	fields    int
}

// decisive reports whether the shape is enough to tell ONNX from the other
// protobuf-shaped formats (TF SavedModel, CoreML). A graph is; a lone
// ir_version is not.
func (m modelShape) decisive() bool {
	return m.graphShaped || m.hasOpset || m.hasMetadata || m.hasFunctions || m.hasTraining || m.hasConfig
}

func (m modelShape) summary() string {
	parts := []string{}
	if m.firstIR {
		parts = append(parts, "ir_version present")
	}
	if m.graphSeen {
		if m.graphShaped {
			parts = append(parts, "graph field is GraphProto-shaped")
		} else {
			parts = append(parts, "graph field present but not GraphProto-shaped")
		}
	}
	if m.hasOpset {
		parts = append(parts, "opset_import present")
	}
	if len(parts) == 0 {
		return "no ONNX-specific field was recognised"
	}
	return strings.Join(parts, "; ")
}

// sniff accepts a stream whose first field is a plausible ir_version, or whose
// fields include a GraphProto-shaped body.
func sniff(s source.Source, _ limits.Limits) (artifact.Format, bool) {
	// The smallest possible ModelProto is a lone ir_version field: a one-byte tag
	// plus a one-byte varint.
	if s.Size() < 2 {
		return artifact.FormatUnknown, false
	}
	sh, ok := sniffShape(newReader(s, 0, s.Size()), s)
	if !ok {
		// The walk stopped early. Only truncation can still be ONNX: an illegal
		// tag or an impossible wire type is a different format's bytes.
		if sh.truncated && sh.firstIR {
			return artifact.FormatONNX, true
		}
		return artifact.FormatUnknown, false
	}
	if sh.firstIR || sh.graphShaped {
		return artifact.FormatONNX, true
	}
	return artifact.FormatUnknown, false
}

// sniffShape walks the top-level field records and reports what it saw. It never
// descends: a graph or an initializer body is skipped by its declared length,
// with a bounded probe for the GraphProto shape, so the cost is one pass over
// the top-level tags however large the model is.
func sniffShape(r *reader, s source.Source) (modelShape, bool) {
	var m modelShape
	m.ok = true
	first := true
	for range maxSniffFields {
		if r.remaining() <= 0 {
			break
		}
		num, typ, _, ok := r.next()
		if !ok {
			m.ok = false
			break
		}
		m.fields++
		if first {
			first = false
			if num != 1 {
				// Not a ModelProto opener; the graph-shaped path below may still
				// recognise it, so keep walking.
				m.firstIR = false
			} else {
				if typ != protowire.VarintType {
					m.ok = false
					break
				}
				v, ok := r.varintValue()
				if !ok || v == 0 || v > maxIRVersion {
					m.ok = false
					break
				}
				m.firstIR = true
				continue
			}
		}
		if sp, known := modelFields[num]; known && !sp.kind.accepts(typ) {
			m.ok = false
			break
		}
		if typ != protowire.BytesType {
			if !r.skipValue(typ) {
				m.ok = false
				break
			}
			continue
		}
		off, n, ok := r.bytesValue()
		if !ok {
			m.ok = false
			break
		}
		switch num {
		case 2, 3, 4, 6:
			// A producer/documented string field: legal, not decisive on its own.
		case 7:
			m.graphSeen = true
			// Only a decisive signal (a node or an initializer shaped like its
			// counterpart) counts: a lone string field also appears in a TF
			// GraphDef or a CoreML message, and claiming ONNX on it would be a
			// guess, which is what SC4N-FORMAT-AMBIGUOUS exists to avoid.
			if shaped, decisive := graphShape(s, off, n); shaped && decisive {
				m.graphShaped = true
			}
		case 8:
			m.hasOpset = true
		case 14:
			m.hasMetadata = true
		case 20:
			m.hasTraining = true
		case 25:
			m.hasFunctions = true
		case 26:
			m.hasConfig = true
		}
	}
	// An unexpected EOF is the slice shape: the declared length runs past the end
	// of the bytes we were given. A parse error is not — that is a tag that cannot
	// be read at all.
	m.truncated = errors.Is(r.err, io.ErrUnexpectedEOF)
	return m, m.ok
}

// modelState is what the full walk learned, for the required-field checks that
// can only be made once the stream has been walked to the end.
type modelState struct {
	hasIRVersion bool
	hasGraph     bool
	hasOpset     bool
}

// walker carries the per-artifact state: the budget counters, the containment
// root for external-data resolution and the recursion guards.
type walker struct {
	s    source.Source
	l    limits.Limits
	sink *report.Sink
	// root is the directory the artifact lives in (external_data locations are
	// relative to it) and contain is the session's containment root, which the
	// resolved path must stay inside when one is set.
	root    string
	contain string
	// partial asks whether the file at a root-relative path is a truncated copy,
	// and partialNoted keeps the informational finding to one per artifact.
	partial      func(rel string) bool
	partialNoted bool
	// selfPartial marks this artifact (not a sibling) as a header slice, and
	// selfNoted keeps its informational finding to one per artifact.
	selfPartial bool
	selfNoted   bool

	elems    int64
	elemsHit bool
	depthHit bool

	msgDepth   int
	graphDepth int

	// domains accumulates one entry per distinct non-standard (domain, kind)
	// pair; domainAt indexes it. The finding is emitted once when the walk ends
	// rather than once per use, because one node in a foreign domain is the same
	// fact as the five hundredth and an onnxruntime-optimised model repeats it
	// hundreds of times.
	domains  []domainUse
	domainAt map[string]int
}

// domainUse is one non-standard domain seen during the walk: the first offset it
// appeared at and how many times it was used.
type domainUse struct {
	domain string
	kind   string
	off    int64
	count  int
}

// noteDomain records one use of a non-standard domain instead of emitting it.
// The evidence for a single use is unchanged; a repeated use is reported once,
// with the count and the first offset, so the aggregate stays verifiable.
func (w *walker) noteDomain(off int64, domain, kind string) {
	k := kind + "\x00" + domain
	if i, ok := w.domainAt[k]; ok {
		w.domains[i].count++
		return
	}
	if w.domainAt == nil {
		w.domainAt = make(map[string]int)
	}
	w.domainAt[k] = len(w.domains)
	w.domains = append(w.domains, domainUse{domain: domain, kind: kind, off: off, count: 1})
}

// flushDomains emits the accumulated non-standard-domain findings, exactly one
// per distinct (domain, kind) pair, in first-use order.
func (w *walker) flushDomains() {
	for i := range w.domains {
		u := &w.domains[i]
		ev := u.kind + " uses the non-standard domain " + u.domain
		if u.count > 1 {
			ev += " (" + strconv.Itoa(u.count) + " occurrences reported as one finding)"
		}
		w.sink.EmitExtra(ruleCustomDomain, u.off, ev, map[string]string{
			"domain":      u.domain,
			"kind":        u.kind,
			"occurrences": strconv.Itoa(u.count),
		})
	}
}

// count consumes one element of the configured element budget. It returns false
// once the budget is spent, at which point the walk stops and the budget
// exhaustion has already been reported.
func (w *walker) count() bool {
	w.elems++
	if w.elems > int64(w.l.MaxEntries) {
		if !w.elemsHit {
			w.elemsHit = true
			limits.Emit(w.sink, limits.RuleEntries, "MaxEntries", w.elems, int64(w.l.MaxEntries), "onnx message elements")
		}
		return false
	}
	return true
}

func (w *walker) structAt(off int64, msg string) {
	w.sink.Emit(ruleStruct, off, msg)
}

func (w *walker) badWire(off int64, what string) {
	if w.selfPartial {
		// The stream ended inside a declared length because the artifact is a
		// prefix of a larger file; the slice note covers it.
		w.noteSlice(0)
		return
	}
	w.sink.Emit(ruleStruct, off, "truncated or malformed "+what)
}

// noteSlice reports, once per artifact, that this artifact is a header slice.
func (w *walker) noteSlice(size int64) {
	if w.selfNoted {
		return
	}
	w.selfNoted = true
	ev := "the artifact is a header slice of a larger file, so the parse stopped at the slice boundary"
	extra := map[string]string{}
	if size > 0 {
		ev = "the artifact is a " + strconv.FormatInt(size, 10) + "-byte slice of a larger file, so the parse stopped at the slice boundary"
		extra["bytes"] = strconv.FormatInt(size, 10)
	}
	w.sink.EmitExtra(artifact.RulePartialSlice, 0, ev, extra)
}

// checkField reports a structure finding when a known field carries a wire type
// its ONNX declaration cannot have. An unknown field number is legal protobuf
// (forward compatibility) and is left to the caller to skip.
func (w *walker) checkField(table map[protowire.Number]fieldSpec, num protowire.Number, typ protowire.Type, off int64, msg string) bool {
	sp, known := table[num]
	if !known {
		return true
	}
	if !sp.kind.accepts(typ) {
		w.structAt(off, msg+" field "+sp.name+" has an impossible wire type")
		return false
	}
	return true
}

// enterMsg and leaveMsg bound the message recursion so a chain of empty nested
// messages cannot exhaust the Go stack.
func (w *walker) enterMsg() bool {
	if w.msgDepth >= maxStructDepth {
		w.structAt(0, "message nesting exceeds the internal depth cap")
		return false
	}
	w.msgDepth++
	return true
}

func (w *walker) leaveMsg() { w.msgDepth-- }

// enterGraph applies the configured container-depth budget to GraphProto
// nesting. A subgraph appears as an attribute value (the control-flow ops), so
// this is the onnx counterpart of the archive depth cap.
func (w *walker) enterGraph() bool {
	if w.graphDepth >= w.l.MaxDepth {
		if !w.depthHit {
			w.depthHit = true
			limits.Emit(w.sink, limits.RuleDepth, "MaxDepth", int64(w.graphDepth+1), int64(w.l.MaxDepth), "onnx nested graph")
		}
		return false
	}
	if !w.enterMsg() {
		return false
	}
	w.graphDepth++
	return true
}

func (w *walker) leaveGraph() {
	w.graphDepth--
	w.leaveMsg()
}

// walkModel walks the top-level ModelProto.
func (w *walker) walkModel(r *reader) modelState {
	var st modelState
	if !w.enterMsg() {
		return st
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return st
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "ModelProto")
			return st
		}
		if !w.checkField(modelFields, num, typ, off, "ModelProto") {
			if !r.skipValue(typ) {
				return st
			}
			continue
		}
		switch num {
		case 1: // ir_version
			if _, ok := r.varintValue(); !ok {
				w.badWire(off, "ir_version")
				return st
			}
			st.hasIRVersion = true
		case 2:
			if !w.scanStringField(r, off, "producer_name") {
				return st
			}
		case 3:
			if !w.scanStringField(r, off, "producer_version") {
				return st
			}
		case 4:
			if !w.scanStringField(r, off, "domain") {
				return st
			}
		case 5: // model_version
			if _, ok := r.varintValue(); !ok {
				w.badWire(off, "model_version")
				return st
			}
		case 6:
			if !w.scanStringField(r, off, "doc_string") {
				return st
			}
		case 7: // graph
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "graph")
				return st
			}
			st.hasGraph = true
			w.walkGraph(newReader(w.s, bo, bo+n))
		case 8: // opset_import
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "opset_import")
				return st
			}
			st.hasOpset = true
			w.walkOpset(newReader(w.s, bo, bo+n))
		case 14: // metadata_props
			if !w.walkEntry(r, off, true) {
				return st
			}
		case 20: // training_info
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "training_info")
				return st
			}
			w.walkTrainingInfo(newReader(w.s, bo, bo+n))
		case 25: // functions
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "functions")
				return st
			}
			w.sink.EmitExtra(ruleFunction, off, "model-local FunctionProto", map[string]string{"field": "functions"})
			w.walkFunction(newReader(w.s, bo, bo+n))
		case 26: // configuration
			if _, _, ok := r.bytesValue(); !ok {
				w.badWire(off, "configuration")
				return st
			}
		default:
			if !r.skipValue(typ) {
				return st
			}
		}
	}
	return st
}

// walkGraph walks a GraphProto.
func (w *walker) walkGraph(r *reader) {
	if !w.enterGraph() {
		return
	}
	defer w.leaveGraph()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "GraphProto")
			return
		}
		if !w.checkField(graphFields, num, typ, off, "GraphProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1: // node
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "node")
				return
			}
			w.walkNode(newReader(w.s, bo, bo+n))
		case 2: // name
			if !w.scanStringField(r, off, "graph name") {
				return
			}
		case 5: // initializer
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "initializer")
				return
			}
			w.walkTensor(newReader(w.s, bo, bo+n))
		case 10: // doc_string
			if !w.scanStringField(r, off, "graph doc_string") {
				return
			}
		case 11, 12, 13: // input, output, value_info
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "value info")
				return
			}
			w.walkValueInfo(newReader(w.s, bo, bo+n))
		case 15: // sparse_initializer
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "sparse_initializer")
				return
			}
			w.walkSparse(newReader(w.s, bo, bo+n))
		case 16: // metadata_props
			if !w.walkEntry(r, off, true) {
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkNode walks a NodeProto.
func (w *walker) walkNode(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "NodeProto")
			return
		}
		if !w.checkField(nodeFields, num, typ, off, "NodeProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1, 2: // input, output tensor names
			if _, _, ok := r.bytesValue(); !ok {
				w.badWire(off, "node input/output")
				return
			}
		case 3: // name
			if !w.scanStringField(r, off, "node name") {
				return
			}
		case 4: // op_type
			if !w.scanStringField(r, off, "node op_type") {
				return
			}
		case 5: // attribute
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "attribute")
				return
			}
			w.walkAttribute(newReader(w.s, bo, bo+n))
		case 6: // doc_string
			if !w.scanStringField(r, off, "node doc_string") {
				return
			}
		case 7: // domain
			if !w.checkDomain(r, off, "node") {
				return
			}
		case 8: // overload
			_, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "overload")
				return
			}
			if n > 0 {
				w.sink.EmitExtra(ruleFunction, off, "node overload binds a model-local function",
					map[string]string{"field": "overload"})
			}
		case 9: // metadata_props
			if !w.walkEntry(r, off, true) {
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkAttribute walks an AttributeProto. Only the string and subgraph-valued
// fields need interpretation: the rest are constants.
func (w *walker) walkAttribute(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "AttributeProto")
			return
		}
		if !w.checkField(attributeFields, num, typ, off, "AttributeProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 4: // s: a string attribute value
			if !w.scanStringField(r, off, "attribute string") {
				return
			}
		case 9: // strings
			if !w.scanStringField(r, off, "attribute string") {
				return
			}
		case 1, 13, 21: // name, doc_string, ref_attr_name
			if !w.scanStringField(r, off, "attribute name/doc_string") {
				return
			}
		case 2, 3, 20: // f, i, type: scalar discriminators
			if !r.skipValue(typ) {
				return
			}
		case 5, 10: // t, tensors: tensor constants, which may reference external data
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "attribute tensor")
				return
			}
			w.walkTensor(newReader(w.s, bo, bo+n))
		case 6, 11: // g, graphs: subgraphs, evaluated by the runtime
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "attribute graph")
				return
			}
			w.walkGraph(newReader(w.s, bo, bo+n))
		case 22, 23: // sparse_tensor, sparse_tensors
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "attribute sparse tensor")
				return
			}
			w.walkSparse(newReader(w.s, bo, bo+n))
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkTensor walks a TensorProto. It checks the raw_data-versus-dims size
// relation and every external_data reference, and it never reads raw_data.
func (w *walker) walkTensor(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	start := r.pos
	var (
		dims         []int64
		rankHit      bool
		dataType     int64
		hasRaw       bool
		rawLen       int64
		dataLocation int64
		ext          externalRef
		hasExternal  bool
	)
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "TensorProto")
			return
		}
		if !w.checkField(tensorFields, num, typ, off, "TensorProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1: // dims, packed or unpacked
			switch typ {
			case protowire.VarintType:
				v, ok := r.varintValue()
				if !ok {
					w.badWire(off, "dims")
					return
				}
				w.addDim(off, int64(v), &dims, &rankHit)
			case protowire.BytesType:
				bo, n, ok := r.bytesValue()
				if !ok {
					w.badWire(off, "dims")
					return
				}
				b := r.view(bo, n)
				for len(b) > 0 && len(dims) <= maxRank {
					v, k := protowire.ConsumeVarint(b)
					if k < 0 {
						w.structAt(off, "packed dims is not a varint list")
						b = nil
						break
					}
					w.addDim(off, int64(v), &dims, &rankHit)
					b = b[k:]
				}
				if len(b) > 0 && !rankHit {
					w.structAt(off, "rank exceeds the internal cap")
					rankHit = true
				}
			}
		case 2: // data_type
			v, ok := r.varintValue()
			if !ok {
				w.badWire(off, "data_type")
				return
			}
			dataType = int64(v)
		case 3: // segment: a chunked tensor, deprecated
			if _, _, ok := r.bytesValue(); !ok {
				w.badWire(off, "segment")
				return
			}
		case 4, 5, 6, 7, 10, 11: // typed element data; not interpreted
			if !r.skipValue(typ) {
				return
			}
		case 8: // name
			if !w.scanStringField(r, off, "tensor name") {
				return
			}
		case 9: // raw_data: length only, never read
			_, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "raw_data")
				return
			}
			hasRaw = true
			rawLen = n
		case 12: // doc_string
			if !w.scanStringField(r, off, "tensor doc_string") {
				return
			}
		case 13: // external_data
			key, val, ok := w.readEntry(r, off, false)
			if !ok {
				return
			}
			if key != "" {
				if ext.vals == nil {
					ext.vals = map[string]string{}
				}
				if _, dup := ext.vals[key]; !dup {
					ext.keys = append(ext.keys, key)
				}
				ext.vals[key] = val
				hasExternal = true
			}
		case 14: // data_location
			v, ok := r.varintValue()
			if !ok {
				w.badWire(off, "data_location")
				return
			}
			dataLocation = int64(v)
		case 16: // metadata_props
			if !w.walkEntry(r, off, true) {
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
	w.checkTensor(start, dims, dataType, hasRaw, rawLen, dataLocation, hasExternal, ext)
}

// addDim records one dimension, reporting a negative dimension and a rank above
// the internal cap rather than growing a slice from an attacker-controlled list.
func (w *walker) addDim(off int64, d int64, dims *[]int64, rankHit *bool) {
	if d < 0 {
		w.structAt(off, "tensor dimension is negative")
	}
	if len(*dims) < maxRank {
		*dims = append(*dims, d)
		return
	}
	if !*rankHit {
		*rankHit = true
		w.structAt(off, "tensor rank exceeds the internal cap")
	}
}

// checkTensor applies the invariants that can only be evaluated once the whole
// TensorProto has been seen.
func (w *walker) checkTensor(off int64, dims []int64, dataType int64, hasRaw bool, rawLen int64, dataLocation int64, hasExternal bool, ext externalRef) {
	if dataType == dataTypeUndefined {
		w.structAt(off, "TensorProto data_type is UNDEFINED")
	}
	if hasRaw && hasExternal {
		w.structAt(off, "TensorProto sets both raw_data and external_data")
	}
	if hasExternal && dataLocation != dataLocationExternal {
		w.structAt(off, "external_data is set but data_location is not EXTERNAL")
	}
	if !hasExternal && dataLocation == dataLocationExternal {
		w.structAt(off, "data_location is EXTERNAL but external_data is empty")
	}
	if hasExternal {
		w.checkExternalData(off, ext)
	}
	if !hasRaw {
		return
	}
	bits, known := dataTypeBits[dataType]
	if !known {
		// An enum value sc4n does not know: forward compatibility, and no size to
		// check against.
		return
	}
	expected, ok := dimsBytes(dims, bits)
	if !ok {
		// Overflow or a negative dimension, already reported where it was seen.
		return
	}
	if expected != uint64(rawLen) {
		w.structAt(off, "raw_data length "+strconv.FormatInt(rawLen, 10)+
			" bytes does not match product(dims) x element size ("+strconv.FormatUint(expected, 10)+" bytes)")
	}
}

// dimsBytes returns the number of raw_data bytes a tensor of the given dims and
// element width occupies, with the product computed in uint64 and every step
// overflow-checked. Sub-byte element types (UINT4/INT4/FLOAT4E2M1 at 4 bits,
// UINT2/INT2 at 2 bits) are packed and the last byte is padded, so the count is
// the specification's ceil(product(dims) x bits / 8); for byte-aligned types the
// rounding is exact. ok is false for a negative dimension or an overflowing
// product, where no size comparison is meaningful.
func dimsBytes(dims []int64, bits uint64) (uint64, bool) {
	prod := uint64(1)
	zero := false
	for _, d := range dims {
		if d < 0 {
			return 0, false
		}
		if d == 0 {
			zero = true
			continue
		}
		if prod > math.MaxUint64/uint64(d) {
			return 0, false
		}
		prod *= uint64(d)
	}
	if zero {
		return 0, true
	}
	// The ceiling needs prod*bits + 7, so bound the multiply by MaxUint64-7 as
	// well as by MaxUint64/bits.
	if bits != 0 && prod > (math.MaxUint64-7)/bits {
		return 0, false
	}
	return (prod*bits + 7) / 8, true
}

// walkValueInfo walks a ValueInfoProto: its name and documentation are strings a
// reviewer reads, its type is skipped.
func (w *walker) walkValueInfo(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "ValueInfoProto")
			return
		}
		if !w.checkField(valueInfoFields, num, typ, off, "ValueInfoProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1:
			if !w.scanStringField(r, off, "value name") {
				return
			}
		case 3:
			if !w.scanStringField(r, off, "value doc_string") {
				return
			}
		case 4:
			if !w.walkEntry(r, off, true) {
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkSparse walks a SparseTensorProto: its value and index tensors carry the
// same external-data and size invariants as a dense initializer.
func (w *walker) walkSparse(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "SparseTensorProto")
			return
		}
		if !w.checkField(sparseFields, num, typ, off, "SparseTensorProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1, 2:
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "sparse tensor")
				return
			}
			w.walkTensor(newReader(w.s, bo, bo+n))
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkOpset walks an OperatorSetIdProto and reports a non-standard domain.
func (w *walker) walkOpset(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "OperatorSetIdProto")
			return
		}
		if !w.checkField(opsetFields, num, typ, off, "OperatorSetIdProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1:
			if !w.checkDomain(r, off, "opset_import") {
				return
			}
		case 2:
			if _, ok := r.varintValue(); !ok {
				w.badWire(off, "opset version")
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkTrainingInfo walks a TrainingInfoProto. Its initialization and algorithm
// graphs are executed during training, so they are walked exactly like the
// inference graph: a non-standard operator domain or an external tensor
// reference hidden in a training algorithm is the same primitive as one in the
// main graph.
func (w *walker) walkTrainingInfo(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "TrainingInfoProto")
			return
		}
		if !w.checkField(trainingInfoFields, num, typ, off, "TrainingInfoProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1, 2: // initialization, algorithm
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "training graph")
				return
			}
			w.walkGraph(newReader(w.s, bo, bo+n))
		case 3, 4: // initialization_binding, update_binding
			if !w.walkEntry(r, off, true) {
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkFunction walks a FunctionProto. Its nodes are walked by the node walker,
// because a model-local function body is exactly where a non-standard domain or
// a nested external reference would hide.
func (w *walker) walkFunction(r *reader) {
	if !w.enterMsg() {
		return
	}
	defer w.leaveMsg()
	for r.remaining() > 0 {
		if !w.count() {
			return
		}
		num, typ, off, ok := r.next()
		if !ok {
			w.badWire(off, "FunctionProto")
			return
		}
		if !w.checkField(functionFields, num, typ, off, "FunctionProto") {
			if !r.skipValue(typ) {
				return
			}
			continue
		}
		switch num {
		case 1, 8, 10, 13: // name, doc_string, domain, overload
			if !w.scanStringField(r, off, "function string") {
				return
			}
		case 7: // node
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "function node")
				return
			}
			w.walkNode(newReader(w.s, bo, bo+n))
		case 9: // opset_import
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "function opset_import")
				return
			}
			w.walkOpset(newReader(w.s, bo, bo+n))
		case 11: // attribute_proto
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "function attribute")
				return
			}
			w.walkAttribute(newReader(w.s, bo, bo+n))
		case 12: // value_info
			bo, n, ok := r.bytesValue()
			if !ok {
				w.badWire(off, "function value_info")
				return
			}
			w.walkValueInfo(newReader(w.s, bo, bo+n))
		case 14: // metadata_props
			if !w.walkEntry(r, off, true) {
				return
			}
		default:
			if !r.skipValue(typ) {
				return
			}
		}
	}
}

// walkEntry reads one StringStringEntryProto (the shape ONNX uses for maps) and
// scans both sides when scan is set. It returns ok=false only when the framing
// itself is unreadable.
func (w *walker) walkEntry(r *reader, off int64, scan bool) bool {
	_, _, ok := w.readEntry(r, off, scan)
	return ok
}

// readEntry is walkEntry with the values returned, for external_data.
func (w *walker) readEntry(r *reader, off int64, scan bool) (key, val string, ok bool) {
	bo, n, ok := r.bytesValue()
	if !ok {
		w.badWire(off, "map entry")
		return "", "", false
	}
	sub := newReader(w.s, bo, bo+n)
	for sub.remaining() > 0 {
		if !w.count() {
			return "", "", true
		}
		num, typ, foff, ok := sub.next()
		if !ok {
			w.badWire(foff, "StringStringEntryProto")
			return "", "", false
		}
		if !w.checkField(entryFields, num, typ, foff, "StringStringEntryProto") {
			if !sub.skipValue(typ) {
				return "", "", false
			}
			continue
		}
		switch num {
		case 1, 2:
			var v string
			if scan {
				if !w.scanStringField(sub, foff, "map entry value") {
					return "", "", false
				}
			} else {
				v, ok = w.readString(sub, foff, "map entry")
				if !ok {
					return "", "", false
				}
			}
			if num == 1 {
				key = v
			} else {
				val = v
			}
		default:
			if !sub.skipValue(typ) {
				return "", "", false
			}
		}
	}
	return key, val, true
}

// scanStringField reads a length-delimited string field and hands it to the
// shared indicator engine. A value over MaxStringBlob is reported and skipped; a
// value that is not UTF-8 text is a structural contradiction (a protobuf string
// field must be valid UTF-8) and is not scanned, because scanning binary bytes
// as metadata is how a scanner manufactures findings out of random data.
func (w *walker) scanStringField(r *reader, off int64, what string) bool {
	bo, n, ok := r.bytesValue()
	if !ok {
		w.badWire(off, what)
		return false
	}
	if n == 0 {
		return true
	}
	if n > w.l.MaxStringBlob {
		limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", n, w.l.MaxStringBlob, "onnx "+what)
		return true
	}
	b := r.view(bo, n)
	if b == nil {
		return true
	}
	if !printableUTF8(b) {
		w.structAt(off, what+" is not valid UTF-8 text")
		return true
	}
	stringscan.Emit(w.sink, bo, b)
	return true
}

// readString reads a length-delimited string field and returns its text, under
// the MaxStringBlob cap and with the same UTF-8 rule as scanStringField.
func (w *walker) readString(r *reader, off int64, what string) (string, bool) {
	bo, n, ok := r.bytesValue()
	if !ok {
		w.badWire(off, what)
		return "", false
	}
	if n == 0 {
		return "", true
	}
	if n > w.l.MaxStringBlob {
		limits.Emit(w.sink, limits.RuleString, "MaxStringBlob", n, w.l.MaxStringBlob, "onnx "+what)
		return "", true
	}
	b := r.view(bo, n)
	if b == nil {
		return "", true
	}
	if !printableUTF8(b) {
		w.structAt(off, what+" is not valid UTF-8 text")
		return "", true
	}
	return string(b), true
}

// checkDomain reads a domain string and notes it (through noteDomain) when it
// is outside the ONNX-defined operator sets. The finding itself is emitted once
// per distinct (domain, kind) after the walk, not once per node.
func (w *walker) checkDomain(r *reader, off int64, what string) bool {
	bo, n, ok := r.bytesValue()
	if !ok {
		w.badWire(off, "domain")
		return false
	}
	if n == 0 || n > w.l.MaxStringBlob {
		return true
	}
	b := r.view(bo, n)
	if b == nil {
		return true
	}
	if !printableUTF8(b) {
		w.structAt(off, what+" domain is not valid UTF-8 text")
		return true
	}
	d := string(b)
	if !standardDomains[d] {
		w.noteDomain(off, clip(d), what)
	}
	return true
}

// printableUTF8 reports whether b is valid UTF-8 with no control characters
// other than tab, newline and carriage return. A protobuf string field must be
// valid UTF-8, and a binary blob behind a string field is either a misread field
// or a deliberate confusion.
func printableUTF8(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return utf8.Valid(b)
}

// isDunder reports whether a key is shaped like a Python protocol attribute
// ("__class__", "__reduce__"). Such a key is the input to the setattr-shaped
// sink in the unpatched loader (CVE-2026-34445), so it is worth naming in the
// evidence rather than treating every stray key alike.
func isDunder(k string) bool {
	return len(k) > 4 && strings.HasPrefix(k, "__") && strings.HasSuffix(k, "__")
}

// clip truncates an attacker-controlled value for evidence so a finding cannot
// carry an unbounded string into every report format.
func clip(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// resolutionPaths returns the directory an external_data location is relative to
// (the artifact's own) and the containment root the resolved path must stay
// inside.
//
// The two are not interchangeable: the location is relative to the model file, so
// resolving it against a campaign's scan root finds nothing and the check goes
// quiet. Measured on BAAI/bge-m3, whose onnx/model.onnx references a sibling data
// file: 389 offset/length checks disappeared when the campaign passed its scan
// root as -root. The artifact's directory is therefore the base; when a session
// root is set the base is expressed inside it and os.Root enforces the boundary.
func resolutionPaths(ctx *artifact.Ctx, s source.Source) (base, contain string) {
	contain = containmentRoot(ctx)
	name := s.Name()
	if i := strings.LastIndexByte(name, ':'); i > 0 && !strings.ContainsRune(name[i+1:], '/') {
		// A nested member is named "<container>:<member>"; the member's bytes live
		// in memory, so the container's directory is what a relative reference
		// would resolve against.
		name = name[:i]
	}
	if name == "" || strings.HasPrefix(name, "<") {
		return contain, contain
	}
	dir := filepath.Dir(name)
	switch {
	case dir == "." || dir == "" || dir == string(filepath.Separator):
		// A bare name (a member, a stdin name) has no directory of its own, so the
		// containment root is the only base there is.
		base = contain
	case filepath.IsAbs(dir):
		base = filepath.Clean(dir)
	case contain != "":
		base = filepath.Join(contain, dir)
	}
	return base, contain
}

// pathEscapeReason reports why a declared external-data path cannot be a
// relative POSIX path under the model directory, or "" when it can. The checks
// run on the raw value, before any cleaning, because that is the value the
// loader sees.
func pathEscapeReason(v string) string {
	switch {
	case strings.ContainsRune(v, 0):
		return "contains a NUL byte"
	case strings.HasPrefix(v, "/"):
		return "is an absolute POSIX path"
	case hasDriveOrUNC(v):
		return "uses a drive letter or UNC prefix"
	case strings.HasPrefix(v, "~"):
		return "is home-relative"
	case hasURLScheme(v):
		return "is a URL"
	case hasDotDotSegment(v):
		return "contains a '..' segment"
	}
	return ""
}

func hasDriveOrUNC(v string) bool {
	if strings.HasPrefix(v, `\\`) || strings.HasPrefix(v, "//") {
		return true
	}
	if len(v) >= 2 && v[1] == ':' && isASCIILetter(v[0]) {
		return true
	}
	return false
}

func hasURLScheme(v string) bool {
	i := strings.Index(v, "://")
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := v[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && c >= '0' && c <= '9':
		case j > 0 && (c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// hasDotDotSegment reports whether any path segment is "..", treating both POSIX
// and Windows separators as separators: a value written with backslashes is not
// a valid ONNX location, but it must not slip past the traversal check on a host
// that would accept it.
func hasDotDotSegment(v string) bool {
	for i := 0; i <= len(v); {
		j := i
		for j < len(v) && v[j] != '/' && v[j] != '\\' {
			j++
		}
		if j-i == 2 && v[i] == '.' && v[i+1] == '.' {
			return true
		}
		if j >= len(v) {
			return false
		}
		i = j + 1
	}
	return false
}

// externalRef is one TensorProto's external_data map. keys preserves the
// on-the-wire order so evidence and findings stay deterministic.
type externalRef struct {
	keys []string
	vals map[string]string
}

func (e *externalRef) get(k string) (string, bool) {
	if e.vals == nil {
		return "", false
	}
	v, ok := e.vals[k]
	return v, ok
}

// checkExternalData applies the external-data rule set to one tensor.
func (w *walker) checkExternalData(off int64, ref externalRef) {
	loc, hasLoc := ref.get("location")
	locSafe := false
	if !hasLoc || loc == "" {
		w.sink.EmitExtra(ruleExternalTraversal, off,
			"external_data has no location key",
			map[string]string{"key": "location", "resolved": "false", "reason": "location is required"})
	} else {
		locSafe = w.checkExternalPath(off, "location", loc)
	}
	if bp, ok := ref.get("basepath"); ok && bp != "" {
		w.checkExternalPath(off, "basepath", bp)
	}

	for _, k := range ref.keys {
		if externalDataKeys[k] {
			continue
		}
		extra := map[string]string{"key": k, "value": clip(ref.vals[k])}
		if isDunder(k) {
			extra["shape"] = "dunder-attribute"
		}
		w.sink.EmitExtra(ruleExternalKey, off,
			"external_data key \""+clip(k)+"\" is outside the loader whitelist", extra)
	}

	var (
		offset            uint64
		length            uint64
		hasOffset, hasLen bool
	)
	if v, ok := ref.get("offset"); ok {
		if n, valid := w.amount(off, "offset", v); valid {
			offset, hasOffset = n, true
		}
	}
	if v, ok := ref.get("length"); ok {
		if n, valid := w.amount(off, "length", v); valid {
			length, hasLen = n, true
		}
	}
	// A value that already failed the path-shape checks is reported by
	// SC4N-ONNX-EXTERNAL-TRAVERSAL; resolving it would only add a second finding
	// for the same bytes.
	if hasLoc && locSafe {
		w.resolveExternal(off, loc, offset, hasOffset, length, hasLen)
	}
}

// amount parses one external_data decimal count and reports the two value-shaped
// violations that need no filesystem access.
func (w *walker) amount(off int64, key, v string) (uint64, bool) {
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		w.sink.EmitExtra(ruleExternalBounds, off,
			"external_data "+key+" is not a non-negative decimal integer",
			map[string]string{"key": key, "value": clip(v)})
		return 0, false
	}
	if n > maxExternalBytes {
		w.sink.EmitExtra(ruleExternalBounds, off,
			"external_data "+key+" is petabyte-scale",
			map[string]string{"key": key, "value": clip(v), "limit": strconv.FormatUint(maxExternalBytes, 10)})
		return 0, false
	}
	return n, true
}

// checkExternalPath reports a location that is not a relative POSIX path and
// returns false when it found one.
func (w *walker) checkExternalPath(off int64, key, val string) bool {
	reason := pathEscapeReason(val)
	if reason == "" {
		if clean := path.Clean(val); clean == ".." || strings.HasPrefix(clean, "../") {
			reason = "cleans to a parent-relative path"
		}
	}
	if reason == "" {
		return true
	}
	w.sink.EmitExtra(ruleExternalTraversal, off,
		"external_data "+key+" "+reason,
		map[string]string{"key": key, "location": clip(val), "resolved": "false", "reason": reason})
	return false
}

// containmentRoot returns the session's containment root, or "" when there is
// none. It is used only to refuse a resolved path that leaves the scanned tree.
func containmentRoot(ctx *artifact.Ctx) string {
	if ctx.Session != nil {
		return ctx.Session.Root
	}
	return ""
}

// resolveExternal resolves a passing location under the containment root and
// applies the checks that need the filesystem: symlink references and
// offset/length past the end of the referenced file. When there is no root (stdin
// or a synthetic name) nothing is resolved, and the value-shaped findings above
// are all that can be said.
func (w *walker) resolveExternal(off int64, loc string, offset uint64, hasOffset bool, length uint64, hasLen bool) {
	if w.root == "" {
		return
	}
	openAt := w.root
	clean := path.Clean(loc)
	if w.contain != "" {
		// Containment is enforced by opening the session root and naming the file
		// relative to it: the artifact's own directory decides what "w.bin" means,
		// the session root decides whether the result may be read at all.
		openAt = w.contain
		rel, err := filepath.Rel(w.contain, w.root)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return
		}
		if rel != "." {
			clean = path.Join(filepath.ToSlash(rel), clean)
		}
	}
	root, err := os.OpenRoot(openAt)
	if err != nil {
		return
	}
	defer root.Close()

	info, err := root.Lstat(clean)
	if err != nil {
		if isEscapeErr(err) {
			w.sink.EmitExtra(rulePathEscape, off,
				"external_data location cannot be resolved inside the scan root",
				map[string]string{"location": clip(loc), "root": clip(openAt), "resolved": "false"})
		}
		return
	}
	if w.partial(clean) {
		// A truncated copy of the referenced file cannot prove an extent: the bytes
		// past the copy's end are exactly the ones a fetch did not carry.
		if !w.partialNoted {
			w.partialNoted = true
			w.sink.EmitExtra(ruleExternalUnverified, off,
				"external_data references a file this scan holds only as a truncated copy, so its offset and length cannot be verified",
				map[string]string{"location": clip(loc), "resolved": "false"})
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		w.sink.EmitExtra(ruleExternalSymlink, off,
			"external_data location is a symlink",
			map[string]string{"location": clip(loc), "resolved": "true"})
	}
	st, err := root.Stat(clean)
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	size := uint64(st.Size())
	if hasLen && length > size {
		w.sink.EmitExtra(ruleExternalBounds, off,
			"external_data length runs past the end of the referenced file",
			map[string]string{"key": "length", "value": strconv.FormatUint(length, 10), "file_size": strconv.FormatUint(size, 10), "resolved": "true"})
		return
	}
	if hasOffset && (offset > size || (hasLen && offset > size-length)) {
		w.sink.EmitExtra(ruleExternalBounds, off,
			"external_data offset runs past the end of the referenced file",
			map[string]string{"key": "offset", "value": strconv.FormatUint(offset, 10), "file_size": strconv.FormatUint(size, 10), "resolved": "true"})
	}
}

// isEscapeErr recognises the os.Root containment rejection. The sentinel is
// unexported, so the only stable handle is its documented text ("path escapes
// from parent"); the alternative would be to treat every open failure as an
// escape, which would report a missing external file as an attack.
func isEscapeErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "path escapes from parent")
}
