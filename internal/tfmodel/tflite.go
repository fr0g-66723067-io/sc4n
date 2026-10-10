package tfmodel

// tflite.go is a minimal TFLite flatbuffer reader.
//
// A .tflite file is a flatbuffer: the root table offset at byte 0, the identifier
// "TFL3" at offset 4, then the ObjectAPI serialisation (model.fbs). sc4n does not
// link a flatbuffer library, so this is a bounded hand-written walk of exactly the
// tables the rules need:
//
//	Model       { version=0, operator_codes=1, subgraphs=2, description=3, buffers=4 }
//	OperatorCode{ deprecated_builtin_code=0, custom_code=1, version=2, builtin_code=3 }
//	SubGraph    { tensors=0, inputs=1, outputs=2, operators=3, name=4 }
//	Operator    { opcode_index=0, inputs=1, outputs=2, builtin_options_type=3,
//	              builtin_options=4, custom_options=5, custom_options_format=6 }
//	Buffer      { data=0 }
//
// Every read is bounds-checked against the file, so a malformed flatbuffer is a
// SC4N-TFLITE-STRUCT finding rather than a panic or a wrong read.

import (
	"encoding/binary"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

const (
	// builtinOperatorCustom is TFLite's BuiltinOperator.CUSTOM.
	builtinOperatorCustom = 32
	// maxFBVector bounds any declared vector length, so a 2^32 count is refused
	// before it is used.
	maxFBVector = 1 << 24
	// tfliteEntropyThreshold is where a buffer stops looking like quantised
	// weights and starts looking compressed or random.
	tfliteEntropyThreshold = 7.9
	// tfliteMaxItems bounds the flatbuffer items one walk may visit, and
	// tfliteMaxScanBytes the buffer bytes it may scan. They are named so the
	// SC4N-LIMIT-ENTRIES finding that a spent budget produces can state the real
	// numbers instead of "reached: 0 > 0".
	tfliteMaxItems     = 1 << 20
	tfliteMaxScanBytes = 64 << 20
)

// tfliteParser is the registered parser for FormatTFLite.
type tfliteParser struct{}

// fb is a bounds-checked little-endian view over a flatbuffer source. w is the
// walk the reads belong to, so a reference that points outside the file can be
// reported where it is detected rather than silently dropping the field. A nil w
// (a caller that only probes the file) reports nothing.
type fb struct {
	s    source.Source
	size int64
	w    *tfliteWalk
}

func (f fb) u8(off int64) (byte, bool) {
	b, _ := f.s.Bytes(off, 1)
	if len(b) < 1 {
		return 0, false
	}
	return b[0], true
}

func (f fb) u16(off int64) (uint16, bool) {
	b, _ := f.s.Bytes(off, 2)
	if len(b) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

func (f fb) u32(off int64) (uint32, bool) {
	if off < 0 || off+4 > f.size {
		return 0, false
	}
	b, _ := f.s.Bytes(off, 4)
	if len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func (f fb) i32(off int64) (int32, bool) {
	v, ok := f.u32(off)
	return int32(v), ok
}

// fbTable is a table whose vtable has been resolved.
type fbTable struct {
	f      fb
	pos    int64
	vt     int64
	vtsize int
}

// table resolves the table at off through its vtable offset.
func (f fb) table(off int64) (fbTable, bool) {
	if off < 0 || off+4 > f.size {
		return fbTable{}, false
	}
	soff, ok := f.i32(off)
	if !ok {
		return fbTable{}, false
	}
	vt := off - int64(soff)
	if vt < 0 || vt+4 > f.size {
		return fbTable{}, false
	}
	vs, ok := f.u16(vt)
	if !ok || vs < 4 {
		return fbTable{}, false
	}
	return fbTable{f: f, pos: off, vt: vt, vtsize: int(vs)}, true
}

// field returns the position of field i's data, or ok=false when it is absent.
func (t fbTable) field(i int) (int64, bool) {
	if i < 0 {
		return 0, false
	}
	if int64(4+2*i+2) > int64(t.vtsize) {
		return 0, false
	}
	fo, ok := t.f.u16(t.vt + 4 + int64(2*i))
	if !ok || fo == 0 {
		return 0, false
	}
	pos := t.pos + int64(fo)
	if pos < 0 || pos >= t.f.size {
		return 0, false
	}
	return pos, true
}

// ref follows a table field's uoffset to the object it points at. An absent field
// (the vtable slot is zero) is not a broken reference and is not reported; a
// present field whose offset or target lies outside the file is.
func (t fbTable) ref(i int) (int64, bool) {
	pos, ok := t.field(i)
	if !ok {
		return 0, false
	}
	rel, ok := t.f.u32(pos)
	if !ok {
		t.f.w.broken(t.f.size, "field "+itoa(i)+" of the table at "+itoa64(t.pos)+" reads past the end of the file")
		return 0, false
	}
	target := pos + int64(rel)
	if target < 0 || target >= t.f.size {
		t.f.w.broken(t.f.size, "field "+itoa(i)+" of the table at "+itoa64(t.pos)+" points outside the file")
		return 0, false
	}
	return target, true
}

func (t fbTable) u32Field(i int) (uint32, bool) {
	pos, ok := t.field(i)
	if !ok {
		return 0, false
	}
	v, ok := t.f.u32(pos)
	if !ok {
		t.f.w.broken(pos, "u32 field "+itoa(i)+" of the table at "+itoa64(t.pos)+" reads past the end of the file")
	}
	return v, ok
}

func (t fbTable) byteField(i int) (byte, bool) {
	pos, ok := t.field(i)
	if !ok {
		return 0, false
	}
	return t.f.u8(pos)
}

func (t fbTable) tableField(i int) (fbTable, bool) {
	target, ok := t.ref(i)
	if !ok {
		return fbTable{}, false
	}
	return t.f.table(target)
}

func (t fbTable) stringField(i int) (string, bool) {
	target, ok := t.ref(i)
	if !ok {
		return "", false
	}
	n, ok := t.f.u32(target)
	if !ok || n > maxFBVector {
		t.f.w.broken(target, "string field "+itoa(i)+" declares a length outside the file")
		return "", false
	}
	start := target + 4
	if start+int64(n) > t.f.size {
		t.f.w.broken(target, "string field "+itoa(i)+" of "+itoa64(int64(n))+" bytes extends past the end of the file")
		return "", false
	}
	b, _ := t.f.s.Bytes(start, int64(n))
	if int64(len(b)) < int64(n) {
		t.f.w.broken(start, "string field "+itoa(i)+" could not be read in full")
		return "", false
	}
	return string(b), true
}

// fbVector is a flatbuffer vector's element region.
type fbVector struct {
	f    fb
	data int64
	n    int
}

// vector resolves field i to a vector, checking the declared length against the
// remaining bytes for an element size of elem.
func (t fbTable) vector(i int, elem int) (fbVector, bool) {
	target, ok := t.ref(i)
	if !ok {
		return fbVector{}, false
	}
	n, ok := t.f.u32(target)
	if !ok || n > maxFBVector {
		t.f.w.broken(target, "vector field "+itoa(i)+" declares a length outside the file")
		return fbVector{}, false
	}
	data := target + 4
	if data+int64(n)*int64(elem) > t.f.size {
		t.f.w.broken(target, "vector field "+itoa(i)+" of "+itoa64(int64(n)*int64(elem))+" bytes extends past the end of the file")
		return fbVector{}, false
	}
	return fbVector{f: t.f, data: data, n: int(n)}, true
}

// tableAt resolves the table element i of a vector of offsets.
func (v fbVector) tableAt(i int) (fbTable, bool) {
	slot := v.data + int64(i)*4
	rel, ok := v.f.u32(slot)
	if !ok {
		v.f.w.broken(slot, "vector element "+itoa(i)+" reads past the end of the file")
		return fbTable{}, false
	}
	target := slot + int64(rel)
	if target < 0 || target >= v.f.size {
		v.f.w.broken(slot, "vector element "+itoa(i)+" points outside the file")
		return fbTable{}, false
	}
	t, ok := v.f.table(target)
	if !ok {
		v.f.w.broken(target, "vector element "+itoa(i)+" does not resolve to a table (its vtable is outside the file)")
	}
	return t, ok
}

// bytes returns the vector's inline byte payload.
func (v fbVector) bytes() []byte {
	if v.data < 0 || v.data > v.f.size {
		return nil
	}
	b, _ := v.f.s.Bytes(v.data, int64(v.n))
	if int64(len(b)) < int64(v.n) {
		return nil
	}
	return b
}

// Parse walks the flatbuffer root table and applies the rule set.
func (tfliteParser) Parse(ctx *artifact.Ctx, s source.Source) error {
	if s.Size() < 8 {
		ctx.Sink.Emit(ruleTFLiteStruct, 0, "file is shorter than the flatbuffer root offset + identifier")
		return nil
	}
	id, _ := s.Bytes(4, 4)
	if string(id) != "TFL3" {
		ctx.Sink.Emit(ruleTFLiteStruct, 4, "identifier is not 'TFL3' at offset 4")
		return nil
	}
	w := &tfliteWalk{ctx: ctx, itemsLeft: tfliteMaxItems, scanBytesLeft: tfliteMaxScanBytes}
	f := fb{s: s, size: s.Size(), w: w}
	root, ok := f.u32(0)
	if !ok || root == 0 || int64(root) >= f.size {
		ctx.Sink.Emit(ruleTFLiteStruct, 0, "root table offset is outside the file")
		return nil
	}
	model, ok := f.table(int64(root))
	if !ok {
		ctx.Sink.Emit(ruleTFLiteStruct, int64(root), "root table's vtable reference is outside the file")
		return nil
	}
	w.parseOperatorCodes(model)
	w.parseSubgraphs(model)
	w.parseBuffers(model)
	return nil
}

// tfliteWalk carries the per-artifact work budget. The flatbuffer's declared
// vector lengths are bounded by the file size, but a 1 GiB file could still
// declare millions of operators, so the walk spends a shared item budget and a
// byte budget for buffer scans. Real models are orders of magnitude below both.
type tfliteWalk struct {
	ctx           *artifact.Ctx
	itemsLeft     int
	scanBytesLeft int64
	// reported guards the one structural finding the walk emits for a broken
	// reference; budgetReported guards the one limit finding.
	reported       bool
	budgetReported bool
}

// broken reports the first reference that leaves the file, once per walk. The
// rule's text promises that "the walk stops at the broken reference and reports
// it"; before this the walk stopped and said nothing, so a file whose operator
// vector pointed outside it reported clean. One finding per walk keeps a
// malformed file from spending the whole finding budget on its own damage.
func (w *tfliteWalk) broken(off int64, what string) {
	if w == nil || w.reported {
		return
	}
	w.reported = true
	w.ctx.Sink.Emit(ruleTFLiteStruct, off, what)
}

// budget reports that a work budget stopped the walk, so the reader can see that
// the file was not walked to the end rather than reading the absence of findings
// as a clean file.
func (w *tfliteWalk) budget(rule *report.Rule, limit string, reached, cap int64, what string) {
	if w == nil || w.budgetReported {
		return
	}
	w.budgetReported = true
	limits.Emit(w.ctx.Sink, rule, limit, reached, cap, what)
}

func (w *tfliteWalk) take() bool {
	if w.itemsLeft <= 0 {
		w.budget(limits.RuleEntries, "MaxArrayElements", tfliteMaxItems, tfliteMaxItems,
			"TFLite walk item budget exhausted, so the remaining tables were not walked")
		return false
	}
	w.itemsLeft--
	return true
}

// parseOperatorCodes reports custom operators declared in the code table.
func (w *tfliteWalk) parseOperatorCodes(model fbTable) {
	vec, ok := model.vector(1, 4)
	if !ok {
		return
	}
	n := vec.n
	if n > 65536 {
		w.budget(limits.RuleEntries, "MaxArrayElements", int64(n), 65536,
			"operator code vector was truncated, so the codes past the cap were not examined")
		n = 65536
	}
	for i := range n {
		if !w.take() {
			return
		}
		code, ok := vec.tableAt(i)
		if !ok {
			continue
		}
		custom, _ := code.stringField(1)
		builtin, hasBuiltin := code.u32Field(3)
		switch {
		case custom != "":
			w.ctx.Sink.EmitExtra(ruleTFLiteCustomOp, 0,
				"custom operator code "+clip(custom, 120),
				map[string]string{"custom_code": clip(custom, 120), "index": itoa(i)})
		case hasBuiltin && int32(builtin) == builtinOperatorCustom:
			w.ctx.Sink.EmitExtra(ruleTFLiteCustomOp, 0,
				"operator code with BuiltinOperator.CUSTOM",
				map[string]string{"builtin_code": "CUSTOM", "index": itoa(i)})
		}
	}
}

// parseSubgraphs reports custom_options on any operator.
func (w *tfliteWalk) parseSubgraphs(model fbTable) {
	vec, ok := model.vector(2, 4)
	if !ok {
		return
	}
	n := vec.n
	if n > 1024 {
		w.budget(limits.RuleEntries, "MaxArrayElements", int64(n), 1024,
			"subgraph vector was truncated, so the subgraphs past the cap were not examined")
		n = 1024
	}
	for i := range n {
		if !w.take() {
			return
		}
		sg, ok := vec.tableAt(i)
		if !ok {
			continue
		}
		ops, ok := sg.vector(3, 4)
		if !ok {
			continue
		}
		m := ops.n
		if m > 65536 {
			w.budget(limits.RuleEntries, "MaxArrayElements", int64(m), 65536,
				"operator vector was truncated, so the operators past the cap were not examined")
			m = 65536
		}
		for j := range m {
			if !w.take() {
				return
			}
			op, ok := ops.tableAt(j)
			if !ok {
				continue
			}
			if co, ok := op.vector(5, 1); ok && co.n > 0 {
				w.ctx.Sink.EmitExtra(ruleTFLiteCustomOp, 0,
					"operator "+itoa(j)+" carries a custom_options blob of "+itoa(co.n)+" bytes",
					map[string]string{"subgraph": itoa(i), "operator": itoa(j), "custom_options_bytes": itoa(co.n)})
			}
		}
	}
}

// parseBuffers scans each buffer's data region for embedded native code and for
// compressed/random entropy.
func (w *tfliteWalk) parseBuffers(model fbTable) {
	vec, ok := model.vector(4, 4)
	if !ok {
		return
	}
	n := vec.n
	if n > 65536 {
		w.budget(limits.RuleEntries, "MaxArrayElements", int64(n), 65536,
			"buffer vector was truncated, so the buffers past the cap were not examined")
		n = 65536
	}
	for i := range n {
		if w.scanBytesLeft <= 0 {
			w.budget(limits.RuleEntries, "MaxArrayElements", tfliteMaxScanBytes, tfliteMaxScanBytes,
				"TFLite buffer scan byte budget exhausted, so the remaining buffers were not scanned")
			return
		}
		if !w.take() {
			return
		}
		buf, ok := vec.tableAt(i)
		if !ok {
			continue
		}
		data, ok := buf.vector(0, 1)
		if !ok || data.n == 0 {
			continue
		}
		w.scanTFLiteBuffer(data)
	}
}

// scanTFLiteBuffer inspects one buffer payload.
func (w *tfliteWalk) scanTFLiteBuffer(data fbVector) {
	// Native magic: a validated header in the first 4 KiB of the buffer.
	start := data.data
	probe := int64(data.n)
	if probe > 4096 {
		probe = 4096
	}
	if b, err := data.f.s.Bytes(start, probe); err == nil && len(b) > 0 {
		if kind, ok := bytescan.ValidNative(b); ok {
			w.ctx.Sink.EmitExtra(ruleTFLiteNativeMagic, start,
				"validated "+kind.String()+" header in a TFLite buffer",
				map[string]string{"kind": kind.String(), "buffer_offset": itoa64(start)})
		} else if k, off, ok := bytescan.FindNative(b); ok {
			w.ctx.Sink.EmitExtra(ruleTFLiteNativeMagic, start+int64(off),
				"embedded "+k.String()+" magic in a TFLite buffer",
				map[string]string{"kind": k.String(), "buffer_offset": itoa64(start)})
		}
	}

	// Entropy: sampled so a multi-megabyte buffer is bounded.
	if data.n < 4096 {
		return
	}
	sample := int64(data.n)
	if sample > 64<<10 {
		sample = 64 << 10
	}
	if sample > w.scanBytesLeft {
		sample = w.scanBytesLeft
	}
	w.scanBytesLeft -= sample
	if sample <= 0 {
		return
	}
	if b, err := data.f.s.Bytes(start, sample); err == nil && len(b) > 0 {
		if e := bytescan.Entropy(b); e >= tfliteEntropyThreshold {
			w.ctx.Sink.EmitExtra(ruleTFLiteEntropy, start,
				"buffer entropy "+itoaF(e)+" bits/byte",
				map[string]string{"entropy": itoaF(e), "buffer_offset": itoa64(start)})
		}
	}
}
