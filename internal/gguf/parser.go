package gguf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/jinja"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// Magic is the four bytes every GGUF file starts with.
const Magic = "GGUF"

const (
	// defaultAlignment is general.alignment's default when the key is absent.
	defaultAlignment = 32

	// maxKeyBytes is the GGUF metadata key length cap.
	maxKeyBytes = 65535
	// maxTensorNameBytes is the GGUF tensor name length cap.
	maxTensorNameBytes = 64
	// maxDims is the GGUF tensor rank cap.
	maxDims = 4
	// maxArrayDepth bounds metadata ARRAY-of-ARRAY nesting.
	maxArrayDepth = 8
	// dimsReadGuard bounds how many dimensions sc4n will read before believing
	// n_dims: a rank far above maxDims is a structural error, and reading it
	// anyway would allocate an attacker-sized loop body.
	dimsReadGuard = 32

	// minKVBytes / minTensorInfoBytes are the smallest byte counts one KV pair
	// and one tensor info can occupy; they turn a declared count into a
	// plausibility bound against the file size (the count-beyond-file check).
	minKVBytes         = 12 // u64 key length + u32 value type (0-byte key, 0-byte value)
	minTensorInfoBytes = 24 // u64 name length + u32 n_dims + u32 type + u64 offset

	// hardStringCap bounds a materialised metadata string when the caller's
	// MaxStringBlob is unset (zero means unlimited to limits, which is not safe
	// here because a metadata string can otherwise be the whole file).
	hardStringCap = 64 << 20

	// String-array sampling. A tokenizer vocab is a legitimate multi-megabyte
	// ARRAY of strings, so the indicator engine is applied to a bounded sample
	// rather than the whole thing; chat templates are always collected in full.
	sampleArrayBytes = 64 << 10
	sampleArrayElems = 4096
	maxTemplates     = 256

	// Polyglot windows: the APE/llamafile preamble and appended payload live at
	// one end or the other; the residual sample is what the trailing-data
	// evidence reports on.
	polyglotHeadBytes = 8 << 10
	polyglotTailBytes = 1 << 20
	residualSample    = 1 << 20
)

// ErrNotGGUF is returned when the bytes are not a GGUF file at all. Structural
// violations inside a GGUF are findings, not errors, because parsing can
// continue; this error means there is nothing to parse.
var ErrNotGGUF = errors.New("gguf: not a GGUF file")

// apeSigils are the llamafile/APE self-extracting-executable signatures.
var apeSigils = [][]byte{[]byte("MZqFpD='"), []byte("jartsr='")}

// Meta is what the parser extracted, including the chat templates the Jinja
// analyzer will consume.
type Meta struct {
	Version     uint32
	BigEndian   bool
	TensorCount uint64
	KVCount     uint64
	Alignment   uint64
	// Templates holds every tokenizer.chat_template value (a scalar string, or
	// each element of an ARRAY of strings), in file order.
	Templates []string
}

// Parse reads the GGUF structure and emits findings through sink. A nil sink
// collects Meta only, which is what ChatTemplates uses.
//
// A structural violation is a finding and parsing continues where it is
// meaningful; the returned error is only ErrNotGGUF (or an unreadable source).
func Parse(s source.Source, l limits.Limits, sink *report.Sink) (*Meta, error) {
	st := &state{src: s, sink: sink, lim: l, meta: &Meta{Alignment: defaultAlignment}}
	size := s.Size()

	// Format-independent evidence first: it stays valid even when the structure
	// below is unreadable, and it is how a llamafile is recognised.
	st.polyglot(size)

	if size < 4 {
		st.structf(0, "file is %d bytes, too short for the GGUF magic", size)
		return st.meta, ErrNotGGUF
	}
	magic, err := s.Bytes(0, 4)
	if err != nil && len(magic) < 4 {
		st.structf(0, "cannot read the magic: %v", err)
		return st.meta, err
	}
	if string(magic) != Magic {
		st.structf(0, "magic is % x, not GGUF", magic)
		return st.meta, ErrNotGGUF
	}
	if size < 24 {
		st.structf(4, "file is %d bytes, too short for the version and counts", size)
		return st.meta, nil
	}

	ord, version, ok := detectHeaderOrder(s)
	if !ok {
		raw, _ := s.Bytes(4, 4)
		st.structf(4, "version field % x is neither 2 nor 3 in little- or big-endian", raw)
		return st.meta, nil
	}
	st.meta.Version = version
	st.meta.BigEndian = ord == binary.BigEndian

	if version == 3 {
		// Version 3 added a big-endian variant and carries no flag naming the
		// byte order, so the declared counts are tested in both orders. The
		// order implied by the version field wins, but a genuinely ambiguous
		// file is reported rather than silently guessed at.
		le := probeCounts(s, size, binary.LittleEndian)
		be := probeCounts(s, size, binary.BigEndian)
		switch {
		case le && be:
			st.emitExtra(RuleEndianAmbiguous, 4,
				"declared counts are plausible in both byte orders; parsed as "+orderName(ord),
				map[string]string{"order": orderName(ord)})
		case !le && be && ord == binary.LittleEndian:
			st.emitExtra(RuleEndianAmbiguous, 4,
				"declared counts are only plausible as big-endian; parsed as big-endian",
				map[string]string{"order": "big"})
			ord = binary.BigEndian
			st.meta.BigEndian = true
		case le && !be && ord == binary.BigEndian:
			st.emitExtra(RuleEndianAmbiguous, 4,
				"declared counts are only plausible as little-endian; parsed as little-endian",
				map[string]string{"order": "little"})
			ord = binary.LittleEndian
			st.meta.BigEndian = false
		}
	}

	r := &reader{s: s, size: size, ord: ord, off: 4}
	if _, ok := r.u32(); !ok { // version, already decoded
		st.structf(4, "header is truncated inside the version field")
		return st.meta, nil
	}
	tensorCount, okT := r.u64()
	kvCount, okK := r.u64()
	if !okT || !okK {
		st.structf(8, "header is truncated before both counts")
		return st.meta, nil
	}
	st.meta.TensorCount = tensorCount
	st.meta.KVCount = kvCount

	if tensorCount > uint64(size)/minTensorInfoBytes+1 {
		st.structf(8, "tensor_count %d cannot fit in a %d-byte file", tensorCount, size)
	}
	if kvCount > uint64(size)/minKVBytes+1 {
		st.structf(16, "metadata_kv_count %d cannot fit in a %d-byte file", kvCount, size)
	}

	defaultLimits(&st.lim)
	if st.lim.MaxEntries > 0 {
		if kvCount > uint64(st.lim.MaxEntries) {
			st.limit(limits.RuleEntries, "MaxEntries", clampInt64(kvCount), int64(st.lim.MaxEntries), "metadata_kv_count")
		}
		if tensorCount > uint64(st.lim.MaxEntries) {
			st.limit(limits.RuleEntries, "MaxEntries", clampInt64(tensorCount), int64(st.lim.MaxEntries), "tensor_count")
		}
	}

	// Metadata.
	seen := make(map[string]bool, minU64(kvCount, 1024))
	for range kvCount {
		keyOff := r.off
		kl, ok := r.u64()
		if !ok {
			st.structf(keyOff, "metadata_kv_count %d exceeds the bytes present", kvCount)
			return st.meta, nil
		}
		if kl > maxKeyBytes {
			st.structf(keyOff, "metadata key length %d exceeds %d", kl, maxKeyBytes)
		}
		kb, ok := r.take(kl)
		if !ok {
			st.structf(keyOff, "metadata key of %d bytes runs past EOF", kl)
			return st.meta, nil
		}
		key := string(kb)
		if !validKey(key) {
			st.structf(keyOff, "metadata key %q is not non-empty printable ASCII", trunc(key, 64))
		}
		if seen[key] {
			st.structf(keyOff, "duplicate metadata key %q", key)
		}
		seen[key] = true

		vtOff := r.off
		vt, ok := r.u32()
		if !ok {
			st.structf(vtOff, "metadata value type for key %q runs past EOF", key)
			return st.meta, nil
		}
		if vt > 12 {
			st.structf(vtOff, "metadata value type %d for key %q is outside 0..12", vt, key)
			return st.meta, nil
		}
		v, ok := st.value(r, vt, key, 0)
		if !ok {
			return st.meta, nil
		}
		if key == "general.alignment" {
			if a, ok := alignmentOf(v); ok && a != 0 {
				st.meta.Alignment = a
			}
		}
	}

	// Tensor infos.
	type tensor struct {
		name    string
		dims    []uint64
		typ     uint32
		off     uint64
		infoOff int64
	}
	tensors := make([]tensor, 0, minU64(tensorCount, 4096))
	for range tensorCount {
		infoOff := r.off
		nl, ok := r.u64()
		if !ok {
			st.structf(infoOff, "tensor_count %d exceeds the bytes present", tensorCount)
			return st.meta, nil
		}
		if nl > maxTensorNameBytes {
			st.structf(infoOff, "tensor name length %d exceeds %d", nl, maxTensorNameBytes)
		}
		nb, ok := r.take(nl)
		if !ok {
			st.structf(infoOff, "tensor name of %d bytes runs past EOF", nl)
			return st.meta, nil
		}
		name := string(nb)

		ndOff := r.off
		nd, ok := r.u32()
		if !ok {
			st.structf(ndOff, "truncated n_dims for tensor %q", name)
			return st.meta, nil
		}
		if nd > maxDims {
			st.structf(ndOff, "tensor %q declares %d dimensions; the maximum is %d", name, nd, maxDims)
		}
		if nd > dimsReadGuard {
			st.structf(ndOff, "tensor %q declares %d dimensions, too many to read", name, nd)
			return st.meta, nil
		}
		dims := make([]uint64, 0, nd)
		for d := range nd {
			dimOff := r.off
			dim, ok := r.u64()
			if !ok {
				st.structf(dimOff, "truncated dimension %d of tensor %q", d, name)
				return st.meta, nil
			}
			if dim == 0 {
				st.structf(dimOff, "tensor %q has dimension %d equal to 0", name, d)
			}
			dims = append(dims, dim)
		}

		typOff := r.off
		typ, ok := r.u32()
		if !ok {
			st.structf(typOff, "truncated ggml type for tensor %q", name)
			return st.meta, nil
		}
		if typ >= ggmlTypeCount || retiredType(typ) {
			st.structf(typOff, "tensor %q uses ggml type id %d, which is retired or outside the pinned 0..%d", name, typ, ggmlTypeCount-1)
		}
		offOff := r.off
		toff, ok := r.u64()
		if !ok {
			st.structf(offOff, "truncated data offset for tensor %q", name)
			return st.meta, nil
		}
		tensors = append(tensors, tensor{name: name, dims: dims, typ: typ, off: toff, infoOff: infoOff})
	}

	// Alignment and the padding that separates the metadata region from the
	// tensor data section.
	align := st.meta.Alignment
	if align == 0 || align%8 != 0 || align > 1<<20 {
		st.structf(r.off, "general.alignment %d is not a multiple of 8 (or is implausibly large); using %d", align, defaultAlignment)
		align = defaultAlignment
		st.meta.Alignment = align
	}
	endInfos := r.off
	dataStart := alignUp(endInfos, int64(align))
	if tensorCount == 0 {
		// A vocabulary-only GGUF (llama.cpp ships one per tokenizer) has no tensor
		// data section at all, so there is no alignment padding to require: the
		// metadata simply ends inside the file. Requiring the padding reported
		// every one of those files as structurally broken.
		if endInfos > size {
			st.structf(endInfos, "the metadata section ends at %d, past EOF (%d)", endInfos, size)
		}
		return st.meta, nil
	}
	if dataStart > size {
		st.structf(endInfos, "the aligned data section starts at %d, past EOF (%d)", dataStart, size)
		return st.meta, nil
	}
	if pad := dataStart - endInfos; pad > 0 {
		pb, ok := r.take(uint64(pad))
		if !ok {
			st.structf(endInfos, "the %d padding bytes before the data section run past EOF", pad)
			return st.meta, nil
		}
		if !allZero(pb) {
			st.structf(endInfos, "the %d padding bytes before the data section are not zero", pad)
		}
	}

	// Tensor geometry. Every check here is deliberately fail-open in exactly one
	// way: an unverified extent suppresses the overlap and trailing-data checks
	// rather than risking a fabricated one.
	var (
		maxEnd       uint64
		allVerified        = true
		prevOff      int64 = -1
		prevEnd      int64
		prevVerified bool
	)
	for i := range tensors {
		t := &tensors[i]
		if t.off%uint64(align) != 0 {
			st.structf(t.infoOff, "tensor %q offset %d is not a multiple of alignment %d", t.name, t.off, align)
		}
		if t.off > math.MaxInt64 {
			st.structf(t.infoOff, "tensor %q offset %d is beyond int64", t.name, t.off)
			allVerified = false
			prevOff, prevVerified = int64(t.off), false
			continue
		}
		if prevOff >= 0 && int64(t.off) < prevOff {
			st.structf(t.infoOff, "tensor %q offset %d is out of declaration order (previous %d)", t.name, t.off, prevOff)
		}

		nelem, prodOK := product(t.dims)
		nbytes, verified := tensorBytes(t.typ, nelem)
		_, _, _, _, typeKnown := TypeInfo(t.typ)
		if !typeKnown {
			// The tensor-info pass already reported the retired/out-of-range
			// type as SC4N-GGUF-STRUCT; its extent is meaningless.
			allVerified = false
			prevOff, prevVerified = int64(t.off), false
			continue
		}
		if !prodOK || !verified {
			st.emitExtra(RuleExtentUnverified, t.infoOff,
				fmt.Sprintf("tensor %q (type %s, %d element(s)) extent could not be computed; geometry checks skipped", t.name, typeName(t.typ), nelem),
				map[string]string{"tensor": t.name, "type": typeName(t.typ)})
			allVerified = false
			if !prevVerified {
				prevEnd = int64(t.off)
			}
			prevOff, prevVerified = int64(t.off), false
			continue
		}
		if t.off > math.MaxUint64-nbytes {
			st.structf(t.infoOff, "tensor %q extent overflows uint64", t.name)
			allVerified = false
			prevOff, prevVerified = int64(t.off), false
			continue
		}
		end := t.off + nbytes
		if end > uint64(size)-uint64(dataStart) {
			st.structf(t.infoOff, "tensor %q extent ends at %d, past EOF (%d)", t.name, int64(dataStart)+int64(end), size)
			allVerified = false
		}
		if prevVerified && int64(t.off) < prevEnd {
			st.structf(t.infoOff, "tensor %q offset %d overlaps the previous tensor's end %d", t.name, t.off, prevEnd)
		}
		if end > maxEnd {
			maxEnd = end
		}
		prevOff, prevEnd, prevVerified = int64(t.off), int64(end), true
	}

	if allVerified {
		if expected := uint64(dataStart) + maxEnd; uint64(size) > expected {
			st.trailing(int64(expected), int64(uint64(size)-expected))
		}
	}
	return st.meta, nil
}

// ChatTemplates returns every chat template string the parser found, for the
// Jinja analyzer to consume. The wiring is done by the format layer (the
// integrator), not by this parser: internal/jinja is a separate package and
// gguf deliberately does not import it, so this package stays a pure GGUF
// reader.
func ChatTemplates(s source.Source, l limits.Limits) ([]string, error) {
	m, err := Parse(s, l, nil)
	if err != nil {
		return nil, err
	}
	return m.Templates, nil
}

// parser is the registered parser for a bare GGUF artifact.
type parser struct{}

// Parse implements artifact.Parser.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	_, err := Parse(s, ctx.Limits, ctx.Sink)
	return err
}

// state carries the sink, budget and collected metadata through the walk.
type state struct {
	src  source.Source
	sink *report.Sink
	lim  limits.Limits
	meta *Meta

	sampledElems int
	sampledBytes int64
}

func (st *state) emit(r *report.Rule, off int64, ev string) {
	if st.sink != nil {
		st.sink.Emit(r, off, ev)
	}
}

func (st *state) emitExtra(r *report.Rule, off int64, ev string, extra map[string]string) {
	if st.sink != nil {
		st.sink.EmitExtra(r, off, ev, extra)
	}
}

func (st *state) structf(off int64, format string, args ...any) {
	st.emit(RuleStruct, off, fmt.Sprintf(format, args...))
}

func (st *state) limit(r *report.Rule, name string, value, cap int64, detail string) {
	if st.sink == nil {
		return
	}
	limits.Emit(st.sink, r, name, value, cap, detail)
}

// value reads one metadata value of type vt, advancing r past it. It returns the
// decoded scalar (nil for arrays) and false when parsing cannot continue.
func (st *state) value(r *reader, vt uint32, key string, depth int) (any, bool) {
	off := r.off
	switch vt {
	case 0: // UINT8
		b, ok := r.u8()
		if !ok {
			st.structf(off, "truncated uint8 value for %q", key)
			return nil, false
		}
		return uint64(b), true
	case 1: // INT8
		b, ok := r.u8()
		if !ok {
			st.structf(off, "truncated int8 value for %q", key)
			return nil, false
		}
		return int64(int8(b)), true
	case 2: // UINT16
		v, ok := r.u16()
		if !ok {
			st.structf(off, "truncated uint16 value for %q", key)
			return nil, false
		}
		return uint64(v), true
	case 3: // INT16
		v, ok := r.u16()
		if !ok {
			st.structf(off, "truncated int16 value for %q", key)
			return nil, false
		}
		return int64(int16(v)), true
	case 4: // UINT32
		v, ok := r.u32()
		if !ok {
			st.structf(off, "truncated uint32 value for %q", key)
			return nil, false
		}
		return uint64(v), true
	case 5: // INT32
		v, ok := r.u32()
		if !ok {
			st.structf(off, "truncated int32 value for %q", key)
			return nil, false
		}
		return int64(int32(v)), true
	case 6: // FLOAT32
		v, ok := r.u32()
		if !ok {
			st.structf(off, "truncated float32 value for %q", key)
			return nil, false
		}
		return float64(math.Float32frombits(v)), true
	case 7: // BOOL
		b, ok := r.u8()
		if !ok {
			st.structf(off, "truncated bool value for %q", key)
			return nil, false
		}
		if b != 0 && b != 1 {
			st.structf(off, "bool value %d for %q is neither 0 nor 1", b, key)
		}
		return b == 1, true
	case 8: // STRING
		return st.readString(r, key, false)
	case 9: // ARRAY
		return nil, st.readArray(r, key, depth)
	case 10: // UINT64
		v, ok := r.u64()
		if !ok {
			st.structf(off, "truncated uint64 value for %q", key)
			return nil, false
		}
		return v, true
	case 11: // INT64
		v, ok := r.u64()
		if !ok {
			st.structf(off, "truncated int64 value for %q", key)
			return nil, false
		}
		return int64(v), true
	case 12: // FLOAT64
		v, ok := r.u64()
		if !ok {
			st.structf(off, "truncated float64 value for %q", key)
			return nil, false
		}
		return math.Float64frombits(v), true
	default:
		st.structf(off, "metadata value type %d for %q is unknown", vt, key)
		return nil, false
	}
}

// readArray reads an ARRAY value (u32 element type, u64 element count, elements).
func (st *state) readArray(r *reader, key string, depth int) bool {
	off := r.off
	if depth >= maxArrayDepth {
		st.structf(off, "metadata array %q nests deeper than %d", key, maxArrayDepth)
		return false
	}
	et, ok := r.u32()
	if !ok {
		st.structf(off, "truncated array element type for %q", key)
		return false
	}
	if et > 12 {
		st.structf(off, "array element type %d for %q is outside 0..12", et, key)
		return false
	}
	cnt, ok := r.u64()
	if !ok {
		st.structf(off, "truncated array length for %q", key)
		return false
	}
	minElem := uint64(minValueBytes(et))
	remaining := uint64(r.size - r.off)
	if cnt > remaining/minElem+1 {
		st.structf(off, "array %q declares %d elements but only %d bytes remain", key, cnt, remaining)
		return false
	}
	// A metadata array is bounded by MaxArrayElements, not MaxEntries: a 256 000
	// token vocabulary is an ordinary file, while a 256 000 member archive is not.
	// The array is walked to its end either way, so the finding must name the cap
	// that actually applies rather than one the walk does not enforce.
	if st.lim.MaxArrayElements > 0 && cnt > uint64(st.lim.MaxArrayElements) {
		st.limit(limits.RuleEntries, "MaxArrayElements", clampInt64(cnt), int64(st.lim.MaxArrayElements), "array "+key)
	}
	for range cnt {
		if _, ok := st.value(r, et, key, depth+1); !ok {
			return false
		}
	}
	return true
}

// readString reads a gguf_string (u64 length + bytes), scans it and collects it
// when it is a chat template. It advances r past the whole declared string even
// when the materialised prefix is capped.
func (st *state) readString(r *reader, key string, inArray bool) (any, bool) {
	off := r.off
	n, ok := r.u64()
	if !ok {
		st.structf(off, "truncated string length for %q", key)
		return nil, false
	}
	dataOff := r.off
	if n > uint64(r.size-dataOff) {
		st.structf(off, "string %q declares %d bytes but only %d remain", key, n, r.size-dataOff)
		r.off = r.size
		return nil, false
	}
	cap := st.lim.MaxStringBlob
	if cap <= 0 {
		cap = hardStringCap
	}
	retain := int64(n)
	if retain > cap {
		st.limit(limits.RuleString, "MaxStringBlob", int64(n), cap, "metadata value "+key)
		retain = cap
	}
	b, ok := r.take(uint64(retain))
	if !ok {
		st.structf(off, "string %q runs past EOF", key)
		r.off = r.size
		return nil, false
	}
	r.off = dataOff + int64(n) // past the whole declared string, truncated or not
	st.considerString(key, dataOff, b, inArray)
	return string(b), true
}

// considerString applies the shared indicator engine and the chat-template
// checks to one metadata string.
func (st *state) considerString(key string, off int64, b []byte, inArray bool) {
	// Indicator engine: general.* and tokenizer.* values only, with ARRAY
	// element strings sampled under a cap so a vocab cannot cost a full pass.
	if strings.HasPrefix(key, "general.") || strings.HasPrefix(key, "tokenizer.") {
		scan := true
		if inArray {
			if st.sampledElems >= sampleArrayElems || st.sampledBytes >= sampleArrayBytes {
				scan = false
			} else {
				st.sampledElems++
				st.sampledBytes += int64(len(b))
			}
		}
		if scan && st.sink != nil {
			// A tokenizer.ggml.* value is a vocabulary entry or a regex, not
			// prose: `<|im_start|>` is a token the model is *supposed* to emit,
			// and `os.system` is a substring of a BPE merge rule as easily as it
			// is a call. Only a reachable secret or endpoint is a finding there.
			// A chat template is a program that emits text, so the instruction
			// indicator belongs to the template checks below, not to the generic
			// metadata rule.
			kind := stringscan.KindText
			switch {
			case isTemplateKey(key):
				kind = stringscan.KindTemplate
			case strings.HasPrefix(key, "tokenizer.ggml."):
				kind = stringscan.KindSecrets
			}
			stringscan.EmitKind(st.sink, off, b, kind)
		}
	}

	// Chat templates: collected in full (up to a bound) and checked here, since
	// internal/jinja is not wired into this parser.
	if isTemplateKey(key) && len(st.meta.Templates) < maxTemplates {
		tmpl := string(b)
		st.meta.Templates = append(st.meta.Templates, tmpl)
		st.templateChecks(off, tmpl)
	}
}

// templateChecks reports Python-object introspection and instruction-override
// text inside a chat template.
func (st *state) templateChecks(off int64, tmpl string) {
	if construct, ok := findSSTI(tmpl); ok {
		st.emitExtra(RuleTemplateSSTI, off,
			"chat template contains the Python-object introspection construct "+construct+" at offset "+strconv.FormatInt(off, 10),
			map[string]string{"construct": construct})
	}
	if directive, ok := findBackdoorDirective(tmpl); ok {
		// The same split the Jinja analyser makes: an override directive is the
		// attack's own words, while a concealment phrase or a chat pseudo-tag is
		// also how a legitimate tool-use instruction reads.
		rule := RuleTemplateBackdoorWeak
		if jinja.OverrideDirective(directive) {
			rule = RuleTemplateBackdoor
		}
		st.emitExtra(rule, off,
			"chat template contains the instruction-override directive "+strconv.Quote(directive),
			map[string]string{"directive": directive})
	}
}

// trailing reports undeclared bytes after the last tensor's extent.
func (st *state) trailing(off, n int64) {
	if n <= 0 {
		return
	}
	sample := n
	if sample > residualSample {
		sample = residualSample
	}
	extra := map[string]string{"bytes": strconv.FormatInt(n, 10)}
	ev := fmt.Sprintf("file ends %d byte(s) past the last tensor's extent at offset %d", n, off)
	if b, err := st.src.Bytes(off, sample); err == nil || len(b) > 0 {
		if int64(len(b)) > sample {
			b = b[:sample]
		}
		extra["entropy"] = strconv.FormatFloat(bytescan.Entropy(b), 'f', 3, 64)
		if kind, i, ok := bytescan.FindNative(b); ok {
			extra["native"] = kind.String()
			ev += fmt.Sprintf("; validated %s at offset %d", kind, off+int64(i))
		}
	}
	st.emitExtra(RuleTrailing, off, ev, extra)
}

// polyglot looks at the head and tail windows for the llamafile/APE sigils and
// for a validated native executable.
func (st *state) polyglot(size int64) {
	if size <= 0 {
		return
	}
	head := min64(size, polyglotHeadBytes)
	st.scanRegion("head", 0, head)
	if size > polyglotHeadBytes {
		start := size - polyglotTailBytes
		if start < 0 {
			start = 0
		}
		st.scanRegion("tail", start, size-start)
	}
}

func (st *state) scanRegion(region string, base, n int64) {
	if n <= 0 {
		return
	}
	b, err := st.src.Bytes(base, n)
	if err != nil && len(b) == 0 {
		return
	}
	if int64(len(b)) > n {
		b = b[:n]
	}
	for _, sig := range apeSigils {
		if i := bytes.Index(b, sig); i >= 0 {
			st.emitExtra(RulePolyglot, base+int64(i),
				fmt.Sprintf("APE/llamafile sigil %q in the %s region", string(sig), region),
				map[string]string{"kind": "ape", "sigil": string(sig), "region": region})
		}
	}
	if kind, i, ok := bytescan.FindNative(b); ok {
		st.emitExtra(RulePolyglot, base+int64(i),
			fmt.Sprintf("validated %s executable in the %s region", kind, region),
			map[string]string{"kind": "native", "native": kind.String(), "region": region})
	}
}

// findSSTI returns the introspection construct a Jinja template reaches, if any.
func findSSTI(tmpl string) (string, bool) {
	for _, d := range sstiDunders {
		if strings.Contains(tmpl, d) {
			return d, true
		}
	}
	if i := strings.Index(tmpl, "|attr"); i >= 0 {
		rest := tmpl[i:]
		if len(rest) > 24 {
			rest = rest[:24]
		}
		if strings.ContainsRune(rest, '_') {
			return "|attr with an underscore-prefixed name", true
		}
	}
	return "", false
}

// sstiDunders are the Python object internals that turn a rendered template into
// arbitrary code execution.
var sstiDunders = []string{
	"__class__", "__mro__", "__subclasses__", "__globals__", "__builtins__",
	"__import__", "__reduce__", "__getattribute__", "__code__", "__loader__",
	"__bases__", "__base__", "__dict__", "__init__", "__name__", "__module__",
}

// backdoorDirectives are instruction-override/hidden-directive phrases in a chat
// template. The list is a subset of the shared injection indicators, expressed
// here because the finding is about the template context specifically.
var backdoorDirectives = []string{
	"ignore previous instructions", "ignore all previous", "disregard previous",
	"do not tell the user", "don't tell the user", "do not inform the user",
	"do not mention this", "never mention this", "do not reveal this",
	"override your instructions", "ignore your instructions",
	"new instructions:", "system prompt:", "<|system|>", "<system>", "act as if",
}

func findBackdoorDirective(tmpl string) (string, bool) {
	lower := strings.ToLower(tmpl)
	for _, d := range backdoorDirectives {
		if strings.Contains(lower, strings.ToLower(d)) {
			return d, true
		}
	}
	return "", false
}

// isTemplateKey reports whether a metadata key holds a chat template.
func isTemplateKey(k string) bool {
	return k == "tokenizer.chat_template" || k == "tokenizer.chat_templates" ||
		strings.HasPrefix(k, "tokenizer.chat_template.")
}

// detectHeaderOrder reads the version field in both byte orders. Only one order
// can decode it to 2 or 3 (0x00000002/3 versus 0x02000000/0x03000000), so this
// is unambiguous.
func detectHeaderOrder(s source.Source) (binary.ByteOrder, uint32, bool) {
	b, err := s.Bytes(4, 4)
	if err != nil && len(b) < 4 {
		return binary.LittleEndian, 0, false
	}
	le := binary.LittleEndian.Uint32(b)
	be := binary.BigEndian.Uint32(b)
	leOK := le == 2 || le == 3
	beOK := be == 2 || be == 3
	switch {
	case leOK:
		return binary.LittleEndian, le, true
	case beOK:
		return binary.BigEndian, be, true
	}
	return binary.LittleEndian, le, false
}

// probeCounts reports whether the declared counts (and the first key length when
// there is a first key) are plausible for the given byte order.
func probeCounts(s source.Source, size int64, ord binary.ByteOrder) bool {
	if size < 24 {
		return false
	}
	tc, ok1 := readU64At(s, 8, ord)
	kc, ok2 := readU64At(s, 16, ord)
	if !ok1 || !ok2 {
		return false
	}
	if tc > uint64(size)/minTensorInfoBytes+1 || kc > uint64(size)/minKVBytes+1 {
		return false
	}
	if kc > 0 {
		if size < 32 {
			return false
		}
		kl, ok := readU64At(s, 24, ord)
		if !ok || kl > maxKeyBytes || int64(kl) > size-32 {
			return false
		}
	}
	return true
}

func readU64At(s source.Source, off int64, ord binary.ByteOrder) (uint64, bool) {
	b, err := s.Bytes(off, 8)
	if err != nil && len(b) < 8 {
		return 0, false
	}
	return ord.Uint64(b), true
}

// reader is a bounds-checked cursor over a Source in one byte order.
type reader struct {
	s    source.Source
	size int64
	off  int64
	ord  binary.ByteOrder
}

func (r *reader) take(n uint64) ([]byte, bool) {
	if r.off > r.size || n > uint64(r.size-r.off) {
		return nil, false
	}
	b, err := r.s.Bytes(r.off, int64(n))
	if int64(len(b)) < int64(n) {
		_ = err
		return nil, false
	}
	r.off += int64(n)
	return b, true
}

func (r *reader) u8() (byte, bool) {
	b, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func (r *reader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return r.ord.Uint16(b), true
}

func (r *reader) u32() (uint32, bool) {
	b, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return r.ord.Uint32(b), true
}

func (r *reader) u64() (uint64, bool) {
	b, ok := r.take(8)
	if !ok {
		return 0, false
	}
	return r.ord.Uint64(b), true
}

func typeName(id uint32) string {
	if n, _, _, _, ok := TypeInfo(id); ok {
		return n
	}
	return "type(" + strconv.FormatUint(uint64(id), 10) + ")"
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i := range k {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func alignmentOf(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case int64:
		if x >= 0 {
			return uint64(x), true
		}
	case uint32:
		return uint64(x), true
	}
	return 0, false
}

func minValueBytes(vt uint32) int {
	switch vt {
	case 0, 1, 7:
		return 1
	case 2, 3:
		return 2
	case 4, 5, 6:
		return 4
	case 8:
		return 8
	case 9:
		return 12
	case 10, 11, 12:
		return 8
	}
	return 1
}

func alignUp(x, a int64) int64 {
	if a <= 0 {
		return x
	}
	r := x % a
	if r == 0 {
		return x
	}
	if x > math.MaxInt64-(a-r) {
		return math.MaxInt64
	}
	return x + (a - r)
}

func orderName(ord binary.ByteOrder) string {
	if ord == binary.BigEndian {
		return "big-endian"
	}
	return "little-endian"
}

func defaultLimits(l *limits.Limits) {
	if l.MaxEntries == 0 {
		l.MaxEntries = limits.Default().MaxEntries
	}
	if l.MaxStringBlob == 0 {
		l.MaxStringBlob = limits.Default().MaxStringBlob
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func clampInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
