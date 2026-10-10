package safetensors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"unicode/utf8"
)

// referenceHeaderCap is the reference safetensors implementation's own cap on
// the declared header length. A header larger than this is rejected by the
// reference loader (and is a resource-exhaustion vector for anyone who does not
// copy that check), so sc4n reports it rather than attempting to read it.
const referenceHeaderCap = 100_000_000

// metadataKey is the only special top-level key. Every other key is a tensor
// name; the reference validator documents exactly this rule (V11), so an unknown
// top-level key is a tensor, never an extension point.
const metadataKey = "__metadata__"

// entry is one tensor declaration from the header.
type entry struct {
	name  string
	dtype string
	shape []int64
	begin int64
	end   int64
	// off is the byte offset of the tensor's key within the header JSON, used
	// only to place evidence. It is approximate when the key contains JSON
	// escapes; the value is never used for a bounds decision.
	off int64
}

// metaEntry is one __metadata__ key/value, kept in document order so emission is
// deterministic.
type metaEntry struct {
	key   string
	value string
	off   int64
}

// header is the decoded safetensors header region.
type header struct {
	entries []entry
	meta    []metaEntry
}

// dtypeBits maps every dtype the reference implementation defines to its size in
// bits. Transcribed from safetensors/src/tensor.rs (Dtype::bitsize); a dtype
// absent from this table is reported by RuleDtypeUnknown and its size equation
// is skipped rather than guessed.
var dtypeBits = map[string]int{
	"BOOL":        8,
	"F4":          4,
	"F6_E2M3":     6,
	"F6_E3M2":     6,
	"U8":          8,
	"I8":          8,
	"F8_E5M2":     8,
	"F8_E4M3":     8,
	"F8_E8M0":     8,
	"F8_E4M3FNUZ": 8,
	"F8_E5M2FNUZ": 8,
	"I16":         16,
	"U16":         16,
	"F16":         16,
	"BF16":        16,
	"I32":         32,
	"U32":         32,
	"F32":         32,
	"C64":         64,
	"F64":         64,
	"I64":         64,
	"U64":         64,
}

// allSpaces reports whether b is entirely 0x20. The reference pads the header
// JSON on the right with spaces and allows nothing else after the object.
func allSpaces(b []byte) bool {
	for _, c := range b {
		if c != ' ' {
			return false
		}
	}
	return true
}

// decodeHeader parses the header region (exactly the declared n bytes) into a
// header plus a list of structural violations, each a distinct evidence string.
//
// It is total: a malformed value is recorded and parsing continues where the
// JSON grammar allows, so a single bad tensor does not hide the rest. The
// violations are not emitted here -- parse.go decides where they go -- because
// the same decoder is used by the sniffer's light probe.
func decodeHeader(raw []byte) (*header, []string) {
	h := &header{}
	var viol []string
	if !utf8.Valid(raw) {
		viol = append(viol, "header region is not valid UTF-8")
	}
	if len(raw) == 0 || raw[0] != '{' {
		viol = append(viol, "header JSON does not begin with '{'")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		viol = append(viol, "header is not valid JSON: "+err.Error())
		return h, viol
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		viol = append(viol, "header JSON is not an object")
		return h, viol
	}

	seen := make(map[string]bool)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			viol = append(viol, "header JSON ended inside the top-level object: "+err.Error())
			return h, viol
		}
		key, ok := keyTok.(string)
		if !ok {
			viol = append(viol, "top-level object key is not a string")
			return h, viol
		}
		if seen[key] {
			viol = append(viol, fmt.Sprintf("duplicate top-level key %q", key))
		}
		seen[key] = true
		keyOff := dec.InputOffset() - int64(len(key))
		if key == metadataKey {
			decodeMetadata(dec, h, &viol)
		} else {
			decodeEntry(dec, h, key, keyOff, &viol)
		}
	}
	if _, err := dec.Token(); err != nil {
		viol = append(viol, "header JSON has no closing brace: "+err.Error())
		return h, viol
	}
	if end := dec.InputOffset(); end < int64(len(raw)) && !allSpaces(raw[end:]) {
		viol = append(viol, "header JSON has trailing data after the object")
	}
	return h, viol
}

// decodeMetadata consumes the __metadata__ value, which MUST be an object whose
// values are all strings. A non-string value is illegal (the reference type is
// HashMap<String, String>) and is recorded, not coerced.
func decodeMetadata(dec *json.Decoder, h *header, viol *[]string) {
	tok, err := dec.Token()
	if err != nil {
		*viol = append(*viol, "__metadata__ is malformed: "+err.Error())
		return
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		*viol = append(*viol, "__metadata__ is not an object")
		if ok && d == '[' {
			skipContainer(dec, d)
		}
		return
	}
	seen := make(map[string]bool)
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			*viol = append(*viol, "__metadata__ ended mid-object: "+err.Error())
			return
		}
		k, ok := kt.(string)
		if !ok {
			*viol = append(*viol, "__metadata__ key is not a string")
			skipValue(dec)
			continue
		}
		if seen[k] {
			*viol = append(*viol, fmt.Sprintf("duplicate __metadata__ key %q", k))
		}
		seen[k] = true
		vt, err := dec.Token()
		if err != nil {
			*viol = append(*viol, "__metadata__ ended mid-object: "+err.Error())
			return
		}
		s, ok := vt.(string)
		if !ok {
			*viol = append(*viol, fmt.Sprintf("__metadata__ value for key %q is not a string", k))
			if dd, is := vt.(json.Delim); is {
				skipContainer(dec, dd)
			}
			continue
		}
		h.meta = append(h.meta, metaEntry{key: k, value: s, off: dec.InputOffset() - int64(len(s))})
	}
	_, _ = dec.Token() // closing '}'
}

// decodeEntry consumes one tensor entry. Unknown keys inside an entry are
// recorded because the reference struct has exactly three fields; a fourth key
// is data the loader would ignore and a reviewer would miss.
func decodeEntry(dec *json.Decoder, h *header, name string, keyOff int64, viol *[]string) {
	e := entry{name: name, off: keyOff, begin: -1, end: -1}
	tok, err := dec.Token()
	if err != nil {
		*viol = append(*viol, fmt.Sprintf("tensor %q entry is malformed: %v", name, err))
		return
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		*viol = append(*viol, fmt.Sprintf("tensor %q is not an object", name))
		if ok && d == '[' {
			skipContainer(dec, d)
		}
		return
	}
	var haveDtype, haveShape, haveOffsets bool
	seen := make(map[string]bool)
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			*viol = append(*viol, fmt.Sprintf("tensor %q entry ended mid-object: %v", name, err))
			return
		}
		k, ok := kt.(string)
		if !ok {
			skipValue(dec)
			continue
		}
		if seen[k] {
			*viol = append(*viol, fmt.Sprintf("tensor %q: duplicate key %q", name, k))
		}
		seen[k] = true
		switch k {
		case "dtype":
			vt, err := dec.Token()
			if err != nil {
				*viol = append(*viol, fmt.Sprintf("tensor %q entry ended mid-object: %v", name, err))
				return
			}
			s, ok := vt.(string)
			if !ok {
				*viol = append(*viol, fmt.Sprintf("tensor %q: dtype is not a string", name))
				continue
			}
			e.dtype = s
			haveDtype = true
		case "shape":
			shape, ok := decodeIntArray(dec, viol, fmt.Sprintf("tensor %q: shape", name))
			if !ok {
				*viol = append(*viol, fmt.Sprintf("tensor %q: shape is not an array of integers", name))
				continue
			}
			e.shape = shape
			haveShape = true
		case "data_offsets":
			offs, ok := decodeIntArray(dec, viol, fmt.Sprintf("tensor %q: data_offsets", name))
			if !ok || len(offs) != 2 {
				*viol = append(*viol, fmt.Sprintf("tensor %q: data_offsets must be an array of exactly 2 integers", name))
				continue
			}
			e.begin, e.end = offs[0], offs[1]
			haveOffsets = true
		default:
			*viol = append(*viol, fmt.Sprintf("tensor %q: unknown key %q", name, k))
			skipValue(dec)
		}
	}
	_, _ = dec.Token() // closing '}'
	if !haveDtype {
		*viol = append(*viol, fmt.Sprintf("tensor %q: missing dtype", name))
	}
	if !haveShape {
		*viol = append(*viol, fmt.Sprintf("tensor %q: missing shape", name))
	}
	if !haveOffsets {
		*viol = append(*viol, fmt.Sprintf("tensor %q: missing data_offsets", name))
	}
	h.entries = append(h.entries, e)
}

// decodeIntArray reads one JSON array whose elements MUST all be integers. A
// negative element is recorded through viol (naming the value) and still
// returned: the reference loader deserialises data_offsets as (usize, usize), so
// a negative is rejected at deserialisation and is a structural violation, not a
// value to clamp. The bool reports only whether every element was an integer.
func decodeIntArray(dec *json.Decoder, viol *[]string, what string) ([]int64, bool) {
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '[' {
		if ok && d == '{' {
			skipContainer(dec, d)
		}
		return nil, false
	}
	var out []int64
	good := true
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return out, false
		}
		num, ok := t.(json.Number)
		if !ok {
			good = false
			if dd, is := t.(json.Delim); is {
				skipContainer(dec, dd)
			}
			continue
		}
		v, err := num.Int64()
		if err != nil {
			good = false
			continue
		}
		if v < 0 {
			*viol = append(*viol, fmt.Sprintf("%s value %d is negative", what, v))
		}
		out = append(out, v)
	}
	_, _ = dec.Token() // closing ']'
	return out, good
}

// skipValue consumes one JSON value of any kind.
func skipValue(dec *json.Decoder) {
	tok, err := dec.Token()
	if err != nil {
		return
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
		skipContainer(dec, d)
	}
}

// skipContainer consumes the remainder of an already-opened object or array.
func skipContainer(dec *json.Decoder, open json.Delim) {
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			default:
				depth--
			}
		}
	}
}

// productShape multiplies a shape in uint64, reporting overflow. An empty shape
// (a 0-rank scalar) is the product of no factors, i.e. 1 element -- that is what
// the reference implementation computes and it is why `shape: []` is legal.
func productShape(shape []int64) (uint64, bool) {
	var p uint64 = 1
	for _, d := range shape {
		if d < 0 {
			return 0, false
		}
		hi, lo := bits.Mul64(uint64(d), p)
		if hi != 0 {
			return 0, false
		}
		p = lo
	}
	return p, true
}
