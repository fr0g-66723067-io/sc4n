package pickle

import "strings"

// valKind is the coarse type of a stack value.
//
// The walker does not build Python objects: it needs just enough type
// information to evaluate the loader's behavioural guards, all of which are
// checks of the form "is this a dict?", "is this a Tensor?", "is this tuple
// ('storage', ...)?". Anything the walker cannot classify is kUnknown, and a
// guard against an unknown value is reported at a lower confidence rather than
// assumed to pass.
type valKind uint8

const (
	kUnknown valKind = iota
	kNone
	kBool
	kInt
	kFloat
	kStr
	kBytes
	kByteArray
	kList
	kTuple
	kDict
	kSet
	kFrozenSet
	// kGlobal is a name that came out of the stream: GLOBAL, STACK_GLOBAL,
	// INST's class, or a memo slot holding one of those.
	kGlobal
	// kInstance is the result of INST/OBJ/NEWOBJ/NEWOBJ_EX/REDUCE: an object
	// whose class the walker knows.
	kInstance
	kPersID
	kMark
	kBuffer
)

func (k valKind) String() string {
	switch k {
	case kNone:
		return "None"
	case kBool:
		return "bool"
	case kInt:
		return "int"
	case kFloat:
		return "float"
	case kStr:
		return "str"
	case kBytes:
		return "bytes"
	case kByteArray:
		return "bytearray"
	case kList:
		return "list"
	case kTuple:
		return "tuple"
	case kDict:
		return "dict"
	case kSet:
		return "set"
	case kFrozenSet:
		return "frozenset"
	case kGlobal:
		return "global"
	case kInstance:
		return "instance"
	case kPersID:
		return "persid"
	case kMark:
		return "mark"
	case kBuffer:
		return "buffer"
	default:
		return "?"
	}
}

// maxRetainElems caps how many elements of a container the walker keeps. The
// guards need the first few elements of a tuple (BINPERSID's ("storage", …)) and
// the elements of a REDUCE argument tuple (to look for a code string), never all
// of them; retaining everything a crafted stream pushes would be the OOM the
// stack-depth cap exists to prevent.
const maxRetainElems = 64

// Val is one stack value.
type Val struct {
	kind valKind
	// text is the decoded content of a str/bytes value (capped), the class name
	// of an instance, or the "module.name" of a global.
	text string
	// raw is the constant's own bytes when it was scanned in place instead of
	// being decoded (text is empty then). It is a view of the artifact, so it
	// costs nothing to keep, and it is what lets the code-string rule read a
	// constant whose head is binary without materialising it: the extraction
	// happens at the REDUCE site, not here.
	raw []byte
	// global is set for kGlobal and for kInstance (the class it was built from).
	global *Global
	// elems are the retained elements of a container, newest retention first.
	elems []Val
	// n is the container's element count, which may exceed len(elems); -1 means
	// the count is not known.
	n int
}

// Global is a name that came out of the stream, plus the verdicts computed for
// it. Computing the verdict once, at the point the name appears, is what lets
// every use of the same memo slot share it.
type Global struct {
	Module string
	Name   string
	// Off is the offset of the opcode that introduced the name.
	Off int64
	// StackBuilt is true when the name was assembled by STACK_GLOBAL from two
	// strings already on the stack, which is the obfuscation-friendly form: the
	// name never appears as a literal in the stream.
	StackBuilt bool
	// Allows is the allowlist verdict for this name.
	Allows AllowVerdict
	// Gadget is the gadget-severity verdict for this name.
	Gadget Gadget
}

// QualName is "module.name".
func (g *Global) QualName() string {
	if g == nil {
		return ""
	}
	return g.Module + "." + g.Name
}

// ModuleMatches reports whether the global's module is m or is inside m.
//
// The suffix rule is mandatory, not a nicety: matching on an exact module name is
// how picklescan's denylist was bypassed through asyncio.subprocess in
// CVE-2025-10157 (CVSS 8.3). Every denylisted package must therefore match its
// whole subtree, and TestModuleMatchesEnumeratesSubmodules pins that for each
// denylisted package.
func (g *Global) ModuleMatches(m string) bool {
	if g == nil {
		return false
	}
	return g.Module == m || strings.HasPrefix(g.Module, m+".")
}

// containerOf builds a container value from its retained elements.
func containerOf(k valKind, elems []Val, total int) Val {
	retained := elems
	if len(retained) > maxRetainElems {
		retained = retained[:maxRetainElems]
	}
	if total < len(elems) {
		total = len(elems)
	}
	return Val{kind: k, elems: retained, n: total}
}

// extend appends elements to a container, respecting the retention cap, and
// returns the container's new total count.
func (v Val) extend(more []Val) Val {
	total := v.n
	if total < 0 {
		total = len(v.elems)
	}
	total += len(more)
	room := maxRetainElems - len(v.elems)
	if room > 0 {
		if room > len(more) {
			room = len(more)
		}
		v.elems = append(v.elems, more[:room]...)
	}
	v.n = total
	return v
}

// stack is the operand stack plus the memo table. It is a plain slice because the
// depth cap is enforced by the walker, so no allocation can outrun the budget.
type stack struct {
	vals []Val
}

func (s *stack) push(v Val) { s.vals = append(s.vals, v) }

func (s *stack) pop() (Val, bool) {
	if len(s.vals) == 0 {
		return Val{}, false
	}
	v := s.vals[len(s.vals)-1]
	s.vals = s.vals[:len(s.vals)-1]
	return v, true
}

func (s *stack) top() (Val, bool) {
	if len(s.vals) == 0 {
		return Val{}, false
	}
	return s.vals[len(s.vals)-1], true
}

// popMark pops everything down to and including the nearest mark, returning the
// intervening values in push order. ok is false when there is no mark, which is a
// structural error (the reference unpickler raises here).
func (s *stack) popMark() ([]Val, bool) {
	for i := len(s.vals) - 1; i >= 0; i-- {
		if s.vals[i].kind == kMark {
			out := make([]Val, len(s.vals)-i-1)
			copy(out, s.vals[i+1:])
			s.vals = s.vals[:i]
			return out, true
		}
	}
	return nil, false
}

// memo is the memo table. Slots may be written out of order (BINPUT writes an
// arbitrary index), so a slot beyond the current length is materialised as a hole
// and the hole is reported rather than panicking.
type memo struct {
	slots []Val
	set   []bool
	// byGlobal records, for every qualified name, which *distinct* memo slots held
	// it, in the order they were first seen. Two slots holding the same name is
	// the ShadowPickle signal (SC4N-PICKLE-MEMO-ALIAS): a benign stream binds a
	// name once. The slots are a set, not a log: a stream that binds a name in
	// slot 0 and then BINGETs it once per tensor has one binding, and recording
	// one entry per read made every real multi-tensor state_dict a high-severity
	// finding whose evidence contradicted itself ("bound in 3 memo slots ([0 0 0])").
	byGlobal map[string][]int
	// overwrites counts slots written twice, which is the other half of the same
	// signal.
	overwrites int
	// limit is the dense ceiling: indices below it live in slots, the rest in
	// high. count is how many distinct slots hold a value — the number the
	// loader's dict would have, which is what MEMOIZE's implicit index is.
	limit int
	count int
	// high holds the indices the dense table will not: the loader's memo is a
	// dict, so a large index is a key rather than a reason to reject the stream.
	high map[int]Val
}

// newMemo returns a memo whose dense table is bounded by streamLen, the length of
// the bytes the walk is looking at. Indices beyond that are held in a map.
func newMemo(streamLen int) *memo {
	limit := streamLen
	if limit > maxMemoSlots {
		limit = maxMemoSlots
	}
	if limit < 0 {
		limit = 0
	}
	return &memo{byGlobal: map[string][]int{}, limit: limit}
}

func (m *memo) get(i int) (Val, bool) {
	if i < 0 {
		return Val{}, false
	}
	if i >= m.limit {
		v, ok := m.high[i]
		return v, ok
	}
	if i >= len(m.slots) || !m.set[i] {
		return Val{}, false
	}
	return m.slots[i], true
}

// maxMemoSlots caps the memo table in two ways, because BINPUT/LONG_BINPUT carry
// an attacker-chosen index:
//
//   - the dense slice holds indices below the stream length (newMemo's limit):
//     a slot can only exist if an earlier byte of the stream wrote it, since every
//     write costs at least one opcode byte, so a nine-byte stream cannot justify a
//     megabyte of address space;
//   - indices above that go to a map, which is what the loader's memo is, so a
//     stream that writes slot 999 stays loadable instead of being called
//     malformed. The map is capped at maxMemoSlots entries, which is where a
//     refusal — reported as a structural violation — can still happen.
const maxMemoSlots = 1 << 20

// put stores v at slot i and reports whether the slot already held a value. ok is
// false only when the sparse map is at its entry cap, which the caller reports as
// a structural violation.
func (m *memo) put(i int, v Val) (overwrote bool, ok bool) {
	if i < 0 {
		return false, false
	}
	if i >= m.limit {
		if m.high == nil {
			m.high = map[int]Val{}
		}
		_, overwrote = m.high[i]
		if !overwrote {
			if len(m.high) >= maxMemoSlots {
				return false, false
			}
			m.count++
		}
		m.high[i] = v
	} else {
		if i >= len(m.slots) {
			grow := i + 1 - len(m.slots)
			if grow < 16 {
				grow = 16
			}
			m.slots = append(m.slots, make([]Val, grow)...)
			m.set = append(m.set, make([]bool, grow)...)
		}
		overwrote = m.set[i]
		if !overwrote {
			m.count++
		}
		m.slots[i] = v
		m.set[i] = true
	}
	// Only a value that *is* a name records a binding. Val.global is also set on
	// kInstance (the class an object was built from), so counting every value that
	// merely carries a name recorded the class *and* each instance built from it:
	// every protocol-4/5 class+instance pair then reported SC4N-PICKLE-MEMO-ALIAS
	// ("bound in 2 memo slots"), on an ordinary numpy or joblib stream, where the
	// name is bound once and the instance is a different value.
	if v.kind == kGlobal && v.global != nil {
		m.noteGlobal(v.global.QualName(), i)
	}
	if overwrote {
		m.overwrites++
	}
	return overwrote, true
}

// noteGlobal records that slot i holds the name, if no other slot already does.
func (m *memo) noteGlobal(name string, i int) {
	for _, existing := range m.byGlobal[name] {
		if existing == i {
			return
		}
	}
	m.byGlobal[name] = append(m.byGlobal[name], i)
}

// next is the index MEMOIZE uses: the number of entries the loader's dict holds,
// which counts distinct slots rather than the slice's length (a BINPUT to a high
// index pre-grows the slice, so the two disagree).
func (m *memo) next() int { return m.count }
