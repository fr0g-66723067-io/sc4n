package pickle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// StringScan is installed by internal/stringscan so that the pickle engine runs
// the shared indicator set over reconstructed str/bytes constants. It is a hook
// rather than an import because the indicator tables must not depend on the pickle
// engine (they are format-agnostic); the default no-op keeps the walker usable on
// its own, and in the fuzz targets, without the tables linked.
var StringScan = func(sink *report.Sink, off int64, text string) {}

// BytesScan is installed by internal/stringscan alongside StringScan. It exists so
// that a binary constant can be scanned without first being decoded into a string:
// the automaton is byte-oriented, so the decode bought nothing for a tensor blob
// and cost a copy of every one of them.
var BytesScan = func(sink *report.Sink, off int64, b []byte) {}

// StringUse is installed by internal/stringscan and called for a string that is an
// argument to a named callable. It exists because one of the strongest shapes in
// the whole engine is only visible with both halves at once: a long opaque literal
// passed to a decoder. Neither half means anything alone — a 60-character base64
// string is a hash, and base64.b64decode is ordinary library usage — and the pickle
// walker is the only place that sees the pair.
var StringUse = func(sink *report.Sink, off int64, text, callable string) {}

// Options configures one walk.
type Options struct {
	// TrailingIsStorage marks the window as a container's object pickle, where the
	// bytes after the first STOP are that container's payload: legacy torch
	// checkpoints append raw storage, and joblib appends array bodies. The flag is
	// set only by the legacy-torch and joblib parsers — never by a user-facing
	// option — because a payload after STOP in a *bare* pickle is the nullifAI
	// shape and must stay a finding.
	TrailingIsStorage bool
	// StorageDescription names the payload for the evidence.
	StorageDescription string
}

// Stream is the result of a walk.
type Stream struct {
	// Proto is the protocol declared by the first PROTO opcode, or 0 when the
	// stream declares none.
	Proto byte
	// Ops is the number of opcodes successfully decoded.
	Ops int
	// Bytes is the window length walked.
	Bytes int64
	// EndOffset is the offset just past the last STOP of the first segment.
	EndOffset int64
	// SawStop reports whether any segment reached a STOP.
	SawStop bool
	// Globals are the names that appeared, in first-seen order.
	Globals []*Global
	// StructErrors counts structural violations found.
	StructErrors int
	// RequiresUnsafeLoader reports whether any opcode outside the weights-only
	// accepted set appeared.
	RequiresUnsafeLoader bool
}

// Walk analyses the whole window at off 0 of s.
//
// It is total: after a decode error it records the violation and resumes at the
// next byte, and after a STOP it decides whether the remaining bytes are another
// pickle, a container payload, or an appended attack. The loader executes a
// malformed stream; a scanner that stops at the first error does not, and that
// asymmetry is the whole of exception-oriented programming (arXiv 2508.19774).
func Walk(ctx *artifact.Ctx, s source.Source, opt Options) (*Stream, error) {
	data, err := s.Bytes(0, s.Size())
	if err != nil && len(data) == 0 {
		return nil, err
	}
	if len(data) == 0 {
		return &Stream{}, nil
	}
	w := &walker{
		sink:    ctx.Sink,
		lim:     ctx.Limits,
		data:    data,
		opt:     opt,
		mm:      newMemo(len(data)),
		globals: map[string]*Global{},
		structs: map[string]*structStat{},
		once:    map[string]bool{},

		memoOverwriteOff: -1,
	}
	w.run()
	w.flush()
	return &w.stream, nil
}

// structStat accumulates one structural violation kind.
type structStat struct {
	rule  *report.Rule
	off   int64
	ev    string
	count int
}

// walker is the single-pass state.
type walker struct {
	sink *report.Sink
	lim  limits.Limits
	data []byte
	opt  Options
	// silent suppresses emission for the dry probe the sniffer runs.
	silent bool

	st stack
	mm *memo

	stream Stream
	limit  int

	// globals is keyed by qualified name so that a state_dict's hundreds of
	// references to one rebuild function produce one finding.
	globals map[string]*Global

	// retained is how much text the walk is keeping alive, against
	// Limits.MaxRetainedText.
	retained int64

	// structs deduplicates structural violations by kind.
	structs map[string]*structStat

	// once guards findings that should appear at most once per stream.
	once map[string]bool

	// resyncRun counts consecutive bytes that produced no decoded opcode; it
	// bounds the cost of walking a region that is not opcodes at all.
	resyncRun int

	// firstSegmentDone is set after the first STOP.
	firstSegmentDone bool
	// windowStart is the offset the stream was located at (0 for a clean start).
	windowStart int
	// memoOverwriteOff is the offset of the first memo rebinding, or -1 when
	// none was seen. flush emits the one SC4N-PICKLE-MEMO-ALIAS finding from it,
	// so the evidence carries the final rebinding count.
	memoOverwriteOff int64
}

const (
	// maxProbeBytes bounds the sniffer's dry walk so that sniffing a multi-gigabyte
	// pickle does not cost a whole extra pass.
	maxProbeBytes = 256 << 10
	// maxResyncRun bounds how many consecutive undecodable bytes are scanned before
	// the walk gives up on the region. It is large enough to cross the malformed
	// opcode the field-observed PoCs place *after* the payload, and small enough
	// that a file which is not a pickle at all costs milliseconds.
	maxResyncRun = 1 << 16
	// maxRetainString caps the text materialised from a str/bytes constant.
	maxRetainString = 1 << 16
)

// end is the exclusive offset the walk stops at. A probe sets it to its byte
// budget so that sniffing a multi-gigabyte pickle cannot cost a whole pass.
func (w *walker) end() int {
	if w.limit > 0 && w.limit < len(w.data) {
		return w.limit
	}
	return len(w.data)
}

// run walks the whole window.
func (w *walker) run() {
	size := int64(len(w.data))
	w.stream.Bytes = size
	start := 0
	if !w.probePickle(0) {
		// The window does not open with a clean pickle. If a clean one starts
		// later, the bytes in front of it are a prefix (the nullifAI shape) and
		// are reported as such.
		if k, ok := w.locateStreamStart(); ok {
			w.emitPrefix(0, k)
			w.windowStart = k
			start = k
		}
	}
	pos := start
	for pos < int(size) {
		next, fatal := w.segment(pos)
		if fatal || next <= pos {
			return
		}
		pos = next
		if !w.firstSegmentDone {
			w.firstSegmentDone = true
			w.stream.EndOffset = int64(pos)
		}
		if w.opt.TrailingIsStorage {
			// The container owns everything past the object pickle.
			return
		}
		if pos >= int(size) {
			return
		}
		// Decide what the bytes after the STOP are.
		if w.probePickle(pos) {
			w.emitOnce("segment", ruleSegment, int64(pos),
				"a second pickle starts at this offset; STOP is not end-of-file and a reader that loops over load() executes every segment")
			continue
		}
		w.emitTrailing(pos)
		return
	}
	// A stream that never reached STOP is truncated.
	if !w.stream.SawStop {
		w.structFinding("missing-STOP", "the stream ended without a STOP opcode", size)
	}
}

// plausibleStart reports whether the bytes at off can be the first opcode of a
// pickle: a PROTO with a sane protocol byte, or a protocol-0/1 opener.
func (w *walker) plausibleStart(off int) bool {
	if off >= len(w.data) {
		return false
	}
	code := w.data[off]
	if code == opPROTO {
		return off+1 < len(w.data) && w.data[off+1] >= 1 && w.data[off+1] <= highestProtocol
	}
	info := opTable[code]
	if info.name == "" {
		return false
	}
	// A protocol-0/1 stream has no PROTO, so its first opcode must itself be
	// protocol-0/1. Anything else means the stream was prefixed.
	return info.proto <= 1
}

// locateStreamStart searches for the first offset at which a clean pickle begins.
// It is how a leading payload (the nullifAI shape) is classified as a prefix
// rather than walked as garbage: the payload bytes are reported, and the pickle
// that follows them is decoded normally.
func (w *walker) locateStreamStart() (int, bool) {
	const maxCandidates = 64
	tried := 0
	for i := 1; i+1 < len(w.data); i++ {
		if w.data[i] != opPROTO || w.data[i+1] < 1 || w.data[i+1] > highestProtocol {
			continue
		}
		tried++
		if tried > maxCandidates {
			return 0, false
		}
		if w.probePickle(i) {
			return i, true
		}
	}
	return 0, false
}

// probePickle runs a silent walk from off and reports whether a clean pickle
// begins there.
func (w *walker) probePickle(off int) bool {
	if off < 0 || off >= len(w.data) {
		return false
	}
	if w.data[off] != opPROTO && !w.plausibleStart(off) {
		return false
	}
	budget := len(w.data)
	if off+maxProbeBytes < budget {
		budget = off + maxProbeBytes
	}
	probe := &walker{
		silent:  true,
		lim:     w.lim,
		data:    w.data,
		limit:   budget,
		mm:      newMemo(budget),
		globals: map[string]*Global{},
		structs: map[string]*structStat{},
		once:    map[string]bool{},
	}
	probe.segment(off)
	hasProto := w.data[off] == opPROTO
	if probe.stream.StructErrors > 0 {
		return false
	}
	if probe.stream.SawStop {
		return true
	}
	// A huge valid pickle may not reach its STOP inside the probe budget. Accept
	// it only when the stream declares a protocol (so a protocol-4 file that walks
	// cleanly for 256 KiB is a pickle) and enough opcodes decoded to rule out a
	// coincidence.
	return hasProto && probe.stream.Ops >= 8
}

// segment walks one pickle, from start to its STOP. It returns the offset just
// past the STOP (or the end of the data) and whether the walk must stop entirely.
func (w *walker) segment(start int) (int, bool) {
	pos := start
	w.resyncRun = 0
	end := w.end()
	for pos < end {
		if w.lim.MaxStackDepth > 0 && len(w.st.vals) > w.lim.MaxStackDepth {
			w.emitOnce("stack", ruleStack, int64(pos),
				fmt.Sprintf("operand stack depth %d exceeds MaxStackDepth %d; the remainder of the stream was not walked", len(w.st.vals), w.lim.MaxStackDepth))
			return pos, true
		}
		code := w.data[pos]
		info := opTable[code]
		if info.name == "" {
			w.structFinding("unknown-opcode",
				fmt.Sprintf("0x%02x is not an opcode", code), int64(pos))
			w.emitOnce("incomplete:"+strconv.Itoa(pos), ruleIncomplete, int64(pos),
				fmt.Sprintf("the walk could not decode the byte at this offset (0x%02x is not an opcode); scanning resumed at the next byte so that anything after it is still reported", code))
			w.resyncRun++
			if w.resyncRun > maxResyncRun {
				w.structFinding("undecodable-region",
					fmt.Sprintf("%d consecutive bytes decoded as no opcode; the walk stopped here", w.resyncRun), int64(pos))
				return pos, true
			}
			pos++
			continue
		}

		arg, next, err := w.decodeArg(info, pos)
		if err != nil {
			w.structFinding(errKind(err), err.Error(), int64(pos))
			w.emitOnce("incomplete:"+strconv.Itoa(pos)+":"+err.Error(), ruleIncomplete, int64(pos), err.Error())
			w.resyncRun++
			if w.resyncRun > maxResyncRun {
				w.structFinding("undecodable-region",
					fmt.Sprintf("%d consecutive bytes decoded as no opcode; the walk stopped here", w.resyncRun), int64(pos))
				return pos, true
			}
			pos++
			continue
		}

		// An opcode is deliberately not checked against the declared protocol.
		// Neither the reference unpickler nor pickletools enforces opcode/protocol
		// agreement (CPython consults self.proto only in find_class, and pickletools
		// gates nothing), so a protocol-1 stream — which carries no PROTO opcode at
		// all, since CPython writes one only from protocol 2 — would otherwise be
		// rejected as structurally invalid and never dispatched to this walker.

		w.resyncRun = 0
		w.stream.Ops++
		if requiresUnsafeLoader(code) {
			w.stream.RequiresUnsafeLoader = true
		}
		if pos == w.windowStart && isExecutableStartOpcode(code) {
			w.emitOnce("offset-zero", ruleOffsetZero, int64(pos),
				fmt.Sprintf("the stream's first byte is %s: the payload is at offset 0, which a scanner that starts its opcode scan at index 1 never sees", info.name))
		}

		if code == opSTOP {
			// STOP pops the result; an underflow here is a structural violation
			// but not a reason to stop walking.
			if _, ok := w.st.pop(); !ok {
				w.structFinding("stack-underflow", "STOP with an empty operand stack", int64(pos))
			}
			w.stream.SawStop = true
			return next, false
		}

		if fatal := w.apply(code, arg, pos, info); fatal {
			return next, true
		}
		pos = next
	}
	return pos, false
}

func isExecutableStartOpcode(code byte) bool {
	switch code {
	case opGLOBAL, opSTACK_GLOBAL, opREDUCE, opINST, opOBJ, opNEWOBJ, opNEWOBJ_EX, opEXT1, opEXT2, opEXT4, opPERSID, opBINPERSID:
		return true
	}
	return false
}

// apply performs an opcode's stack effect and emits its findings. It returns true
// when the walk must stop.
func (w *walker) apply(code byte, arg any, off int, info opcodeInfo) bool {
	switch code {
	case opPROTO:
		if p, ok := argInt(arg); ok {
			if pos := w.stream.Ops; pos == 1 {
				w.stream.Proto = byte(p)
			}
			if p > int64(highestProtocol) {
				w.structFinding("proto-too-high",
					fmt.Sprintf("declared protocol %d is above the highest known protocol %d", p, highestProtocol), int64(off))
			}
		}

	case opFRAME:
		// FRAME's length is a prefetch hint: the reference unpickler reads it and
		// then keeps reading opcodes from the same stream regardless of whether
		// they fit the frame, so enforcing it would diverge from the loader. It is
		// parsed and deliberately not checked, and emits no rule.

	case opMARK:
		w.st.push(Val{kind: kMark})

	case opPOP:
		if _, ok := w.st.pop(); !ok {
			w.structFinding("stack-underflow", "POP with an empty operand stack", int64(off))
		}

	case opPOP_MARK:
		if _, ok := w.st.popMark(); !ok {
			w.structFinding("no-mark", "POP_MARK with no MARK on the stack", int64(off))
		}

	case opDUP:
		top, ok := w.st.top()
		if !ok {
			w.structFinding("stack-underflow", "DUP with an empty operand stack", int64(off))
			break
		}
		w.st.push(top)

	case opFLOAT, opBINFLOAT:
		w.st.push(Val{kind: kFloat, text: strconv.FormatFloat(argFloat(arg), 'g', -1, 64)})

	case opINT, opBININT, opBININT1, opLONG, opBININT2, opLONG1, opLONG4:
		n, _ := argInt(arg)
		w.st.push(Val{kind: kInt, text: strconv.FormatInt(n, 10)})

	case opNONE:
		w.st.push(Val{kind: kNone})

	case opNEWTRUE, opNEWFALSE:
		w.st.push(Val{kind: kBool, text: strconv.FormatBool(code == opNEWTRUE)})

	case opPERSID:
		if s, ok := argString(arg); ok {
			w.emitOnce("persid:PERSID", rulePersID, int64(off),
				"PERSID hands the loader's persistent_load hook the id "+quote(s)+", which is not the (\"storage\", …) shape the weights-only unpickler accepts")
			w.st.push(Val{kind: kPersID, text: s})
		}

	case opBINPERSID:
		pid, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "BINPERSID with an empty operand stack", int64(off))
			break
		}
		if !isPersistentStorageID(pid) {
			w.emitOnce("persid:BINPERSID", rulePersID, int64(off),
				"BINPERSID passes a "+pid.kind.String()+" to persistent_load; the weights-only unpickler accepts only a (\"storage\", …) tuple or an int")
		}
		w.st.push(Val{kind: kPersID})

	case opSHORT_BINSTRING, opBINSTRING, opSTRING, opUNICODE, opBINUNICODE, opSHORT_BINUNICODE, opBINUNICODE8:
		v := w.stringValue(arg, off)
		w.st.push(v)

	case opSHORT_BINBYTES, opBINBYTES, opBINBYTES8:
		w.st.push(w.bytesValue(arg, off, kBytes))

	case opBYTEARRAY8:
		w.st.push(w.bytesValue(arg, off, kByteArray))

	case opEMPTY_LIST:
		w.st.push(Val{kind: kList})
	case opEMPTY_DICT:
		w.st.push(Val{kind: kDict})
	case opEMPTY_SET:
		w.st.push(Val{kind: kSet})
	case opEMPTY_TUPLE:
		w.st.push(Val{kind: kTuple})
	case opFROZENSET:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "FROZENSET with no MARK on the stack", int64(off))
			break
		}
		w.st.push(containerOf(kFrozenSet, items, len(items)))
	case opLIST:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "LIST with no MARK on the stack", int64(off))
			break
		}
		w.st.push(containerOf(kList, items, len(items)))
	case opDICT:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "DICT with no MARK on the stack", int64(off))
			break
		}
		w.st.push(containerOf(kDict, items, len(items)/2))
	case opTUPLE:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "TUPLE with no MARK on the stack", int64(off))
			break
		}
		w.st.push(containerOf(kTuple, items, len(items)))
	case opTUPLE1, opTUPLE2, opTUPLE3:
		n := int(code - opTUPLE1 + 1)
		items, ok := w.popN(n)
		if !ok {
			w.structFinding("stack-underflow", "tuple opcode with an empty operand stack", int64(off))
			break
		}
		w.st.push(containerOf(kTuple, items, len(items)))

	case opAPPEND:
		val, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "APPEND with an empty operand stack", int64(off))
			break
		}
		target, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "APPEND with no container beneath the value", int64(off))
			break
		}
		if !isListLike(target) {
			w.emitOnce("append:APPEND", ruleAppendTarget, int64(off),
				"APPEND targets a "+target.kind.String()+"; the reference loader requires a list")
		}
		w.st.push(target.extend([]Val{val}))

	case opAPPENDS:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "APPENDS with no MARK on the stack", int64(off))
			break
		}
		target, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "APPENDS with no container beneath the mark", int64(off))
			break
		}
		if !isListLike(target) {
			w.emitOnce("append:APPENDS", ruleAppendTarget, int64(off),
				"APPENDS targets a "+target.kind.String()+"; the reference loader requires a list")
		}
		w.st.push(target.extend(items))

	case opADDITEMS:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "ADDITEMS with no MARK on the stack", int64(off))
			break
		}
		target, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "ADDITEMS with no container beneath the mark", int64(off))
			break
		}
		w.st.push(target.extend(items))

	case opSETITEM:
		val, ok1 := w.st.pop()
		key, ok2 := w.st.pop()
		if !ok1 || !ok2 {
			w.structFinding("stack-underflow", "SETITEM with fewer than three operands", int64(off))
			break
		}
		target, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "SETITEM with no target beneath the key and value", int64(off))
			break
		}
		if !isDictLike(target) {
			w.emitOnce("setitem:SETITEM", ruleSetItemTarget, int64(off),
				"SETITEM assigns into a "+target.kind.String()+" ("+describe(target)+"); the reference loader does not check the target type, which is the heap-corruption class of CVE-2026-24747 / GHSA-63cw-57p8-fm3p")
		}
		w.st.push(target.extend([]Val{key, val}))

	case opSETITEMS:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "SETITEMS with no MARK on the stack", int64(off))
			break
		}
		target, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "SETITEMS with no target beneath the mark", int64(off))
			break
		}
		if !isDictLike(target) {
			w.emitOnce("setitem:SETITEMS", ruleSetItemTarget, int64(off),
				"SETITEMS assigns into a "+target.kind.String()+" ("+describe(target)+"); the reference loader does not check the target type, which is the heap-corruption class of CVE-2026-24747 / GHSA-63cw-57p8-fm3p")
		}
		w.st.push(target.extend(items))

	case opBUILD:
		state, ok := w.st.pop()
		if !ok {
			w.structFinding("stack-underflow", "BUILD with an empty operand stack", int64(off))
			break
		}
		inst, ok := w.st.top()
		if !ok {
			w.structFinding("stack-underflow", "BUILD with no target beneath the state", int64(off))
			break
		}
		if !isBuildableClass(inst.global) {
			w.emitOnce("build:"+describe(inst), ruleBuildState, int64(off),
				"BUILD applies stream-controlled state to "+describe(inst)+"; the reference loader permits only torch.Tensor, torch.nn.Parameter, collections.OrderedDict and user-allowlisted classes")
		}
		w.checkCodeStrings(state, off, "the BUILD state", callableName(inst))

	case opGLOBAL:
		mod, name, ok := argPair(arg)
		if !ok {
			w.structFinding("truncated-argument", "GLOBAL without a module/name pair", int64(off))
			break
		}
		w.st.push(w.globalValue(mod, name, int64(off), false))

	case opSTACK_GLOBAL:
		nameV, ok1 := w.st.pop()
		modV, ok2 := w.st.pop()
		if !ok1 || !ok2 {
			w.structFinding("stack-underflow", "STACK_GLOBAL with fewer than two operands", int64(off))
			break
		}
		if modV.kind != kStr || nameV.kind != kStr {
			w.structFinding("stack-global-operands",
				"STACK_GLOBAL operands are "+modV.kind.String()+" and "+nameV.kind.String()+", not two str values", int64(off))
			w.st.push(Val{kind: kUnknown})
			break
		}
		w.st.push(w.globalValue(modV.text, nameV.text, int64(off), true))

	case opINST:
		mod, name, ok := argPair(arg)
		if !ok {
			w.structFinding("truncated-argument", "INST without a module/name pair", int64(off))
			break
		}
		g := w.globalValue(mod, name, int64(off), false)
		if _, marked := w.st.popMark(); !marked {
			w.structFinding("no-mark", "INST with no MARK on the stack", int64(off))
		}
		w.emitOnce("inst:"+g.text, ruleInst, int64(off),
			"INST constructs "+g.text+"; the weights-only unpickler does not implement INST")
		w.st.push(Val{kind: kInstance, text: g.text, global: g.global})

	case opOBJ:
		items, ok := w.st.popMark()
		if !ok {
			w.structFinding("no-mark", "OBJ with no MARK on the stack", int64(off))
			break
		}
		cls := Val{}
		if len(items) > 0 {
			cls = items[0]
		}
		w.emitOnce("obj:"+describe(cls), ruleObj, int64(off),
			"OBJ constructs "+describe(cls)+" from values on the stack; the class name can be assembled by STACK_GLOBAL, and the weights-only unpickler does not implement OBJ")
		w.st.push(Val{kind: kInstance, text: cls.text, global: cls.global})

	case opNEWOBJ:
		args, ok1 := w.st.pop()
		cls, ok2 := w.st.pop()
		if !ok1 || !ok2 {
			w.structFinding("stack-underflow", "NEWOBJ with fewer than two operands", int64(off))
			break
		}
		if !isBuildableClass(cls.global) && cls.global != nil {
			w.emitOnce("newobj:"+cls.text, ruleNewObj, int64(off),
				"NEWOBJ calls __new__ on "+cls.text+"; the reference loader permits only torch.nn.Parameter and allowlisted classes")
		}
		w.checkCodeStrings(args, off, "the NEWOBJ argument", callableName(cls))
		w.st.push(Val{kind: kInstance, text: cls.text, global: cls.global})

	case opNEWOBJ_EX:
		kwargs, ok1 := w.st.pop()
		args, ok2 := w.st.pop()
		cls, ok3 := w.st.pop()
		if !ok1 || !ok2 || !ok3 {
			w.structFinding("stack-underflow", "NEWOBJ_EX with fewer than three operands", int64(off))
			break
		}
		w.emitOnce("newobj_ex:"+cls.text, ruleNewObjEx, int64(off),
			"NEWOBJ_EX constructs "+describe(cls)+" with keyword state; the weights-only unpickler does not implement it")
		w.checkCodeStrings(args, off, "the NEWOBJ_EX argument", callableName(cls))
		w.checkCodeStrings(kwargs, off, "the NEWOBJ_EX keyword state", callableName(cls))
		w.st.push(Val{kind: kInstance, text: cls.text, global: cls.global})

	case opREDUCE:
		args, ok1 := w.st.pop()
		callableV, ok2 := w.st.pop()
		if !ok1 || !ok2 {
			w.structFinding("stack-underflow", "REDUCE with fewer than two operands", int64(off))
			break
		}
		w.reportReduce(callableV, args, off)
		w.st.push(Val{kind: kInstance, text: callableV.text, global: callableV.global})

	case opGET, opBINGET, opLONG_BINGET:
		idx, ok := argInt(arg)
		if !ok {
			w.structFinding("truncated-argument", info.name+" without an index", int64(off))
			break
		}
		v, found := w.mm.get(int(idx))
		if !found {
			w.structFinding("memo-hole",
				fmt.Sprintf("%s reads memo slot %d, which was never written", info.name, idx), int64(off))
			w.st.push(Val{kind: kUnknown})
			break
		}
		w.st.push(v)
		if v.kind == kGlobal && v.global != nil {
			// A name reached through the memo is the same name in the same slot:
			// record the slot, so that two slots holding it show up. The kind guard
			// matters because Val.global is also set on an instance (the class it
			// was built from), and attributing a class name to a slot on every read
			// of an instance is the same mistake put() already avoids.
			w.mm.noteGlobal(v.global, int(idx))
		}

	case opPUT, opBINPUT, opLONG_BINPUT:
		idx, ok := argInt(arg)
		if !ok {
			w.structFinding("truncated-argument", info.name+" without an index", int64(off))
			break
		}
		top, ok := w.st.top()
		if !ok {
			w.structFinding("stack-underflow", info.name+" with an empty operand stack", int64(off))
			break
		}
		if idx < 0 {
			w.structFinding("negative-length", fmt.Sprintf("%s index %d is negative", info.name, idx), int64(off))
			break
		}
		overwrote, ok := w.mm.put(int(idx), top)
		if !ok {
			w.structFinding("memo-table-full",
				fmt.Sprintf("%s writes memo slot %d and the sparse table already holds %d entries, the budget for indices beyond the %d a stream of these bytes can justify", info.name, idx, maxMemoSlots, w.mm.limit), int64(off))
			break
		}
		if overwrote {
			w.noteMemoOverwrite(int64(off))
		}

	case opMEMOIZE:
		idx := w.mm.next()
		top, ok := w.st.top()
		if !ok {
			w.structFinding("stack-underflow", "MEMOIZE with an empty operand stack", int64(off))
			break
		}
		if overwrote, ok := w.mm.put(idx, top); ok && overwrote {
			w.noteMemoOverwrite(int64(off))
		}

	case opEXT1, opEXT2, opEXT4:
		w.emitOnce("ext", ruleExt, int64(off),
			info.name+" resolves a code object through copyreg's extension registry, which is environment-dependent and carries no name in the stream")
		w.st.push(Val{kind: kUnknown})

	case opNEXT_BUFFER:
		w.st.push(Val{kind: kBuffer})

	case opREADONLY_BUFFER:
		if v, ok := w.st.pop(); ok {
			w.st.push(v)
		} else {
			w.structFinding("stack-underflow", "READONLY_BUFFER with an empty operand stack", int64(off))
		}

	default:
		w.structFinding("unhandled-opcode",
			"opcode "+info.name+" has no stack effect implemented", int64(off))
	}
	return false
}

// popN pops n values in push order.
func (w *walker) popN(n int) ([]Val, bool) {
	if len(w.st.vals) < n {
		return nil, false
	}
	out := make([]Val, n)
	copy(out, w.st.vals[len(w.st.vals)-n:])
	w.st.vals = w.st.vals[:len(w.st.vals)-n]
	return out, true
}

// globalValue classifies a name and records it.
func (w *walker) globalValue(module, name string, off int64, stackBuilt bool) Val {
	resolvedModule, resolvedName, remapped := resolveGlobal(module, name)
	verdict := isAllowed(resolvedModule, resolvedName)
	g := &Global{
		Module:     resolvedModule,
		Name:       resolvedName,
		SrcModule:  module,
		SrcName:    name,
		Off:        off,
		StackBuilt: stackBuilt,
		Allows:     verdict,
		Gadget:     classifyGadget(resolvedModule, resolvedName),
	}
	if verdict == AllowDefault {
		g.Gadget.Class = GadgetAllowlisted
		g.Gadget.Sink = "allowlisted by torch.load(weights_only=True)"
		g.Gadget.Entry = g.QualName()
	}
	if prev, seen := w.globals[g.QualName()]; seen {
		// A second binding of the same name in a different place: the name was
		// referenced again, which is normal, but count the binding sites for the
		// alias rule.
		_ = prev
		return Val{kind: kGlobal, text: g.textKey(), global: g}
	}
	w.globals[g.QualName()] = g
	w.stream.Globals = append(w.stream.Globals, g)

	switch {
	case verdict == AllowBlocked:
		w.emitOnce("global:"+g.QualName(), ruleGlobalCritical, off,
			fmt.Sprintf("%s: sink %s; its module is in the weights-only blocklist ({sys, os, posix, nt}), which the unpickler consults before its allowlist, so no add_safe_globals entry can make this loadable", g.QualName(), g.Gadget.Sink))
	case verdict == AllowDefault:
		// Nothing to report: this is a name the loader accepts on its own.
	default:
		sink := g.Gadget.Sink
		ev := fmt.Sprintf("%s — %s", g.QualName(), sink)
		if g.Gadget.Entry != g.QualName() {
			ev = fmt.Sprintf("%s (matched table entry %s) — %s", g.QualName(), g.Gadget.Entry, sink)
		}
		if stackBuilt {
			ev += "; the name was assembled by STACK_GLOBAL from strings rather than written as a literal"
		}
		if remapped {
			ev += "; the name was remapped from " + module + "." + name + " by the loader's Python-2 compatibility table"
		}
		switch g.Gadget.Class {
		case GadgetDirect:
			w.emitOnce("global:"+g.QualName(), ruleGlobalCritical, off, ev)
		case GadgetLibrary:
			w.emitOnce("global:"+g.QualName(), ruleGlobalHigh, off, ev)
		default:
			w.emitOnce("global:"+g.QualName(), ruleGlobalUnknown, off, ev)
		}
	}
	return Val{kind: kGlobal, text: g.textKey(), global: g}
}

func (g *Global) textKey() string { return g.Module + "." + g.Name }

// reportReduce emits the REDUCE findings and inspects the arguments.
func (w *walker) reportReduce(callableV, args Val, off int) {
	g := callableV.global
	if g == nil {
		w.emitOnce("reduce-unknown:"+describe(callableV), ruleReduce, int64(off),
			"REDUCE calls "+describe(callableV)+", which the walker could not resolve to a name")
		w.checkCodeStrings(args, off, "the REDUCE argument", callableName(callableV))
		return
	}
	if g.Allows != AllowDefault {
		w.emitOnce("reduce:"+g.QualName(), ruleReduce, int64(off),
			"REDUCE calls "+g.QualName()+", which is not in the weights-only allowlist (the reference loader raises \"Trying to call reduce for unrecognized function\"); sink: "+g.Gadget.Sink)
	}
	w.checkCodeStrings(args, off, "the REDUCE argument", callableName(callableV))
}

// checkCodeStrings applies the code-string rule to a value's retained contents,
// and hands every string to the indicator engine together with the callable it was
// passed to.
//
// The code-string rule is the one detector that fires on an otherwise allowlisted
// stream, and it exists because of the ShadowPickle motivating example: `GLOBAL
// collections OrderedDict` + `BINUNICODE <source>` + REDUCE + BUILD, where the
// callable is allowlisted and the *argument* is the payload.
func (w *walker) checkCodeStrings(v Val, off int, where string, callable string) {
	visit := func(text string) {
		if callable != "" && !w.silent {
			StringUse(w.sink, int64(off), text, callable)
		}
		if len(text) < codeStringMinBytes {
			return
		}
		if ind := looksLikeCode(text); ind != "" {
			w.emitExtraOnce("code-string:"+ind+":"+strconv.Itoa(off)+":"+text[:codeStringMinBytes], ruleCodeString, int64(off),
				fmt.Sprintf("%s carries a %d-byte string that looks like source (indicator %q): %s", where, len(text), ind, quote(text)),
				map[string]string{"indicator": ind, "where": where, "length": strconv.Itoa(len(text))})
		}
	}
	walkStrings(v, 0, visit)
}

// callableName is the qualified name of a callable value, or "" when the walker
// could not resolve one.
func callableName(v Val) string {
	if v.global != nil {
		return v.global.QualName()
	}
	return ""
}

// walkStrings visits the string/bytes values inside v, to a nesting depth of 4.
func walkStrings(v Val, depth int, visit func(string)) {
	if depth > 4 {
		return
	}
	switch v.kind {
	case kStr, kBytes, kByteArray:
		if v.text != "" {
			visit(v.text)
			return
		}
		// A constant that was scanned in place rather than decoded: the code
		// string is in its printable runs, which is how a REDUCE argument whose
		// first bytes are padding was previously invisible to this rule.
		if len(v.raw) > 0 {
			if s := asciiPrefix(v.raw); len(s) >= codeStringMinBytes {
				visit(s)
			}
		}
	case kList, kTuple, kSet, kFrozenSet, kDict:
		for _, e := range v.elems {
			walkStrings(e, depth+1, visit)
		}
	}
}

const codeStringMinBytes = 24

// looksLikeCode reports the indicator that makes a string look like executable
// source, or "" when it does not.
func looksLikeCode(s string) string {
	for _, ind := range []string{
		"__import__", "import ", "subprocess", "__reduce__", "os.system", "os.popen",
		"system(", "exec(", "eval(", "open(", "compile(", "popen(", "chr(",
		"/bin/sh", "/bin/bash", "curl ", "wget ", "base64", "socket.",
	} {
		if strings.Contains(s, ind) {
			return ind
		}
	}
	// `for … in …` is the shape of a comprehension or loop, which a metadata
	// string never has; both halves are required so that an ordinary sentence
	// containing "for" is not enough.
	if strings.Contains(s, "for ") && strings.Contains(s, " in ") {
		return "for … in …"
	}
	if strings.Contains(s, ");") && strings.Contains(s, "(") {
		return "); / ("
	}
	return ""
}

// noteMemoOverwrite records that a memo slot was written twice. The finding is
// emitted once, from flush, so the evidence carries the final count rather than
// the count at the first rebinding — and so a stream of rebindings produces one
// finding instead of one per rebinding. (The emit key used to embed
// w.mm.overwrites, which made it unique per rebinding: a 400 KB stream of
// BINPUT 0 produced 100000 findings and grew w.once by as many entries.)
func (w *walker) noteMemoOverwrite(off int64) {
	if w.memoOverwriteOff < 0 {
		w.memoOverwriteOff = off
	}
}

// routeNames renders the distinct routes to a name for the evidence, sorted so
// the output is deterministic.
func routeNames(routes map[bindingRoute]struct{}) []string {
	out := make([]string, 0, len(routes))
	for r := range routes {
		s := r.srcModule + "." + r.srcName
		if r.stackBuilt {
			s += " (assembled)"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// flush emits the findings that are decisions about the whole stream.
func (w *walker) flush() {
	if w.silent {
		return
	}
	if w.mm.overwrites > 0 {
		w.sink.Emit(ruleMemoAlias, w.memoOverwriteOff,
			fmt.Sprintf("memo slot written more than once (%d rebinding(s)); allowlist-by-name scanners see one binding per name, and ShadowPickle uses a rebinding to present an allowlisted name while binding something else", w.mm.overwrites))
	}
	// Names reachable through more than one route. A second *slot* is not the
	// signal: any serializer that reconstructs a global per object binds it more
	// than once (joblib's NumpyArrayWrapper emits its own STACK_GLOBAL numpy.dtype
	// per array), so counting slots reported an ordinary sklearn model as high. A
	// second *route* is: a name-keyed allowlist sees one spelling and the loader
	// resolves another, which is the ShadowPickle bypass.
	for name, b := range w.mm.byGlobal {
		if len(b.routes) > 1 {
			off := int64(0)
			if g, ok := w.globals[name]; ok {
				off = g.Off
			}
			w.sink.EmitExtra(ruleMemoAlias, off,
				fmt.Sprintf("%s is reachable through %d distinct bindings (%s) in memo slots %v; a benign stream binds a name one way",
					name, len(b.routes), strings.Join(routeNames(b.routes), ", "), b.slots),
				map[string]string{
					"global": name,
					"slots":  strconv.Itoa(len(b.slots)),
					"routes": strconv.Itoa(len(b.routes)),
				})
		}
	}
	// Out-of-allowlist requirement.
	var named, allowed int
	for _, g := range w.stream.Globals {
		switch g.Allows {
		case AllowDefault:
			allowed++
		default:
			named++
		}
	}
	if named > 0 && allowed == 0 {
		w.sink.EmitExtra(ruleSafeGlobalsNeeded, w.stream.Globals[0].Off,
			fmt.Sprintf("all %d global(s) in this stream are outside the built-in weights-only allowlist; loading it with weights_only=True requires torch.serialization.add_safe_globals", named),
			map[string]string{"globals": strconv.Itoa(named)})
	}
	if w.stream.RequiresUnsafeLoader {
		w.sink.EmitExtra(ruleRequiresUnsafeLoader, 0,
			"the stream uses at least one opcode the weights-only unpickler rejects, so torch.load(weights_only=True) cannot load it. Protocol 4 and 5 files trip this without being suspicious — the weights-only unpickler is protocol-2-shaped — which is why the confidence is low.",
			map[string]string{"proto": strconv.Itoa(int(w.stream.Proto))})
	}
	for _, st := range w.structs {
		ev := st.ev
		if st.count > 1 {
			ev = fmt.Sprintf("%s (%d occurrences reported as one finding)", ev, st.count)
		}
		w.sink.EmitExtra(st.rule, st.off, ev, map[string]string{"occurrences": strconv.Itoa(st.count)})
	}
}

// emitPrefix reports leading bytes ahead of the first opcode.
func (w *walker) emitPrefix(from, to int) {
	if w.silent || to <= from {
		return
	}
	region := w.data[from:to]
	ev := fmt.Sprintf("%d byte(s) precede the first pickle opcode (entropy %.2f bits/byte)", to-from, bytescan.Entropy(sampleForEntropy(region)))
	if kind, off, ok := bytescan.FindNative(region); ok {
		ev += fmt.Sprintf("; a validated %s header starts at +0x%x inside them", kind, off)
	}
	if shebang, ok := bytescan.ShebangAt(region); ok {
		ev += "; a shebang names the interpreter " + shebang
	}
	w.emitOnce("prefix", rulePrefix, int64(from), ev)
}

// emitTrailing reports bytes after the last STOP that are not another pickle.
func (w *walker) emitTrailing(from int) {
	if w.silent || from >= len(w.data) {
		return
	}
	region := w.data[from:]
	ev := fmt.Sprintf("%d byte(s) follow a complete pickle and are not a pickle themselves (entropy %.2f bits/byte)", len(region), bytescan.Entropy(sampleForEntropy(region)))
	extra := map[string]string{"bytes": strconv.Itoa(len(region))}
	if kind, off, ok := bytescan.FindNative(region); ok {
		ev += fmt.Sprintf("; a validated %s header starts at +0x%x inside them", kind, off)
		extra["native"] = kind.String()
		extra["nativeOffset"] = strconv.Itoa(off)
	}
	if shebang, ok := bytescan.ShebangAt(region); ok {
		ev += "; a shebang names the interpreter " + shebang
		extra["shebang"] = shebang
	}
	if w.opt.TrailingIsStorage {
		// Only reachable when a container passes a window whose tail it misjudged;
		// the container's own description is what makes the evidence readable.
		ev = w.opt.StorageDescription + ": " + ev
	}
	w.emitExtraOnce("trailing", ruleTrailing, int64(from), ev, extra)
}

// sampleForEntropy bounds the entropy computation so that a multi-gigabyte tail
// costs a constant amount of work: 64 KiB sampled from the head of the region is
// enough to separate compressed from padded from text.
func sampleForEntropy(b []byte) []byte {
	const n = 64 << 10
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// structFinding records a structural violation, deduplicated by kind. It records
// even in a silent (sniffing) walk: the sniffer's verdict is "this decodes
// cleanly", so suppressing the accounting would make every byte soup a pickle.
func (w *walker) structFinding(kind, detail string, off int64) {
	st, ok := w.structs[kind]
	if !ok {
		st = &structStat{rule: ruleStruct, off: off, ev: kind + ": " + detail}
		w.structs[kind] = st
	}
	st.count++
	// The count is maintained here rather than derived in flush, because a silent
	// sniffing walk never reaches flush and its whole verdict is this number.
	w.stream.StructErrors++
}

// emitOnce emits a finding at most once per key for this stream.
func (w *walker) emitOnce(key string, r *report.Rule, off int64, ev string) {
	if w.silent || w.once[key] {
		return
	}
	w.once[key] = true
	w.sink.Emit(r, off, ev)
}

// emitExtraOnce is emitOnce with extra fields.
func (w *walker) emitExtraOnce(key string, r *report.Rule, off int64, ev string, extra map[string]string) {
	if w.silent || w.once[key] {
		return
	}
	w.once[key] = true
	w.sink.EmitExtra(r, off, ev, extra)
}

// stringValue builds a str value from a decoded argument.
//
// The scan sees the whole constant up to MaxStringBlob; only the *retained* copy
// is limited to maxRetainString. Taking the 64 KiB slice before the scan — which
// is what this did — meant an indicator past byte 65536 of a large constant was
// never seen, which contradicts retain()'s own comment.
func (w *walker) stringValue(arg any, off int) Val {
	s, _ := argString(arg)
	full := len(s)
	scan := s
	if cap := w.blobCap(); int64(len(scan)) > cap {
		w.reportBlobCap(off, len(scan), cap, "str constant")
		scan = scan[:cap]
	}
	w.scanString(scan, int64(off))
	if full > maxRetainString {
		s = s[:maxRetainString]
	}
	return Val{kind: kStr, text: w.retain(s), n: full}
}

// blobCap is how much of one constant the walk scans: MaxStringBlob, the same cap
// every other parser materialises a value under.
func (w *walker) blobCap() int64 {
	if w.lim.MaxStringBlob > 0 {
		return w.lim.MaxStringBlob
	}
	return limits.Default().MaxStringBlob
}

// reportBlobCap reports a constant that is larger than the scan budget, once, in
// the shape limits.Emit produces.
func (w *walker) reportBlobCap(off, full int, cap int64, what string) {
	w.emitExtraOnce("limit-string-blob", limits.RuleString, int64(off),
		"MaxStringBlob reached: "+strconv.Itoa(full)+" > "+strconv.FormatInt(cap, 10)+"; "+what+" scanned up to the cap",
		map[string]string{"limit": "MaxStringBlob", "value": strconv.Itoa(full), "cap": strconv.FormatInt(cap, 10)})
}

// retain applies the walk's total retention budget. Indicator matching has already
// run on the value by the time this is called, so what the budget costs is the
// ability to re-inspect the text later in the walk — not the ability to see it at
// all — and the truncation is reported once through SC4N-LIMIT-RETAINED rather
// than being invisible.
func (w *walker) retain(s string) string {
	if w.lim.MaxRetainedText <= 0 || w.retained+int64(len(s)) <= w.lim.MaxRetainedText {
		w.retained += int64(len(s))
		return s
	}
	w.emitOnce("limit-retained", limits.RuleRetained, 0,
		"retained text budget reached; later values keep their length and kind but not their text")
	if len(s) > retainAfterBudget {
		return s[:retainAfterBudget]
	}
	return s
}

// retainAfterBudget is how much of a value survives once the budget is spent. It
// is enough for evidence to name the value and for a rule that inspects a prefix
// (a magic, a `#!` line, an opcode word) to still work.
const retainAfterBudget = 256

// bytesValue builds a bytes value.
//
// A constant that is text is decoded and kept (subject to the retention budget),
// because rules later in the walk inspect it — the ShadowPickle case is a code
// string passed to an allowlisted callable. A constant that is binary is scanned
// *in place*: the indicator engine reads bytes, so materialising a 64 KiB tensor
// blob as a string only to scan it and drop it is pure waste, and on a
// state_dict-shaped pickle that waste was the walk's largest allocation.
func (w *walker) bytesValue(arg any, off int, kind valKind) Val {
	b := argBytes(arg)
	full := len(b)
	scan := b
	if cap := w.blobCap(); int64(len(scan)) > cap {
		w.reportBlobCap(off, len(scan), cap, "bytes constant")
		scan = scan[:cap]
	}
	if !mostlyText(scan) {
		w.scanBytes(scan, int64(off))
		// text stays empty (nothing was decoded) but the bytes are kept as a view
		// of the artifact, so the code-string rule can read the constant later
		// without this allocating anything.
		return Val{kind: kind, text: "", raw: scan, n: full}
	}
	// One decode for the common case: a constant within the retention cap is
	// decoded once and that string is both scanned and kept. Only a constant
	// larger than the cap is decoded twice, which is the price of scanning the
	// whole constant rather than its first 64 KiB.
	if len(scan) <= maxRetainString {
		s := latin1String(scan)
		w.scanString(s, int64(off))
		return Val{kind: kind, text: w.retain(s), n: full}
	}
	w.scanString(latin1String(scan), int64(off))
	return Val{kind: kind, text: w.retain(latin1String(scan[:maxRetainString])), n: full}
}

// asciiPrefix extracts the printable runs from a binary constant, bounded by
// maxRetainString, so that looksLikeCode can be applied to it. It is called at the
// REDUCE site (see walkStrings), not when the constant is created: a state_dict
// has thousands of tensor blobs and extracting a prefix for each of them at
// creation time would spend the retention budget on values no rule reads.
func asciiPrefix(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b) && sb.Len() < maxRetainString; {
		if !printableByte(b[i]) {
			i++
			continue
		}
		j := i
		for j < len(b) && printableByte(b[j]) {
			j++
		}
		if j-i >= 4 {
			sb.Write(b[i:j])
			sb.WriteByte('\n')
		}
		i = j
	}
	return sb.String()
}

func printableByte(c byte) bool { return c >= 0x20 && c < 0x7f }

// scanBytes runs the indicator engine over a byte constant without decoding it.
func (w *walker) scanBytes(b []byte, off int64) {
	if w.silent || len(b) < 8 {
		return
	}
	BytesScan(w.sink, off, b)
}

func (w *walker) scanString(s string, off int64) {
	if w.silent || len(s) < 8 {
		return
	}
	StringScan(w.sink, off, s)
}

// describe renders a value for evidence.
func describe(v Val) string {
	switch v.kind {
	case kGlobal, kInstance:
		if v.global != nil {
			return v.global.QualName()
		}
		if v.text != "" {
			return quote(v.text)
		}
		return "an unnamed " + v.kind.String()
	default:
		if v.text != "" {
			return "a " + v.kind.String() + " " + quote(v.text)
		}
		return "a " + v.kind.String()
	}
}

// quote renders a string for a one-line finding, escaping control bytes and
// truncating hard so that a crafted string cannot reflow a report.
func quote(s string) string {
	const max = 160
	var b strings.Builder
	// Grow is bounded by the truncation: a 1 MiB PERSID argument must not make the
	// builder reserve 1 MiB to emit at most max runes — each escaping to at most
	// four bytes, since every escape is \xNN and a rune is at most four bytes —
	// plus the two quotes and the three-byte ellipsis.
	grow := len(s) + 2
	if grow > max*4+5 {
		grow = max*4 + 5
	}
	b.Grow(grow)
	b.WriteByte('"')
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r == '"':
			b.WriteString("\\\"")
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
		n++
	}
	b.WriteByte('"')
	return b.String()
}

// --- argument decoding ---

// argError carries the structural kind of a decode failure.
type argError struct {
	kind string
	msg  string
}

func (e *argError) Error() string { return e.msg }

func errKind(err error) string {
	var ae *argError
	if errors.As(err, &ae) {
		return ae.kind
	}
	return "decode-error"
}

func argErr(kind, msg string) error { return &argError{kind: kind, msg: msg} }

// decodeArg decodes the argument of the opcode at pos and returns the offset just
// past the whole opcode.
func (w *walker) decodeArg(info opcodeInfo, pos int) (any, int, error) {
	p := pos + 1
	d := w.data
	need := func(n int) bool { return p+n <= len(d) }
	switch info.arg {
	case argNone:
		return nil, p, nil

	case argUint1:
		if !need(1) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 1 byte of argument expected")
		}
		return int64(d[p]), p + 1, nil

	case argUint2:
		if !need(2) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 2 bytes of argument expected")
		}
		return int64(binary.LittleEndian.Uint16(d[p:])), p + 2, nil

	case argUint4:
		if !need(4) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 4 bytes of argument expected")
		}
		return int64(binary.LittleEndian.Uint32(d[p:])), p + 4, nil

	case argInt4:
		if !need(4) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 4 bytes of argument expected")
		}
		return int64(int32(binary.LittleEndian.Uint32(d[p:]))), p + 4, nil

	case argUint8:
		if !need(8) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 8 bytes of argument expected")
		}
		return int64(binary.LittleEndian.Uint64(d[p:])), p + 8, nil

	case argFloat8:
		// BINFLOAT is the one big-endian fixed-width argument. Getting this wrong
		// would mis-decode every FLOAT in every stream, which is why the table is
		// generated rather than hand-written.
		if !need(8) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 8 bytes of argument expected")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d[p:])), p + 8, nil

	case argDecimalnlShort, argDecimalnlLong:
		raw, next, err := w.readNewline(info, p)
		if err != nil {
			return nil, p, err
		}
		if info.arg == argDecimalnlShort {
			if bytes.Equal(raw, []byte("00")) {
				return false, next, nil
			}
			if bytes.Equal(raw, []byte("01")) {
				return true, next, nil
			}
		}
		s := string(raw)
		if info.arg == argDecimalnlLong {
			s = strings.TrimSuffix(s, "L")
		}
		n, perr := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if perr != nil {
			return nil, p, argErr("bad-decimal", fmt.Sprintf("%s has an unparsable decimal argument %q", info.name, truncateForEvidence(s)))
		}
		return n, next, nil

	case argFloatnl:
		raw, next, err := w.readNewline(info, p)
		if err != nil {
			return nil, p, err
		}
		f, perr := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if perr != nil {
			return nil, p, argErr("bad-float", fmt.Sprintf("%s has an unparsable float argument %q", info.name, truncateForEvidence(string(raw))))
		}
		return f, next, nil

	case argStringnl, argStringnlNoescape:
		raw, next, err := w.readNewline(info, p)
		if err != nil {
			return nil, p, err
		}
		if info.arg == argStringnlNoescape {
			if !utf8.Valid(raw) {
				w.structFinding("non-utf8", info.name+" carries a payload that is not valid UTF-8", int64(pos))
			}
			return string(raw), next, nil
		}
		body, qerr := stripQuotes(raw)
		if qerr != nil {
			return latin1String(body), next, qerr
		}
		decoded, derr := unescape(body)
		if derr != nil {
			w.structFinding("bad-escape", derr.Error(), int64(pos))
		}
		return latin1String(decoded), next, nil

	case argStringnlNoescapePair:
		first, next, err := w.readNewline(info, p)
		if err != nil {
			return nil, p, err
		}
		second, next2, err := w.readNewline(info, next)
		if err != nil {
			return nil, p, err
		}
		if !utf8.Valid(first) || !utf8.Valid(second) {
			w.structFinding("non-utf8", info.name+" carries a module/name pair that is not valid UTF-8", int64(pos))
		}
		return [2]string{string(first), string(second)}, next2, nil

	case argUnicodestringnl:
		raw, next, err := w.readNewline(info, p)
		if err != nil {
			return nil, p, err
		}
		if !utf8.Valid(raw) {
			w.structFinding("non-utf8", info.name+" carries a payload that is not valid UTF-8", int64(pos))
		}
		return string(raw), next, nil

	case argString1:
		if !need(1) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 1-byte string length expected")
		}
		n := int64(d[p])
		return w.countedString(info, p+1, n, latin1String)

	case argString4:
		if !need(4) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 4-byte string length expected")
		}
		n := int64(int32(binary.LittleEndian.Uint32(d[p:])))
		if n < 0 {
			return nil, p, argErr("negative-length", fmt.Sprintf("%s declares a negative string length %d", info.name, n))
		}
		return w.countedString(info, p+4, n, latin1String)

	case argBytes1:
		if !need(1) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 1-byte length expected")
		}
		return w.countedBytes(info, p+1, int64(d[p]))

	case argBytes4:
		if !need(4) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 4-byte length expected")
		}
		return w.countedBytes(info, p+4, int64(binary.LittleEndian.Uint32(d[p:])))

	case argBytes8, argBytearray8:
		if !need(8) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 8-byte length expected")
		}
		n := int64(binary.LittleEndian.Uint64(d[p:]))
		if n < 0 {
			return nil, p, argErr("negative-length", fmt.Sprintf("%s declares a length %d that does not fit in an int64", info.name, n))
		}
		return w.countedBytes(info, p+8, n)

	case argUnicodestring1:
		if !need(1) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 1-byte length expected")
		}
		return w.countedString(info, p+1, int64(d[p]), utf8String)

	case argUnicodestring4:
		if !need(4) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 4-byte length expected")
		}
		return w.countedString(info, p+4, int64(binary.LittleEndian.Uint32(d[p:])), utf8String)

	case argUnicodestring8:
		if !need(8) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 8-byte length expected")
		}
		n := int64(binary.LittleEndian.Uint64(d[p:]))
		if n < 0 {
			return nil, p, argErr("negative-length", fmt.Sprintf("%s declares a length %d that does not fit in an int64", info.name, n))
		}
		return w.countedString(info, p+8, n, utf8String)

	case argLong1:
		if !need(1) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 1-byte length expected")
		}
		return w.countedLong(info, p+1, int64(d[p]))

	case argLong4:
		if !need(4) {
			return nil, p, argErr("truncated-argument", info.name+" is truncated: 4-byte length expected")
		}
		n := int64(int32(binary.LittleEndian.Uint32(d[p:])))
		if n < 0 {
			return nil, p, argErr("negative-length", fmt.Sprintf("%s declares a negative length %d", info.name, n))
		}
		return w.countedLong(info, p+4, n)
	}
	return nil, p, argErr("unknown-arg-kind",
		fmt.Sprintf("opcode %s has an argument kind the walker does not implement (%d)", info.name, info.arg))
}

// readNewline reads a newline-terminated argument. The scan is bounded: every
// newline-terminated argument in the grammar is a name, a number or a small
// string, so a region without a newline is a structural violation rather than an
// invitation to walk the whole file.
func (w *walker) readNewline(info opcodeInfo, p int) ([]byte, int, error) {
	const maxScan = 1 << 20
	limit := len(w.data)
	if p+maxScan < limit {
		limit = p + maxScan
	}
	i := bytes.IndexByte(w.data[p:limit], '\n')
	if i < 0 {
		return nil, p, argErr("no-newline",
			fmt.Sprintf("%s has no newline within %d bytes, so its argument cannot be read", info.name, maxScan))
	}
	return w.data[p : p+i], p + i + 1, nil
}

// countedString reads n bytes of string payload after start.
func (w *walker) countedString(info opcodeInfo, start int, n int64, decode func([]byte) string) (any, int, error) {
	if n < 0 {
		return nil, start, argErr("negative-length", fmt.Sprintf("%s declares a negative length %d", info.name, n))
	}
	// Compare as "remaining bytes" rather than "start+length" so that an
	// attacker-chosen length near MaxInt64 cannot overflow into a passing check
	// (and a passing check would then slice out of range).
	remaining := int64(len(w.data) - start)
	if n > remaining {
		return nil, start, argErr("truncated-argument",
			fmt.Sprintf("%s declares %d bytes but only %d remain in the stream", info.name, n, remaining))
	}
	raw := w.data[start : start+int(n)]
	next := start + int(n)
	if info.arg != argString1 && info.arg != argString4 && !utf8.Valid(raw) {
		// CPython decodes a *UNICODE* payload with "surrogatepass", which accepts
		// any byte sequence; a payload that is not valid UTF-8 is therefore a
		// structural violation in a stream a CPython writer produced. The value is
		// still returned so that the walk continues past it.
		w.structFinding("non-utf8", info.name+" carries a payload that is not valid UTF-8", int64(start-1))
	}
	return decode(raw), next, nil
}

func (w *walker) countedBytes(info opcodeInfo, start int, n int64) (any, int, error) {
	if n < 0 {
		return nil, start, argErr("negative-length", fmt.Sprintf("%s declares a negative length %d", info.name, n))
	}
	remaining := int64(len(w.data) - start)
	if n > remaining {
		return nil, start, argErr("truncated-argument",
			fmt.Sprintf("%s declares %d bytes but only %d remain in the stream", info.name, n, remaining))
	}
	return w.data[start : start+int(n)], start + int(n), nil
}

// countedLong decodes a little-endian two's-complement big integer, the way
// CPython's _decode_long does: fold the bytes, then subtract 1 << (8*len) when the
// top bit is set. The value is not materialised as a big.Int: the walker only needs
// a scalar for the stack, and an attacker-controlled thousand-digit integer must
// not cost an allocation, so a value wider than eight bytes keeps its most
// significant eight bytes — the sign survives — and is clamped to MinInt64 when
// negative.
func (w *walker) countedLong(info opcodeInfo, start int, n int64) (any, int, error) {
	if n < 0 {
		return nil, start, argErr("negative-length", fmt.Sprintf("%s declares a negative length %d", info.name, n))
	}
	remaining := int64(len(w.data) - start)
	if n > remaining {
		return nil, start, argErr("truncated-argument",
			fmt.Sprintf("%s declares %d bytes but only %d remain in the stream", info.name, n, remaining))
	}
	if n == 0 {
		return int64(0), start, nil
	}
	raw := w.data[start : start+int(n)]
	var v int64
	// Fold the eight most significant bytes — the fold runs from the last byte
	// down, so what is kept is the top of the little-endian value. For a value of
	// at most eight bytes that is all of it; for a wider one it is the true value
	// shifted down, so the magnitude is a floor of it.
	for i := len(raw) - 1; i >= 0 && i >= len(raw)-8; i-- {
		v = v<<8 | int64(raw[i])
	}
	negative := raw[len(raw)-1]&0x80 != 0
	switch {
	case len(raw) < 8:
		if negative {
			// CPython's _decode_long subtracts 1 << (8*len(data)) rather than
			// masking the sign bit, so one byte 0xff is -1 and not -255.
			v -= int64(1) << (8 * uint(len(raw)))
		}
	case len(raw) == 8:
		// The fold already produced the two's-complement value.
	default:
		// More than 64 bits: the exact value does not fit an int64, so only the
		// most significant eight bytes are kept — the sign survives — and the
		// magnitude is a floor of the true one. A negative value is clamped rather
		// than reported as a positive number the stream does not contain.
		if negative {
			v = math.MinInt64
		}
	}
	return v, start + int(n), nil
}

// --- small helpers ---

func argInt(a any) (int64, bool) {
	switch v := a.(type) {
	case int64:
		return v, true
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

func argFloat(a any) float64 {
	if f, ok := a.(float64); ok {
		return f
	}
	return 0
}

func argString(a any) (string, bool) {
	s, ok := a.(string)
	return s, ok
}

func argBytes(a any) []byte {
	switch v := a.(type) {
	case []byte:
		return v
	default:
		return nil
	}
}

func argPair(a any) (string, string, bool) {
	if p, ok := a.([2]string); ok {
		return p[0], p[1], true
	}
	return "", "", false
}

// latin1String widens each byte to a rune, matching CPython's latin-1 decode of a
// STRING/BINSTRING payload.
// latin1String renders bytes as text the way Python's Latin-1 codec would.
//
// It is only used for constants that are actually text. Decoding an arbitrary
// 64 KiB binary constant — which is what the bulk of a state_dict pickle is — into
// UTF-8 doubles its size and spends a per-rune loop on it, for a string the
// indicator engine then reads byte by byte and never matches. Binary constants are
// therefore handed over as a plain byte string: the engine's automaton is
// byte-oriented, so the matches it can find are exactly the ASCII ones, and the
// Latin-1 decode is only what makes the handful of non-ASCII indicators reachable
// in text.
func latin1String(b []byte) string {
	if !mostlyText(b) {
		return string(b)
	}
	// Exact size first: a strings.Builder would double its buffer as the runes
	// expand, which for a 64 KiB constant is megabytes of needless garbage.
	n := 0
	for _, c := range b {
		if c < 0x80 {
			n++
		} else {
			n += 2
		}
	}
	out := make([]byte, 0, n)
	for _, c := range b {
		out = utf8.AppendRune(out, rune(c))
	}
	return string(out)
}

// textSample is how many bytes mostlyText looks at. A constant is either text
// throughout (a config, a tokenizer entry) or binary throughout (tensor bytes), so
// sampling the head answers the question, and sampling keeps this decision off the
// walk's hot path: measured over the whole of a 64 KiB constant it was 28% of the
// walk's CPU on a state_dict-shaped pickle, which is a lot of time to spend
// deciding whether to run a decode that is usually skipped.
const textSample = 4096

// printable marks the bytes that count as text: printable ASCII, the three
// whitespace controls, and the upper Latin-1 range that a Latin-1 decode would
// expand. A table beats five comparisons in a per-byte loop.
var printable = func() [256]bool {
	var t [256]bool
	for c := 0x20; c < 0x7f; c++ {
		t[c] = true
	}
	t['\t'], t['\n'], t['\r'] = true, true, true
	for c := 0xa0; c < 0x100; c++ {
		t[c] = true
	}
	return t
}()

// mostlyText reports whether b is plausibly text rather than a binary blob. The
// threshold is deliberately high: a tensor constant is binary almost throughout,
// while a config or a tokenizer entry is printable almost throughout, and the two
// want opposite treatment.
func mostlyText(b []byte) bool {
	n := len(b)
	if n == 0 {
		return false
	}
	sample := b
	if n > textSample {
		sample = b[:textSample]
	}
	text := 0
	for _, c := range sample {
		if printable[c] {
			text++
		}
	}
	return text*10 >= len(sample)*9
}

func utf8String(b []byte) string { return string(b) }

// stripQuotes removes the matching quote pair that stringnl requires.
func stripQuotes(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return b, argErr("bad-stringnl", "STRING argument is too short to carry quotes")
	}
	q := b[0]
	if q != '"' && q != '\'' {
		return b, argErr("bad-stringnl", "STRING argument is not quoted")
	}
	if b[len(b)-1] != q {
		return b, argErr("bad-stringnl", "STRING argument's closing quote does not match its opening quote")
	}
	return b[1 : len(b)-1], nil
}

// unescape performs the escape decoding that stringnl applies, tolerantly: an
// unknown escape is reported by the caller and kept verbatim rather than aborting
// the walk, because a stream that makes a scanner bail is exactly the evasion this
// engine is built against.
func unescape(b []byte) ([]byte, error) {
	if bytes.IndexByte(b, '\\') < 0 {
		return b, nil
	}
	out := make([]byte, 0, len(b))
	var firstErr error
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(b) {
			if firstErr == nil {
				firstErr = argErr("bad-escape", "STRING argument ends with a lone backslash")
			}
			break
		}
		switch e := b[i]; e {
		case 'x':
			if i+2 < len(b) {
				if hi, ok1 := hexVal(b[i+1]); ok1 {
					if lo, ok2 := hexVal(b[i+2]); ok2 {
						out = append(out, hi<<4|lo)
						i += 2
						continue
					}
				}
			}
			if firstErr == nil {
				firstErr = argErr("bad-escape", "STRING argument has a truncated \\x escape")
			}
			out = append(out, '\\', 'x')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case 'f':
			out = append(out, '\f')
		case 'b':
			out = append(out, '\b')
		case 'a':
			out = append(out, 7)
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int(e - '0')
			for k := 0; k < 2 && i+1 < len(b); k++ {
				if o := b[i+1]; o >= '0' && o <= '7' {
					v = v<<3 | int(o-'0')
					i++
					continue
				}
				break
			}
			out = append(out, byte(v))
		case '\\', '\'', '"':
			out = append(out, e)
		case '\n':
			// Escaped newline: a line continuation, contributing nothing.
		default:
			if firstErr == nil {
				firstErr = argErr("bad-escape", fmt.Sprintf("STRING argument has an unknown escape \\%c", e))
			}
			out = append(out, '\\', e)
		}
	}
	return out, firstErr
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func truncateForEvidence(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
