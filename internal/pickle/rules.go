package pickle

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The pickle rule set. Severity calibration follows the plan's documented rule:
// critical means code execution or credential exfiltration reachable from the
// artifact's normal load path, high means exploitable file access or an
// unvalidated code-loading surface, medium means suspicious but unproven, low and
// info are structural anomalies.

var (
	// ruleGlobalCritical fires at the opcode that introduces a direct primitive.
	ruleGlobalCritical = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-GLOBAL-CRITICAL",
		Title:      "Pickle references a direct code-execution primitive",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-94"},
		Class:      "pickle",
		Description: "The stream names a class or function that is itself a sink: the members of os/posix/nt, " +
			"subprocess, pty, socket, ctypes, importlib, runpy, builtins.eval/exec/compile/__import__/open, " +
			"functools.reduce, pickle.load(s), dill/cloudpickle and the rest of the table in " +
			"internal/pickle/gadgets.go. `torch.load(weights_only=True)` rejects every one of these names " +
			"(the allowlist is transcribed from torch/_weights_only_unpickler.py), and an unsafe " +
			"`torch.load` or a bare `pickle.load` calls them. Module matching is subtree-aware, so " +
			"asyncio.subprocess cannot slip past asyncio (that exact mistake was picklescan " +
			"CVE-2025-10157, CVSS 8.3).",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://github.com/pytorch/pytorch/blob/v2.7.0/torch/_weights_only_unpickler.py",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-10157",
		},
	})

	// ruleGlobalHigh fires for a library gadget: a helper that reaches a sink.
	ruleGlobalHigh = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-GLOBAL-HIGH",
		Title:      "Pickle references a reachable library gadget",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "The stream names a standard-library helper that is not a sink itself but reaches one " +
			"with the right arguments: numpy.f2py.crackfortran.myeval (an eval by another name), " +
			"pydoc.pipepager (a shell pipeline), logging.config._install_handlers (instantiates an " +
			"arbitrary class), xmlrpc.server.resolve_dotted_attribute (resolves a dotted name and returns " +
			"it), sympy.parsing.sympy_parser.eval_expr, dataclasses._create_fn (exec of generated source) " +
			"and the rest of PickleCloak's published gadget set (arXiv 2508.19774, Table VI). Name-denylist " +
			"scanners miss most of these. The severity is high rather than critical because the gadget " +
			"needs arguments the scanner cannot always prove it has.",
		Refs: []string{
			"https://arxiv.org/abs/2508.19774",
			"https://cwe.mitre.org/data/definitions/502.html",
		},
	})

	// ruleGlobalUnknown fires for any callable name outside the allowlist.
	ruleGlobalUnknown = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-GLOBAL-UNKNOWN",
		Title:      "Pickle references a global outside the weights-only allowlist",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "The stream names a class or function that is neither allowlisted by " +
			"torch.load(weights_only=True) nor present in sc4n's gadget tables. Two readings are " +
			"possible: an ordinary library object that the weights-only unpickler would reject (so the " +
			"user must opt into the unsafe loader), or a name crafted to look ordinary. Either way the " +
			"artifact cannot be loaded with weights_only=True as written.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleSafeGlobalsNeeded fires when the stream appears to rely on a user
	// extension rather than the built-in allowlist.
	ruleSafeGlobalsNeeded = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-SAFE-GLOBALS",
		Title:      "Pickle requires a user allowlist entry to load weights-only",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceMedium,
		Class:      "pickle",
		Description: "Every global in this stream is outside the built-in weights-only allowlist, so loading " +
			"it with weights_only=True requires torch.serialization.add_safe_globals. That is a " +
			"deliberate act by the user, and the names involved are reported individually; this finding " +
			"exists so that a reader can see the artifact's loading requirement as a single fact rather " +
			"than reconstructing it from the per-global findings. The ID is historical and reads like a " +
			"clearance; it is not one — the Title is the statement.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleReduce fires when REDUCE's callable is not allowlisted.
	ruleReduce = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-REDUCE",
		Title:      "REDUCE calls a non-allowlisted callable",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-94"},
		Class:      "pickle",
		Description: "REDUCE pops a callable and an argument tuple and calls the callable. The reference " +
			"weights-only unpickler permits this only for names in its allowlist " +
			"(\"Trying to call reduce for unrecognized function\"), so a REDUCE over any other name is " +
			"both a rejection and the point at which a pickle stream becomes a program. The per-global " +
			"finding names the callable and its sink.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleBuildState fires when BUILD applies attacker state to a non-allowlisted
	// class.
	ruleBuildState = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-BUILD-STATE",
		Title:      "BUILD applies stream-controlled state to a non-allowlisted class",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-915"},
		Class:      "pickle",
		Description: "BUILD pops a state object and applies it to the value beneath it. The reference loader " +
			"permits that only for torch.Tensor, torch.nn.Parameter, collections.OrderedDict and classes a " +
			"user allowlisted (\"Can only build Tensor, Parameter, OrderedDict or types allowlisted\"). A " +
			"BUILD outside that set either drives __setstate__ on an arbitrary class or, worse, sets " +
			"attributes from stream data: the ShadowPickle shape is exactly `allowlisted class + payload " +
			"state + BUILD`.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/915.html",
			"https://arxiv.org/abs/2607.17503",
		},
	})

	// ruleInst / ruleObj / ruleNewObj / ruleNewObjEx fire on the class-construction
	// opcodes.
	ruleInst = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-INST",
		Title:      "INST constructs a class named by the stream",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "INST builds an instance of the class named in the opcode argument, calling it with the " +
			"arguments on the stack. The weights-only unpickler does not implement INST at all, so a " +
			"stream containing it requires the unsafe loader by construction.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	ruleObj = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-OBJ",
		Title:      "OBJ constructs a class named on the stack",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "OBJ is INST with the class taken from the stack, which means the class name can be " +
			"reconstructed by STACK_GLOBAL from strings. The weights-only unpickler does not implement OBJ.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	ruleNewObj = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-NEWOBJ",
		Title:      "NEWOBJ constructs an instance of a stream-named class",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "NEWOBJ calls cls.__new__(cls, *args). The reference loader permits it only for " +
			"torch.nn.Parameter and for classes in the allowlist (\"Can only create new object for " +
			"nn.Parameter or classes allowlisted\"); anything else is a rejection, and with an " +
			"attacker-chosen class in a less strict unpickler it is object construction from stream data.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	ruleNewObjEx = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-NEWOBJ_EX",
		Title:      "NEWOBJ_EX constructs an instance with keyword state",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "NEWOBJ_EX is NEWOBJ with a keyword-argument state dict, which the weights-only " +
			"unpickler does not implement. It is also the opcode PROTECTED_SETATTR-style payloads use, " +
			"because the state dict gives the attacker control over attribute names as well as values.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleSetItemTarget is the loader guard the current reference policy does not
	// implement.
	ruleSetItemTarget = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-SETITEM-TARGET",
		Title:      "SETITEM/SETITEMS targets a non-dict",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-787", "CWE-502"},
		Class:      "pickle",
		Description: "SETITEM and SETITEMS assign into the object beneath them. The reference weights-only " +
			"unpickler performs `self.stack[-1][k] = v` without checking the target's type, which is the " +
			"heap-corruption class CVE-2026-24747 / GHSA-63cw-57p8-fm3p fixed in torch 2.10.0 by adding " +
			"the check. A stream whose SETITEM target is not a dict therefore corrupts memory on a " +
			"2.7-era loader and is rejected by a fixed one.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/787.html",
			"https://github.com/pytorch/pytorch/security/advisories/GHSA-63cw-57p8-fm3p",
		},
	})

	// ruleAppendTarget is the loader's APPEND/APPENDS guard.
	ruleAppendTarget = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-APPEND-TARGET",
		Title:      "APPEND/APPENDS targets a non-list",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "APPEND pops a value and appends it to the object beneath; the reference weights-only " +
			"unpickler requires that object to be exactly a list (\"Can only append to lists\"). Appending " +
			"into anything else either mutates an object the loader did not intend to expose or, for a " +
			"class with a custom append, calls attacker-selected code. Confidence is medium because the " +
			"walker cannot distinguish a list from a list subclass.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// rulePersID covers persistent-id loading, which the reference loader refuses
	// outright.
	rulePersID = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-PERSID",
		Title:      "Persistent id is not a (\"storage\", …) tuple",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "PERSID/BINPERSID hand a stream-controlled id to the loader's persistent_load hook. The " +
			"weights-only unpickler accepts only a tuple whose first element is \"storage\" (and a bare " +
			"int, for old checkpoints), and its persistent_load raises unconditionally. Any other shape " +
			"means the stream expects a host application to resolve an attacker-chosen identifier, which " +
			"is an arbitrary-load primitive in any application that implements the hook.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleExt covers the extension registry.
	ruleExt = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-EXT",
		Title:      "Extension-registry lookup (EXT1/EXT2/EXT4)",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "EXT1/EXT2/EXT4 resolve a small integer through copyreg's extension registry, which is " +
			"populated by whatever the loading process imported. The opcode carries no name, so the " +
			"artifact's behaviour depends on the host environment and cannot be verified statically: the " +
			"same file can resolve to a benign class on one host and to a code-execution primitive on " +
			"another. The weights-only unpickler does not implement these opcodes.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleMemoAlias is the ShadowPickle signal.
	ruleMemoAlias = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-MEMO-ALIAS",
		Title:      "Memo slot rebound or one name bound in several slots",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502", "CWE-694"},
		Class:      "pickle",
		Description: "Either a memo slot is written twice, or two different slots hold the same qualified " +
			"name. The reference unpickler's counterpart, torch's get_globals_in_pkl, scans a stream for " +
			"names and therefore sees exactly one binding per name; a stream that binds an allowlisted " +
			"name in two places, or rebinds a slot, is the ShadowPickle shape (arXiv 2607.17503) that " +
			"defeats allowlist-by-name. A benign stream binds each *name* once — the class an object was " +
			"built from is a different value in a different slot, and is not a second binding.",
		Refs: []string{"https://arxiv.org/abs/2607.17503"},
	})

	// ruleStruct is the structural rule.
	ruleStruct = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-STRUCT",
		Title:      "Pickle stream violates the opcode grammar",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-20"},
		Class:      "structure",
		Description: "An unknown opcode, an argument that a declared protocol cannot carry, a truncated or " +
			"negative counted length, a missing STOP, a memo or stack reference that does not resolve, or " +
			"a non-UTF-8 payload inside a unicode opcode. The extra field names the specific violation. " +
			"Structurally invalid pickles are the IDS-evasion family of arXiv 2508.15987 (PickleBall): " +
			"the stream is still executed by the loader while a scanner that stops at the first error sees " +
			"nothing beyond it, which is why sc4n reports the violation and keeps walking.",
		Refs: []string{
			"https://arxiv.org/abs/2508.15987",
			"https://cwe.mitre.org/data/definitions/502.html",
		},
	})

	// ruleCodeString is the one rule that fires on an otherwise allowlisted stream.
	ruleCodeString = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-CODE-STRING",
		Title:      "Code-like string passed as a REDUCE argument",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-94", "CWE-502"},
		Class:      "pickle",
		Description: "A str or bytes constant of at least 24 bytes that is passed as an argument to REDUCE, " +
			"and that looks like source: `import `, `__import__`, `open(`, `os.`, `system(`, " +
			"`subprocess`, `exec(`, `eval(`, `for ` with `in `, `);`. This is the rule that catches the " +
			"ShadowPickle motivating stream, where the *callable is allowlisted* — " +
			"`GLOBAL collections OrderedDict` plus a code string plus REDUCE plus BUILD — so nothing in a " +
			"name-based policy can see it (arXiv 2607.17503). The threshold exists to keep short benign " +
			"metadata strings (dtype names, sizes, small labels) out of the finding list.",
		Refs: []string{
			"https://arxiv.org/abs/2607.17503",
			"https://cwe.mitre.org/data/definitions/94.html",
		},
	})

	// ruleRequiresUnsafeLoader is the honest "this needs the unsafe path" signal.
	ruleRequiresUnsafeLoader = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
		Title:      "Stream uses opcodes the weights-only unpickler rejects",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "The stream contains opcodes outside the weights-only unpickler's accepted set " +
			"(STACK_GLOBAL, INST, OBJ, NEWOBJ_EX, EXT1/2/4, PERSID, BINPERSID, FRAME, MEMOIZE, LONG4, " +
			"BINBYTES, BINUNICODE8, BYTEARRAY8, NEXT_BUFFER, READONLY_BUFFER), so torch.load with " +
			"weights_only=True cannot load it and the user must opt into the unsafe unpickler. Confidence " +
			"is low and the finding says so honestly: the weights-only unpickler is protocol-2-shaped, so " +
			"any protocol 4 or 5 file — including entirely benign metadata pickles written by current " +
			"torch.save — trips this set. Treat it as \"this artifact needs a decision\", not as evidence " +
			"of malice, unless another finding co-occurs.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// rulePrefix covers bytes before the first PROTO.
	rulePrefix = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-PREFIX",
		Title:      "Data before the pickle stream's first opcode",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "pickle",
		Description: "The stream does not begin with a pickle opcode: there are bytes ahead of the first " +
			"PROTO/first opcode, and the payload begins after them. This is the nullifAI shape from the " +
			"February 2025 Hugging Face campaign, where a broken-pickle file put its payload first and a " +
			"malformed opcode after it precisely so that scanners which start at the first valid opcode " +
			"see nothing. sc4n reports the leading bytes (with their entropy and any embedded native " +
			"magic) and then walks the stream that follows them.",
		Refs: []string{
			"https://huggingface.co/blog/notable-models-scanned",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
	})

	// ruleTrailing covers bytes after the last STOP.
	ruleTrailing = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-TRAILING",
		Title:      "Data after the pickle stream's STOP",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "pickle",
		Description: "Bytes follow a complete pickle and do not themselves start a pickle. The reference " +
			"unpickler stops at the first STOP, so nothing legitimate is there, while any reader that " +
			"loops over load() — joblib, a legacy torch archive, a hand-rolled loader — executes what " +
			"follows. This is the other half of the nullifAI broken-pickle shape and the mechanism behind " +
			"scanner-bypassing stacked-pickle files.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	})

	// ruleSegment covers concatenated pickles.
	ruleSegment = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-SEGMENT",
		Title:      "Concatenated pickle segments",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "pickle",
		Description: "STOP is not end-of-file: the bytes after it start another complete pickle, so the file " +
			"holds several segments (joblib, legacy torch checkpoints and stacked-pickle files all do " +
			"this legitimately). sc4n walks and reports every segment. The finding is informational on " +
			"its own; read the segments' own findings, because a payload in the second segment is exactly " +
			"how a scanner that reads one pickle per file misses it.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	})

	// ruleIncomplete covers a walk that could not decode the rest.
	ruleIncomplete = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-INCOMPLETE",
		Title:      "Pickle stream could not be decoded past this offset",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "structure",
		Description: "The walker hit an opcode it could not decode — an unknown byte, a truncated or " +
			"negative counted argument, or a memo reference that does not resolve — and resumed scanning " +
			"byte by byte from the next position so that anything after it is still reported. This is the " +
			"counter to exception-oriented programming (arXiv 2508.19774, 9 instances, 7 of them bypassing " +
			"every SOTA scanner): a scanner that aborts or returns at the first error never reaches the " +
			"payload, while the loader does.",
		Refs: []string{"https://arxiv.org/abs/2508.19774"},
	})

	// ruleOffsetZero is the field-observed off-by-one scanner bug.
	ruleOffsetZero = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-OFFSET-ZERO",
		Title:      "Executable opcode at stream offset 0",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "pickle",
		Description: "The very first byte of the stream is a GLOBAL/REDUCE-class opcode rather than the " +
			"PROTO a modern pickle opens with. This is reported separately because a widely-deployed " +
			"scanner bug starts its opcode scan at index 1 and therefore never sees it. The checked " +
			"condition is what matters: if the first opcode introduces a global or drives a call, the " +
			"payload is at offset 0 and any scanner that skips byte 0 is blind to the whole stream.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
	})

	// ruleStack covers the operand-stack budget.
	ruleStack = report.DefineRule(report.Rule{
		ID:         "SC4N-PICKLE-STACK",
		Title:      "Operand stack exceeded MaxStackDepth",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-674"},
		Class:      "limits",
		Description: "The stream pushes more values than the stack budget allows, so the walk stopped at the " +
			"cap and the remainder was not analysed. A real torch state_dict builds a stack a few hundred " +
			"entries deep; a stream that exceeds a million is either an accident or an attempt to exhaust " +
			"the scanner before it reaches the payload.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/674.html"},
	})
)
