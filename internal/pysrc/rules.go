package pysrc

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// The Python rule set. Two families live here:
//
//   - SC4N-CODE-*: a taint-ish rule set over (source, sink) pairs plus standalone
//     obfuscation detectors. There is no type inference, so the rules reason about
//     one statement at a time and about variables assigned from a source earlier
//     in the same function.
//   - SC4N-LOADER-*: a loader-safety lint that fires on the *absence* of a
//     guard (no weights_only=True, no pinned revision), which is complementary to
//     the pickle/artifact rules: those read an artifact, this reads the code that
//     would load it.
//
// Severity calibration follows the plan: critical is code execution or credential
// exfiltration reachable from the artifact's normal load path, high is an
// exploitable file/network access or an unvalidated code-loading surface, medium
// is suspicious but unproven, low/info is a structural anomaly.

var (
	ruleTaintExec = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-EXEC",
		Title:      "Data from an untrusted source reaches a code-execution sink",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-94"},
		Class:      "code",
		Description: "A value derived from an external source (input, argv, environment, a file or socket " +
			"read, a decoded blob, a downloaded model) is passed to exec/eval/compile/__import__, " +
			"importlib.import_module, runpy, a ctypes native-library load, or an interactive interpreter. " +
			"The taint is statement-level and intra-function: sc4n does not model containers, aliases or " +
			"closure capture, so a finding is an upper bound on risk and a clean result is not a proof.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
		Tags: []string{"execution"},
	})

	ruleTaintShell = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-SHELL",
		Title:      "Data from an untrusted source reaches a shell or process sink",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-78"},
		Class:      "code",
		Description: "A value derived from an external source is passed to os.system, os.popen, " +
			"os.exec*/os.spawn*, subprocess.*, pty.spawn or commands.getoutput. Builder-style APIs that " +
			"pass an argument vector are still reported, because the vector element is only one quoting " +
			"mistake away from a shell; `shell=True` is recorded in the finding's extra fields when it is " +
			"written next to the call.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/78.html"},
		Tags: []string{"execution"},
	})

	ruleTaintDeserialize = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-DESERIALIZE",
		Title:      "Data from an untrusted source is deserialised",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "code",
		Description: "A value derived from an external source is passed to pickle.load(s), dill/cloudpickle, " +
			"marshal.loads, torch.load, or yaml.load/unsafe_load. Deserialising attacker-influenced bytes is " +
			"the pickle RCE class (CWE-502); the loader-safety family flags the same calls when they are " +
			"missing their guard.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Tags: []string{"deserialization"},
	})

	ruleTaintDynamic = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-DYNAMIC",
		Title:      "Attribute name is resolved from an untrusted source",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-94"},
		Class:      "code",
		Description: "getattr/setattr/delattr is called with a name derived from an external source, which " +
			"lets the caller select which attribute (or method) is reached. Confidence is low because the " +
			"same pattern is common in legitimate plugin code; read the source value before acting on it.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
		Tags: []string{"dynamic-attribute"},
	})

	ruleTaintFile = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-FILE",
		Title:      "A file is written to a path derived from an untrusted source",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-22", "CWE-73"},
		Class:      "code",
		Description: "open() is called in a writing mode ('w'/'a'/'x') with a path derived from an external " +
			"source, so the caller controls where bytes land (path traversal / arbitrary write). The mode " +
			"is read from the second positional argument or the mode= keyword.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/22.html"},
		Tags: []string{"file-write"},
	})

	ruleTaintDelete = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-DELETE",
		Title:      "A path derived from an untrusted source is deleted or moved",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-73"},
		Class:      "code",
		Description: "shutil.rmtree/os.remove/os.unlink/os.rmdir/os.rename/shutil.move is called with a path " +
			"derived from an external source, so the caller controls which file is removed or moved.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/73.html"},
		Tags: []string{"file-delete"},
	})

	ruleTaintNetwork = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-NETWORK",
		Title:      "Data from an untrusted source is sent to a network sink",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-918"},
		Class:      "code",
		Description: "A value derived from an external source is sent through requests/httpx/urllib, " +
			"webbrowser.open, or a socket connect. Inside a model script this is the exfiltration half of " +
			"the credential-shaped rules: the value is usually a token read from the environment or the " +
			"Hugging Face cache.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/918.html"},
		Tags: []string{"exfiltration"},
	})

	ruleTaintTemplate = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-TAINT-TEMPLATE",
		Title:      "Data from an untrusted source is rendered as a template",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-1336"},
		Class:      "code",
		Description: "Jinja2 from_string/from_file is called with a template string derived from an external " +
			"source (a chat template, a metadata value, a downloaded config). Untrusted template source is " +
			"server-side template injection; the Jinja analyser in internal/jinja reads the template's own " +
			"contents, while this rule fires on the code path that would render it.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/1336.html"},
		Tags: []string{"template-injection"},
	})

	ruleObfuscation = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-OBFUSCATION",
		Title:      "Code is assembled from obfuscated string or character fragments",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "code",
		Description: "The statement builds a string from obfuscated pieces: a chain of chr() calls, a " +
			"\"\".join([...]) of many literals, a long run of \\x escapes, a long bytes([...]) literal, or " +
			"an f-string with nested replacement fields. Each is a way to keep a command out of the readable " +
			"text a reviewer greps for; the finding names which construct was seen.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/1336.html"},
		Tags: []string{"obfuscation"},
	})

	ruleEncodedPayload = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-ENCODED-PAYLOAD",
		Title:      "A long encoded literal is decoded in the same statement",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "code",
		Description: "A base64- or hex-shaped literal of at least 32 characters appears in a statement that " +
			"also calls a decoder (base64.b64decode, codecs.decode, bytes.fromhex, binascii.*, zlib). The " +
			"pairing is the standard second-stage shape: the literal alone is opaque data and the decoder " +
			"alone is ordinary library use.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/1336.html"},
		Tags: []string{"obfuscation"},
	})

	ruleCompileExec = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-COMPILE-EXEC",
		Title:      "compile() is called with an exec mode",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-94"},
		Class:      "code",
		Description: "compile(source, filename, mode) is called with mode 'exec' (or a mode string " +
			"containing it), which compiles a whole module body rather than a single expression. It is the " +
			"explicit form of the exec() pattern and is rare in ordinary model-loading code.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
		Tags: []string{"execution"},
	})

	ruleNotebookMagic = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-NOTEBOOK-MAGIC",
		Title:      "Notebook cell uses an IPython magic or shell escape",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-78", "CWE-94"},
		Class:      "code",
		Description: "A code cell runs an IPython magic or a shell escape: `!cmd`, `%%bash`, `%%sh`, " +
			"`%%javascript`, `%%html`, `%%writefile`, `%run` or `%system`. These are executed by the " +
			"notebook kernel (the `!`/`%%bash` forms through a shell), so they are not visible to a Python " +
			"lexer's ordinary rules and a notebook that looks like harmless Python can still spawn a " +
			"process when opened and run. The finding reports the line in the .ipynb file, not in the cell.",
		Refs: []string{"https://ipython.readthedocs.io/en/stable/interactive/magics.html"},
		Tags: []string{"notebook", "execution"},
	})

	ruleLoaderTorchUnsafe = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-TORCH-UNSAFE",
		Title:      "torch.load is called without weights_only=True",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "torch.load is called with no weights_only=True (or with weights_only=False). Without " +
			"the flag the loader uses the unrestricted unpickler, which executes whatever the file " +
			"contains. torch 2.6 flipped the default, but a pinned older dependency, or an explicit " +
			"weights_only=False, still reaches the unsafe path (CWE-502; a payload file may be a torch " +
			"archive, a legacy pickle, or a 7z archive renamed .pt).",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://pytorch.org/docs/stable/generated/torch.load.html",
		},
		Tags: []string{"loader", "pickle"},
	})

	ruleLoaderPickleRemote = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-PICKLE-REMOTE",
		Title:      "pickle.load is called on data fetched from a network source",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "pickle.load(s) is called on a value that came from a network or download source " +
			"(urlopen, requests, socket.recv, hf_hub_download, from_pretrained). Loading a pickle from a " +
			"host you did not choose is remote code execution by design.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Tags: []string{"loader", "pickle"},
	})

	ruleLoaderTrustRemoteCode = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-TRUST-REMOTE-CODE",
		Title:      "trust_remote_code=True enables execution of repository code",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "trust_remote_code=True tells a Hugging Face loader to import and run Python shipped in " +
			"the model repository (the auto_map path). It converts a data download into code execution and " +
			"is the flag the `config.json` auto_map rule warns about from the artifact side.",
		Refs: []string{"https://huggingface.co/docs/hub/security"},
		Tags: []string{"loader", "supply-chain"},
	})

	ruleLoaderAllowPickle = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-ALLOW-PICKLE",
		Title:      "allow_pickle=True permits object arrays to be unpickled",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "numpy.load(..., allow_pickle=True) lets a .npy/.npz object-dtype array reach " +
			"pickle.load. The array's data section is a pickle stream, so the flag re-enables the pickle " +
			"RCE class on a format that is otherwise data-only.",
		Refs: []string{"https://numpy.org/doc/stable/reference/generated/numpy.load.html"},
		Tags: []string{"loader", "pickle"},
	})

	ruleLoaderNoRevision = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-NO-REVISION",
		Title:      "Model is downloaded without a pinned commit revision",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-494"},
		Class:      "loader",
		Description: "from_pretrained/hf_hub_download is called with a literal model id and without a " +
			"revision= argument (or with a revision that is not a 40-hex commit id). Without a pin the " +
			"download follows the repository's default branch, so a later force-push changes which bytes " +
			"are loaded. A call whose model argument is a variable is not reported: nothing in the source " +
			"says which repository it will reach, so the finding would be about a loader function rather " +
			"than about a download.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/494.html"},
		Tags: []string{"loader", "supply-chain"},
	})

	ruleLoaderNoLocalOnly = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-NO-LOCAL-ONLY",
		Title:      "A local model path is loaded without local_files_only",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-494"},
		Class:      "loader",
		Description: "An Auto* from_pretrained is given a path-shaped first argument (starting with './', " +
			"'/', '~') and no local_files_only=True. If the directory is absent or incomplete the library " +
			"falls back to downloading a repository of the same name, which is how a local-looking load " +
			"silently becomes a remote one. Confidence is low because path-shaped strings are also used " +
			"for legitimate local models.",
		Refs: []string{"https://huggingface.co/docs/transformers/main_classes/model"},
		Tags: []string{"loader", "supply-chain"},
	})

	ruleLoaderJinjaFromString = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-JINJA-FROMSTRING",
		Title:      "jinja2.Environment renders a template from a string or file",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1336"},
		Class:      "loader",
		Description: "A jinja2.Environment is used with from_string/from_file in the same statement. " +
			"Rendering an untrusted template with the default environment is server-side template " +
			"injection; the CVE-2026-5760 SGLang RCE is this shape reached through /v1/rerank with an " +
			"unsandboxed Jinja2 environment.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/1336.html",
			"https://nvd.nist.gov/vuln/detail/CVE-2026-5760",
		},
		Tags: []string{"loader", "template-injection"},
	})

	ruleLoaderYAMLUnsafe = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-YAML-UNSAFE",
		Title:      "yaml.load is called without a safe loader",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "yaml.load is called with no SafeLoader/CSafeLoader (or yaml.unsafe_load is called " +
			"directly). The default loader constructs arbitrary Python objects from the document, which is " +
			"the PyYAML object-instantiation RCE class; yaml.safe_load is the guarded form.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Tags: []string{"loader", "deserialization"},
	})

	ruleLoaderKerasSafeMode = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-KERAS-SAFE-MODE",
		Title:      "keras load_model is called with safe_mode=False",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "tf.keras.models.load_model(..., safe_mode=False) disables Keras' safe-mode loading, " +
			"which is the guard that refuses Lambda layers and unregistered classes. The .keras " +
			"Lambda/TorchModuleWrapper rules describe what the file can then execute.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Tags: []string{"loader", "keras"},
	})

	// ruleCodeReduceBuilder fires for a class that defines __reduce__ returning a
	// code-executing callable *and* a serialiser dump in the same file: the pair is
	// a pickle payload generator, whose output the pickle engine reports when it
	// meets the dumped file.
	ruleCodeReduceBuilder = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-REDUCE-BUILDER",
		Title:      "Python source builds a pickle payload with __reduce__",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502", "CWE-94"},
		Class:      "code",
		Description: "A class in this file defines __reduce__ or __reduce_ex__ returning a callable that " +
			"executes code (eval, exec, os.system, subprocess.*, __import__, marshal.loads, pickle.loads, " +
			"ctypes.*) together with a serialiser dump (pickle/dill/cloudpickle/joblib dump, torch.save). " +
			"The pair is what a pickle payload generator looks like: the class is inert until something " +
			"unpickles the file it was dumped into, so the generator is the human-readable half of the attack.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Tags: []string{"payload-builder", "pickle"},
	})

	// ruleCodeReverseShell fires when one artifact contains a socket constructor, a
	// connect call, a receive call and a command sink. Any single call is ordinary;
	// the combination is a reverse shell, and the payload text a generator embeds in
	// a string literal counts the same as the code it runs.
	// ruleCodeRemoteToolLoader fires for transformers.load_tool('org/repo'), which
	// imports and runs the code of a Hub repository inside the current process.
	// ruleCodeAgentCodeExec fires for an agent that is constructed with a code
	// executor, i.e. a model whose tool output is executed rather than returned.
	ruleCodeAgentCodeExec = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-AGENT-CODE-EXEC",
		Title:      "Agent is constructed with a code executor",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-94"},
		Class:      "code",
		Description: "The source builds an agent (Agent, LlmAgent, AgentTool) whose tools include a code " +
			"executor (BuiltInCodeExecutor, code_executor=/CodeExecutor) and that also exposes an MCP " +
			"session, a retrieval corpus or HTTP requests. Together they describe an agent that can be " +
			"driven to execute code and to reach the network, so the artifact's behaviour depends on " +
			"inputs it fetches at run time rather than on the code in the file.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
		Tags: []string{"agent", "code-execution"},
	})

	ruleCodeRemoteToolLoader = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-REMOTE-TOOL-LOADER",
		Title:      "Python source loads and runs code from a Hub repository",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-829", "CWE-94"},
		Class:      "code",
		Description: "transformers.load_tool('org/repo') resolves a Space or repository from the Hub and " +
			"imports its Python module into the current process, so the repository's code runs with the " +
			"caller's privileges. A model card cannot make that code inspectable: the trust decision is " +
			"delegated to whoever controls the named repository, at whatever revision it currently has.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/829.html",
			"https://cwe.mitre.org/data/definitions/94.html",
		},
		Tags: []string{"remote-code"},
	})

	ruleCodeReverseShell = report.DefineRule(report.Rule{
		ID:         "SC4N-CODE-REVERSE-SHELL",
		Title:      "Python source contains a reverse-shell shape",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-78", "CWE-306"},
		Class:      "code",
		Description: "One artifact contains a socket constructor, a connect call, a receive call and a " +
			"command sink (subprocess.*, os.system, os.popen). Each of those alone is ordinary; together " +
			"they describe a connection that receives commands and runs them, which is the interactive " +
			"access payload a model file or a training script carries. The markers are matched over the " +
			"whole artifact, because a generator that embeds the payload in a string literal carries the " +
			"same signal as one that runs it.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/78.html",
			"https://cwe.mitre.org/data/definitions/306.html",
		},
		Tags: []string{"reverse-shell"},
	})

	ruleLoaderKerasLambda = report.DefineRule(report.Rule{
		ID:         "SC4N-LOADER-KERAS-LAMBDA",
		Title:      "keras.layers.Lambda constructs a layer from a Python function",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "loader",
		Description: "keras.layers.Lambda wraps a Python function (often marshalled bytecode) into a layer. " +
			"A saved model containing one executes it on load, which is the Keras Lambda RCE class " +
			"(VU#253266 / CVE-2024-3660).",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/502.html",
			"https://kb.cert.org/vuls/id/253266",
		},
		Tags: []string{"loader", "keras"},
	})
)

// Analyze runs the Python rules over a source buffer, emitting findings through
// ctx.Sink at the buffer's own line numbers.
func Analyze(ctx *artifact.Ctx, src []byte) { analyze(ctx, src, nil) }

// analyze is Analyze with an optional line map: when cellLines is non-nil,
// cellLines[k] is the original line number (in the containing file) of the
// buffer's line k+1. The notebook parser uses it to report a finding inside a cell
// at the .ipynb line the reviewer will open.
func analyze(ctx *artifact.Ctx, src []byte, cellLines []int) {
	src = capSource(ctx, src)
	a := &analyzer{
		ctx:        ctx,
		src:        src,
		li:         newLineIndex(src),
		cell:       cellLines,
		tainted:    map[string]bool{},
		netTainted: map[string]bool{},
		callBudget: maxCallTokens,
	}
	a.reverseShell()
	a.agentCodeExec()
	stmts := Statements(src, Lex(src))
	for _, st := range stmts {
		a.stmt(st)
	}
	a.finish()
}

// agentCodeExec reports an agent constructed with a code executor and a tool
// surface that reaches outside the process.
func (a *analyzer) agentCodeExec() {
	off, markers, ok := agentCodeExecMarkers(a.src)
	if !ok {
		return
	}
	line, col := a.at(off)
	a.ctx.Sink.EmitAtExtra(ruleCodeAgentCodeExec, line, col,
		"agent with a code-execution tool: "+strings.Join(markers, ","),
		map[string]string{"markers": strings.Join(markers, ",")})
}

// agentCodeExecMarkers reports whether src builds an agent wired to a code
// executor. It needs a code-executor marker, an agent constructor and a tool
// surface: any one of them alone is an ordinary import.
func agentCodeExecMarkers(src []byte) (int32, []string, bool) {
	exec := -1
	for _, m := range []string{"BuiltInCodeExecutor", "code_executor=", "CodeExecutor"} {
		if i := bytes.Index(src, []byte(m)); i >= 0 && (exec < 0 || i < exec) {
			exec = i
		}
	}
	if exec < 0 {
		return 0, nil, false
	}
	if !hasAnyMarker(src, "Agent(", "LlmAgent(", "AgentTool(") {
		return 0, nil, false
	}
	if !hasAnyMarker(src, "MCPToolset", "mcp_session", "VertexAiRagRetrieval", "requests.") {
		return 0, nil, false
	}
	markers := make([]string, 0, 8)
	for _, m := range []string{
		"BuiltInCodeExecutor", "code_executor=", "Agent(", "LlmAgent(", "AgentTool(",
		"MCPToolset", "mcp_session", "VertexAiRagRetrieval", "requests.",
	} {
		if bytes.Contains(src, []byte(m)) {
			markers = append(markers, m)
		}
	}
	return int32(exec), markers, true
}

// reverseShell reports an artifact that combines a socket constructor, a connect
// call, a receive call and a command sink.
func (a *analyzer) reverseShell() {
	off, markers, ok := reverseShellMarkers(a.src)
	if !ok {
		return
	}
	line, col := a.at(off)
	a.ctx.Sink.EmitAtExtra(ruleCodeReverseShell, line, col,
		"reverse-shell shape: socket + connect + recv + a command sink in one artifact",
		map[string]string{"markers": strings.Join(markers, ",")})
}

// reverseShellMarkers reports whether src holds all four reverse-shell groups and
// which markers were seen. The groups are: a socket constructor; a connect call;
// a command sink; a receive call. threading.Thread and the specific sink names are
// reported when present but are not required.
func reverseShellMarkers(src []byte) (int32, []string, bool) {
	sock := bytes.Index(src, []byte("socket.socket("))
	if sock < 0 {
		return 0, nil, false
	}
	if !hasAnyMarker(src, ".connect(") {
		return 0, nil, false
	}
	if !hasAnyMarker(src, "subprocess.", "os.system(", "os.popen(") {
		return 0, nil, false
	}
	if !hasAnyMarker(src, ".recv(", ".recvfrom(") {
		return 0, nil, false
	}
	markers := []string{"socket.socket("}
	for _, m := range []string{
		".connect(", ".recv(", ".recvfrom(", "subprocess.getoutput", "subprocess.Popen",
		"subprocess.run", "os.system(", "os.popen(", "threading.Thread(",
	} {
		if bytes.Contains(src, []byte(m)) {
			markers = append(markers, m)
		}
	}
	return int32(sock), markers, true
}

// hasAnyMarker reports whether src contains any of the markers.
func hasAnyMarker(src []byte, markers ...string) bool {
	for _, m := range markers {
		if bytes.Contains(src, []byte(m)) {
			return true
		}
	}
	return false
}

// finish emits the artifact-level rule that pairs a reducing class with a
// serialiser dump. One finding per artifact: the first hit names the class.
func (a *analyzer) finish() {
	// Taint sites first: they are the broadest family, and the reduce-builder
	// finding below is emitted at the end so it can see the whole body.
	keys := make([]string, 0, len(a.taintSites))
	for k := range a.taintSites {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		site := a.taintSites[k]
		extra := site.extra
		ev := site.ev
		if site.count > 1 {
			extra["sites"] = strconv.Itoa(site.count)
			ev += " (+" + strconv.Itoa(site.count-1) + " more call sites)"
		}
		line, col := a.at(site.off)
		a.ctx.Sink.EmitAtExtra(site.rule, line, col, ev, extra)
	}
	if !a.dumped || len(a.reduceHits) == 0 {
		return
	}
	h := a.reduceHits[0]
	line, col := a.at(h.off)
	a.ctx.Sink.EmitAtExtra(ruleCodeReduceBuilder, line, col,
		"class defines __reduce__ returning "+h.callable+"; the file serialises it with a pickle dump",
		map[string]string{"callable": h.callable})
}

// capSource enforces MaxStringBlob on a source buffer. A truncated buffer is
// reported (never silently dropped) so a finding positioned past the cap cannot be
// mistaken for a clean file.
func capSource(ctx *artifact.Ctx, src []byte) []byte {
	cap := ctx.Limits.MaxStringBlob
	if cap <= 0 || int64(len(src)) <= cap {
		return src
	}
	limits.Emit(ctx.Sink, limits.RuleString, "MaxStringBlob", int64(len(src)), cap, "python source truncated")
	return src[:cap]
}

type lineIndex struct{ starts []int32 }

func newLineIndex(src []byte) lineIndex {
	st := make([]int32, 1, len(src)/32+1)
	st[0] = 0
	for i := range src {
		if src[i] == '\n' {
			st = append(st, int32(i+1))
		}
	}
	return lineIndex{st}
}

// at returns the 1-based line and column of off.
func (li lineIndex) at(off int32) (int, int) {
	lo, hi := 0, len(li.starts)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if li.starts[mid] <= off {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	line := lo
	col := int(off-li.starts[lo-1]) + 1
	return line, col
}

type analyzer struct {
	ctx  *artifact.Ctx
	src  []byte
	li   lineIndex
	cell []int
	// tainted holds the names assigned from a source since the last function
	// boundary. It is deliberately coarse: no containers, no attribute paths.
	tainted    map[string]bool
	taintSites map[string]*taintSite
	// netTainted is the subset of tainted assigned from a network/download source,
	// used by the pickle-load-of-remote-data rule.
	netTainted map[string]bool
	// callBudget is the statement tokens the call analysis may still scan; see
	// maxCallTokens. callRead and callReported exist so the truncation is reported
	// once, with the amount actually read.
	callBudget   int64
	callRead     int64
	callReported bool
	// reducing is set while the current function is a __reduce__ or __reduce_ex__
	// definition, so a return inside it can be read as the payload the class will
	// hand the unpickler.
	reducing bool
	// reduceHits are the dangerous callables those methods return.
	reduceHits []reduceHit
	// dumped records that the file serialises an object with a pickle-family dump,
	// which is what turns a reducing class into an on-disk payload.
	dumped bool
}

// reduceHit is one __reduce__ return that names a code-executing callable.
type reduceHit struct {
	off      int32
	callable string
}

// maxCallTokens bounds the total statement tokens one artifact's call analysis
// may scan. Calls is O(statement length) per call, because parseArgs scans from a
// call's `(` to the end of the statement, so a statement of n nested calls is
// O(n^2): 60 000 nested `exec(` in one statement (480 KB) measured over 60 s.
// There is no deadline check inside a parser — the scan deadline is observed
// between artifacts, by design — so a cap is what bounds the cost, not -timeout.
//
// The budget is about 40 ms of scanning and far above what a real module needs;
// a file that exhausts it is reported (SC4N-LIMIT-ENTRIES) rather than analysed
// at quadratic cost.
const maxCallTokens = 1 << 24

// callsFor indexes the statement's calls within the artifact's call-analysis
// budget. Once the budget is exhausted the rest of the file gets no call
// analysis, which is reported once so a truncated file is not read as clean.
func (a *analyzer) callsFor(st []Token) []Call {
	if a.callBudget <= 0 {
		return nil
	}
	calls, read, exhausted := Calls(a.src, st, a.callBudget)
	a.callBudget -= read
	a.callRead += read
	if !exhausted {
		return calls
	}
	a.callBudget = 0
	if !a.callReported {
		a.callReported = true
		limits.Emit(a.ctx.Sink, limits.RuleEntries, "MaxCallTokens", a.callRead, maxCallTokens,
			"python call analysis stopped; later statements' calls were not indexed")
	}
	return calls
}

func (a *analyzer) at(off int32) (int, int) {
	line, col := a.li.at(off)
	if a.cell != nil {
		if line-1 >= 0 && line-1 < len(a.cell) && a.cell[line-1] > 0 {
			line = a.cell[line-1]
		}
	}
	return line, col
}

// reducedCallable reads the first expression of a return statement, skipping an
// opening parenthesis, and returns its text and offset. Both published generator
// shapes are covered: a bare `return eval, (payload,), None, None, None` and a
// parenthesised `return (exec, (cmd,))`.
func reducedCallable(src []byte, st []Token) (string, int32, bool) {
	start := -1
	for i := 1; i < len(st); i++ {
		if i == 1 && st[i].Text(src) == "(" {
			continue
		}
		start = int(st[i].Off)
		break
	}
	if start < 0 || start >= len(src) {
		return "", 0, false
	}
	limit := len(src)
	if n := len(st); n > 0 {
		limit = int(st[n-1].End)
	}
	depth := 0
	end := start
scan:
	for ; end < limit; end++ {
		switch src[end] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				break scan
			}
			depth--
		case ',':
			if depth == 0 {
				break scan
			}
		}
	}
	name := strings.TrimSpace(string(src[start:end]))
	return name, int32(start), name != ""
}

// isReduceSink reports whether the callable a __reduce__ returns executes code or
// imports a module. A prefix entry matches the callable itself and every member of
// its family (os.execv, subprocess.Popen, ctypes.CDLL).
func isReduceSink(name string) bool {
	switch name {
	case "eval", "exec", "compile", "__import__", "importlib.import_module",
		"os.system", "os.popen", "marshal.loads", "pickle.loads", "dill.loads",
		"builtins.eval", "builtins.exec":
		return true
	}
	for _, p := range []string{"os.exec", "os.spawn", "subprocess.", "ctypes."} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// isSerializerDump reports whether one of the statement's calls writes an object
// with a pickle-family serialiser.
func isSerializerDump(calls []Call) bool {
	for _, c := range calls {
		d := c.Dotted
		if d == "torch.save" {
			return true
		}
		last := dottedLast(d)
		if last != "dump" && last != "dumps" {
			continue
		}
		for _, pkg := range []string{"pickle.", "dill.", "cloudpickle.", "joblib."} {
			if strings.HasPrefix(d, pkg) {
				return true
			}
		}
	}
	return false
}

// emitAtExtra is emitAt with an extras map.
func (a *analyzer) emitAtExtra(r *report.Rule, off int32, ev string, extra map[string]string) {
	line, col := a.at(off)
	a.ctx.Sink.EmitAtExtra(r, line, col, report.TruncateEvidence(ev, 160), extra)
}

func (a *analyzer) emitAt(r *report.Rule, off int32, ev string) {
	line, col := a.at(off)
	a.ctx.Sink.EmitAt(r, line, col, report.TruncateEvidence(ev, 160))
}

func (a *analyzer) stmt(st []Token) {
	if len(st) == 0 {
		return
	}
	if st[0].Kind == TokKeyword {
		switch kw := st[0].Text(a.src); kw {
		case "def", "class":
			// A new function body starts with a clean taint set: sc4n does not model
			// closure capture across a def boundary.
			a.tainted = map[string]bool{}
			a.netTainted = map[string]bool{}
			// A reducing method is reducing only inside its own body: a nested def
			// ends the state, as does any other def or class.
			a.reducing = kw == "def" && len(st) > 1 &&
				(st[1].Text(a.src) == "__reduce__" || st[1].Text(a.src) == "__reduce_ex__")
		case "return":
			if a.reducing {
				if name, off, ok := reducedCallable(a.src, st); ok && isReduceSink(name) {
					a.reduceHits = append(a.reduceHits, reduceHit{off: off, callable: name})
				}
			}
		}
	}
	calls := a.callsFor(st)
	if !a.dumped && isSerializerDump(calls) {
		a.dumped = true
	}
	text := spanText(a.src, Span{st[0].Off, st[len(st)-1].End})

	// Loader lint and standalone obfuscation detectors run on every statement.
	a.loaderRules(st, calls, text)
	a.obfuscationRules(st, calls)
	a.encodedPayloadRules(st, text)
	a.compileExecRules(st, calls)

	// Taint rules: a sink is reported when one of its arguments expresses a
	// source or a variable assigned from one.
	a.taintRules(st, calls, text)

	// Propagate: a statement that contains a source marks the names it assigns.
	if a.rangeTainted(st, 0, len(st)-1) {
		a.markAssigned(st, a.rangeNetworkTainted(st, 0, len(st)-1))
	}
}

// ---- source / taint detection -------------------------------------------------

// sourcePrefixes and networkSourcePrefixes are the package roots whose every
// attribute access is a source. They are shared by the predicates below and by
// rangeSource (which tests a chain's non-final elements against them), so a
// chain scan and the predicates agree on what a prefix match is.
var (
	sourcePrefixes        = []string{"requests."}
	networkSourcePrefixes = []string{"requests.", "socket.", "urllib.", "httpx.", "aiohttp."}
)

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func isSourceDotted(d string) bool {
	if d == "" {
		return false
	}
	switch d {
	case "input", "sys.argv", "os.environ", "os.getenv", "os.environ.get",
		"base64.b64decode", "base64.decodebytes", "base64.b32decode", "base64.b85decode",
		"base64.b16decode", "codecs.decode", "marshal.loads", "zlib.decompress",
		"bytes.fromhex", "binascii.unhexlify", "binascii.a2b_base64",
		"pickle.load", "pickle.loads", "torch.load", "hf_hub_download",
		"numpy.frombuffer", "np.frombuffer", "urlopen", "urllib.request.urlopen",
		"socket.recv", "socket.recvfrom", "os.read", "sys.stdin.read":
		return true
	}
	switch dottedLast(d) {
	case "read", "readline", "readlines", "recv", "recvfrom", "getenv", "b64decode", "fromhex", "decode":
		return true
	}
	if hasAnyPrefix(d, sourcePrefixes) {
		return true
	}
	return false
}

func isNetworkSourceDotted(d string) bool {
	switch d {
	case "urlopen", "urllib.request.urlopen", "hf_hub_download",
		"socket.recv", "socket.recvfrom":
		return true
	}
	if hasAnyPrefix(d, networkSourcePrefixes) {
		return true
	}
	return dottedLast(d) == "from_pretrained"
}

// rangeTainted reports whether tokens [s,e] contain a source expression or a name
// previously marked tainted.
func (a *analyzer) rangeTainted(st []Token, s, e int) bool {
	return a.rangeSource(st, s, e, a.tainted, isSourceDotted, sourcePrefixes)
}

// rangeNetworkTainted reports whether tokens [s,e] contain a network or download
// source, used by the pickle-load-of-remote-data rule.
func (a *analyzer) rangeNetworkTainted(st []Token, s, e int) bool {
	return a.rangeSource(st, s, e, a.netTainted, isNetworkSourceDotted, networkSourcePrefixes)
}

// rangeSource reports whether tokens [s,e] contain a name in tainted or a dotted
// name that isSource accepts. Each dotted chain is walked once and the scan
// resumes after it, so the pass is linear in the token count; the previous shape
// called chainAt (and strings.Join) for every element of every chain, which was
// quadratic on a long dotted chain (`a.` x 200000 measured > 120 s).
//
// Every element-aligned suffix of a chain is still tested, which is what the
// previous per-element chainAt did. isSource matches a suffix in exactly three
// ways: an exact name of at most three elements, a final element from its
// dottedLast set, or a leading package prefix (prefixes). So the last three
// suffixes are built and checked -- the single-element one covers the dottedLast
// rule for every suffix, since the last element is the same for all of them --
// and each non-final element is tested against the package prefixes. isSource is
// never called with a suffix longer than it can match.
//
// tainted holds simple names only (markAssigned skips attribute targets), so the
// per-element taint test is the only taint test a suffix needs; the old
// `a.tainted[d]` term for a dotted d was always false.
//
// e is always the last token of a statement or of an argument, never a token
// inside a dotted chain, so the chain that starts at or before e also ends at or
// before e and every element is inside the scanned range (the old scan iterated
// k in [s,e] and chainAt ran to the chain's end either way).
func (a *analyzer) rangeSource(st []Token, s, e int, tainted map[string]bool, isSource func(string) bool, prefixes []string) bool {
	if s < 0 {
		s = 0
	}
	if e >= len(st) {
		e = len(st) - 1
	}
	for k := s; k <= e; k++ {
		t := st[k]
		if t.Kind != TokName && t.Kind != TokKeyword {
			continue
		}
		if tainted[t.Text(a.src)] {
			return true
		}
		last := chainEnd(a.src, st, k)
		elems := make([]string, 0, (last-k)/2+1)
		for j := k; j <= last; j += 2 {
			elems = append(elems, st[j].Text(a.src))
		}
		for i := 1; i < len(elems); i++ {
			if tainted[elems[i]] {
				return true
			}
		}
		// An exact name has at most three elements, so only the chain itself and
		// its last two element-aligned suffixes can match one.
		for i := len(elems) - 1; i >= 0 && i >= len(elems)-3; i-- {
			if isSource(strings.Join(elems[i:], ".")) {
				return true
			}
		}
		// A non-final package element makes every suffix from it a prefix match.
		for i := range len(elems) - 1 {
			if hasAnyPrefix(elems[i]+".", prefixes) {
				return true
			}
		}
		k = last
	}
	return false
}

func (a *analyzer) callArgTainted(st []Token, c Call) bool {
	for _, rg := range c.argToks {
		if a.rangeTainted(st, int(rg[0]), int(rg[1])) {
			return true
		}
	}
	for _, rg := range c.kwToks {
		if a.rangeTainted(st, int(rg[0]), int(rg[1])) {
			return true
		}
	}
	return false
}

func (a *analyzer) callArgNetworkTainted(st []Token, c Call) bool {
	for _, rg := range c.argToks {
		if a.rangeNetworkTainted(st, int(rg[0]), int(rg[1])) {
			return true
		}
	}
	for _, rg := range c.kwToks {
		if a.rangeNetworkTainted(st, int(rg[0]), int(rg[1])) {
			return true
		}
	}
	return false
}

// markAssigned adds the simple names on the left of a top-level `=` to the taint
// set. It deliberately ignores attribute targets (`self.x =`), because resolving
// attribute taint needs type information.
func (a *analyzer) markAssigned(st []Token, network bool) {
	depth := 0
	eq := -1
	for i := range st {
		t := st[i]
		if t.Kind != TokOp {
			continue
		}
		b := t.Bytes(a.src)
		if len(b) == 0 {
			continue
		}
		switch b[0] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '=':
			if len(b) == 1 && depth == 0 {
				eq = i
			}
		}
		if eq >= 0 {
			break
		}
	}
	if eq <= 0 {
		return
	}
	for i := 0; i < eq; i++ {
		if st[i].Kind != TokName {
			continue
		}
		if i > 0 && isDot(a.src, st[i-1]) {
			continue
		}
		a.tainted[st[i].Text(a.src)] = true
		if network {
			a.netTainted[st[i].Text(a.src)] = true
		}
	}
}

// ---- taint rules --------------------------------------------------------------

// taintSite is one sink reached by tainted data. The finding is emitted once per
// (rule, callee) at the end rather than once per call site: a test client that
// posts seven times through requests.post is one decision to send data over the
// network, and sglang's streaming kit produced seven identical
// SC4N-CODE-TAINT-NETWORK findings for exactly that.
type taintSite struct {
	rule  *report.Rule
	calle string
	off   int32
	ev    string
	extra map[string]string
	count int
}

func (a *analyzer) taintRules(st []Token, calls []Call, stmtText string) {
	for _, c := range calls {
		r := a.sinkFor(c, stmtText)
		if r == nil {
			continue
		}
		// getattr/setattr/delattr resolve an attribute *name*: only a tainted name
		// argument is the hazard the rule describes. Checking every argument
		// reported getattr(args, "profile_prefill_url", None) — a literal name on
		// an argparse namespace — thirteen times on the benign corpus.
		if r == ruleTaintDynamic && !a.nameArgTainted(st, c) {
			continue
		}
		if !a.callArgTainted(st, c) {
			continue
		}
		extra := map[string]string{"call": c.Dotted}
		if strings.Contains(stmtText, "shell=True") {
			extra["shell"] = "True"
		}
		key := r.ID + "|" + c.Dotted
		if a.taintSites == nil {
			a.taintSites = map[string]*taintSite{}
		}
		if site, ok := a.taintSites[key]; ok {
			site.count++
			continue
		}
		a.taintSites[key] = &taintSite{
			rule:  r,
			calle: c.Dotted,
			off:   c.Off,
			ev:    report.TruncateEvidence(callEvidence(a.src, c), 160),
			extra: extra,
			count: 1,
		}
	}
}

// nameArgTainted reports whether the attribute-name argument of getattr/setattr/
// delattr is tainted. It is the second positional argument, or the `name=` keyword.
func (a *analyzer) nameArgTainted(st []Token, c Call) bool {
	if len(c.Args) > 1 {
		rg := c.argToks[1]
		return a.rangeTainted(st, int(rg[0]), int(rg[1]))
	}
	if rg, ok := c.kwToks["name"]; ok {
		return a.rangeTainted(st, int(rg[0]), int(rg[1]))
	}
	return false
}

func (a *analyzer) sinkFor(c Call, stmtText string) *report.Rule {
	d := c.Dotted
	last := dottedLast(d)
	switch {
	case last == "from_string" || last == "from_file":
		return ruleTaintTemplate
	case d == "exec" || d == "eval" || d == "compile" || d == "__import__" ||
		d == "importlib.import_module" || d == "importlib.__import__" ||
		d == "runpy.run_path" || d == "runpy.run_module" ||
		last == "InteractiveInterpreter" || strings.HasSuffix(last, "runcode") ||
		strings.HasPrefix(d, "ctypes.") || d == "cdll.LoadLibrary":
		return ruleTaintExec
	case isShellSink(d, last):
		return ruleTaintShell
	case isDeserializeSink(d, last):
		return ruleTaintDeserialize
	case d == "getattr" || d == "setattr" || d == "delattr":
		return ruleTaintDynamic
	case d == "shutil.rmtree" || d == "shutil.move" || d == "os.remove" || d == "os.unlink" ||
		d == "os.rmdir" || d == "os.removedirs" || d == "os.rename":
		return ruleTaintDelete
	case d == "webbrowser.open" || isNetworkSink(d, last, stmtText):
		return ruleTaintNetwork
	case d == "open" && a.openIsWrite(c):
		return ruleTaintFile
	}
	return nil
}

func isShellSink(d, last string) bool {
	if (dottedHasPackage(d, "os") || dottedHasPackage(d, "posix") || dottedHasPackage(d, "nt")) &&
		(last == "system" || last == "popen" || last == "posix_spawn" ||
			strings.HasPrefix(last, "exec") || strings.HasPrefix(last, "spawn")) {
		return true
	}
	if strings.HasPrefix(d, "subprocess.") {
		// The execution functions only. `subprocess.CalledProcessError(...)` and
		// `subprocess.list2cmdline(...)` are an exception constructor and a quoting
		// helper: neither runs anything, and both were reported as critical
		// SC4N-CODE-TAINT-SHELL findings on sglang's wheel.
		switch last {
		case "run", "call", "check_call", "check_output", "Popen",
			"getoutput", "getstatusoutput", "getstatus_output":
			return true
		}
		return false
	}
	switch d {
	case "pty.spawn", "pty.openpty", "commands.getoutput", "commands.getstatusoutput", "os.fork":
		return true
	}
	return false
}

func isDeserializeSink(d, last string) bool {
	switch d {
	case "pickle.load", "pickle.loads", "torch.load", "torch.jit.load", "torch.serialization.load",
		"dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads",
		"marshal.loads", "yaml.unsafe_load", "yaml.load", "yaml.full_load":
		return true
	}
	if (dottedHasPackage(d, "pickle") || dottedHasPackage(d, "dill") || dottedHasPackage(d, "cloudpickle")) &&
		(last == "load" || last == "loads") {
		return true
	}
	return false
}

func isNetworkSink(d, last, stmtText string) bool {
	if strings.HasPrefix(d, "requests.") || strings.HasPrefix(d, "httpx.") ||
		strings.HasPrefix(d, "aiohttp.") || strings.HasPrefix(d, "urllib.") {
		return true
	}
	if d == "urlopen" {
		return true
	}
	if last == "connect" && strings.Contains(stmtText, "socket") {
		return true
	}
	return false
}

func (a *analyzer) openIsWrite(c Call) bool {
	var modes []Span
	if sp, ok := c.Kwargs["mode"]; ok {
		modes = append(modes, sp)
	} else if len(c.Args) >= 2 {
		modes = append(modes, c.Args[1])
	}
	for _, sp := range modes {
		t := sp.Text(a.src)
		if strings.ContainsAny(t, "wax") {
			return true
		}
	}
	return false
}

// ---- loader lint --------------------------------------------------------------

func (a *analyzer) loaderRules(st []Token, calls []Call, stmtText string) {
	for _, c := range calls {
		switch {
		case c.Dotted == "torch.load":
			v, ok := c.Kwargs["weights_only"]
			if !ok || !spanIsTrue(a.src, v) {
				a.emitAt(ruleLoaderTorchUnsafe, c.Off, "torch.load without weights_only=True: "+callEvidence(a.src, c))
			}
		case c.Dotted == "pickle.load" || c.Dotted == "pickle.loads":
			if a.callArgNetworkTainted(st, c) {
				a.emitAt(ruleLoaderPickleRemote, c.Off, "pickle load of a network-fetched value: "+callEvidence(a.src, c))
			}
		case dottedLast(c.Dotted) == "from_pretrained" || c.Dotted == "hf_hub_download":
			// Only a literal model argument names a download. A bare variable —
			// `AutoModel.from_pretrained(model_name)` in a training script — is
			// loader code, not a claim about where this repository's weights come
			// from; four sentence-transformers training scripts were reported for it
			// on the benign corpus.
			if a.modelArgIsLiteral(c) && !a.hasRevision(c) {
				a.emitAt(ruleLoaderNoRevision, c.Off, "no pinned revision: "+callEvidence(a.src, c))
			}
			if a.isAutoFromPretrained(c) && a.localPathArg(c) {
				if _, ok := c.Kwargs["local_files_only"]; !ok {
					a.emitAt(ruleLoaderNoLocalOnly, c.Off, "local path with no local_files_only: "+callEvidence(a.src, c))
				}
			}
		case c.Dotted == "yaml.load":
			if !a.hasSafeLoader(st, c) {
				a.emitAt(ruleLoaderYAMLUnsafe, c.Off, "yaml.load without SafeLoader: "+callEvidence(a.src, c))
			}
		case c.Dotted == "yaml.unsafe_load":
			a.emitAt(ruleLoaderYAMLUnsafe, c.Off, "yaml.unsafe_load: "+callEvidence(a.src, c))
		case dottedLast(c.Dotted) == "load_model" && strings.Contains(stmtText, "safe_mode") && strings.Contains(stmtText, "False"):
			a.emitAt(ruleLoaderKerasSafeMode, c.Off, "load_model with safe_mode=False: "+callEvidence(a.src, c))
		case dottedLast(c.Dotted) == "Lambda" || strings.HasSuffix(c.Dotted, "layers.Lambda"):
			a.emitAt(ruleLoaderKerasLambda, c.Off, "keras Lambda layer: "+callEvidence(a.src, c))
		case dottedLast(c.Dotted) == "load_tool":
			if repo, ok := a.stringArg(c, 0); ok && looksLikeRepoID(repo) {
				a.emitAtExtra(ruleCodeRemoteToolLoader, c.Off,
					"load_tool('"+repo+"') imports and runs code from a Hub repository",
					map[string]string{"repo": repo})
			}
		case (dottedLast(c.Dotted) == "from_string" || dottedLast(c.Dotted) == "from_file") && strings.Contains(stmtText, "Environment"):
			a.emitAt(ruleLoaderJinjaFromString, c.Off, "jinja2 Environment rendering an untrusted template: "+callEvidence(a.src, c))
		}
	}
	if off, ok := a.keywordTrue(st, "trust_remote_code"); ok {
		a.emitAt(ruleLoaderTrustRemoteCode, off, "trust_remote_code=True")
	}
	if off, ok := a.keywordTrue(st, "allow_pickle"); ok {
		a.emitAt(ruleLoaderAllowPickle, off, "allow_pickle=True")
	}
}

func (a *analyzer) hasRevision(c Call) bool {
	sp, ok := c.Kwargs["revision"]
	if !ok {
		return false
	}
	t := strings.TrimSpace(sp.Text(a.src))
	if len(t) > 0 && (t[0] == '\'' || t[0] == '"') {
		// A literal revision must be a 40-hex commit id to count as a pin.
		v := strings.Trim(t, "'\"")
		return isHex40(v)
	}
	// A variable revision cannot be resolved statically; assume the author pinned
	// it rather than reporting a false positive.
	return true
}

// modelArgIsLiteral reports whether the call names its model with a string
// literal, positionally or by keyword. Without one the call sites a loader
// generically and no revision can be resolved from the text.
func (a *analyzer) modelArgIsLiteral(c Call) bool {
	if _, ok := a.stringArg(c, 0); ok {
		return true
	}
	for _, k := range []string{"pretrained_model_name_or_path", "repo_id", "model_id", "model"} {
		sp, ok := c.Kwargs[k]
		if !ok {
			continue
		}
		t := strings.TrimSpace(sp.Text(a.src))
		if len(t) >= 2 && (t[0] == '\'' || t[0] == '"') && t[len(t)-1] == t[0] {
			return true
		}
	}
	return false
}

func (a *analyzer) isAutoFromPretrained(c Call) bool {
	if dottedLast(c.Dotted) != "from_pretrained" {
		return false
	}
	recv := strings.TrimSuffix(c.Dotted, ".from_pretrained")
	for _, p := range []string{"AutoModel", "AutoTokenizer", "AutoConfig", "AutoProcessor",
		"AutoImageProcessor", "AutoModelForCausalLM", "AutoModelForSequenceClassification",
		"AutoModelForTokenClassification", "AutoModelForQuestionAnswering"} {
		if recv == p || strings.HasPrefix(recv, p+"For") || strings.HasPrefix(recv, p+"With") {
			return true
		}
	}
	return false
}

// looksLikeRepoID reports whether s names a Hub repository: exactly two
// non-empty components and no filesystem prefix. A local directory
// ("./tools/x", "../x/y", "/opt/tool") loads local code and is not this rule.
func looksLikeRepoID(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	return parts[0] != "" && parts[1] != ""
}

// stringArg returns the unquoted value of the call's i-th positional argument when
// it is a plain string literal. A prefix that builds the name at run time (f-string,
// concatenation) is not a literal and is not reported by the literal rules.
func (a *analyzer) stringArg(c Call, i int) (string, bool) {
	if i < 0 || i >= len(c.Args) {
		return "", false
	}
	t := strings.TrimSpace(c.Args[i].Text(a.src))
	if len(t) < 2 || (t[0] != '\'' && t[0] != '"') || t[len(t)-1] != t[0] {
		return "", false
	}
	return t[1 : len(t)-1], true
}

func (a *analyzer) localPathArg(c Call) bool {
	if len(c.Args) == 0 {
		return false
	}
	t := strings.TrimSpace(c.Args[0].Text(a.src))
	if len(t) < 3 || (t[0] != '\'' && t[0] != '"') {
		return false
	}
	inner := strings.Trim(t, "'\"")
	return strings.HasPrefix(inner, "./") || strings.HasPrefix(inner, "../") ||
		strings.HasPrefix(inner, "/") || strings.HasPrefix(inner, "~")
}

func (a *analyzer) hasSafeLoader(st []Token, c Call) bool {
	for _, rg := range c.argToks {
		if a.rangeMentions(st, int(rg[0]), int(rg[1]), "SafeLoader") || a.rangeMentions(st, int(rg[0]), int(rg[1]), "CSafeLoader") {
			return true
		}
	}
	for _, rg := range c.kwToks {
		if a.rangeMentions(st, int(rg[0]), int(rg[1]), "SafeLoader") || a.rangeMentions(st, int(rg[0]), int(rg[1]), "CSafeLoader") {
			return true
		}
	}
	return false
}

func (a *analyzer) rangeMentions(st []Token, s, e int, sub string) bool {
	if e >= len(st) {
		e = len(st) - 1
	}
	for k := s; k <= e; k++ {
		if strings.Contains(st[k].Text(a.src), sub) {
			return true
		}
	}
	return false
}

// keywordTrue finds an assignment of the literal True (or 1) to name in the
// statement and returns the offset of the name token.
func (a *analyzer) keywordTrue(st []Token, name string) (int32, bool) {
	for i := 0; i+2 < len(st); i++ {
		if (st[i].Kind != TokName && st[i].Kind != TokKeyword) || st[i].Text(a.src) != name {
			continue
		}
		if !isAssignOp(a.src, st[i+1]) {
			continue
		}
		switch st[i+2].Text(a.src) {
		case "True", "1":
			return st[i].Off, true
		}
	}
	return 0, false
}

// ---- obfuscation --------------------------------------------------------------

func (a *analyzer) obfuscationRules(st []Token, calls []Call) {
	chrCount := 0
	var firstChr int32
	for _, c := range calls {
		if c.Dotted == "chr" {
			chrCount++
			if firstChr == 0 {
				firstChr = c.Off
			}
		}
		if c.Dotted == "bytes" && a.listOfNumbers(st, c) {
			a.emitAt(ruleObfuscation, c.Off, "bytes([...]) literal array")
		}
	}
	if chrCount >= 2 {
		a.emitAt(ruleObfuscation, firstChr, "chr() chain ("+strconv.Itoa(chrCount)+" calls)")
	}
	if strings.Contains(stmtTextOf(a.src, st), ".join(") && hasOpenBracket(a.src, st) && countKind(st, TokString) >= 3 {
		a.emitAt(ruleObfuscation, st[0].Off, "join of many string literals")
	}
	for i := range st {
		if st[i].Kind != TokString {
			continue
		}
		b := st[i].Bytes(a.src)
		if countByteSeq(b, '\\', 'x') >= 16 {
			a.emitAt(ruleObfuscation, st[i].Off, "long run of \\x escapes")
		}
		if IsStringToken(st[i], a.src, 'f') && maxBraceDepth(StringValue(st[i], a.src, 4096)) >= 2 {
			a.emitAt(ruleObfuscation, st[i].Off, "nested f-string replacement fields")
		}
	}
}

func (a *analyzer) listOfNumbers(st []Token, c Call) bool {
	if len(c.argToks) == 0 {
		return false
	}
	rg := c.argToks[0]
	if int(rg[0]) >= len(st) {
		return false
	}
	if !(st[rg[0]].Kind == TokOp && st[rg[0]].Bytes(a.src)[0] == '[') {
		return false
	}
	return countKindRange(st, TokNumber, int(rg[0]), int(rg[1])) >= 16
}

func (a *analyzer) encodedPayloadRules(st []Token, stmtText string) {
	if !statementHasDecoder(stmtText) {
		return
	}
	for i := range st {
		if st[i].Kind != TokString {
			continue
		}
		v := StringValue(st[i], a.src, 8192)
		if len(v) >= 32 && looksEncoded(v) {
			a.emitAt(ruleEncodedPayload, st[i].Off, "encoded literal of "+strconv.Itoa(len(v))+" characters decoded in the same statement")
		}
	}
}

func (a *analyzer) compileExecRules(st []Token, calls []Call) {
	for _, c := range calls {
		if c.Dotted != "compile" || len(c.argToks) < 3 {
			continue
		}
		rg := c.argToks[2]
		if int(rg[0]) >= len(st) || st[rg[0]].Kind != TokString {
			continue
		}
		if strings.Contains(StringValue(st[rg[0]], a.src, 64), "exec") {
			a.emitAt(ruleCompileExec, c.Off, "compile() with exec mode")
		}
	}
}

func statementHasDecoder(s string) bool {
	for _, d := range []string{"b64decode", "decodebytes", "b32decode", "b16decode", "a2b_base64",
		"unhexlify", "fromhex", "codecs.decode", "zlib.decompress", "marshal.loads"} {
		if strings.Contains(s, d) {
			return true
		}
	}
	return false
}

// looksEncoded is a shape test for a base64 or hex literal. It is deliberately
// conservative: a plain word of the same length is not reported, and neither is a
// decimal number.
func looksEncoded(v string) bool {
	if !isASCII(v) {
		return false
	}
	hexish := true
	for i := range len(v) {
		if !isHexByte(v[i]) {
			hexish = false
			break
		}
	}
	if hexish && len(v)%2 == 0 {
		return true
	}
	b64ish := true
	var upper, lower, digit, special bool
	for i := range len(v) {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		case c == '+' || c == '/' || c == '=':
			special = true
		default:
			b64ish = false
		}
		if !b64ish {
			break
		}
	}
	return b64ish && (special || (upper && lower && digit))
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := range len(s) {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func maxBraceDepth(s string) int {
	depth, max := 0, 0
	for i := range len(s) {
		switch s[i] {
		case '{':
			depth++
			if depth > max {
				max = depth
			}
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return max
}

func countByteSeq(b []byte, a, c byte) int {
	n := 0
	for i := 0; i+1 < len(b); i++ {
		if b[i] == a && b[i+1] == c {
			n++
		}
	}
	return n
}

// ---- small helpers ------------------------------------------------------------

func spanText(src []byte, sp Span) string { return sp.Text(src) }

func callEvidence(src []byte, c Call) string {
	s := c.Dotted + "("
	for i, a := range c.Args {
		if i > 0 {
			s += ", "
		}
		s += report.TruncateEvidence(a.Text(src), 160)
	}
	s += ")"
	return s
}

func spanIsTrue(src []byte, sp Span) bool {
	return strings.TrimSpace(sp.Text(src)) == "True"
}

func stmtTextOf(src []byte, st []Token) string {
	if len(st) == 0 {
		return ""
	}
	return spanText(src, Span{st[0].Off, st[len(st)-1].End})
}

func hasOpenBracket(src []byte, st []Token) bool {
	for i := range st {
		if st[i].Kind == TokOp && st[i].Len() == 1 && st[i].Bytes(src)[0] == '[' {
			return true
		}
	}
	return false
}

func countKind(st []Token, k Kind) int {
	n := 0
	for i := range st {
		if st[i].Kind == k {
			n++
		}
	}
	return n
}

func countKindRange(st []Token, k Kind, s, e int) int {
	if e >= len(st) {
		e = len(st) - 1
	}
	n := 0
	for i := s; i <= e; i++ {
		if st[i].Kind == k {
			n++
		}
	}
	return n
}
