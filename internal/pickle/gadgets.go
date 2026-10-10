package pickle

import (
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// Gadget classification.
//
// This is where sc4n differs from picklescan and modelscan, which both carry a
// denylist of names and stop there. A denylist answers "is this name in my list";
// the question that matters is "if the loader calls this name, what can the caller
// make it do". A three-tier table answers that:
//
//   - direct primitives (critical): the name *is* a sink. `os.system`,
//     `builtins.exec`, `subprocess.*`, `ctypes.*`. Reaching one from a pickle is
//     code execution with no further steps.
//   - library gadgets (high): standard-library helpers that are not sinks
//     themselves but reach one when called with the right arguments. Seeded from
//     PickleCloak's published gadget set (arXiv 2508.19774, Table VI), which is
//     the current state of the art in "what is actually reachable": entries like
//     `numpy.f2py.crackfortran.myeval` (an eval by another name),
//     `pydoc.pipepager` (runs a shell pipeline) and
//     `logging.config._install_handlers` (instantiates an arbitrary class). Most
//     of them are missed by name-denylist scanners.
//   - everything else callable (medium): unknown to the table. Reported because
//     the allowlist-by-default loader rejects it anyway, and because "a name I do
//     not recognise" is precisely what an evasive payload looks like.
//
// Matching is module-subtree aware everywhere. An exact-name check is how
// picklescan's denylist was bypassed through asyncio.subprocess in CVE-2025-10157
// (CVSS 8.3), and the same mistake would let `numpy.f2py.crackfortran.myeval_`
// slip past a `...crackfortran.myeval` entry.

// GadgetClass is the tier a name falls in.
type GadgetClass uint8

const (
	GadgetUnknown GadgetClass = iota
	GadgetAllowlisted
	GadgetUnknownCallable
	GadgetLibrary
	GadgetDirect
)

func (g GadgetClass) String() string {
	switch g {
	case GadgetAllowlisted:
		return "allowlisted"
	case GadgetUnknownCallable:
		return "unknown-callable"
	case GadgetLibrary:
		return "library-gadget"
	case GadgetDirect:
		return "direct-primitive"
	default:
		return "none"
	}
}

// Gadget is the classification of one qualified name.
type Gadget struct {
	Class GadgetClass
	// Sink names what the callable reaches when called. It is the evidence text a
	// reviewer needs to decide without going to the source.
	Sink string
	// Entry is the table entry that matched, so the evidence names the exact
	// package or function the finding came from.
	Entry string
}

// Severity maps a tier onto the report's severity.
func (g Gadget) Severity() report.Severity {
	switch g.Class {
	case GadgetDirect:
		return report.SeverityCritical
	case GadgetLibrary:
		return report.SeverityHigh
	case GadgetAllowlisted:
		return report.SeverityInfo
	default:
		return report.SeverityMedium
	}
}

// directModules maps a module to the sink its whole subtree reaches. Every name
// in these modules (and their submodules) is a direct primitive, which is the
// only formulation that survives `asyncio.subprocess`-style bypasses.
var directModules = map[string]string{
	// Process and filesystem.
	"os":               "process and filesystem primitives (os.system, os.popen, os.exec*, os.spawn*, os.remove, os.chmod, os.putenv)",
	"posix":            "the low-level process and filesystem syscall surface, including posix.system",
	"nt":               "the Windows low-level process and filesystem syscall surface",
	"subprocess":       "process execution (Popen, run, call, check_output, and the submodules under it)",
	"pty":              "pty.spawn/openpty run a program on a pseudo-terminal",
	"_posixsubprocess": "the C-level fork/exec helper that subprocess itself calls",
	"multiprocessing":  "process creation with an arbitrary target callable",
	"shutil":           "filesystem mutation, including shutil.rmtree",
	"tempfile":         "creates files and directories at a predictable path",

	// Network.
	"socket":     "raw network I/O, including connect and send",
	"ssl":        "TLS context construction and unwrapping",
	"http":       "outbound HTTP client",
	"httplib":    "the Python 2 spelling of http.client",
	"urllib":     "outbound HTTP/FTP and file: URL reads",
	"urllib2":    "the Python 2 spelling of urllib",
	"ftplib":     "outbound FTP",
	"smtplib":    "outbound SMTP",
	"telnetlib":  "outbound telnet, historically the fastest interactive shell gadget",
	"requests":   "outbound HTTP with a convenient API",
	"aiohttp":    "outbound HTTP",
	"httpx":      "outbound HTTP",
	"webbrowser": "opens a URL in the user's browser, i.e. an OS-level hand-off",
	"asyncio":    "subprocess transports and event-loop primitives reach process execution",

	// Code loading and execution.
	"importlib":                 "dynamic import, including from a file path",
	"runpy":                     "executes a module or a file as __main__",
	"ctypes":                    "loads a shared library and calls into it: the shortest path from data to native code",
	"cffi":                      "loads a shared library and calls into it",
	"_ctypes":                   "the C-level ctypes backend",
	"builtins":                  "builtins.eval/exec/compile/__import__/open/getattr/apply/breakpoint",
	"__builtin__":               "the Python 2 spelling of builtins",
	"marshal":                   "loads a code object from bytes; marshal.loads plus types.FunctionType is a two-step exec",
	"types":                     "types.FunctionType turns a code object into a callable",
	"code":                      "code.InteractiveInterpreter.runcode executes a compiled object",
	"codeop":                    "compiles source into a code object",
	"site":                      "runs at interpreter start; site.main re-runs site processing",
	"atexit":                    "registers a callable to run at interpreter exit",
	"signal":                    "installs handlers and can deliver signals",
	"pickle":                    "load/loads are a second deserialisation step inside the first",
	"dill":                      "loads and executes pickles with its own, more permissive loader",
	"cloudpickle":               "loads and executes by-reference callables",
	"bdb":                       "the debugger base class can execute inside a trace function",
	"pdb":                       "the interactive debugger reads commands and executes them",
	"torch.serialization":       "torch.serialization.load is a second unpickle of attacker data",
	"torch.hub":                 "torch.hub.load downloads and executes a repository's code",
	"torch.jit":                 "torch.jit.load deserialises a TorchScript archive with its own loader",
	"torch.utils.cpp_extension": "compiles and loads a C++ extension",
	"torch._dynamo":             "codegen and graph-break paths compile and execute generated source",
}

// directNames are exact qualified names that are primitives even though their
// module is not. They are consulted before directModules so that the evidence can
// name the exact function.
//
// The tiering follows the calibrated rule in the design notes: a name belongs here
// when calling it *is* the attack, with no argument the scanner cannot prove. The
// standard-library helpers that need particular arguments to reach a sink are one
// tier down, in libraryGadgets, because calling them is not by itself proof.
var directNames = map[string]string{
	"functools.reduce":                       "applies an arbitrary callable to arbitrary arguments: the canonical bridge from a pickle to any gadget",
	"pickle.load":                            "deserialises a second stream",
	"pickle.loads":                           "deserialises a second stream",
	"pickle.Unpickler":                       "constructs a second unpickler",
	"_pickle.load":                           "the C-level loader",
	"_pickle.loads":                          "the C-level loader",
	"torch.load":                             "torch.load is a second unpickle of attacker data",
	"torch.serialization.load":               "a second unpickle of attacker data",
	"torch._inductor.codecache.compile_file": "compiles a source file and loads the resulting module",
	"copyreg._reconstructor":                 "reconstructs an arbitrary class with arbitrary state",
	"numpy.core.multiarray._reconstruct":     "reconstructs an ndarray, which with object dtype can hold arbitrary objects",
	"numpy.core.multiarray.scalar":           "wraps an arbitrary value in a numpy scalar",
	"yaml.unsafe_load":                       "always constructs arbitrary Python objects",
	"yaml.load":                              "constructs arbitrary Python objects with the default loader",
	"jsonpickle.decode":                      "decodes JSON into arbitrary objects",
	"shelve.open":                            "opens a database file and unpickles from it",
	"os.environ.setdefault":                  "mutates the process environment",
	"subprocess.Popen":                       "spawns a process",
	"pty.spawn":                              "runs a program on a pseudo-terminal",
	"builtins.eval":                          "evaluates a string as an expression",
	"builtins.exec":                          "executes a string as statements",
	"builtins.compile":                       "compiles source into a code object",
	"builtins.__import__":                    "imports a module by name",
	"builtins.open":                          "opens a file by name",
	"marshal.loads":                          "loads a code object from bytes",
	"types.FunctionType":                     "turns a code object into a callable",
}

// libraryGadgets are the standard-library helpers that reach a sink only when a
// caller supplies the right arguments. The list is seeded from PickleCloak's
// published gadget set (arXiv 2508.19774, Table VI) — which is the reason this
// table exists at all, since name-denylist scanners miss most of these entries —
// plus the helpers sc4n's own review found worth naming.
//
// The tier is "high" rather than "critical" because the finding says "this reaches
// a sink when called with the right arguments", not "calling this is the attack".
var libraryGadgets = map[string]string{
	// XML-RPC is the classic allowlisted-callable bridge: it resolves a dotted
	// name and hands back the attribute.
	"xmlrpc.server.resolve_dotted_attribute": "resolves a dotted name and returns the attribute",
	"xmlrpc.client.dumps":                    "builds an XML-RPC payload",
	"xmlrpc.client.loads":                    "decodes an XML-RPC payload",

	// f2py and numpy's own test and build helpers evaluate source strings.
	"numpy.f2py.capi_maps.getinit":               "runs f2py's init handling, which evaluates source",
	"numpy.f2py.crackfortran.myeval":             "an eval() by another name",
	"numpy.f2py.crackfortran.param_eval":         "evaluates parameter expressions",
	"numpy.f2py.crackfortran.analyzevars":        "evaluates variable expressions",
	"numpy.f2py.crackfortran._eval_scalar":       "evaluates a scalar expression",
	"numpy.testing._private.utils.runstring":     "compiles and executes a source string",
	"numpy.testing._private.utils.measure":       "executes a code string while measuring",
	"numpy.distutils.cpuinfo.getoutput":          "runs a command and returns its output",
	"numpy.distutils.cpuinfo.command_by_line":    "runs a command",
	"numpy.distutils.cpuinfo.command_info":       "runs a command",
	"numpy.distutils.exec_command._exec_command": "runs a command",
	"numpy.distutils.exec_command.exec_command":  "runs a command",

	// pydoc imports modules and pipes output through a shell.
	"pydoc.importfile":    "imports a file as a module, executing it",
	"pydoc.locate":        "imports and returns an arbitrary dotted name",
	"pydoc.safeimport":    "imports a module by name",
	"pydoc.pipepager":     "starts a shell pipeline to page output",
	"pydoc.tempfilepager": "writes a temporary file and runs a pager on it",

	// The profilers, tracers and interpreters execute a code string or a code
	// object supplied by the caller.
	"profile.run":                                      "executes a code string under the profiler",
	"profile.Profile.run":                              "executes a code string under the profiler",
	"profile.Profile.runctx":                           "executes a code string under the profiler",
	"cProfile.run":                                     "executes a code string under the profiler",
	"cProfile.Profile.run":                             "executes a code string under the profiler",
	"code.InteractiveInterpreter.runcode":              "executes a compiled code object",
	"code.InteractiveConsole.runcode":                  "executes a compiled code object",
	"idlelib.run.Executive.runcode":                    "executes a code object in an exec context",
	"idlelib.calltip.get_entity":                       "imports an arbitrary dotted name",
	"idlelib.autocomplete.AutoComplete.get_entity":     "imports an arbitrary dotted name",
	"trace.Trace.run":                                  "executes a code string",
	"trace.Trace.runctx":                               "executes a code string",
	"unittest.mock._importer":                          "imports an arbitrary module by name",
	"unittest.loader.TestLoader._get_module_from_name": "imports a test module by name",
	"lib2to3.pgen2.grammar.Grammar.loads":              "loads a grammar that the parser then applies to source",
	"compileall.compile_file":                          "compiles and writes bytecode",
	"py_compile.compile":                               "compiles and writes bytecode",

	// sympy parses and evaluates expressions, and can turn one into a callable.
	"sympy.sympify":                        "parses and evaluates an expression, with eval semantics for some inputs",
	"sympy.lambdify":                       "builds a function from an expression and can execute it",
	"sympy.lazy_function":                  "builds a callable from an expression",
	"sympy.parsing.sympy_parser.eval_expr": "evaluates a parsed expression with builtins available by default",
	"sympy.utilities.source.get_class":     "imports a class from a source file",

	// Generated-source helpers.
	"dataclasses._create_fn":             "builds a function by exec-ing generated source",
	"logging.config._resolve":            "imports and returns an arbitrary dotted callable",
	"logging.config._install_handlers":   "instantiates arbitrary handler classes from configuration",
	"logging.config.dictConfig":          "instantiates arbitrary handler classes from configuration",
	"logging.config.fileConfig":          "instantiates arbitrary handler classes from configuration",
	"logging.Formatter":                  "formats with %-style interpolation",
	"logging.config.ValidatingFormatter": "formats with style-specific interpolation",
	"logging._checkLevel":                "resolves a level name",

	// Shell-out helpers.
	"uuid._get_command_stdout":        "runs a command and reads its output",
	"distutils.spawn.spawn":           "runs a program",
	"distutils.spawn.find_executable": "resolves a program path",
	"_osx_support._read_output":       "runs a command and reads its output",

	// Filesystem and path helpers.
	"io.open":                        "opens a file by name",
	"io.FileIO":                      "opens a file by name",
	"linecache.updatecache":          "reads an arbitrary file into the line cache",
	"linecache.checkcache":           "reads files",
	"tokenize.open":                  "opens and reads a file with encoding detection",
	"fileinput.input":                "opens files, possibly from argv",
	"tarfile.open":                   "opens an archive",
	"zipfile.ZipFile":                "opens an archive",
	"gzip.open":                      "opens a file",
	"bz2.open":                       "opens a file",
	"lzma.open":                      "opens a file",
	"plistlib.load":                  "reads a plist file",
	"configparser.ConfigParser.read": "reads files",
	"json.load":                      "reads a file object",
	"csv.reader":                     "reads an iterable",
	"pathlib.Path":                   "path arithmetic; Path.open/read_text/write_bytes reach the filesystem",
	"pathlib.Path.read_text":         "reads a file",
	"pathlib.Path.read_bytes":        "reads a file",
	"pathlib.Path.write_text":        "writes a file",
	"pathlib.Path.write_bytes":       "writes a file",
	"pathlib.Path.open":              "opens a file",
	"pathlib.Path.resolve":           "resolves a path, including symlinks",
	"os.path.join":                   "path arithmetic used to build a traversal target",
	"os.path.expandvars":             "expands environment variables into a path",
	"os.path.expanduser":             "expands ~ into a home directory",
	"ntpath.join":                    "path arithmetic used to build a traversal target",
	"glob.glob":                      "lists paths by pattern",
	"glob.iglob":                     "lists paths by pattern",
	"fnmatch.filter":                 "matches names",
	"getpass.getuser":                "reads the current user name",

	// Decoding and buffer helpers used to assemble a payload.
	"base64.b64decode":   "decodes an obfuscated blob",
	"base64.b85decode":   "decodes an obfuscated blob",
	"codecs.decode":      "decodes an obfuscated blob",
	"binascii.unhexlify": "decodes an obfuscated blob",
	"zlib.decompress":    "decompresses an embedded blob",
	"gzip.decompress":    "decompresses an embedded blob",
	"bz2.decompress":     "decompresses an embedded blob",
	"lzma.decompress":    "decompresses an embedded blob",
	"struct.unpack":      "reinterprets bytes as values",
	"struct.unpack_from": "reinterprets bytes as values",
	"memoryview":         "views a buffer",
	"array.array":        "builds a typed array from a buffer",

	// Introspection and the XML parsers, which reach a file or a document.
	"inspect.getsource":                "reads a source file",
	"inspect.getfile":                  "resolves a module's file",
	"inspect.stack":                    "walks the call stack",
	"pickletools.genops":               "walks an embedded pickle: a step in nested payloads",
	"sys.modules":                      "reaches every already-imported module",
	"sys.path":                         "controls import resolution",
	"sys.executable":                   "names the interpreter: a step towards spawning it",
	"sys.stdin":                        "reads stdin",
	"sys.argv":                         "reads command-line arguments",
	"xml.etree.ElementTree.parse":      "parses a file path; the XML external-entity family lives behind it",
	"xml.etree.ElementTree.fromstring": "parses attacker XML",
	"xml.sax.parse":                    "parses attacker XML from a path",
	"xml.dom.minidom.parse":            "parses attacker XML from a path",

	// Networking helpers that are not a whole-module primitive.
	"poplib.POP3":           "opens a POP3 connection",
	"imaplib.IMAP4":         "opens an IMAP connection",
	"email.utils.parseaddr": "parses an address",

	// Text processing used to build a payload.
	"re.compile":                      "compiles a pattern",
	"string.Template.substitute":      "interpolates a template",
	"string.Template.safe_substitute": "interpolates a template",
	"ast.parse":                       "parses a source string",
	"ast.unparse":                     "renders a syntax tree back to source",
	"tokenize.generate_tokens":        "tokenises a source string",
	"shlex.split":                     "splits a command line: a step towards shell execution",
	"shlex.quote":                     "quotes for a shell",
	"webbrowser.open":                 "opens a URL through the OS handler",
	"webbrowser.open_new":             "opens a URL through the OS handler",
	"shutil.copy":                     "copies a file",
	"shutil.copyfile":                 "copies a file",
	"shutil.copytree":                 "copies a tree",
	"shutil.move":                     "moves a file",
	"shutil.make_archive":             "builds an archive",
}

// classifyGadget returns the tier for a qualified name.
func classifyGadget(module, name string) Gadget {
	q := module + "." + name

	// 1. Exact-name primitives, including their subtrees.
	if sink, ok := directNames[q]; ok {
		return Gadget{Class: GadgetDirect, Sink: sink, Entry: q}
	}
	for entry, sink := range directNames {
		if strings.HasPrefix(q, entry+".") {
			return Gadget{Class: GadgetDirect, Sink: sink, Entry: entry + ".*"}
		}
	}

	// 2. Whole-module primitives.
	if sink, ok := directModules[module]; ok {
		return Gadget{Class: GadgetDirect, Sink: sink, Entry: module + ".*"}
	}
	for pkg, sink := range directModules {
		if strings.HasPrefix(module, pkg+".") {
			return Gadget{Class: GadgetDirect, Sink: sink, Entry: pkg + ".*"}
		}
	}

	// 3. Library gadgets, exact then subtree.
	if sink, ok := libraryGadgets[q]; ok {
		return Gadget{Class: GadgetLibrary, Sink: sink, Entry: q}
	}
	for entry, sink := range libraryGadgets {
		if strings.HasPrefix(q, entry+".") {
			return Gadget{Class: GadgetLibrary, Sink: sink, Entry: entry + ".*"}
		}
	}

	// 4. Anything else that is callable.
	return Gadget{Class: GadgetUnknownCallable, Sink: "unclassified callable", Entry: q}
}

// moduleSubtreeMatches reports whether a package entry covers a module: the module
// itself or anything inside it. It is exported to the tests through this package
// so that the subtree contract is pinned for every entry in the tables.
func moduleSubtreeMatches(module, pkg string) bool {
	return module == pkg || strings.HasPrefix(module, pkg+".")
}

// isDictLike reports whether v is a type SETITEM/SETITEMS may legally target.
//
// The reference unpickler does *not* check this — `self.stack[-1][k] = v` runs
// unconditionally — which is exactly the pre-2.10 heap-corruption class
// (CVE-2026-24747 / GHSA-63cw-57p8-fm3p, fixed in torch 2.10.0 by adding the
// check). A stream that reaches SETITEM with a non-dict target is therefore
// reported at critical: against a 2.7-era loader it is a memory-safety bug, and
// against a fixed loader it is still a rejection.
func isDictLike(v Val) bool {
	switch v.kind {
	case kDict:
		return true
	case kInstance:
		return isDictLikeClass(v.global)
	}
	return false
}

func isDictLikeClass(g *Global) bool {
	if g == nil {
		return false
	}
	switch g.QualName() {
	case "collections.OrderedDict", "collections.Counter", "builtins.dict", "dict":
		return true
	}
	return false
}

// isBuildableClass reports whether BUILD may legally apply state to a value of
// this class: Tensor, Parameter, OrderedDict, or a class the user allowlisted. A
// build target that is none of those is a rejection in the reference loader.
func isBuildableClass(g *Global) bool {
	if g == nil {
		return false
	}
	return isAllowed(g.Module, g.Name) == AllowDefault
}

// isListLike reports whether v is a list. The reference checks `type(x) is list`,
// so a list *subclass* is not accepted; the walker cannot distinguish a subclass
// from a list, which is why APPEND against a list-class instance is reported at a
// lower confidence than against a known non-list.
func isListLike(v Val) bool { return v.kind == kList }

// isPersistentStorageID reports whether the popped persistent id is the
// ("storage", …) tuple the loader permits.
//
// The reference also accepts a bare int, for backward compatibility with old
// checkpoints; that path is a distinct risk (the int is an index into the loader's
// own storage table), so the two shapes get different evidence.
func isPersistentStorageID(v Val) bool {
	if v.kind == kInt {
		return true
	}
	if v.kind != kTuple || len(v.elems) == 0 {
		return false
	}
	first := v.elems[0]
	if first.kind != kStr && first.kind != kBytes {
		return false
	}
	return first.text == "storage"
}
