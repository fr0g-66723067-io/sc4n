package malice

import "strings"

// IsLoadSink reports whether a dotted call at import time means the module runs
// code, reaches the network or loads native code as it is imported.
//
// The set is deliberately narrower than "any effect". A module that deletes a
// file or chmods a path on import is malicious in spirit, but calling it here
// would make SC4N-MALICE-CONSTRUCTED claim "runs artifact-supplied code" about a
// call that runs no code, and a rule whose statement is broader than its
// evidence is the failure mode this whole grade exists to avoid. Those artifacts
// keep their capability finding (SC4N-CONFIG-AUTO-MAP); the network, exec and
// native-load calls below are the ones whose *mechanism* is code execution,
// process execution, outbound traffic or a second deserialiser.
//
// The same set grades a pickle payload's sink class, so a name added here also
// changes which pickle streams reach the constructed grade.
func IsLoadSink(dotted string) bool {
	if dotted == "" {
		return false
	}
	if loadSinkExact[dotted] {
		return true
	}
	for _, p := range loadSinkPrefix {
		if strings.HasPrefix(dotted, p) {
			return true
		}
	}
	return false
}

// loadSinkExact is the exact-name half of the set.
var loadSinkExact = map[string]bool{
	// Code execution, in its own right.
	"eval":                true,
	"exec":                true,
	"compile":             true,
	"__import__":          true,
	"apply":               true,
	"breakpoint":          true,
	"builtins.eval":       true,
	"builtins.exec":       true,
	"builtins.compile":    true,
	"builtins.__import__": true,
	"builtins.apply":      true,
	// Process execution.
	"os.system":                                  true,
	"os.popen":                                   true,
	"os.posix_spawn":                             true,
	"os.posix_spawnp":                            true,
	"posix.system":                               true,
	"posix.popen":                                true,
	"posix.fork":                                 true,
	"subprocess.Popen":                           true,
	"subprocess.run":                             true,
	"subprocess.call":                            true,
	"subprocess.check_call":                      true,
	"subprocess.check_output":                    true,
	"subprocess.getoutput":                       true,
	"subprocess.getstatusoutput":                 true,
	"asyncio.create_subprocess_exec":             true,
	"asyncio.create_subprocess_shell":            true,
	"asyncio.subprocess.create_subprocess_exec":  true,
	"asyncio.subprocess.create_subprocess_shell": true,
	// Outbound network and DNS resolution.
	"socket.socket":            true,
	"socket.create_connection": true,
	"socket.create_server":     true,
	"socket.socketpair":        true,
	"socket.fromfd":            true,
	"socket.getaddrinfo":       true,
	"socket.gethostbyname":     true,
	"socket.gethostbyname_ex":  true,
	"socket.gethostbyaddr":     true,
	"socket.getnameinfo":       true,
	// Dynamic import and native code loading.
	"importlib.import_module": true,
	"importlib.__import__":    true,
	"importlib.reload":        true,
	"ctypes.CDLL":             true,
	"ctypes.PyDLL":            true,
	"ctypes.WinDLL":           true,
	"ctypes.OleDLL":           true,
	"ctypes.cdll":             true,
	"ctypes.windll":           true,
	"ctypes.oledll":           true,
	"ctypes.pydll":            true,
	"ctypes.pythonapi":        true,
	"ctypes.LibraryLoader":    true,
	// A second deserialiser, which is where the payload usually lives.
	"marshal.load":           true,
	"marshal.loads":          true,
	"pickle.load":            true,
	"pickle.loads":           true,
	"_pickle.load":           true,
	"_pickle.loads":          true,
	"cPickle.load":           true,
	"cPickle.loads":          true,
	"dill.load":              true,
	"dill.loads":             true,
	"cloudpickle.load":       true,
	"cloudpickle.loads":      true,
	"joblib.load":            true,
	"torch.load":             true,
	"torch.jit.load":         true,
	"yaml.load":              true,
	"yaml.load_all":          true,
	"yaml.unsafe_load":       true,
	"yaml.unsafe_load_all":   true,
	"urllib.urlopen":         true,
	"urllib.urlretrieve":     true,
	"urllib2.urlopen":        true,
	"httplib.HTTPConnection": true,
	"webbrowser.open":        true,
	"webbrowser.open_new":    true,
}

// loadSinkPrefix is the package half. Each entry ends in "." so a name is only
// matched on a boundary: "socket." never matches "socketx.f".
var loadSinkPrefix = []string{
	// Outbound network and name resolution.
	"urllib.request.",
	"http.client.",
	"requests.",
	"httpx.",
	"aiohttp.",
	"ftplib.",
	"smtplib.",
	"telnetlib.",
	"poplib.",
	"imaplib.",
	"paramiko.",
	// Process execution and terminal hand-off.
	"os.exec",
	"os.spawn",
	"posix.exec",
	"posix.spawn",
	"pty.",
	// Native code.
	"ctypes.cdll.",
	"ctypes.windll.",
	"ctypes.oledll.",
	"ctypes.pydll.",
	"cffi.",
	// Dynamic import and code compilation.
	"importlib.machinery.",
	"runpy.",
	"codeop.",
	"code.",
	"compileall.",
}
