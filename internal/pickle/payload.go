package pickle

import (
	"fmt"
	"strings"
)

// payloadOf names the artifact-supplied payload a REDUCE hands to a sink that
// runs it, or returns "" when the call's arguments are structural rather than
// payload-bearing.
//
// This is the difference between the two grades sc4n reports for a picked
// stream. SC4N-PICKLE-GLOBAL-CRITICAL says the sink is reachable;
// SC4N-MALICE-CONSTRUCTED says which sink runs and with what, on the loader's
// own path. The distinction is the argument:
//
//	GLOBAL builtins getattr     + "forward"                      -> capability
//	GLOBAL builtins getattr     + "__globals__"                  -> constructed
//	GLOBAL posix system         + "nslookup attacker.example"    -> constructed
//	GLOBAL builtins eval        + "__import__('os').system('id')" -> constructed
//
// A plain attribute name, an allowlisted callable and a constant whose text was
// not retained are not payloads. That is what keeps the REMOTE-code
// torch.load shape - getattr(Model, "forward") on a named class - at
// capability, which is the truthful grade: it reads an attribute, it does not
// run a program.
func payloadOf(g *Global, args Val) string {
	if g == nil || g.Allows == AllowDefault {
		// An allowlisted name is one the reference loader would accept without
		// asking, and it does not run its argument: any string it receives is
		// data. The code-string rule still reports that data separately.
		return ""
	}
	q := g.QualName()
	var texts []string
	walkStrings(args, 0, func(s string) {
		if s != "" && len(texts) < maxPayloadStrings {
			texts = append(texts, s)
		}
	})
	if len(texts) == 0 {
		return ""
	}
	switch {
	case codeSinks[q]:
		return fmt.Sprintf("a %d-byte string that %s compiles and runs", len(texts[0]), q)
	case processSinks[q] || hasAnyPrefix(q, processSinkPrefix):
		return fmt.Sprintf("a %d-byte command string", len(texts[0]))
	case deserialisers[q]:
		return fmt.Sprintf("a %d-byte serialised blob it deserialises in place", len(texts[0]))
	}
	if q == "getattr" || q == "builtins.getattr" {
		// getattr with a dunder name is the introspection escape: it reaches
		// __globals__, __subclasses__ or __builtins__ from a context that
		// expected an attribute read. The name is the payload.
		for _, t := range texts {
			if isDunderName(t) {
				return fmt.Sprintf("the dunder attribute name %q", t)
			}
		}
		return ""
	}
	if g.Gadget.Class == GadgetDirect {
		for _, t := range texts {
			if ind := looksLikeCode(t); ind != "" {
				return fmt.Sprintf("a %d-byte string that looks like source (indicator %q)", len(t), ind)
			}
		}
	}
	return ""
}

// maxPayloadStrings bounds how many argument strings the predicate inspects: it
// needs one to prove the point, and the claim quotes only the first.
const maxPayloadStrings = 8

var codeSinks = map[string]bool{
	"eval":                   true,
	"exec":                   true,
	"compile":                true,
	"__import__":             true,
	"apply":                  true,
	"builtins.eval":          true,
	"builtins.exec":          true,
	"builtins.compile":       true,
	"builtins.__import__":    true,
	"builtins.apply":         true,
	"__builtin__.eval":       true,
	"__builtin__.exec":       true,
	"__builtin__.compile":    true,
	"__builtin__.__import__": true,
}

var processSinks = map[string]bool{
	"os.system":    true,
	"os.popen":     true,
	"posix.system": true,
	"posix.popen":  true,
}

var processSinkPrefix = []string{
	"os.exec", "os.spawn", "posix.exec", "posix.spawn", "subprocess.",
}

var deserialisers = map[string]bool{
	"marshal.load":  true,
	"marshal.loads": true,
	"pickle.load":   true,
	"pickle.loads":  true,
	"_pickle.load":  true,
	"_pickle.loads": true,
	"cPickle.load":  true,
	"cPickle.loads": true,
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// isDunderName reports whether s is a __dunder__ identifier. The name has to be
// an identifier for the check to mean anything: "__globals__ " and
// "__globals__.__class__" are not the attribute name getattr receives.
func isDunderName(s string) bool {
	if len(s) < 5 || !strings.HasPrefix(s, "__") || !strings.HasSuffix(s, "__") {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
