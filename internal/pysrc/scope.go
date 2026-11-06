package pysrc

import "bytes"

// Import-time statement selection.
//
// A module named by a config's auto_map is imported when the model is loaded
// with trust_remote_code=True. Everything that runs at import is attacker-chosen
// code, so the question this file answers is: which statements run then? The
// answer is not "the statements at depth 0".
//
//	try:                       runs at import
//	    socket.getaddrinfo(…)  runs at import - this is the shape the unsafe
//	                           corpus ships, and a depth-0 filter misses it
//	except:
//	    pass
//	if __name__ == "__main__": does not run at import
//	    os.system(…)
//	def f():                   the body does not run at import
//	    os.system(…)
//
// So the block *kind* matters, not the indentation level: the suites of if, try,
// for, while, with, except, else and finally run, and the bodies of def and class
// do not. The lexer already emits INDENT/DEDENT, so this is a stack of header
// kinds over the token stream, and Statements - which drops INDENT/DEDENT - is
// deliberately not reused.

// Sink is one call expression found in import-time code.
type Sink struct {
	// Dotted is the callee as written; a call through an expression receiver
	// carries the method name alone, because resolving the receiver is type
	// inference pysrc does not do.
	Dotted string
	// Off is the byte offset of the callee name, for an evidence offset.
	Off int32
}

const (
	// maxModuleStatements bounds the statements returned for one module. A model
	// module that exceeds it is analysed up to the bound; the caller reports the
	// truncation rather than silently analysing a prefix.
	maxModuleStatements = 1024
	// moduleCallBudget bounds the tokens Calls may read across the whole module,
	// which is the one quadratic walk in this package.
	moduleCallBudget = 1 << 16
)

// blockKind classifies a compound statement's suite.
type blockKind uint8

const (
	// blockRuns is a suite that executes at import: if, try, for, while, with,
	// and the else/elif/except/finally arms.
	blockRuns blockKind = iota
	// blockCode is a def or class body: defined at import, not executed.
	blockCode
	// blockMain is an `if __name__ == "__main__":` suite, which the import
	// machinery never enters.
	blockMain
)

// ModuleStatements returns the statements that run when the file is imported, in
// source order. The returned slices reference toks.
//
// A statement inside a def or class body is excluded, as is the body of an
// `if __name__ == "__main__":` block. The header statements themselves are
// included: a decorator and a class statement are executed at import.
func ModuleStatements(src []byte, toks []Token) [][]Token {
	var (
		out   [][]Token
		cur   []Token
		last  []Token
		stack []blockKind
	)
	skipped := func() bool {
		for _, b := range stack {
			if b != blockRuns {
				return true
			}
		}
		return false
	}
	flush := func() {
		if len(cur) == 0 {
			return
		}
		last = cur
		if !skipped() && len(out) < maxModuleStatements {
			out = append(out, cur)
		}
		cur = nil
	}
	for i := range toks {
		t := toks[i]
		switch t.Kind {
		case TokEnd, TokComment:
			continue
		case TokIndent:
			// The statement just flushed is this suite's header. A suite always
			// follows one, but be explicit about the empty case rather than
			// indexing last[0].
			flush()
			stack = append(stack, classifyBlock(src, last))
		case TokDedent:
			flush()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case TokNewline:
			flush()
		case TokOp:
			if t.Len() == 1 && t.Bytes(src)[0] == ';' {
				flush()
				continue
			}
			cur = append(cur, t)
		default:
			cur = append(cur, t)
		}
	}
	flush()
	return out
}

// classifyBlock names the suite introduced by a header statement.
func classifyBlock(src []byte, header []Token) blockKind {
	if len(header) == 0 {
		// No header to classify: treat the suite as running, because a false
		// positive that a reviewer can check is better than missing the one
		// import-time call that mattered.
		return blockRuns
	}
	switch header[0].Text(src) {
	case "def", "class":
		return blockCode
	case "async":
		if len(header) > 1 && header[1].Text(src) == "def" {
			return blockCode
		}
	case "if":
		if isMainGuard(src, header) {
			return blockMain
		}
	}
	return blockRuns
}

// isMainGuard reports whether an `if` header is `__name__ == "__main__"`. The
// inverted form (`!=`) runs on import and must not be skipped.
func isMainGuard(src []byte, header []Token) bool {
	var sawName, sawEq, sawMain bool
	for _, t := range header {
		switch t.Kind {
		case TokName:
			if t.Text(src) == "__name__" {
				sawName = true
			}
		case TokOp:
			if t.Text(src) == "==" {
				sawEq = true
			} else if t.Text(src) == "!=" {
				return false
			}
		case TokString:
			if bytes.Contains(t.Bytes(src), []byte("__main__")) {
				sawMain = true
			}
		}
	}
	return sawName && sawEq && sawMain
}

// Sinks returns the call expressions in the given statements, in source order.
// It is bounded by moduleCallBudget tokens of argument scanning and stops at the
// bound rather than growing with the module.
func Sinks(src []byte, stmts [][]Token) []Sink {
	var out []Sink
	budget := int64(moduleCallBudget)
	for _, st := range stmts {
		if budget <= 0 {
			break
		}
		calls, read, exhausted := Calls(src, st, budget)
		budget -= read
		for _, c := range calls {
			if c.Dotted != "" {
				out = append(out, Sink{Dotted: c.Dotted, Off: c.Off})
			}
		}
		if exhausted {
			break
		}
	}
	return out
}

// ModuleScopeSinks lexes src and returns the sinks called by import-time
// statements. It is the entry point for callers that do not already have the
// token stream.
func ModuleScopeSinks(src []byte) []Sink {
	toks := Lex(src)
	return Sinks(src, ModuleStatements(src, toks))
}
