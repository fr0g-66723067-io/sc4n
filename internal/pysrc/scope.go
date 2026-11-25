package pysrc

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
//	class C:                   the class body runs at import (only def methods
//	    os.system(…)           inside it are deferred)
//	if __name__ == "__main__": does not run at import
//	    os.system(…)
//	def f():                   the body does not run at import
//	    os.system(…)
//
// So the block *kind* matters, not the indentation level: the suites of if, try,
// for, while, with, except, else, finally and class run, and the bodies of def
// (and async def) do not. The lexer already emits INDENT/DEDENT, so this is a
// stack of header kinds over the token stream, and Statements - which drops
// INDENT/DEDENT - is deliberately not reused.

// Sink is one call expression found in import-time code.
type Sink struct {
	// Dotted is the callee as written (with lightweight import alias resolution);
	// a call through an expression receiver carries the method name alone,
	// because resolving the receiver is type inference pysrc does not do.
	Dotted string
	// Off is the byte offset of the callee name, for an evidence offset.
	Off int32
}

const (
	// MaxModuleStatements bounds the statements returned for one module. A model
	// module that exceeds it is analysed up to the bound; the caller reports the
	// truncation rather than silently analysing a prefix.
	MaxModuleStatements = 1024
	maxModuleStatements = MaxModuleStatements
	// moduleCallBudget bounds the tokens Calls may read across the whole module,
	// which is the one quadratic walk in this package.
	moduleCallBudget = 1 << 16
)

// blockKind classifies a compound statement's suite.
type blockKind uint8

const (
	// blockRuns is a suite that executes at import: if, try, for, while, with,
	// class, and the else/elif/except/finally arms.
	blockRuns blockKind = iota
	// blockCode is a def or async def body: defined at import, not executed.
	blockCode
	// blockMain is an `if __name__ == "__main__":` suite, which the import
	// machinery never enters.
	blockMain
)

// ModuleStatements returns the statements that run when the file is imported, in
// source order, together with whether the statement cap was reached. The
// returned slices reference toks.
//
// A statement inside a def body is excluded, as is the body of a strict
// `if __name__ == "__main__":` block. Class bodies execute at import in Python,
// so statements directly inside a class body are included while methods (`def`)
// inside the class are excluded.
func ModuleStatements(src []byte, toks []Token) ([][]Token, bool) {
	var (
		out       [][]Token
		cur       []Token
		last      []Token
		stack     []blockKind
		truncated bool
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
		if !skipped() {
			if len(out) < maxModuleStatements {
				out = append(out, cur)
			} else {
				truncated = true
			}
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
	return out, truncated
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
	case "def":
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

// isMainGuard reports whether an `if` header is strictly `__name__ == "__main__"`
// (or `"__main__" == __name__`, optionally wrapped in matching outer
// parentheses). Negated or compound conditions (`if not (__name__ == "__main__"):`,
// `if True or __name__ == "__main__":`, `if (__name__ == "__main__") == False:`)
// may execute on import and return false.
func isMainGuard(src []byte, header []Token) bool {
	if len(header) < 4 || header[0].Text(src) != "if" {
		return false
	}
	cond := header[1:]
	if len(cond) > 0 && cond[len(cond)-1].Kind == TokOp && cond[len(cond)-1].Text(src) == ":" {
		cond = cond[:len(cond)-1]
	}
	// Strip balanced outer parentheses wrapping the entire condition.
	for len(cond) >= 2 && cond[0].Kind == TokOp && cond[0].Text(src) == "(" &&
		cond[len(cond)-1].Kind == TokOp && cond[len(cond)-1].Text(src) == ")" {
		depth := 0
		wraps := true
		for i := 0; i < len(cond)-1; i++ {
			if cond[i].Kind == TokOp {
				switch cond[i].Text(src) {
				case "(":
					depth++
				case ")":
					depth--
					if depth == 0 {
						wraps = false
					}
				}
			}
			if !wraps {
				break
			}
		}
		if !wraps {
			break
		}
		cond = cond[1 : len(cond)-1]
	}
	if len(cond) != 3 {
		return false
	}
	if cond[1].Kind != TokOp || cond[1].Text(src) != "==" {
		return false
	}
	isName := func(t Token) bool { return t.Kind == TokName && t.Text(src) == "__name__" }
	isMainStr := func(t Token) bool { return t.Kind == TokString && StringValue(t, src, 32) == "__main__" }
	return (isName(cond[0]) && isMainStr(cond[2])) || (isMainStr(cond[0]) && isName(cond[2]))
}

// Sinks returns the call expressions in the given statements, in source order,
// together with whether the call-token budget was exhausted. It is bounded by
// moduleCallBudget tokens of argument scanning and stops at the bound rather
// than growing with the module.
func Sinks(src []byte, stmts [][]Token) ([]Sink, bool) {
	var out []Sink
	aliases := map[string]string{}
	budget := int64(moduleCallBudget)
	truncated := false
	for _, st := range stmts {
		recordImportAliases(src, st, aliases)
		if budget <= 0 {
			truncated = true
			break
		}
		calls, read, exhausted := Calls(src, st, budget)
		budget -= read
		for _, c := range calls {
			if c.Dotted != "" {
				out = append(out, Sink{Dotted: resolveDottedAlias(c.Dotted, aliases), Off: c.Off})
			}
		}
		if exhausted {
			truncated = true
			break
		}
	}
	return out, truncated
}

// ModuleScopeSinks lexes src and returns the sinks called by import-time
// statements, along with whether statement or call-token budgets truncated the
// analysis. It is the entry point for callers that do not already have the
// token stream.
func ModuleScopeSinks(src []byte) ([]Sink, bool) {
	toks := Lex(src)
	stmts, stmtTrunc := ModuleStatements(src, toks)
	sinks, callTrunc := Sinks(src, stmts)
	return sinks, stmtTrunc || callTrunc
}
