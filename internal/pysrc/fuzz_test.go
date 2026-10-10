package pysrc

import (
	"strings"
	"testing"
)

// FuzzPythonLex asserts the lexer and the statement splicer never panic on
// arbitrary bytes. The lexer is the one parser in the tree that keeps state
// across a whole document (indent stack, string prefixes, f-string nesting), so
// it is the most likely place for a malformed input to escape its bounds.
func FuzzPythonLex(f *testing.F) {
	f.Add([]byte("import os\nos.system('id')\n"))
	f.Add([]byte("def f():\n    return 1\n"))
	f.Add([]byte("x = f'{a!r:>{w}}'\n"))
	f.Add([]byte("rb'''\n"))
	f.Add([]byte("if x:\n\tpass\n"))
	f.Add([]byte("\x00\x01\x02"))
	f.Add([]byte(""))
	// One statement of deeply nested calls. The call analysis scans from each '('
	// to the end of the statement, so the cost is quadratic in the nesting; the
	// call-token budget bounds it (round 3), and the seed keeps the nesting axis in
	// front of the fuzzer.
	f.Add([]byte("exec(" + strings.Repeat("exec(", 400) + "1" + strings.Repeat(")", 401) + "\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		toks := Lex(data)
		_ = Statements(data, toks)
		for _, tok := range toks {
			_ = StringValue(tok, data, 1<<16)
		}
		ctx, _ := newTestCtx(t)
		Analyze(ctx, data)
	})
}
