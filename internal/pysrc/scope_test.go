package pysrc

import (
	"slices"
	"strings"
	"testing"
)

// dotted returns the sink names ModuleScopeSinks finds, in source order.
func dotted(src string) []string {
	var out []string
	sinks, _ := ModuleScopeSinks([]byte(src))
	for _, s := range sinks {
		out = append(out, s.Dotted)
	}
	return out
}

// TestModuleScope — the unsafe corpus module, 0xmoose…/rce-test-pickle-001/
// modeling_malicious.py, reduced to its shape: a network call inside a top-level
// try. A depth-0 filter would miss it, which is why this is the first case.
func TestModuleScope(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
		deny []string
	}{
		{
			name: "try body runs at import",
			src: "import socket\ntry:\n    socket.getaddrinfo('x.rce.lc', 80)\nexcept:\n    pass\n" +
				"class MaliciousModel:\n    pass\n",
			want: []string{"socket.getaddrinfo"},
		},
		{
			name: "def body does not",
			src:  "import os\ndef f():\n    os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			// In Python, statements directly inside a class body execute at
			// import time; only def bodies inside the class are deferred.
			name: "class body runs at import",
			src:  "import os\nclass C:\n    os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "def inside class body does not",
			src:  "import os\nclass C:\n    def m(self):\n        os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "main guard does not",
			src:  "import os\nif __name__ == \"__main__\":\n    os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "parenthesised main guard does not",
			src:  "import os\nif (__name__ == \"__main__\"):\n    os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "reversed main guard does not",
			src:  "import os\nif \"__main__\" == __name__:\n    os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "inverted main guard does",
			src:  "import os\nif __name__ != \"__main__\":\n    os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "negated main guard runs at import",
			src:  "import os\nif not (__name__ == \"__main__\"):\n    os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "compound or main guard runs at import",
			src:  "import os\nif True or __name__ == \"__main__\":\n    os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "compared-false main guard runs at import",
			src:  "import os\nif (__name__ == \"__main__\") == False:\n    os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "aliased import sink runs at import",
			src:  "from os import system\nsystem('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "nested if inside def stays inside def",
			src:  "import os\ndef f():\n    if True:\n        os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "def nested inside a running if",
			src:  "import os\nif True:\n    def f():\n        os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "for body runs",
			src:  "import os\nfor i in range(2):\n    os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "decorator runs",
			src:  "@registry.register('x')\ndef f():\n    pass\n",
			want: []string{"registry.register"},
		},
		{
			name: "inline suite has no indent",
			src:  "import os\nif True: os.system('id')\n",
			want: []string{"os.system"},
		},
		{
			name: "async def body does not",
			src:  "import os\nasync def f():\n    os.system('id')\n",
			deny: []string{"os.system"},
		},
		{
			name: "finally runs",
			src:  "import os\ntry:\n    pass\nfinally:\n    os.system('id')\n",
			want: []string{"os.system"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dotted(c.src)
			for _, w := range c.want {
				if !slices.Contains(got, w) {
					t.Fatalf("sinks %v do not contain %q", got, w)
				}
			}
			for _, d := range c.deny {
				if slices.Contains(got, d) {
					t.Fatalf("sinks %v contain %q, which does not run at import", got, d)
				}
			}
		})
	}
}

// TestModuleScopeBound pins the statement cap: a module with more import-time
// statements than the bound returns exactly the bound and signals truncation.
func TestModuleScopeBound(t *testing.T) {
	var b strings.Builder
	for range maxModuleStatements + 50 {
		b.WriteString("x = 1\n")
	}
	stmts, truncated := ModuleStatements([]byte(b.String()), Lex([]byte(b.String())))
	if len(stmts) != maxModuleStatements {
		t.Fatalf("got %d statements, want the bound %d", len(stmts), maxModuleStatements)
	}
	if !truncated {
		t.Fatal("ModuleStatements did not signal truncation when cap was exceeded")
	}
	_, trunc2 := ModuleScopeSinks([]byte(b.String()))
	if !trunc2 {
		t.Fatal("ModuleScopeSinks did not propagate statement truncation")
	}
}

// TestModuleScopeOffset pins that Off points at the callee, so the finding can
// name a byte offset a reviewer can open.
func TestModuleScopeOffset(t *testing.T) {
	src := "import socket\ntry:\n    socket.getaddrinfo('x', 80)\nexcept:\n    pass\n"
	sinks, truncated := ModuleScopeSinks([]byte(src))
	if truncated {
		t.Fatal("short module reported truncated")
	}
	if len(sinks) != 1 {
		t.Fatalf("got %d sinks, want 1: %v", len(sinks), sinks)
	}
	want := strings.Index(src, "socket.getaddrinfo")
	if int(sinks[0].Off) != want {
		t.Fatalf("Off = %d, want %d", sinks[0].Off, want)
	}
}
