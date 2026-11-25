package boundary

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestNoExecUnderCatchesAllExecPaths(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"clean.go":         "package p\nimport \"os\"\nfunc f() { _ = os.Getenv(\"X\") }\n",
		"ose.go":           "package p\nimport \"os/exec\"\nvar _ = exec.Command\n",
		"plug.go":          "package p\nimport \"plugin\"\nvar _ = plugin.Open\n",
		"sysexec.go":       "package p\nimport s \"syscall\"\nvar _ = s.Exec\n",
		"sysfork.go":       "package p\nimport \"syscall\"\nvar _ = syscall.ForkExec\n",
		"osstart.go":       "package p\nimport o \"os\"\nvar _ = o.StartProcess\n",
		"sysstart.go":      "package p\nimport \"syscall\"\nvar _ = syscall.StartProcess\n",
		"clean_syscall.go": "package p\nimport \"syscall\"\nvar _ = syscall.EINTR\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NoExecUnder(dir)
	if err != nil {
		t.Fatalf("NoExecUnder: %v", err)
	}
	want := []string{"ose.go", "osstart.go", "plug.go", "sysexec.go", "sysfork.go", "sysstart.go"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("NoExecUnder = %v, want %v", got, want)
	}
}

func TestNoNetOutsideEnforcesAllowlist(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("hubapi/client.go", "package hubapi\nimport \"net/http\"\nvar _ = http.Get\n")
	mustWrite("other/other_test.go", "package other\nimport \"net/http\"\nvar _ = http.Get\n")
	mustWrite("other/clean.go", "package other\nimport \"fmt\"\nvar _ = fmt.Println\n")
	mustWrite("other/bad.go", "package other\nimport \"net/http\"\nvar _ = http.Get\n")
	mustWrite("other/sub.go", "package other\nimport \"net/http/httptest\"\nvar _ = httptest.NewServer\n")

	got, err := NoNetOutside(dir, "hubapi")
	if err != nil {
		t.Fatalf("NoNetOutside: %v", err)
	}
	for i := range got {
		got[i] = filepath.ToSlash(got[i])
	}
	slices.Sort(got)
	want := []string{"other/bad.go", "other/sub.go"}
	if !slices.Equal(got, want) {
		t.Fatalf("NoNetOutside = %v, want %v", got, want)
	}
}
