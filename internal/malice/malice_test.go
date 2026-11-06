package malice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

func TestIsLoadSink(t *testing.T) {
	yes := []string{
		"posix.system", "os.system", "os.popen", "os.execv", "os.spawnl",
		"subprocess.run", "subprocess.Popen",
		"socket.getaddrinfo", "socket.socket", "socket.create_connection",
		"urllib.request.urlopen", "requests.get", "http.client.HTTPConnection",
		"ftplib.FTP", "smtplib.SMTP", "paramiko.SSHClient",
		"eval", "exec", "compile", "__import__", "builtins.eval",
		"importlib.import_module", "runpy.run_path",
		"ctypes.CDLL", "cffi.FFI",
		"marshal.loads", "pickle.loads",
	}
	for _, s := range yes {
		if !IsLoadSink(s) {
			t.Errorf("IsLoadSink(%q) = false, want true", s)
		}
	}
	no := []string{
		"", "socketx.f", "subprocessx", "requestsx.get", "os.getcwd", "os.path.join",
		"json.loads", "sys.exit", "collections.OrderedDict", "numpy.array",
		// Effects that run no code are deliberately outside the set: the
		// constructed rule claims code execution, so a delete or a chmod at
		// import time must not be graded by it.
		"shutil.rmtree", "os.remove", "os.unlink", "os.chmod",
	}
	for _, s := range no {
		if IsLoadSink(s) {
			t.Errorf("IsLoadSink(%q) = true, want false", s)
		}
	}
}

func TestConstructedStampsFamilyAndRefusesEmptyClaim(t *testing.T) {
	c := report.NewCollector(0)
	extra := map[string]string{"callable": "posix.system"}
	Constructed(c.For("a.pkl"), 4, FamilyPickleReduce,
		"REDUCE calls posix.system with a 31-byte command string", extra)

	got := c.Findings()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].RuleID != RuleConstructed.ID {
		t.Fatalf("rule %s, want %s", got[0].RuleID, RuleConstructed.ID)
	}
	if got[0].Extra["family"] != FamilyPickleReduce {
		t.Fatalf("family %q, want %q", got[0].Extra["family"], FamilyPickleReduce)
	}
	if _, mutated := extra["family"]; mutated {
		t.Fatal("Constructed mutated the caller's extra map")
	}
	// An empty claim is the one case where the finding would say nothing, so it
	// must not be emitted at all.
	Constructed(c.For("b.pkl"), 0, FamilyImportScope, "", nil)
	if n := len(c.Findings()); n != 1 {
		t.Fatalf("empty claim emitted a finding: %d findings", n)
	}
}

const goodDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestLoadAttestation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok.json", `{"version":"sc4nconfirm/1","runs":[
		{"sha256":"`+goodDigest+`","loader":"torch.load","loaded":true,
		 "exec":["/bin/sh -c id","/bin/sh -c whoami"],"connect":["93.184.216.34:80"]}]}`)

	ix, err := Load(ok)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ix.Len() != 1 {
		t.Fatalf("Len = %d, want 1", ix.Len())
	}
	r := ix.For("full", strings.ToUpper(goodDigest))
	if r == nil {
		t.Fatal("For did not match an upper-case digest")
	}
	if !sorted(r.Exec) {
		t.Fatalf("exec list not sorted: %v", r.Exec)
	}
	// A prefix digest identifies no file, so it must never match.
	if ix.For("prefix:4096", goodDigest) != nil {
		t.Fatal("For matched a prefix digest")
	}
	if ix.Matched() != 1 {
		t.Fatalf("Matched = %d, want 1", ix.Matched())
	}

	bad := map[string]string{
		"version":   `{"version":"sc4nconfirm/2","runs":[{"sha256":"` + goodDigest + `","loaded":true}]}`,
		"duplicate": `{"version":"sc4nconfirm/1","runs":[{"sha256":"` + goodDigest + `"},{"sha256":"` + goodDigest + `"}]}`,
		"short":     `{"version":"sc4nconfirm/1","runs":[{"sha256":"abc"}]}`,
		"nothex":    `{"version":"sc4nconfirm/1","runs":[{"sha256":"` + strings.Repeat("z", 64) + `"}]}`,
		"noruns":    `{"version":"sc4nconfirm/1","runs":[]}`,
		"unknown":   `{"version":"sc4nconfirm/1","runs":[],"extra":1}`,
	}
	for name, body := range bad {
		if _, err := Load(write(name+".json", body)); err == nil {
			t.Errorf("%s: Load accepted a bad attestation", name)
		}
	}
}

func TestMergeGradesOnlyRecordedEffects(t *testing.T) {
	c := report.NewCollector(0)
	// A failed load that names a missing module demonstrates nothing: the
	// framework was absent, which is not evidence that the artifact is inert.
	Merge(c, "w.pkl", &Run{
		SHA256: goodDigest, Loader: "torch.load", Loaded: false,
		Error: "ModuleNotFoundError: ultralytics", MissingModules: []string{"ultralytics"},
	})
	if n := len(c.Findings()); n != 0 {
		t.Fatalf("a load error produced %d findings, want 0", n)
	}
	Merge(c, "w.pkl", &Run{
		SHA256: goodDigest, Loader: "torch.load", Loaded: true,
		Exec: []string{"/bin/sh -c nslookup x"},
	})
	got := c.Findings()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].RuleID != RuleDemonstrated.ID {
		t.Fatalf("rule %s, want %s", got[0].RuleID, RuleDemonstrated.ID)
	}
	if !strings.Contains(got[0].Evidence, "nslookup x") {
		t.Fatalf("evidence does not name the executed program: %q", got[0].Evidence)
	}
	if got[0].Extra["exec"] != "1" || got[0].Extra["family"] != "attested" {
		t.Fatalf("extra = %v", got[0].Extra)
	}
	if got[0].Severity != report.SeverityCritical {
		t.Fatalf("severity %v, want critical", got[0].Severity)
	}
}

func TestDescribeBoundsLongLists(t *testing.T) {
	r := &Run{Loaded: true, Loader: "pickle.load", Exec: []string{"a", "b", "c", "d", "e"}}
	ev := describe(r)
	if !strings.Contains(ev, "and 2 more") {
		t.Fatalf("evidence did not bound the list: %q", ev)
	}
}

func sorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
