package torch

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"

	// The torch parser dispatches members by content, so the pickle engine and
	// the Python analyser must be linked for a member to reach them.
	_ "github.com/fr0g-66723067-io/sc4n/internal/pickle"
	_ "github.com/fr0g-66723067-io/sc4n/internal/pysrc"
)

const fixtureRoot = "../../testdata/fixtures"

// scanBytes runs the full dispatch (sniff + universal layers + parser) over data
// and returns the sniffed format and the finding rule IDs.
func scanBytes(t *testing.T, name string, data []byte) (artifact.Format, []string) {
	t.Helper()
	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	src := source.Mem(name, data)
	defer src.Close()
	f, err := artifact.Scan(sess.NewCtx(name, l), src)
	if err != nil {
		t.Fatalf("Scan(%s): %v", name, err)
	}
	var ids []string
	for _, fd := range c.Findings() {
		ids = append(ids, fd.RuleID)
	}
	sort.Strings(ids)
	return f, ids
}

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot, rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

func has(ids []string, id string) bool {
	for _, s := range ids {
		if s == id {
			return true
		}
	}
	return false
}

// TestSniffShapes pins which container each fixture is recognised as. The point
// is the discriminator: a new-format zip and a TorchScript archive share
// data.pkl, and a prefixed zip must still be a torch shape rather than generic.
func TestSniffShapes(t *testing.T) {
	cases := []struct {
		file string
		want artifact.Format
	}{
		{"torch_new_zip.pt", artifact.FormatTorchNew},
		{"torch_prefixed_zip.pt", artifact.FormatTorchNew},
		{"torch_script.pt", artifact.FormatTorchScript},
		{"torch_legacy.pt", artifact.FormatTorchLegacy},
		{"torch_legacy_tar.pt", artifact.FormatTorchLegacy},
		{"torch_7z.pt", artifact.FormatSevenZip},
		{"torch_pt2.pt2", artifact.FormatPT2},
		{"benign/torch_clean.pt", artifact.FormatTorchNew},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, _ := scanBytes(t, filepath.Base(tc.file), readFixture(t, tc.file))
			if got != tc.want {
				t.Fatalf("sniffed %s, want %s", got, tc.want)
			}
		})
	}
}

// TestFixtureRules is the package-local half of the corpus gate: each fixture
// must produce the rule that identifies its shape, and the pickle engine must
// actually run through the torch path (SC4N-PICKLE-REDUCE on the gadget).
func TestFixtureRules(t *testing.T) {
	cases := []struct {
		file   string
		expect []string
		forbid []string
	}{
		{"torch_new_zip.pt", []string{"SC4N-TORCH-ZIP", "SC4N-PICKLE-REDUCE"},
			[]string{"SC4N-TORCH-PREFIXED-ARCHIVE", "SC4N-TORCH-7Z", "SC4N-TORCH-STRUCT"}},
		{"torch_prefixed_zip.pt", []string{"SC4N-TORCH-PREFIXED-ARCHIVE", "SC4N-TORCH-ZIP", "SC4N-PICKLE-REDUCE"}, nil},
		{"torch_script.pt", []string{"SC4N-TORCH-SCRIPT", "SC4N-PICKLE-REDUCE", "SC4N-CODE-TAINT-SHELL"}, nil},
		{"torch_legacy.pt", []string{"SC4N-TORCH-LEGACY", "SC4N-PICKLE-REDUCE"}, []string{"SC4N-PICKLE-TRAILING"}},
		{"torch_legacy_tar.pt", []string{"SC4N-TORCH-LEGACY-TAR", "SC4N-PICKLE-REDUCE"}, nil},
		{"torch_7z.pt", []string{"SC4N-TORCH-7Z", "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION"}, nil},
		{"torch_pt2.pt2", []string{"SC4N-TORCH-PT2", "SC4N-PICKLE-REDUCE"}, nil},
		{"benign/torch_clean.pt", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			_, ids := scanBytes(t, filepath.Base(tc.file), readFixture(t, tc.file))
			for _, want := range tc.expect {
				if !has(ids, want) {
					t.Errorf("%s: missing %s; got %v", tc.file, want, ids)
				}
			}
			for _, bad := range tc.forbid {
				if has(ids, bad) {
					t.Errorf("%s: unexpected %s; got %v", tc.file, bad, ids)
				}
			}
		})
	}
}

// TestBenignTorchZipIsClean proves the whole torch path is not noisy: a real
// torch state dict yields no high/critical finding.
func TestBenignTorchZipIsClean(t *testing.T) {
	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	src := source.Mem("torch_clean.pt", readFixture(t, "benign/torch_clean.pt"))
	defer src.Close()
	if _, err := artifact.Scan(sess.NewCtx("torch_clean.pt", l), src); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := c.MaxSeverity(); got >= report.SeverityHigh {
		t.Fatalf("benign torch zip produced %s findings: %v", got, c.Findings())
	}
}

// TestLegacyRawMagicVariant covers the raw little-endian magic forms (the plan's
// "qword") in addition to the pickled form the fixtures use, so a writer that
// emits the raw magic is not silently missed.
func TestLegacyRawMagicVariant(t *testing.T) {
	raw8 := append(append([]byte{}, torchMagicLE[:8]...), 0x00)
	raw10 := append(append([]byte{}, torchMagicLE...), 0x00)
	for _, tc := range []struct {
		name string
		m    int
	}{{"raw8", 8}, {"raw10", 10}} {
		data := raw8
		if tc.m == 10 {
			data = raw10
		}
		after, ok := detectLegacy(data)
		if !ok || after != tc.m {
			t.Fatalf("%s: detectLegacy = (%d,%v), want (%d,true)", tc.name, after, ok, tc.m)
		}
	}
	// The pickled form the fixtures use must report afterMagic 0 (the magic is the
	// first pickle to walk).
	if after, ok := detectLegacy(torchLegacyBytesForTest()); !ok || after != 0 {
		t.Fatalf("pickled magic: detectLegacy = (%d,%v), want (0,true)", after, ok)
	}
}

func torchLegacyBytesForTest() []byte {
	// PROTO 2, LONG1, len 10, the ten magic bytes, STOP.
	b := []byte{0x80, 0x02, 0x8a, byte(len(torchMagicLE))}
	b = append(b, torchMagicLE...)
	return append(b, 0x2e)
}

// TestNoPanicOnAdversarialBytes feeds malformed and truncated inputs straight
// into the parser; the contract is that malformed input is a finding, never a
// panic.
func TestNoPanicOnAdversarialBytes(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x80},
		{0x80, 0x02},
		append([]byte{0x80, 0x02, 0x8a, 0x0a}, torchMagicLE[:3]...), // truncated magic pickle
		torchLegacyBytesForTest(),                                   // magic only
		append(torchLegacyBytesForTest(), 0x80, 0x02),               // magic then truncated pickle
		[]byte("PK\x03\x04"),
		append([]byte("PK\x03\x04"), make([]byte, 40)...),
		append([]byte("junk"), []byte("PK\x03\x04")...),
		torchMagicLE[:8],
		torchMagicLE,
		{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
	}
	for i, in := range inputs {
		name := "torch_adversarial.pt"
		l := limits.Default()
		c := report.NewCollector(0)
		sess := artifact.NewSession(c, "", l)
		src := source.Mem(name, in)
		_, _ = artifact.Scan(sess.NewCtx(name, l), src)
		src.Close()
		_ = i
	}
}

// FuzzTorch exercises the whole torch dispatch on arbitrary bytes. The invariant
// is "no panic, bounded allocation, terminates"; the parsers cap every
// attacker-controlled length against the bytes that actually remain.
func FuzzTorch(f *testing.F) {
	for _, name := range []string{
		"torch_new_zip.pt", "torch_prefixed_zip.pt", "torch_script.pt",
		"torch_legacy.pt", "torch_legacy_tar.pt", "torch_7z.pt", "torch_pt2.pt2",
	} {
		if b, err := os.ReadFile(filepath.Join(fixtureRoot, name)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("PK\x03\x04\x00\x00"))
	f.Add(torchLegacyBytesForTest())
	f.Fuzz(func(t *testing.T, data []byte) {
		l := limits.Default()
		l.MaxArtifactBytes = 8 << 20
		c := report.NewCollector(2000)
		sess := artifact.NewSession(c, "", l)
		src := source.Mem("fuzz.pt", data)
		defer src.Close()
		_, _ = artifact.Scan(sess.NewCtx("fuzz.pt", l), src)
	})
}

// TestDeterministicFindings hashes nothing, but asserts the finding set (and its
// order, which the Collector sorts) is identical across two runs over the fixture
// corpus, which is the property a CI gate needs.
func TestDeterministicFindings(t *testing.T) {
	var first []string
	for _, name := range []string{"torch_new_zip.pt", "torch_prefixed_zip.pt", "torch_legacy.pt", "torch_pt2.pt2"} {
		data := readFixture(t, name)
		_, ids := scanBytes(t, name, data)
		first = append(first, ids...)
	}
	var second []string
	for _, name := range []string{"torch_new_zip.pt", "torch_prefixed_zip.pt", "torch_legacy.pt", "torch_pt2.pt2"} {
		data := readFixture(t, name)
		_, ids := scanBytes(t, name, data)
		second = append(second, ids...)
	}
	if len(first) != len(second) {
		t.Fatalf("finding count differs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("finding %d differs: %s vs %s", i, first[i], second[i])
		}
	}
}
