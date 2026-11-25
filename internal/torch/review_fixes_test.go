package torch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestClassifyZipRecognisesTopLevelPrefixAndBinExt(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  artifact.Format
	}{
		{"archive/data.pkl", []string{"archive/data.pkl", "archive/version"}, artifact.FormatTorchNew},
		{"custom-prefix/data.pkl", []string{"model/data.pkl", "model/data/0"}, artifact.FormatTorchNew},
		{"prefixed torchscript constants", []string{"archive/data.pkl", "archive/constants.pkl"}, artifact.FormatTorchScript},
		{"prefixed torchscript code", []string{"archive/data.pkl", "archive/code/__torch__/m.py"}, artifact.FormatTorchScript},
		{"prefixed pt2", []string{"export/archive_format", "export/version"}, artifact.FormatPT2},
		{"deeply nested not torch", []string{"a/b/data.pkl"}, artifact.FormatUnknown},
	}
	for _, tc := range cases {
		got, ok := classifyZip(tc.files)
		if tc.want == artifact.FormatUnknown {
			if ok {
				t.Errorf("%s: got %s, want unknown", tc.name, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("%s: got %s, %v; want %s, true", tc.name, got, ok, tc.want)
		}
	}

	if !isTorchExt("pytorch_model.bin") {
		t.Fatal(".bin must be in torchExts for prefixed checkpoint probing")
	}

	// Prefixed .bin zip with archive/data.pkl must sniff as FormatTorchNew.
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("archive/data.pkl")
	_, _ = w.Write([]byte{0x80, 0x04, 0x7d, 0x2e})
	_ = zw.Close()
	prefixed := append([]byte("PREF"), zbuf.Bytes()...)
	got, _ := scanBytes(t, "pytorch_model.bin", prefixed)
	if got != artifact.FormatTorchNew {
		t.Fatalf("prefixed pytorch_model.bin sniffed as %s, want %s", got, artifact.FormatTorchNew)
	}
}

func TestLegacyProtocol4FrameAndProtocol0Checkpoints(t *testing.T) {
	gadget := []byte("cos\nsystem\n(S'id'\ntR.")
	p4Magic := []byte{0x80, 0x04, 0x95, 13, 0, 0, 0, 0, 0, 0, 0, 0x8a, byte(len(torchMagicLE))}
	p4Magic = append(p4Magic, torchMagicLE...)
	p4Magic = append(p4Magic, 0x2e)
	p4Int := []byte{0x80, 0x04, 0x95, 4, 0, 0, 0, 0, 0, 0, 0, 0x4d, 0xe9, 0x03, 0x2e}
	p4Dict := []byte{0x80, 0x04, 0x95, 2, 0, 0, 0, 0, 0, 0, 0, 0x7d, 0x2e}
	p4Obj := []byte{0x80, 0x04, 0x8c, 2, 'o', 's', 0x8c, 6, 's', 'y', 's', 't', 'e', 'm', 0x93, 0x8c, 2, 'i', 'd', 0x85, 0x52, 0x2e}
	p4Keys := []byte{0x80, 0x04, 0x5d, 0x2e}

	var p4 []byte
	p4 = append(p4, p4Magic...)
	p4 = append(p4, p4Int...)
	p4 = append(p4, p4Dict...)
	p4 = append(p4, p4Obj...)
	p4 = append(p4, p4Keys...)
	p4 = append(p4, make([]byte, 32)...)

	f4, ids4 := scanBytes(t, "legacy_p4.pt", p4)
	if f4 != artifact.FormatTorchLegacy {
		t.Fatalf("p4 legacy sniffed as %s, want %s", f4, artifact.FormatTorchLegacy)
	}
	if !has(ids4, "SC4N-TORCH-LEGACY") || !has(ids4, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("p4 legacy findings = %v", ids4)
	}
	if has(ids4, "SC4N-TORCH-STRUCT") {
		t.Fatalf("p4 legacy emitted unexpected SC4N-TORCH-STRUCT: %v", ids4)
	}

	// Protocol-0 legacy checkpoint: MAGIC_NUMBER as L119547037146038801333356L\n.
	var p0 []byte
	p0 = append(p0, []byte("L119547037146038801333356L\n.")...)
	p0 = append(p0, []byte("I1001\n.")...)
	p0 = append(p0, []byte("(d.")...)
	p0 = append(p0, gadget...)
	p0 = append(p0, []byte("(l.")...)
	p0 = append(p0, make([]byte, 32)...)

	f0, ids0 := scanBytes(t, "legacy_p0.pt", p0)
	if f0 != artifact.FormatTorchLegacy {
		t.Fatalf("p0 legacy sniffed as %s, want %s", f0, artifact.FormatTorchLegacy)
	}
	if !has(ids0, "SC4N-TORCH-LEGACY") || !has(ids0, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("p0 legacy findings = %v", ids0)
	}
	if has(ids0, "SC4N-TORCH-STRUCT") {
		t.Fatalf("p0 legacy emitted unexpected SC4N-TORCH-STRUCT: %v", ids0)
	}
}

func TestLegacyTarNoDoubleNestingAndLargeStoragesPrefix(t *testing.T) {
	gadget := []byte("cos\nsystem\n(S'id'\ntR.")
	var tbuf bytes.Buffer
	tw := tar.NewWriter(&tbuf)
	add := func(name string, body []byte) {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
			ModTime:  time.Unix(0, 0),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	// storages has a leading metadata pickle followed by raw storage larger than MaxStringBlob.
	add("storages", append(append([]byte{}, gadget...), make([]byte, 4096)...))
	add("tensors", []byte{0x80, 0x02, 0x7d, 0x2e})
	add("pickle", []byte{0x80, 0x02, 0x7d, 0x2e})
	add("extra.pkl", gadget)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	l := limits.Default()
	l.MaxStringBlob = 1024 // storages (4117 bytes) exceeds MaxStringBlob
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	src := source.Mem("model.pt", tbuf.Bytes())
	defer src.Close()
	if _, err := artifact.Scan(sess.NewCtx("model.pt", l), src); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var sawStoragesCritical, sawExtraCritical bool
	for _, f := range c.Findings() {
		if f.Artifact == "model.pt:extra.pkl:extra.pkl" {
			t.Fatalf("double-nested artifact name: %+v", f)
		}
		if f.RuleID == "SC4N-PICKLE-GLOBAL-CRITICAL" {
			if f.Artifact == "model.pt:storages" {
				sawStoragesCritical = true
			}
			if f.Artifact == "model.pt:extra.pkl" {
				sawExtraCritical = true
			}
		}
		if f.RuleID == "SC4N-LIMIT-STRING" {
			t.Fatalf("storages whose metadata pickle finished inside MaxStringBlob emitted SC4N-LIMIT-STRING: %+v", f)
		}
	}
	if !sawStoragesCritical {
		t.Fatalf("leading metadata pickle in large storages member was not scanned; findings=%v", c.Findings())
	}
	if !sawExtraCritical {
		t.Fatalf("extra.pkl member was not scanned at model.pt:extra.pkl; findings=%v", c.Findings())
	}
}
