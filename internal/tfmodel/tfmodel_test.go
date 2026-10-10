package tfmodel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// newTestCtx builds a standalone scan context: a fresh collector and session, so
// a test can assert on the exact finding set.
func newTestCtx() (*artifact.Ctx, *report.Collector) {
	l := limits.Default()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	return sess.NewCtx("test", l), c
}

// ids returns the set of rule IDs in a collector.
func ids(c *report.Collector) map[string]bool {
	out := map[string]bool{}
	for _, f := range c.Findings() {
		out[f.RuleID] = true
	}
	return out
}

// fixture reads a generated fixture, skipping the test when the corpus has not
// been generated on this checkout.
func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", filepath.FromSlash(rel)))
	if err != nil {
		t.Skipf("fixture %s not present: %v", rel, err)
	}
	return b
}

func parseBytes(t *testing.T, p artifact.Parser, name string, data []byte) *report.Collector {
	t.Helper()
	ctx, c := newTestCtx()
	src := source.Mem(name, data)
	defer src.Close()
	_ = p.Parse(ctx, src)
	return c
}

// --- class allowlist ---------------------------------------------------

func TestKerasClassAllowlist(t *testing.T) {
	cases := []struct {
		name string
		safe bool
	}{
		{"Sequential", true},
		{"Functional", true},
		{"InputLayer", true},
		{"Dense", true},
		{"Conv2D", true},
		{"SeparableConv1D", true},
		{"GlobalAveragePooling2D", true},
		{"BatchNormalization", true},
		{"LayerNormalization", true},
		{"RandomFlip", true},
		{"PreprocessingNormalization", true},
		{"Dropout", true},
		{"MultiHeadAttention", true},
		{"__lambda__", true}, // the Lambda marker is owned by the Lambda rule
		{"", true},
		{"EvilCustomLayer", false},
		// Lambda and TorchModuleWrapper are not in the safe set; checkKerasClass
		// reports them with their own critical rules before consulting it.
		{"Lambda", false},
		{"TorchModuleWrapper", false},
	}
	for _, tc := range cases {
		if got := kerasClassSafe(tc.name); got != tc.safe {
			t.Errorf("kerasClassSafe(%q) = %v, want %v", tc.name, got, tc.safe)
		}
	}
}

// --- Keras config analysis ---------------------------------------------

func TestAnalyzeKerasDocumentClasses(t *testing.T) {
	doc := `{"class_name":"Sequential","config":{"layers":[` +
		`{"class_name":"Dense","config":{"units":4}},` +
		`{"class_name":"EvilLayer","config":{}},` +
		`{"class_name":"Lambda","config":{"function":{"class_name":"__lambda__","config":{"code":"aW1wb3J0IG9z"}}}}]}}`
	ctx, c := newTestCtx()
	analyzeKerasDocument(ctx, 0, "config.json", []byte(doc))
	got := ids(c)
	if !got["SC4N-KERAS-LAMBDA"] {
		t.Error("Lambda layer not reported")
	}
	if !got["SC4N-KERAS-CLASS-UNKNOWN"] {
		t.Error("unknown class not reported")
	}
	if got["SC4N-KERAS-TORCH-WRAPPER"] {
		t.Error("TorchModuleWrapper reported for a document without one")
	}
}

func TestAnalyzeKerasTorchWrapper(t *testing.T) {
	doc := `{"class_name":"Functional","config":{"layers":[{"class_name":"TorchModuleWrapper","config":{}}]}}`
	ctx, c := newTestCtx()
	analyzeKerasDocument(ctx, 0, "config.json", []byte(doc))
	if !ids(c)["SC4N-KERAS-TORCH-WRAPPER"] {
		t.Error("TorchModuleWrapper not reported")
	}
}

func TestAnalyzeKerasDocumentMalformed(t *testing.T) {
	ctx, c := newTestCtx()
	analyzeKerasDocument(ctx, 0, "config.json", []byte("{not json"))
	if !ids(c)["SC4N-KERAS-STRUCT"] {
		t.Error("malformed config did not produce SC4N-KERAS-STRUCT")
	}
}

func TestAnalyzeKerasDeterministic(t *testing.T) {
	doc := `{"class_name":"Model","a":{"class_name":"Zeta"},"b":{"class_name":"Alpha"},` +
		`"c":{"class_name":"Mid"},"d":{"class_name":"Alpha"}}`
	render := func() []string {
		ctx, c := newTestCtx()
		analyzeKerasDocument(ctx, 0, "config.json", []byte(doc))
		var out []string
		for _, f := range c.Findings() {
			out = append(out, f.RuleID+"|"+f.Evidence)
		}
		return out
	}
	a, b := render(), render()
	if len(a) != len(b) {
		t.Fatalf("finding count differs between runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("finding %d differs:\n%s\n%s", i, a[i], b[i])
		}
	}
}

// --- fixture-driven parser tests ---------------------------------------

func TestKerasFixtures(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"keras_lambda.keras", "SC4N-KERAS-LAMBDA"},
		{"keras_torch_wrapper.keras", "SC4N-KERAS-TORCH-WRAPPER"},
		{"keras_unknown_class.keras", "SC4N-KERAS-CLASS-UNKNOWN"},
	}
	for _, tc := range cases {
		data := fixture(t, tc.file)
		c := parseBytes(t, kerasParser{}, tc.file, data)
		if !ids(c)[tc.want] {
			t.Errorf("%s: missing %s; got %v", tc.file, tc.want, ids(c))
		}
	}
}

func TestHDF5Fixtures(t *testing.T) {
	c := parseBytes(t, hdf5Parser{}, "h5_lambda.h5", fixture(t, "h5_lambda.h5"))
	if !ids(c)["SC4N-KERAS-LAMBDA"] {
		t.Errorf("h5 lambda not reported; got %v", ids(c))
	}
	c = parseBytes(t, hdf5Parser{}, "h5_external_link.h5", fixture(t, "h5_external_link.h5"))
	if !ids(c)["SC4N-HDF5-EXTERNAL-LINK"] {
		t.Errorf("h5 external link not reported; got %v", ids(c))
	}
}

func TestSavedModelFixtures(t *testing.T) {
	c := parseBytes(t, savedModelParser{}, "saved_model.pb", fixture(t, "tf_savedmodel_bad/saved_model.pb"))
	got := ids(c)
	if !got["SC4N-TF-PYFUNC"] || !got["SC4N-TF-FILE-IO"] {
		t.Errorf("savedmodel findings = %v, want PYFUNC and FILE-IO", got)
	}
}

func TestTFLiteFixtures(t *testing.T) {
	c := parseBytes(t, tfliteParser{}, "tflite_customop.tflite", fixture(t, "tflite_customop.tflite"))
	if !ids(c)["SC4N-TFLITE-CUSTOM-OP"] {
		t.Errorf("custom op not reported; got %v", ids(c))
	}
	c = parseBytes(t, tfliteParser{}, "tflite_native.tflite", fixture(t, "tflite_native.tflite"))
	if !ids(c)["SC4N-TFLITE-NATIVE-MAGIC"] {
		t.Errorf("native magic not reported; got %v", ids(c))
	}
}

func TestTFJSFixture(t *testing.T) {
	c := parseBytes(t, savedModelParser{}, "model.json", fixture(t, "tfjs_flex/model.json"))
	got := ids(c)
	if !got["SC4N-TFJS-FLEX-OP"] || !got["SC4N-TF-FILE-IO"] {
		t.Errorf("tfjs findings = %v, want FLEX-OP and FILE-IO", got)
	}
}

func TestCheckpointFixture(t *testing.T) {
	c := parseBytes(t, checkpointParser{}, "variables.index", fixture(t, "tf_checkpoint/variables.index"))
	if !ids(c)["SC4N-TF-CHECKPOINT-NO-CODE"] {
		t.Errorf("checkpoint note missing; got %v", ids(c))
	}
}

// --- adversarial / no-panic --------------------------------------------

func TestNoPanicTruncatedFixtures(t *testing.T) {
	files := map[string]artifact.Parser{
		"keras_lambda.keras":               kerasParser{},
		"h5_lambda.h5":                     hdf5Parser{},
		"tf_savedmodel_bad/saved_model.pb": savedModelParser{},
		"tflite_customop.tflite":           tfliteParser{},
		"tfjs_flex/model.json":             savedModelParser{},
	}
	for name, p := range files {
		data := fixture(t, name)
		limit := min(len(data), 255)
		for cut := range limit + 1 {
			ctx, _ := newTestCtx()
			src := source.Mem(name, data[:cut])
			_ = p.Parse(ctx, src)
			_ = src.Close()
		}
	}
}

// TestAdversarialBytes feeds each parser deterministic hostile patterns: every
// single byte repeated, an all-0xFF run, and a HDF5/TFL3 magic followed by
// garbage. None may panic, and every parser must return rather than loop.
func TestAdversarialBytes(t *testing.T) {
	parsers := map[string]artifact.Parser{
		"keras.keras":     kerasParser{},
		"h5.h5":           hdf5Parser{},
		"model.pb":        savedModelParser{},
		"model.tflite":    tfliteParser{},
		"variables.index": checkpointParser{},
	}
	var inputs [][]byte
	for _, b := range []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff} {
		inputs = append(inputs, []byte{b, b, b, b, b, b, b, b})
	}
	inputs = append(inputs,
		[]byte("\x89HDF\r\n\x1a\n"+strings.Repeat("\xff", 256)),
		[]byte("\x00\x00\x00\x00TFL3"+strings.Repeat("\xff", 256)),
		[]byte("PK\x03\x04"+strings.Repeat("\x00", 256)),
		[]byte(strings.Repeat("{", 512)),
	)
	for name, p := range parsers {
		for _, in := range inputs {
			ctx, _ := newTestCtx()
			src := source.Mem(name, in)
			_ = p.Parse(ctx, src)
			_ = src.Close()
		}
	}
}

// --- fuzz targets ------------------------------------------------------

func FuzzKerasDocument(f *testing.F) {
	f.Add([]byte(`{"class_name":"Lambda"}`))
	f.Add([]byte(`{"class_name":"Sequential","config":{"layers":[]}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, _ := newTestCtx()
		analyzeKerasDocument(ctx, 0, "config.json", data)
	})
}

func FuzzKerasParse(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("not a zip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, _ := newTestCtx()
		src := source.Mem("fuzz.keras", data)
		defer src.Close()
		_ = kerasParser{}.Parse(ctx, src)
	})
}

func FuzzSavedModelParse(f *testing.F) {
	f.Add([]byte("\x0a\x00"))
	f.Add([]byte(`{"modelTopology":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, _ := newTestCtx()
		src := source.Mem("fuzz.pb", data)
		defer src.Close()
		_ = savedModelParser{}.Parse(ctx, src)
	})
}

func FuzzTFLiteParse(f *testing.F) {
	f.Add([]byte("TFL3"))
	f.Add([]byte{0x08, 0x00, 0x00, 0x00, 'T', 'F', 'L', '3'})
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, _ := newTestCtx()
		src := source.Mem("fuzz.tflite", data)
		defer src.Close()
		_ = tfliteParser{}.Parse(ctx, src)
	})
}

func FuzzHDF5Parse(f *testing.F) {
	f.Add([]byte("\x89HDF\r\n\x1a\n"))
	f.Add([]byte("\x89HDF\r\n\x1a\n\x00\x00\x00\x00{\"class_name\":\"Lambda\"}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, _ := newTestCtx()
		src := source.Mem("fuzz.h5", data)
		defer src.Close()
		_ = hdf5Parser{}.Parse(ctx, src)
	})
}

func FuzzCheckpointParse(f *testing.F) {
	f.Add([]byte("\x08\x01\x10\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, _ := newTestCtx()
		src := source.Mem("fuzz.index", data)
		defer src.Close()
		_ = checkpointParser{}.Parse(ctx, src)
	})
}

// TestPathEscapeReason pins the path classifier used by the file-IO rules.
func TestPathEscapeReason(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"weights.bin", ""},
		{"a/b/c.bin", ""},
		{"/etc/passwd", "absolute path"},
		{"../../etc/passwd", "'..' segment"},
		{"http://evil.example/x", "URL"},
		{"~/.ssh/id_rsa", "home-relative path"},
		{"C:\\x", "drive letter"},
		{"", ""},
		// The false positives measured on a real 40 KB Keras weights file: these
		// are printable runs out of tensor bytes, not paths.
		{"~&=Sa", ""},
		{"~?=t", ""},
		{"~e=)", ""},
		{"~k>Y", ""},
		{"J:=J.", ""},
		{"d=t", ""},
		{"<:c>@_F", ""},
		{"/d=t", ""},
	}
	for _, tc := range cases {
		if got := pathEscapeReason(tc.in); got != tc.want {
			t.Errorf("pathEscapeReason(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBaseNameOf covers the display-name trimming the assets layer relies on.
func TestBaseNameOf(t *testing.T) {
	if got := baseNameOf("a/b/assets/run.sh"); got != "run.sh" {
		t.Errorf("baseNameOf = %q", got)
	}
	if got := memberBase("dir/config.json"); got != "config.json" {
		t.Errorf("memberBase = %q", got)
	}
	if !strings.HasSuffix(clip("abcdef", 3), "...") {
		t.Error("clip did not truncate")
	}
}
