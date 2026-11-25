package tfmodel

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestTFLiteSnifferValidatesFlatBuffers(t *testing.T) {
	// Valid minimal FlatBuffers TFL3 file.
	valid := make([]byte, 64)
	binary.LittleEndian.PutUint32(valid[0:], 24)
	copy(valid[4:8], "TFL3")
	for i, v := range []uint16{8, 8, 0, 0} {
		binary.LittleEndian.PutUint16(valid[12+2*i:], v)
	}
	binary.LittleEndian.PutUint32(valid[24:], 12) // soffset -> vtable @12

	if f, ok := sniffTFLite(source.Mem("m.tflite", valid), limits.Default()); !ok || f != artifact.FormatTFLite {
		t.Fatalf("valid tflite sniffed as %v, %v", f, ok)
	}

	// Counter-examples: pickle, JSON, Python containing "TFL3" at offset 4.
	rejects := map[string][]byte{
		"python": []byte("x = TFL3 + 1\nprint(x)\n"),
		"json":   []byte(`{"a"TFL3:1234567890}`),
		"pickle": append([]byte{0x80, 0x04, 0x95, 0x10}, []byte("TFL3payload12345678")...),
		"badroot": func() []byte {
			b := make([]byte, 64)
			binary.LittleEndian.PutUint32(b[0:], 4) // root < 8
			copy(b[4:8], "TFL3")
			return b
		}(),
		"badvtable": func() []byte {
			b := make([]byte, 32)
			binary.LittleEndian.PutUint32(b[0:], 16)
			copy(b[4:8], "TFL3")
			binary.LittleEndian.PutUint32(b[16:], 9999) // vtable outside file
			return b
		}(),
	}
	for name, data := range rejects {
		if f, ok := sniffTFLite(source.Mem(name, data), limits.Default()); ok {
			t.Errorf("%s with TFL3 at offset 4 was hijacked as %v", name, f)
		}
	}
}

func TestTFJSSnifferDoesNotHijackNonTFJS(t *testing.T) {
	tfjs := []byte(`{"format":"graph-model","modelTopology":{"node":[]},"weightsManifest":[]}`)
	if f, ok := sniffTFJS(source.Mem("model.json", tfjs), limits.Default()); !ok || f != artifact.FormatTFSavedModel {
		t.Fatalf("valid TF-JS sniffed as %v, %v", f, ok)
	}
	// sniffSavedModel must defer JSON to sniffTFJS at its own priority.
	if f, ok := sniffSavedModel(source.Mem("model.json", tfjs), limits.Default()); ok {
		t.Fatalf("sniffSavedModel claimed JSON as %v instead of deferring to sniffTFJS", f)
	}

	rejects := map[string][]byte{
		"tokenizer_config.json": []byte(`{"chat_template":"mention modelTopology here","model_max_length":2048}`),
		"config.json":           []byte(`{"architectures":["LlamaForCausalLM"],"notes":{"weightsManifest":"doc"}}`),
		"notebook.ipynb":        []byte(`{"nbformat":4,"cells":[{"cell_type":"code","source":["x = 'modelTopology'"]}]}`),
		"script.py":             []byte("def load():\n    return 'modelTopology and weightsManifest'\n"),
		"array.json":            []byte(`[{"modelTopology":{}}]`),
	}
	for name, data := range rejects {
		if f, ok := sniffTFJS(source.Mem(name, data), limits.Default()); ok {
			t.Errorf("sniffTFJS hijacked %s as %v", name, f)
		}
		if f, ok := sniffSavedModel(source.Mem(name, data), limits.Default()); ok {
			t.Errorf("sniffSavedModel hijacked %s as %v", name, f)
		}
	}
}

func TestSavedModelConstToFileIOCorrelationAndPyFuncStateless(t *testing.T) {
	// Helper: AttrValue{tensor=8: TensorProto{dtype=1:7, string_val=8 or tensor_content=4}}
	makeConstNode := func(name string, useContent bool, val string) []byte {
		var tensor []byte
		tensor = append(tensor, pbVarintField(1, dtString)...)
		if useContent {
			tc := append(protowire.AppendVarint(nil, uint64(len(val))), []byte(val)...)
			tensor = append(tensor, pbField(4, tc)...)
		} else {
			tensor = append(tensor, pbField(8, []byte(val))...)
		}
		attrVal := pbField(8, tensor)
		attrEntry := append(pbField(1, []byte("value")), pbField(2, attrVal)...)
		node := pbNodeDef(name, "Const")
		return append(node, pbField(5, attrEntry)...)
	}
	makeFileIONode := func(name, op, input string) []byte {
		node := pbNodeDef(name, op)
		return append(node, pbField(3, []byte(input))...)
	}

	// Case 1: Const with string_val -> ReadFile via input "const_sv:0"
	g1 := append(pbField(1, makeConstNode("const_sv", false, "/etc/passwd")),
		pbField(1, makeFileIONode("rf", "ReadFile", "const_sv:0"))...)
	sm1 := append(pbVarintField(1, 1), pbField(2, pbField(2, g1))...)
	if got := ids(parseBytes(t, savedModelParser{}, "saved_model.pb", sm1)); !got["SC4N-TF-FILE-IO"] {
		t.Fatalf("Const(string_val) -> ReadFile not correlated; got %v", got)
	}

	// Case 2: Const with varint-prefixed tensor_content -> WriteFile via input "const_tc"
	g2 := append(pbField(1, makeConstNode("const_tc", true, "../../etc/cron.d/pwn")),
		pbField(1, makeFileIONode("wf", "WriteFile", "const_tc"))...)
	sm2 := append(pbVarintField(1, 1), pbField(2, pbField(2, g2))...)
	if got := ids(parseBytes(t, savedModelParser{}, "saved_model.pb", sm2)); !got["SC4N-TF-FILE-IO"] {
		t.Fatalf("Const(tensor_content) -> WriteFile not correlated; got %v", got)
	}

	// Case 3: PyFuncStateless in protobuf and TF-JS
	g3 := pbField(1, pbNodeDef("pfs", "PyFuncStateless"))
	sm3 := append(pbVarintField(1, 1), pbField(2, pbField(2, g3))...)
	if got := ids(parseBytes(t, savedModelParser{}, "saved_model.pb", sm3)); !got["SC4N-TF-PYFUNC"] {
		t.Fatalf("PyFuncStateless in SavedModel not reported; got %v", got)
	}
	tfjs := []byte(`{"modelTopology":{"node":[{"name":"pfs","op":"PyFuncStateless"}]}}`)
	if got := ids(parseBytes(t, savedModelParser{}, "model.json", tfjs)); !got["SC4N-TF-PYFUNC"] {
		t.Fatalf("PyFuncStateless in TF-JS not reported; got %v", got)
	}
}

func TestBareGraphDefFunctionDefLibraryAndMalformedTags(t *testing.T) {
	// Bare GraphDef: field 1 = NodeDef, field 2 = FunctionDefLibrary{function=1{node_def=3: PyFunc}}
	fnDef := pbField(3, pbNodeDef("hidden_py", "PyFunc"))
	fnLib := pbField(1, fnDef)
	bareGraph := append(pbField(1, pbNodeDef("in", "Placeholder")), pbField(2, fnLib)...)

	got := ids(parseBytes(t, savedModelParser{}, "graph.pb", bareGraph))
	if !got["SC4N-TF-PYFUNC"] {
		t.Fatalf("bare GraphDef FunctionDefLibrary PyFunc was missed; got %v", got)
	}
	if got["SC4N-TF-STRUCT"] {
		t.Fatalf("bare GraphDef FunctionDefLibrary emitted bogus SC4N-TF-STRUCT; got %v", got)
	}

	// Malformed trailing protobuf tag must emit SC4N-TF-STRUCT instead of breaking silently.
	malformed := append(append([]byte{}, bareGraph...), 0xff, 0xff)
	gotBad := ids(parseBytes(t, savedModelParser{}, "bad.pb", malformed))
	if !gotBad["SC4N-TF-STRUCT"] {
		t.Fatalf("malformed trailing protobuf tag was silent; got %v", gotBad)
	}
}

func TestAssetsUniversalRelativePathAndLargeELF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "saved_model.pb"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	assetsDir := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	elfBytes := largeELFWithLateSectionTable(8192)
	t.Chdir(dir)

	c := report.NewCollector(0)
	l := limits.Default()
	sess := artifact.NewSession(c, "", l)
	ctx := sess.NewCtx("assets/libevil.so", l)
	src := source.Mem("assets/libevil.so", elfBytes)
	defer src.Close()
	assetsUniversal(ctx, src, artifact.FormatNative)
	if !ids(c)["SC4N-TF-ASSET-EXECUTABLE"] {
		t.Fatalf("relative assets/libevil.so with >4KiB ELF was missed; got %v", ids(c))
	}
}

// largeELFWithLateSectionTable builds a valid ELF64 binary whose section header
// table sits at shoff (e.g. 8192 > 4 KiB), so validating against a 1 KiB or
// 4 KiB truncated buffer fails while validating against the full source succeeds.
func largeELFWithLateSectionTable(shoff uint64) []byte {
	b := make([]byte, shoff+64)
	copy(b, "\x7fELF")
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // ELFDATA2LSB
	b[6] = 1 // EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], 3)     // ET_DYN
	le.PutUint16(b[18:], 0x3e)  // EM_X86_64
	le.PutUint32(b[20:], 1)     // EV_CURRENT
	le.PutUint64(b[40:], shoff) // e_shoff beyond 4 KiB
	le.PutUint16(b[52:], 64)    // e_ehsize
	le.PutUint16(b[58:], 64)    // e_shentsize
	le.PutUint16(b[60:], 1)     // e_shnum = 1 (null section header at shoff)
	return b
}

func TestTFLiteDeprecatedCustomOpAndLargeBufferELF(t *testing.T) {
	// 1. OperatorCode with deprecated_builtin_code (field 0 == 32) and field 3 absent.
	buf := make([]byte, 256)
	binary.LittleEndian.PutUint32(buf[0:], 32)
	copy(buf[4:8], "TFL3")
	// Root vtable @12: vtsize=8, tablesize=8, field0=0, field1=4
	for i, v := range []uint16{8, 8, 0, 4} {
		binary.LittleEndian.PutUint16(buf[12+2*i:], v)
	}
	// Root table @32: soffset=20 -> vtable@12; field1 @36 -> vector @64 (rel=28)
	binary.LittleEndian.PutUint32(buf[32:], 20)
	binary.LittleEndian.PutUint32(buf[36:], 28)
	// operator_codes vector @64: count=1, slot0 @68 -> OperatorCode @96 (rel=28)
	binary.LittleEndian.PutUint32(buf[64:], 1)
	binary.LittleEndian.PutUint32(buf[68:], 28)
	// OperatorCode vtable @80: vtsize=6, tablesize=8, field0=4 (only deprecated_builtin_code!)
	for i, v := range []uint16{6, 8, 4} {
		binary.LittleEndian.PutUint16(buf[80+2*i:], v)
	}
	// OperatorCode table @96: soffset=16 -> vtable@80; field0 @100 = 32 (CUSTOM)
	binary.LittleEndian.PutUint32(buf[96:], 16)
	buf[100] = builtinOperatorCustom

	if got := ids(parseBytes(t, tfliteParser{}, "dep.tflite", buf)); !got["SC4N-TFLITE-CUSTOM-OP"] {
		t.Fatalf("deprecated_builtin_code CUSTOM not reported; got %v", got)
	}

	// 2. Buffer carrying an ELF whose section header table is past 4 KiB.
	elfPayload := largeELFWithLateSectionTable(8192)
	total := 256 + len(elfPayload)
	tbuf := make([]byte, total)
	binary.LittleEndian.PutUint32(tbuf[0:], 32)
	copy(tbuf[4:8], "TFL3")
	// Root vtable @12: vtsize=14, tablesize=12, field0..4: only field4=4
	for i, v := range []uint16{14, 12, 0, 0, 0, 0, 4} {
		binary.LittleEndian.PutUint16(tbuf[12+2*i:], v)
	}
	// Root table @32: soffset=20 -> vtable@12; field4 @36 -> buffers vector @64 (rel=28)
	binary.LittleEndian.PutUint32(tbuf[32:], 20)
	binary.LittleEndian.PutUint32(tbuf[36:], 28)
	// buffers vector @64: count=1, slot0 @68 -> Buffer table @96 (rel=28)
	binary.LittleEndian.PutUint32(tbuf[64:], 1)
	binary.LittleEndian.PutUint32(tbuf[68:], 28)
	// Buffer vtable @80: vtsize=6, tablesize=8, field0=4
	for i, v := range []uint16{6, 8, 4} {
		binary.LittleEndian.PutUint16(tbuf[80+2*i:], v)
	}
	// Buffer table @96: soffset=16 -> vtable@80; field0 @100 -> byte vector @128 (rel=28)
	binary.LittleEndian.PutUint32(tbuf[96:], 16)
	binary.LittleEndian.PutUint32(tbuf[100:], 28)
	binary.LittleEndian.PutUint32(tbuf[128:], uint32(len(elfPayload)))
	copy(tbuf[132:], elfPayload)

	if got := ids(parseBytes(t, tfliteParser{}, "large_elf.tflite", tbuf)); !got["SC4N-TFLITE-NATIVE-MAGIC"] {
		t.Fatalf("TFLite buffer with >4KiB ELF was missed; got %v", got)
	}
}

func TestKerasAllowlistTightenedAndDepthLimitsReported(t *testing.T) {
	// Wildcard evasion names must NOT be marked safe.
	for _, bad := range []string{"RandomEvil", "ConvExploit", "EvilDropout", "EvilNormalization", "PreprocessingExploit"} {
		if kerasClassSafe(bad) {
			t.Errorf("kerasClassSafe(%q) = true, want false", bad)
		}
	}

	// Non-Keras module prefixes must NOT be stripped to mark safe.
	for _, bad := range []string{"evil_pkg>Dense", "evil.Dense", "custom>Conv2D"} {
		ctx, c := newTestCtx()
		analyzeKerasDocument(ctx, 0, "config.json", []byte(`{"registered_name":"`+bad+`"}`))
		if !ids(c)["SC4N-KERAS-CLASS-UNKNOWN"] {
			t.Errorf("non-Keras qualified name %q was allowed", bad)
		}
	}
	// Legitimate Keras namespaces remain allowed.
	for _, okName := range []string{"keras.layers.Dense", "tensorflow.keras.layers.BatchNormalization", "keras>Conv2D"} {
		ctx, c := newTestCtx()
		analyzeKerasDocument(ctx, 0, "config.json", []byte(`{"registered_name":"`+okName+`"}`))
		if ids(c)["SC4N-KERAS-CLASS-UNKNOWN"] {
			t.Errorf("legitimate Keras name %q was rejected", okName)
		}
	}

	// Depth > maxJSONDepth must emit SC4N-LIMIT-DEPTH.
	deep := strings.Repeat(`{"a":`, maxJSONDepth+5) + `{"class_name":"Evil"}` + strings.Repeat(`}`, maxJSONDepth+5)
	ctx, c := newTestCtx()
	analyzeKerasDocument(ctx, 0, "config.json", []byte(deep))
	if !ids(c)["SC4N-LIMIT-DEPTH"] {
		t.Fatalf("JSON nesting past maxJSONDepth was silent; got %v", ids(c))
	}

	// Exhausted container depth in analyzeCodeValue must emit SC4N-LIMIT-DEPTH.
	l := limits.Default()
	l.MaxDepth = 0
	c2 := report.NewCollector(0)
	sess := artifact.NewSession(c2, "", l)
	ctx2 := sess.NewCtx("config.json", l)
	analyzeCodeValue(ctx2, 0, "config.json", "function_source", "import os\nos.system('id')\n", &kerasBudget{})
	if !ids(c2)["SC4N-LIMIT-DEPTH"] {
		t.Fatalf("analyzeCodeValue depth exhaustion was silent; got %v", ids(c2))
	}
}

func TestHDF5TailWindowCloses16To17MiBGap(t *testing.T) {
	// 16.5 MiB HDF5 file with a Lambda JSON placed at 16 MiB + 64 KiB.
	const size = hdf5MaxPrefix + (512 << 10)
	data := make([]byte, size)
	copy(data, "\x89HDF\r\n\x1a\n")
	copy(data[hdf5MaxPrefix+(64<<10):], `{"class_name":"Lambda","config":{}}`)

	c := parseBytes(t, hdf5Parser{}, "gap.h5", data)
	if !ids(c)["SC4N-KERAS-LAMBDA"] {
		t.Fatalf("Lambda inside the 16-17 MiB gap was missed; got %v", ids(c))
	}
}
