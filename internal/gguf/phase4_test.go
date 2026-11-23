package gguf_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/gguf"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestOversizedMetadataKeyIsSkippedNotMaterialised(t *testing.T) {
	key := strings.Repeat("k", 70000)
	data := build(spec{version: 3, kvs: []kv{
		{key: key, valType: 0, val: []byte{1}},
		{key: "general.alignment", valType: 0, val: []byte{32}},
	}})
	fs := findingsFor(t, data)
	if !hasRule(fs, "SC4N-GGUF-STRUCT") {
		t.Fatalf("oversized key was not reported; findings=%v", fs)
	}
}

func TestOversizedTensorNameIsNotMaterialised(t *testing.T) {
	name := strings.Repeat("t", 5000)
	data := build(spec{version: 3, tensors: []tensor{{name: name, dims: []uint64{1}, typ: 0, offset: 0}}, dataLen: 4})
	fs := findingsFor(t, data)
	if !hasRule(fs, "SC4N-GGUF-STRUCT") {
		t.Fatalf("oversized tensor name was not reported; findings=%v", fs)
	}
}

func TestTemplateAfterTheOldCapIsStillAnalysed(t *testing.T) {
	kvs := make([]kv, 0, 257)
	for i := 0; i < 257; i++ {
		kvs = append(kvs, kv{
			key:     "tokenizer.chat_template." + strconvItoa(i),
			valType: 8,
			val:     strb("{{ cycler.__init__.__globals__ }}", binary.LittleEndian),
		})
	}
	fs := findingsFor(t, build(spec{version: 3, kvs: kvs}))
	if !hasRule(fs, "SC4N-JINJA-PY-OBJECT") {
		t.Fatalf("a template after the old 256 cap was not analysed; findings=%v", fs)
	}
}

func TestChatTemplateRetentionHonoursMaxRetainedText(t *testing.T) {
	data := build(spec{version: 3, kvs: []kv{{
		key: "tokenizer.chat_template", valType: 8,
		val: strb("{{ cycler.__init__.__globals__ }}", binary.LittleEndian),
	}}})
	l := limits.Default()
	l.MaxRetainedText = 4
	c := reportCollector()
	m, err := gguf.Parse(source.Mem("t.gguf", data), l, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Templates) != 0 {
		t.Fatalf("retained %d templates under a 4-byte budget", len(m.Templates))
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func reportCollector() *report.Sink {
	return report.NewCollector(0).For("t.gguf")
}
