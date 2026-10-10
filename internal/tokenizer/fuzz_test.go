package tokenizer

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// FuzzTokenizerJSON asserts the tokenizer analyser never panics on arbitrary
// bytes. It parses an untrusted JSON document with its own decoder (the shapes
// it needs are nested and repeated), then walks every regex-shaped string
// looking for a catastrophic backtracking pattern.
func FuzzTokenizerJSON(f *testing.F) {
	f.Add(`{"pre_tokenizer":{"Regex":"(a+)+"}}`)
	f.Add(`{"model":{"type":"BPE","vocab":{}}}`)
	f.Add(`{"chat_template":"{{ ''.__class__ }}","added_tokens":[]}`)
	f.Add(`{"pre_tokenizer":{"type":"Sequence","pretokenizers":[{"type":"Split","pattern":{"Regex":"[0-9]+"}}]}}`)
	f.Add(`{`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, doc string) {
		if len(doc) > 1<<20 {
			t.Skip()
		}
		c := report.NewCollector(0)
		AnalyzeJSON(c.For("tokenizer.json"), 0, "tokenizer.json", []byte(doc))
		_ = ChatTemplates([]byte(doc))
	})
}
