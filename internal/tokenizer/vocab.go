// Vocabulary data vs tokenizer configuration.
//
// A tokenizer document is two things in one file: configuration the loader acts
// on (pre_tokenizer patterns, normalizer rules, decoder settings) and the
// vocabulary itself, a table of every token the model can emit. The vocabulary is
// *data*: byte-level BPE fills it with joiners, soft hyphens and bidi marks, and
// ordinary words such as `subprocess` are tokens like any other. Scanning the
// table as prose reported a code-execution finding on every Qwen tokenizer
// (Qwen3-0.6B/tokenizer.json:540591, vocab.json:346400) and a Unicode-anomaly
// finding on every multilingual one (bge-m3:799448, MiniLM-L12:550709).
package tokenizer

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// VocabSpans returns the byte ranges of a tokenizer document that hold vocabulary
// data, so a caller can scan the rest of the document and leave the table alone
// (stringscan.EmitExcept).
//
// It covers the shapes the Hub actually publishes: tokenizer.json keeps the table
// at `model.vocab` (token → id) and `model.merges` (a list of pairs); tiktoken-style
// files put `vocab` and `merges` at the top level; unigram.json carries
// `vocab` as a list of [token, score] pairs; and added_tokens[].content names a
// special token. A flat `{token: id}` document (vocab.json) has no marker at all,
// which is why the caller must know the file is a vocabulary before calling this.
//
// A malformed or truncated document yields the spans found before the error: the
// prefix that did decode is still vocabulary.
func VocabSpans(data []byte) []stringscan.Span {
	var spans []stringscan.Span
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		if err := walkValue(dec, nil, false, &spans); err != nil {
			return spans
		}
	}
}

// walkValue consumes exactly one JSON value, recording the span of every subtree
// whose path names vocabulary data. skipAll marks a subtree already inside such a
// span, so the table is recorded once instead of once per entry.
func walkValue(dec *json.Decoder, path []string, skipAll bool, spans *[]stringscan.Span) error {
	start := dec.InputOffset()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	entering := !skipAll && isVocabPath(path)
	skip := skipAll || entering
	d, delim := tok.(json.Delim)
	if !delim {
		if entering {
			*spans = append(*spans, stringscan.Span{Start: start, End: dec.InputOffset()})
		}
		return nil
	}
	switch d {
	case '{':
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			var nextPath []string
			if !skip {
				key, _ := kt.(string)
				nextPath = append(path, key)
			}
			if err := walkValue(dec, nextPath, skip, spans); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			var nextPath []string
			if !skip {
				nextPath = append(path, strconv.Itoa(i))
			}
			if err := walkValue(dec, nextPath, skip, spans); err != nil {
				return err
			}
		}
	default:
		// A closing delimiter cannot open a value; the stream is malformed.
		return io.ErrUnexpectedEOF
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if entering {
		*spans = append(*spans, stringscan.Span{Start: start, End: dec.InputOffset()})
	}
	return nil
}

// isVocabPath reports whether path names a vocabulary row.
func isVocabPath(path []string) bool {
	switch len(path) {
	case 1:
		return path[0] == "vocab" || path[0] == "merges"
	case 2:
		if path[0] == "model" {
			return path[1] == "vocab" || path[1] == "merges"
		}
		// An entry of a top-level vocab list or map: unigram.json's
		// [token, score] pairs, or a tiktoken-style vocab object.
		return path[0] == "vocab"
	case 3:
		return path[0] == "added_tokens" && path[2] == "content"
	}
	return false
}
