package main

// tokenizerFixtures writes the fixtures for vocabulary data in tokenizer
// documents.
//
// A tokenizer document is configuration beside a table. The table holds every
// token the model can emit: byte-level BPE fills it with joiners, soft hyphens
// and bidi marks, and ordinary words such as `subprocess` are tokens like any
// other. Judging the table as prose reported code execution on every Qwen
// tokenizer (Qwen3-0.6B/tokenizer.json:540591, vocab.json:346400) and a
// Unicode-anomaly finding on every multilingual one (bge-m3:799448,
// MiniLM-L12:550709). The configuration around the table is still scanned, which
// is why each fixture here also asserts what must NOT be suppressed.
func init() {
	register(contributor{
		name:     "tokenizer",
		fixtures: tokenizerFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"tokenizer_vocab/tokenizer.json": {
					Expect: []string{"SC4N-TOKENIZER-REDOS"},
					Forbid: []string{"SC4N-METADATA-CODE", "SC4N-UNICODE-ANOMALY"},
					Notes: "A BPE tokenizer whose vocabulary holds the token `subprocess` and a token " +
						"carrying a bidi override, plus a pre_tokenizer pattern that backtracks " +
						"catastrophically. The vocabulary is data and is not judged as prose; the pattern " +
						"is configuration and is still reported.",
				},
				"tokenizer_vocab/vocab.json": {
					Forbid: []string{"SC4N-METADATA-CODE", "SC4N-UNICODE-ANOMALY"},
					Notes: "A flat {token: id} table with no marker for where the table starts, so the " +
						"whole document is vocabulary data: only the reachable-secret tier applies.",
				},
				"tokenizer_vocab/unigram.json": {
					Forbid: []string{"SC4N-METADATA-CODE", "SC4N-UNICODE-ANOMALY"},
					Notes: "A sentencepiece unigram vocabulary: the tokens sit in a top-level `vocab` " +
						"list of [token, score] pairs, which is a different shape from tokenizer.json's " +
						"`model.vocab` object.",
				},
				"tokenizer_vocab_control/tokenizer.json": {
					Expect: []string{"SC4N-METADATA-CODE"},
					Forbid: []string{"SC4N-UNICODE-ANOMALY"},
					Notes: "The positive control: the same vocabulary token `subprocess` is suppressed, " +
						"while an indicator outside the vocabulary (the normalizer chain) is still " +
						"reported at its own offset. Proves the suppression is scoped to the table.",
				},
				"benign/tokenizer_clean/tokenizer.json": {
					Notes: "An ordinary BPE tokenizer with no vocabulary anomaly and no RE2-hostile " +
						"pattern: a clean tokenizer must not gain a finding from the vocabulary pass.",
				},
			}, nil
		},
	})
}

func tokenizerFixtures(f *fixtureSet) {
	// The bidi override is written as the rune, not as a JSON escape: an escaped
	// \u202c would be ASCII in the file and would not discriminate.
	const bidi = "\u202c"

	f.addText("tokenizer_vocab/tokenizer.json",
		`{
  "version": "1.0",
  "truncation": null,
  "padding": null,
  "added_tokens": [
    {"id": 0, "content": "<pad>", "special": true}
  ],
  "normalizer": null,
  "pre_tokenizer": {
    "type": "Sequence",
    "pretokenizers": [
      {"type": "Split", "pattern": {"Regex": "(\\w+)+"}, "behavior": "Isolated"}
    ]
  },
  "post_processor": null,
  "decoder": null,
  "model": {
    "type": "BPE",
    "dropout": null,
    "unk_token": "<unk>",
    "continuing_subword_prefix": null,
    "end_of_word_suffix": null,
    "fuse_unk": false,
    "vocab": {"<unk>": 0, "subprocess": 1, "a`+bidi+`b": 2, "Ġt": 3},
    "merges": ["a b", "Ġ t"]
  }
}
`)

	f.addText("tokenizer_vocab/vocab.json",
		`{"<unk>":0,"subprocess":1,"a`+bidi+`b":2,"Ġt":3}`+"\n")

	f.addText("tokenizer_vocab/unigram.json",
		`{
  "type": "Unigram",
  "unk_id": 3,
  "vocab": [
    ["<s>", 0.0],
    ["a`+bidi+`b", -3.4635426998138428],
    ["subprocess", -4.0]
  ]
}
`)

	f.addText("tokenizer_vocab_control/tokenizer.json",
		`{
  "version": "1.0",
  "added_tokens": [{"id": 0, "content": "<pad>", "special": true}],
  "normalizer": {"type": "Sequence", "normalizers": [{"type": "Prepend", "prepend": "eval("}]},
  "pre_tokenizer": {"type": "Whitespace"},
  "model": {
    "type": "BPE",
    "unk_token": "<unk>",
    "vocab": {"<unk>": 0, "subprocess": 1},
    "merges": []
  }
}
`)

	f.addText("benign/tokenizer_clean/tokenizer.json",
		`{
  "version": "1.0",
  "added_tokens": [{"id": 0, "content": "<pad>", "special": true}],
  "normalizer": {"type": "Lowercase"},
  "pre_tokenizer": {"type": "Whitespace"},
  "decoder": {"type": "WordPiece", "prefix": "##", "cleanup": true},
  "model": {
    "type": "WordPiece",
    "unk_token": "[UNK]",
    "continuing_subword_prefix": "##",
    "max_input_chars_per_word": 100,
    "vocab": {"[UNK]": 0, "[CLS]": 1, "hello": 2, "world": 3}
  }
}
`)
}
