package formats

import (
	// The text-content routing layer: it reads README/model cards, tokenizer
	// JSON, Jinja templates, the HF config.json family and .gitattributes, and
	// runs the shared indicator engine over every other text file. Importing it
	// is what makes a .md, .json or .jinja artifact produce findings instead of
	// being read by nothing.
	_ "github.com/fr0g-66723067-io/sc4n/internal/content"
)
