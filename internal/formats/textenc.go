package formats

import (
	// UTF-16 text: BOM or NUL-interleaved recognition, decode to UTF-8 and
	// re-dispatch through the normal pipeline.
	_ "github.com/fr0g-66723067-io/sc4n/internal/utf16text"
)
