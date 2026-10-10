// Package formats exists only to register every format parser and universal scan
// layer with internal/artifact.
//
// Registration happens in package init, so a parser that nothing imports is
// silently absent from a binary: `sc4n scan` would report "unsupported format" for
// a pickle and still exit 0. Importing this package is therefore how a binary
// states which formats it contains, and it is the one place to extend when a new
// parser lands.
package formats

import (
	// Pickle family: bare pickles, and the walker every container reuses.
	_ "github.com/fr0g-66723067-io/sc4n/internal/pickle"
)
