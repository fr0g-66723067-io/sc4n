package formats

import (
	// The shared indicator engine. It installs itself into the pickle engine's
	// string hook from its own init, so importing it is what makes a payload hidden
	// in a pickle string visible to the same rules that read a metadata value.
	_ "github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)
