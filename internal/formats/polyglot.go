package formats

import (
	// The universal polyglot/native-magic layer. It installs itself with
	// artifact.RegisterUniversal from its own init, so importing it is what makes
	// every artifact (and every nested member) pass through it.
	_ "github.com/fr0g-66723067-io/sc4n/internal/polyglot"
)
