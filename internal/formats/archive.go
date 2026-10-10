package formats

import (
	// Zip, tar and the single-stream compression wrappers. Importing this file is
	// what links the archive walker into a binary; without it a zip would be
	// sniffed, reported as a container with no parser, and its members never
	// dispatched.
	_ "github.com/fr0g-66723067-io/sc4n/internal/archive"
)
