package formats

import (
	// GGUF: the llama.cpp / ggml on-device model format. Importing it registers
	// the content sniffer and the parser with internal/artifact.
	_ "github.com/fr0g-66723067-io/sc4n/internal/gguf"
)
