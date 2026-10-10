package formats

import (
	// TensorFlow family: .keras (class allowlist, Lambda/TorchModuleWrapper), the
	// shallow .h5 reader, SavedModel/GraphDef and TF-JS protobuf+JSON walking, bare
	// TF checkpoints, and the TFLite flatbuffer.
	_ "github.com/fr0g-66723067-io/sc4n/internal/tfmodel"
)
