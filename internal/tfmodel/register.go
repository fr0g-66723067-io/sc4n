package tfmodel

// register.go wires the TensorFlow family into the artifact registry: the five
// capability rows, the discriminating sniffers and the parsers.
//
// Sniffer priorities and why they sit where they do:
//
//   - keras-zip 103: above the generic magic sniffer (100), because a file that
//     starts PK\x03\x04 is claimed as a bare zip there. The member set
//     (config.json + model.weights.h5) is disjoint from torch/pt2/npz, so it
//     neither swallows nor is swallowed by them.
//   - tfjs-model 64: JSON, above the text fallback, below the Python/notebook
//     sniffers that may also see a JSON-ish file.
//   - tf-checkpoint 61: above the ONNX sniffer (60), because a checkpoint index
//     happens to open with a field-1 varint that ONNX's shape probe reads as a
//     plausible ir_version. There is no magic to dispatch on, so the name
//     suffix .index is the discriminator.
//   - tf-savedmodel 58: below ONNX (60), so the more decisive ModelProto probe
//     gets first refusal and the plan's "record the ambiguity, do not guess"
//     posture is preserved.
//
// HDF5 and TFLite need no sniffer: both have fixed magics that the magic table
// already claims (HDF5 at offset 0, "TFL3" at offset 4), so only the parsers and
// capability rows are registered here.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatKeras,
		Magic:     "PK\\x03\\x04 with config.json and model.weights.h5 members",
		Depth:     artifact.DepthDeep,
		Container: true,
		Notes: "the .keras zip's config.json and metadata.json are decoded and the class allowlist is " +
			"applied to every class_name/registered_name; Lambda and TorchModuleWrapper are critical. Code " +
			"strings (including the base64 Lambda payload) are handed to the Python analyzer and the " +
			"indicator engine. Every member is then walked by the generic archive parser, so a pickle, an " +
			"embedded HDF5 or an executable member reaches its own engine. The weights themselves are not " +
			"decoded.",
	})
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatHDF5,
		Magic:     "\\x89HDF\\r\\n\\x1a\\n",
		Depth:     artifact.DepthShallow,
		Container: false,
		Notes: "SHALLOW: v1 does NOT implement an HDF5 object-header reader, so the object graph is not " +
			"walked. The scan is bounded to the first 16 MiB and last 1 MiB of the file, from which it " +
			"recovers JSON documents (a Keras model_config) and applies the same class allowlist as " +
			".keras, and reports path-shaped strings as a low-confidence SC4N-HDF5-EXTERNAL-LINK. " +
			"Keras ignores safe_mode for H5, so a Lambda here is at least as dangerous as one in a " +
			".keras. Attributes outside the scanned window are not seen.",
	})
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatTFSavedModel,
		Magic:  "protobuf SavedModel/MetaGraphDef/GraphDef, or a TF-JS model.json",
		Depth:  artifact.DepthStructural,
		Notes: "the protobuf is walked SavedModel -> MetaGraphDef -> GraphDef -> NodeDef (and " +
			"FunctionDefLibrary -> FunctionDef -> NodeDef); PyFunc/EagerPyFunc and file-IO ops with an " +
			"escaping path are reported, and op attributes are run through the indicator engine. TF-JS " +
			"model.json is walked for op names, Flex ops and manifest paths. The variables.data-* shard " +
			"contents are not decoded.",
	})
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatTFCheckpoint,
		Magic:  "protobuf BundleHeaderProto; recognised by a .index name plus shard-count shape",
		Depth:  artifact.DepthShallow,
		Notes: "a bare checkpoint stores variables and no graph, so there is no inline code to find. Only " +
			"the bundle header framing and a bounded indicator scan run; an informational note records " +
			"that the verdict means \"no code here\", not \"safe to load\".",
	})
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatTFLite,
		Magic:  "TFL3 at offset 4",
		Depth:  artifact.DepthStructural,
		Notes: "a minimal flatbuffer walk of the root Model table: operator codes (custom_code, " +
			"BuiltinOperator.CUSTOM), operators (custom_options) and buffers (embedded native magic, " +
			"entropy outliers). The tensor payloads are not decoded and the builtin operator semantics " +
			"are not modelled.",
	})

	artifact.RegisterSniffer("keras-zip", 103, sniffKeras)
	artifact.RegisterSniffer("tfjs-model", 64, sniffTFJS)
	artifact.RegisterSniffer("tf-checkpoint", 61, sniffCheckpoint)
	artifact.RegisterSniffer("tf-savedmodel", 58, sniffSavedModel)

	artifact.RegisterParser(artifact.FormatKeras, kerasParser{})
	artifact.RegisterParser(artifact.FormatHDF5, hdf5Parser{})
	artifact.RegisterParser(artifact.FormatTFSavedModel, savedModelParser{})
	artifact.RegisterParser(artifact.FormatTFCheckpoint, checkpointParser{})
	artifact.RegisterParser(artifact.FormatTFLite, tfliteParser{})

	artifact.RegisterUniversal("tf-savedmodel-assets", assetsUniversal)
}

// assetsUniversal reports an executable parked under a SavedModel's assets/
// directory.
//
// The engine scans files individually, so a SavedModel directory is not one
// artifact: assets/run.sh is its own artifact and no parser can see its sibling
// saved_model.pb. This layer therefore fires when the display name is under an
// assets/ (or assets.extra/) directory AND an ancestor directory holds a
// saved_model.pb, which is what makes the finding about a SavedModel and not about
// any directory that happens to be called assets.
func assetsUniversal(ctx *artifact.Ctx, s source.Source, f artifact.Format) {
	name := ctx.Sink.Artifact()
	if strings.ContainsRune(name, ':') {
		return // an archive member: the on-disk ancestor check does not apply
	}
	if !strings.Contains(name, "/assets/") && !strings.Contains(name, "/assets.extra/") {
		return
	}
	if !savedModelAncestor(name) {
		return
	}
	n := s.Size()
	if n > 1024 {
		n = 1024
	}
	b, err := s.Bytes(0, n)
	if err != nil && len(b) == 0 {
		return
	}
	if kind, ok := bytescan.ValidNative(b); ok {
		ctx.Sink.EmitExtra(ruleTFAssetExecutable, 0,
			"validated "+kind.String()+" under a SavedModel assets directory",
			map[string]string{"kind": kind.String(), "path": baseNameOf(name)})
		return
	}
	if interp, ok := bytescan.ShebangAt(b); ok {
		ctx.Sink.EmitExtra(ruleTFAssetExecutable, 0,
			"script ("+interp+") under a SavedModel assets directory",
			map[string]string{"interpreter": interp, "path": baseNameOf(name)})
	}
}

// savedModelAncestor reports whether a directory at or above name's parent holds
// saved_model.pb. The walk is bounded so a path deep in a tree cannot make it
// unbounded.
func savedModelAncestor(name string) bool {
	dir := filepath.Dir(name)
	for range 5 {
		if _, err := os.Stat(filepath.Join(dir, "saved_model.pb")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "." {
			return false
		}
		dir = parent
	}
	return false
}

// baseNameOf returns the final path element of a display name.
func baseNameOf(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}
