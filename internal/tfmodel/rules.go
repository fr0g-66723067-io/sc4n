package tfmodel

// The TensorFlow / Keras / TFLite rule set.
//
// Every rule here is a detector rather than a style opinion, and each cites the
// advisory that makes it one. The Keras loader family is the densest: Keras
// deserialises a whole Python callable out of a JSON document, so a model file is
// a code-execution primitive on its normal load path (VU#253266 / CVE-2024-3660),
// the safe_mode checks have been bypassed repeatedly (CVE-2025-1550,
// CVE-2026-12481) and H5 loading silently ignores safe_mode altogether
// (GHSA-36rr-ww3j-vrjv).
//
// Severity is calibrated to the ecosystem, per docs/architecture.md: critical is
// code execution reachable from the normal load path, high is exploitable file
// access or an unvalidated code-loading surface, medium is suspicious but
// unproven, info is a structural note.

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// ruleKerasLambda reports a Lambda layer, whose embedded function carries
// marshalled Python bytecode.
//
// Keras' func_load base64-decodes config.code, runs marshal.loads on the result
// and rebuilds a FunctionType: loading the model executes attacker bytecode.
// This fires for the class name alone, because the class is the trigger; the
// Lambda is a critical finding whether or not the code blob decodes cleanly.
//
// Evidence: VU#253266 / CVE-2024-3660 (Lambda RCE), CVE-2025-1550 (crafted
// config.json defeating safe_mode=True) and CVE-2026-12481 (safe_mode=None
// falsey fallback reaching func_load).
var ruleKerasLambda = report.DefineRule(report.Rule{
	ID:         "SC4N-KERAS-LAMBDA",
	Title:      "Keras Lambda layer carries embedded executable code",
	Severity:   report.SeverityCritical,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-502", "CWE-94"},
	Class:      "code",
	Description: "A Keras model document declares a 'Lambda' layer. Keras reconstructs the layer from its " +
		"'function' config by base64-decoding 'code', running marshal.loads on it and rebuilding a " +
		"runtime FunctionType, so the model executes that bytecode when it is loaded. The code string is " +
		"scanned too, but the class name alone is the finding: the Lambda is the loader's own " +
		"deserialisation-to-code path, not a data value. Applies to .keras, and to .h5 where safe_mode is " +
		"silently ignored (GHSA-36rr-ww3j-vrjv). Evidence: VU#253266 / CVE-2024-3660, CVE-2025-1550, " +
		"CVE-2026-12481.",
	Refs: []string{
		"https://kb.cert.org/vuls/id/253266",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-3660",
		"https://nvd.nist.gov/vuln/detail/CVE-2025-1550",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12481",
		"https://github.com/advisories/GHSA-36rr-ww3j-vrjv",
	},
	Tags: []string{"keras", "code-execution"},
})

// ruleKerasTorchWrapper reports a TorchModuleWrapper layer, whose from_config
// hands attacker-controlled data straight to torch.load.
//
// Evidence: CVE-2026-12484.
var ruleKerasTorchWrapper = report.DefineRule(report.Rule{
	ID:         "SC4N-KERAS-TORCH-WRAPPER",
	Title:      "Keras TorchModuleWrapper deserialises a torch checkpoint on load",
	Severity:   report.SeverityCritical,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-502"},
	Class:      "code",
	Description: "A Keras model document declares a 'TorchModuleWrapper' layer. Its from_config passes " +
		"attacker-controlled data to torch.load, so loading the Keras model reaches the pickle " +
		"deserialiser with input the model file supplies. That makes the .keras file equivalent to an " +
		"untrusted torch checkpoint. Evidence: CVE-2026-12484.",
	Refs: []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12484",
	},
	Tags: []string{"keras", "pickle"},
})

// ruleKerasClassUnknown reports a class_name/registered_name outside the curated
// safe set.
//
// The safe set is the layer classes Keras itself defines; anything else is a
// class the *host* must provide or a custom object the model asks Keras to
// reconstruct, which is the surface the Lambda and safe_mode bypasses live behind.
var ruleKerasClassUnknown = report.DefineRule(report.Rule{
	ID:         "SC4N-KERAS-CLASS-UNKNOWN",
	Title:      "Keras model references a layer class outside the safe set",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceMedium,
	CWE:        []string{"CWE-502"},
	Class:      "code",
	Description: "A Keras config or metadata document names a class (class_name or registered_name) that is " +
		"not one of the layer, model, preprocessing or serialization classes Keras itself provides. " +
		"Restoring such a class runs host-registered code or the custom-object loader, which is exactly " +
		"the path safe_mode is meant to refuse and has been bypassed on more than once. The mediation is " +
		"to confirm the class is expected, not to assume it is benign. Sibling Keras loader bugs in the " +
		"same release family: CVE-2026-12479 (path traversal), CVE-2026-12480 (HDF5 arbitrary read), " +
		"CVE-2026-12570 (shape-bomb DoS). Evidence: CVE-2025-1550, CVE-2026-12481, CVE-2026-12482.",
	Refs: []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2025-1550",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12479",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12480",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12481",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12482",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12570",
	},
	Tags: []string{"keras", "deserialization"},
})

// ruleKerasStruct reports a .keras container that is not a readable zip or a
// config document that is not valid JSON.
var ruleKerasStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-KERAS-STRUCT",
	Title:      ".keras container or config document is malformed",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "structure",
	Description: "The .keras file is not a readable zip container, or one of its JSON documents " +
		"(config.json/metadata.json) does not decode. A parser that stopped here would be " +
		"indistinguishable from one that found nothing, so the failure is reported and the remaining " +
		"members are still walked.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/20.html"},
	Tags: []string{"keras"},
})

// ruleHDF5ExternalLink reports an HDF5 external-link or external-storage path.
//
// This is deliberately a heuristic: v1 does not implement an HDF5 object-header
// reader (see the capability Notes), so it cannot follow an object header to the
// Link Info / External File List message. It reports path-shaped strings that only
// make sense as an external reference, at low confidence.
var ruleHDF5ExternalLink = report.DefineRule(report.Rule{
	ID:         "SC4N-HDF5-EXTERNAL-LINK",
	Title:      "HDF5 file references an external path",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceLow,
	CWE:        []string{"CWE-22", "CWE-73"},
	Class:      "path",
	Description: "A path-shaped string was found inside an HDF5 file: a URL scheme, an absolute path or a " +
		"'..' segment. HDF5 external links and external raw-data storage name a file the loader then " +
		"opens, so on an untrusted model this is a file-access primitive. The finding is low confidence " +
		"because v1 does not implement the HDF5 object-header reader that would prove the string is an " +
		"external-link value rather than an ordinary attribute, so treat it as a pointer to verify. " +
		"Evidence: CVE-2026-12480 (HDF5 arbitrary read in the Keras loader family).",
	Refs: []string{
		"https://cwe.mitre.org/data/definitions/22.html",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-12480",
	},
	Tags: []string{"hdf5", "file-read"},
})

// ruleHDF5Struct reports a file whose HDF5 superblock is truncated.
var ruleHDF5Struct = report.DefineRule(report.Rule{
	ID:         "SC4N-HDF5-STRUCT",
	Title:      "HDF5 file is shorter than its superblock",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "structure",
	Description: "The file carries the HDF5 signature but is too short to hold a superblock, so no " +
		"attribute could be located. Only the shallow signature and string scan ran.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/20.html"},
	Tags: []string{"hdf5"},
})

// ruleTFPyFunc reports a PyFunc/EagerPyFunc op, which calls into Python at graph
// execution time.
var ruleTFPyFunc = report.DefineRule(report.Rule{
	ID:         "SC4N-TF-PYFUNC",
	Title:      "TensorFlow graph calls an arbitrary Python function",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-94", "CWE-502"},
	Class:      "code",
	Description: "A SavedModel/GraphDef contains a PyFunc or EagerPyFunc op. Executing the graph calls the " +
		"registered Python function that the op names, on data the graph controls, so the model is not a " +
		"pure data-flow artifact: a native op that performs file or network IO can be reached from a " +
		"model file. Confirm the named token is one the deployment registered deliberately.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
	Tags: []string{"tensorflow", "code-execution"},
})

// ruleTFFileIO reports a TF file-IO op whose path constant escapes the model
// directory.
var ruleTFFileIO = report.DefineRule(report.Rule{
	ID:         "SC4N-TF-FILE-IO",
	Title:      "TensorFlow op reads or writes an out-of-tree path",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-22", "CWE-73"},
	Class:      "path",
	Description: "A SavedModel/GraphDef contains a file-IO op (ReadFile/WriteFile/SaveV2/RestoreV2/" +
		"ReaderRead*/MatchingFiles/FileName) whose path constant is absolute, contains a '..' segment, " +
		"uses a drive letter or UNC prefix, is a URL or starts with '~'. The loader reads or writes that " +
		"path when the graph runs, so the artifact is a file-access primitive rather than a model.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/22.html"},
	Tags: []string{"tensorflow", "file-read"},
})

// ruleTFAssetExecutable reports an executable or script under a SavedModel
// assets/ directory.
var ruleTFAssetExecutable = report.DefineRule(report.Rule{
	ID:         "SC4N-TF-ASSET-EXECUTABLE",
	Title:      "SavedModel assets directory holds an executable or script",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-94", "CWE-506"},
	Class:      "code",
	Description: "A file under a SavedModel's assets/ or assets.extra/ directory is a native executable " +
		"(validated ELF/PE/Mach-O header) or carries a shell shebang. assets/ exists to carry files the " +
		"graph names at run time, and TF's own asset ops (ReadFile, MatchingFiles) reach it, so an " +
		"executable parked there is either a loader path the model names or a stub the surrounding " +
		"deployment runs.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	Tags: []string{"tensorflow", "assets"},
})

// ruleTFStruct reports a SavedModel/GraphDef whose protobuf structure is broken.
var ruleTFStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-TF-STRUCT",
	Title:      "TensorFlow protobuf is truncated or malformed",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "structure",
	Description: "A SavedModel/GraphDef protobuf has a field whose declared length runs past the end of " +
		"the message, or a wire type its declaration cannot carry. The walk stopped at that point and " +
		"reports how far it got, rather than treating a parse failure as an absence of findings.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/20.html"},
	Tags: []string{"tensorflow"},
})

// ruleTFCheckpointNoCode is the informational note on a bare TF checkpoint.
var ruleTFCheckpointNoCode = report.DefineRule(report.Rule{
	ID:         "SC4N-TF-CHECKPOINT-NO-CODE",
	Title:      "TensorFlow checkpoint carries no inline code",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        nil,
	Class:      "content",
	Description: "The artifact is a bare TensorFlow checkpoint (.index / .data shards), which stores tensor " +
		"variables and no graph and no inline code, so there is nothing here for sc4n to execute and no " +
		"code to find. This note exists so a clean verdict is not misread as \"safe to load blindly\": a " +
		"checkpoint is only as trustworthy as the code that names its variables and runs it.",
	Refs: []string{"https://www.tensorflow.org/guide/checkpoint"},
	Tags: []string{"tensorflow", "checkpoint"},
})

// ruleTFCheckpointStruct reports a malformed .index bundle header.
var ruleTFCheckpointStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-TF-CHECKPOINT-STRUCT",
	Title:      "TensorFlow checkpoint index is malformed",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "structure",
	Description: "A .index file does not begin with a plausible BundleHeaderProto: its first field is not a " +
		"varint shard count, or a later field runs past the end of the file. The structure is only " +
		"outlined (v1 does not rebuild the object graph), so the note is about what was and was not " +
		"checked.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/20.html"},
	Tags: []string{"tensorflow", "checkpoint"},
})

// ruleTFJSFlexOp reports a Flex-prefixed op in a TF-JS model graph.
var ruleTFJSFlexOp = report.DefineRule(report.Rule{
	ID:         "SC4N-TFJS-FLEX-OP",
	Title:      "TensorFlow-JS graph uses a Flex op",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceMedium,
	CWE:        []string{"CWE-94"},
	Class:      "code",
	Description: "A TF-JS model.json graph (or a TF GraphDef carried as JSON) names a Flex-prefixed op. " +
		"Flex ops delegate to TensorFlow's C++ kernels rather than the portable JS kernel set, so " +
		"executing the graph requires a runtime that links the full TF native library, which is a much " +
		"larger attack surface than the model's own op set implies.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/94.html"},
	Tags: []string{"tensorflow", "tfjs"},
})

// ruleTFLiteCustomOp reports a TFLite custom op, whose implementation the host
// must provide as native code.
var ruleTFLiteCustomOp = report.DefineRule(report.Rule{
	ID:         "SC4N-TFLITE-CUSTOM-OP",
	Title:      "TFLite model declares a custom operator",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-94", "CWE-506"},
	Class:      "code",
	Description: "A TFLite model names a custom operator (a non-empty custom_code, builtin_code CUSTOM, or a " +
		"custom_options blob). A custom op has no implementation in the model: the runtime resolves the " +
		"name to a device plugin it has already loaded, so the model's behaviour is decided by native " +
		"code outside the artifact. A model that requires one is not portable data.",
	Refs: []string{"https://www.tensorflow.org/lite/guide/ops_custom"},
	Tags: []string{"tflite", "native"},
})

// ruleTFLiteNativeMagic reports a native executable embedded in a TFLite buffer.
var ruleTFLiteNativeMagic = report.DefineRule(report.Rule{
	ID:         "SC4N-TFLITE-NATIVE-MAGIC",
	Title:      "TFLite model embeds a native executable in a buffer",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-506"},
	Class:      "code",
	Description: "A TFLite buffer holds a validated native executable (ELF/PE/Mach-O header) rather than " +
		"tensor data. TFLite buffers are model weights; an executable among them is a payload the format " +
		"has no reason to carry, and the shape used to smuggle native code past a data-only scanner.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	Tags: []string{"tflite", "polyglot"},
})

// ruleTFLiteEntropy reports an unexpectedly high-entropy buffer.
var ruleTFLiteEntropy = report.DefineRule(report.Rule{
	ID:         "SC4N-TFLITE-ENTROPY",
	Title:      "TFLite buffer has compressed or encrypted entropy",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceLow,
	CWE:        nil,
	Class:      "content",
	Description: "A TFLite buffer's byte entropy is at or above 7.9 bits/byte, which says the region looks " +
		"compressed, encrypted or randomly padded rather than like quantised weights. This is " +
		"informational only: quantised weights can legitimately look random, so it is a pointer for a " +
		"reviewer, not a finding that changes the verdict.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
	Tags: []string{"tflite"},
})

// ruleTFLiteStruct reports a TFLite flatbuffer whose header or table geometry is
// invalid.
var ruleTFLiteStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-TFLITE-STRUCT",
	Title:      "TFLite flatbuffer header or table is malformed",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "structure",
	Description: "A .tflite file's root table offset or a vtable/vector/string reference points outside the " +
		"file, or the identifier is not 'TFL3' at offset 4. The walk stops at the broken reference and " +
		"reports it, so a malformed flatbuffer is visible rather than silently unread.",
	Refs: []string{"https://cwe.mitre.org/data/definitions/20.html"},
	Tags: []string{"tflite"},
})
