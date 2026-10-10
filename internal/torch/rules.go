package torch

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The torch-family rule set.
//
// Torch is the single highest-value target in sc4n: `torch.save` writes a Python
// pickle, and every one of the documented load paths reaches it (new zip
// `data.pkl`, TorchScript `constants.pkl`/`*.debug_pkl`, `.pt2`
// `data/sample_inputs/*.pt`, legacy binary and legacy tar objects). So the rules
// here are shape/structural, and the code-execution verdicts come from the pickle
// engine those shapes are routed into. The only torch-specific findings are the
// shapes whose *container* is the evasion:
//
//   - a prefixed archive (leading bytes before the first PK\x03\x04) that a
//     Python-side `_is_zipfile` check would miss while the C++ PyTorchStreamReader
//     still deserialises it;
//   - a 7z file renamed `.pt` (the February 2025 Hugging Face campaign), where an
//     extension-driven scanner saw "not a zip" while a patched loader still loaded
//     the payload.
//
// Severity calibration follows the plan: `critical` is code execution reachable
// from the artifact's normal load path, `high` is an unvalidated code-loading or
// file-access surface, `medium`/`info` are structural anomalies. A plain,
// well-formed torch archive is *not* itself a finding -- the pickle engine grades
// its contents -- so the shape rules are informational.

var (
	// ruleTorchZip identifies a new-format (uncompressed zip) torch checkpoint.
	ruleTorchZip = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-ZIP",
		Title:      "PyTorch new-format archive (zip) recognised",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "torch",
		Description: "The artifact is a PyTorch new-format checkpoint: an uncompressed zip whose first local " +
			"file header is PK\\x03\\x04 and whose members are data.pkl, byteorder and data/<n> storages. " +
			"data.pkl is a Python pickle and is analysed by the pickle engine; the rule exists so a reader " +
			"can see which torch shape was recognised rather than inferring it from the absence of findings.",
		Refs: []string{"https://docs.pytorch.org/docs/stable/notes/serialization.html"},
		Tags: []string{"deserialization"},
	})

	// ruleTorchScript identifies a TorchScript archive, whose code/*.py members
	// are attacker-controlled source stored as data.
	ruleTorchScript = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-SCRIPT",
		Title:      "TorchScript archive recognised",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "torch",
		Description: "The artifact is a TorchScript archive: a zip carrying data.pkl plus constants.pkl and/or " +
			"code/**/*.py. The code/*.py members are valid Python stored as *data* and are attacker-controlled, " +
			"so they are handed to the Python analyser; data.pkl, constants.pkl and *.debug_pkl are handed to " +
			"the pickle engine.",
		Refs: []string{"https://docs.pytorch.org/docs/stable/jit.html"},
		Tags: []string{"deserialization"},
	})

	// ruleTorchPT2 identifies a .pt2 export archive.
	ruleTorchPT2 = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-PT2",
		Title:      "PyTorch .pt2 export archive recognised",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "torch",
		Description: "The artifact is a .pt2 export archive (zip with archive_format + models/<m>.json + " +
			"data/weights + data/sample_inputs). data/sample_inputs/*.pt are genuine torch.save pickles and " +
			"data/constants/custom_obj_* are TorchBind objects, so both reach the pickle engine; any " +
			"*.wrapper.so member is native code and is reported by the archive layer as " +
			"SC4N-ARCHIVE-NATIVE-MEMBER.",
		Refs: []string{"https://pytorch.org/docs/stable/export.html"},
		Tags: []string{"deserialization"},
	})

	// ruleTorchLegacy identifies the pre-1.6 binary checkpoint layout.
	ruleTorchLegacy = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-LEGACY",
		Title:      "PyTorch legacy binary checkpoint recognised",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "torch",
		Description: "The artifact is a legacy PyTorch checkpoint (written by _legacy_save, i.e. " +
			"_use_new_zipfile_serialization=False or any pre-1.6 torch): a pickled MAGIC_NUMBER, then " +
			"PROTOCOL_VERSION, sys_info, the object pickle and the storage_keys pickle, followed by raw " +
			"storage bytes. Each leading pickle is walked individually with the storage tail treated as " +
			"storage, so a child-checkpoint's appended storage is not misreported as an attack suffix.",
		Refs: []string{"https://docs.pytorch.org/docs/stable/notes/serialization.html"},
		Tags: []string{"deserialization"},
	})

	// ruleTorchLegacyTar identifies the legacy tar checkpoint laid out by
	// torch 0.x (arXiv 2508.19774 Appendix B2).
	ruleTorchLegacyTar = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-LEGACY-TAR",
		Title:      "PyTorch legacy tar checkpoint recognised",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-502"},
		Class:      "torch",
		Description: "The artifact is a legacy tar checkpoint with the members storages, tensors and pickle. " +
			"The pickle member is the object graph and is handed to the pickle engine; storages and tensors " +
			"begin with metadata pickles and then carry raw storage bytes, which are treated as storage.",
		Refs: []string{"https://arxiv.org/abs/2508.19774"},
		Tags: []string{"deserialization"},
	})

	// ruleTorchPrefixedArchive fires for a zip with leading bytes before the first
	// local file header.
	ruleTorchPrefixedArchive = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-PREFIXED-ARCHIVE",
		Title:      "PyTorch archive has bytes before the zip local header",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-436"},
		Class:      "torch",
		Description: "The artifact is a valid zip whose first byte is not PK\\x03\\x04: arbitrary bytes precede " +
			"the first local file header. Python's _is_zipfile only checks the current offset, but the C++ " +
			"PyTorchStreamReader initialises miniz over the whole byte range and derives the archive prefix " +
			"from the first record, so the loader still deserialises the payload while an offset-sensitive " +
			"scanner reports \"not a zip\". sc4n unwraps it and scans every member.",
		Refs: []string{"https://docs.pytorch.org/docs/stable/notes/serialization.html"},
		Tags: []string{"format-confusion"},
	})

	// ruleTorch7z fires for a 7z archive named like a torch checkpoint.
	ruleTorch7z = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-7Z",
		Title:      "7z archive disguised as a PyTorch checkpoint",
		Severity:   report.SeverityCritical,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-436"},
		Class:      "torch",
		Description: "The artifact's name says it is a torch checkpoint (.pt/.pth/.ckpt/.ptl/.pt2) but its bytes " +
			"begin with the 7z signature 37 7A BC AF 27 1C. This is the February 2025 Hugging Face campaign: " +
			"a patched loader still deserialised the payload while every extension-driven scanner saw \"not a " +
			"zip\". sc4n cannot decode 7z (no stdlib decoder) and says so with " +
			"SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION; the pickle inside is NOT scanned.",
		Refs: []string{"https://huggingface.co/blog/", "https://cwe.mitre.org/data/definitions/436.html"},
		Tags: []string{"format-confusion"},
	})

	// ruleTorchStruct fires when a torch container is structurally malformed.
	ruleTorchStruct = report.DefineRule(report.Rule{
		ID:         "SC4N-TORCH-STRUCT",
		Title:      "Torch checkpoint structure is malformed",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-502"},
		Class:      "torch",
		Description: "A torch container's structure does not match its declared shape: the legacy magic or " +
			"protocol-version pickle is missing, a leading pickle did not reach a STOP, or a section of the " +
			"file could not be carved as a pickle. A loader that tolerates the same malformation may still " +
			"execute the payload, so this is a finding rather than a reason to skip the file.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Tags: []string{"deserialization"},
	})
)
