package safetensors

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The safetensors rule set.
//
// Calibration context that the rules below depend on:
//
//   - safetensors has **no published security advisories**. Its reference
//     implementation (HuggingFace's Rust crate and the Python `safetensors`
//     package) is a pure, allocation-bounded deserialiser whose own validation
//     already *rejects* trailing bytes and overlapping or non-contiguous offsets
//     before a single tensor is handed to the caller. A trailing-data or
//     overlap finding therefore does not mean "the reference loader will run
//     this"; it means "this file is not what the reference loader would accept",
//     which is the polyglot / steganography / smuggling shape a loader other
//     than the reference one (or a future, looser one) would consume. That is
//     why trailing data and offset violations are `high`, not `critical`.
//   - The one place this rule set must not over-claim is escape processing. A
//     JSON string containing the six ASCII characters `\u0000` is exactly that
//     to a JSON parser — six characters, no NUL byte. Nothing here reports the
//     escaped form as a hidden NUL; if a real NUL is required it is a real NUL
//     byte in the header, which shows up in the UTF-8 validity check instead.
var (
	// RuleStruct covers the header-shape invariants V1-V11 of the reference
	// validator: the declared header length, the UTF-8/JSON shape, per-entry
	// dtype/shape/offsets typing, END >= BEGIN, contiguity, and the
	// product(shape)*bitsize size equation. Each violation is emitted with its
	// own evidence string naming the entry and the value, so a reader can tell
	// which check reproduced the reference implementation's error.
	RuleStruct = report.DefineRule(report.Rule{
		ID:         "SC4N-SAFETENSORS-STRUCT",
		Title:      "safetensors header violates a structural invariant",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20"},
		Class:      "format",
		Description: "The header does not satisfy one of the invariants the reference safetensors loader enforces " +
			"before returning any tensor: the declared header length is within the 100 MB cap, the file is at " +
			"least 8+header bytes long, the header is valid UTF-8 JSON beginning with '{', '__metadata__' maps " +
			"strings to strings, every other top-level key is a tensor entry of {dtype, shape, data_offsets} " +
			"with no duplicate keys, shapes are integers, END >= BEGIN, offsets tile the byte buffer with no " +
			"overlap and no hole, and product(shape)*bitsize/8 equals the declared span and is byte-aligned. " +
			"safetensors has no published advisories and the reference loader fails closed on every one of " +
			"these, so the finding means the file is malformed for the reference loader -- the shape that " +
			"matters when something other than the reference loader reads it.",
		Refs: []string{
			"https://github.com/huggingface/safetensors",
			"https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs",
		},
		Tags: []string{"format", "malformed"},
	})

	// RuleTrailingData fires when the declared tensor extents do not cover the
	// whole byte buffer, i.e. there are bytes after the last tensor. The
	// reference loader rejects these; their only purpose is to carry something
	// the format has no field for (an appended executable, a second container, a
	// steganographic blob).
	RuleTrailingData = report.DefineRule(report.Rule{
		ID:         "SC4N-SAFETENSORS-TRAILING-DATA",
		Title:      "Bytes follow the last declared tensor",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20"},
		Class:      "format",
		Description: "The last tensor's data_offsets end before the end of the byte buffer, so the file carries " +
			"bytes the safetensors format has no field for. The reference loader computes coverage and rejects " +
			"such a file, so this is not a loader-reachable payload in the reference implementation -- it is the " +
			"polyglot/steganography shape: an appended native executable, a second serialisation or an " +
			"obfuscated blob that a looser reader, a hex editor or a smuggled re-write would expose. Severity " +
			"is high rather than critical precisely because the reference loader fails closed.",
		Refs: []string{
			"https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs",
		},
		Tags: []string{"polyglot", "smuggling"},
	})

	// RuleTruncated fires when the file is shorter than the header declares or a
	// tensor extent reaches past the end of the byte buffer.
	RuleTruncated = report.DefineRule(report.Rule{
		ID:         "SC4N-SAFETENSORS-TRUNCATED",
		Title:      "Declared header or tensor extent runs past the end of the file",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20"},
		Class:      "format",
		Description: "The file is shorter than its 8-byte header length declares, or a tensor's data_offsets reach " +
			"past the end of the byte buffer. The reference loader fails closed on both. The finding is recorded " +
			"rather than treated as an unreadable file because a truncated model is the shape a partially " +
			"downloaded or deliberately clipped artifact takes, and a scanner that reports nothing for it is " +
			"indistinguishable from one that found nothing.",
		Refs: []string{
			"https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs",
		},
		Tags: []string{"format", "malformed"},
	})

	// RuleDtypeUnknown fires for a dtype string outside the reference set. The
	// element size is unknown, so the size equation is skipped for that tensor
	// (never guessed) and the tensor bytes go unread by the statistics pass.
	RuleDtypeUnknown = report.DefineRule(report.Rule{
		ID:         "SC4N-SAFETENSORS-DTYPE-UNKNOWN",
		Title:      "Tensor declares a dtype outside the known set",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-20"},
		Class:      "format",
		Description: "A tensor's dtype is not one of the dtypes the reference implementation defines (BOOL, U8, " +
			"I8, F8 variants, F4, F6 variants, I16, U16, F16, BF16, I32, U32, F32, C64, F64, I64, U64). A " +
			"loader that extends the set (a custom dtype registration, a renamed float format) may still read " +
			"it, but its element size is not known to sc4n, so the per-tensor size check is deliberately " +
			"skipped for this entry rather than guessed -- a wrong guess would fabricate an overlap or " +
			"trailing-data finding.",
		Refs: []string{
			"https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs",
		},
		Tags: []string{"format"},
	})

	// RuleNativeMagic fires when a *validated* native executable header (ELF, PE,
	// Mach-O) appears in the safetensors header region or in the bytes after the
	// last tensor. Validated means the standard library's own header parser
	// accepted it, which separates a real executable from three bytes of a
	// tensor that happen to spell 0x7f 'E' 'L' 'F'.
	RuleNativeMagic = report.DefineRule(report.Rule{
		ID:         "SC4N-SAFETENSORS-NATIVE-MAGIC",
		Title:      "Native executable header embedded in a safetensors file",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "polyglot",
		Description: "A validated ELF, PE or Mach-O header appears inside the safetensors header region or in the " +
			"trailing bytes. The header was accepted by Go's own debug/elf, debug/pe or debug/macho parser, so " +
			"it is a real executable image and not a coincidental byte match. The reference loader rejects the " +
			"trailing bytes, so this is the derived-artifact shape: the file loads as a model while a second " +
			"toolchain can extract and run the embedded image.",
		Refs: []string{
			"https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs",
		},
		Tags: []string{"polyglot", "embedded-executable"},
	})

	// RuleNativeMagicUnverified fires for a bare native magic whose header the
	// standard library parser rejected. It is informational: a tensor of bytes
	// can contain 0x7f 'E' 'L' 'F' in three lanes, and reporting that at high
	// would be an over-attribution.
	RuleNativeMagicUnverified = report.DefineRule(report.Rule{
		ID:         "SC4N-SAFETENSORS-NATIVE-MAGIC-UNVERIFIED",
		Title:      "Bare native executable magic in a safetensors file",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		CWE:        []string{"CWE-506"},
		Class:      "polyglot",
		Description: "A native-executable magic (ELF, PE, Mach-O, ar, OLE) appears in the header region or " +
			"trailing bytes but the standard library's header parser did not accept it as a valid image. On " +
			"its own this is ordinary data (three bytes of a 16-bit tensor lane can spell the ELF prefix); the " +
			"finding is info so a reader can see the region without the scanner claiming an executable.",
		Tags: []string{"polyglot"},
	})
)

// The weight-level statistics rule family. Every one is informational and is
// emitted only behind -deep-stats: a statistic over tensor values is a hint for
// a human, never a gate. The plan is explicit that Neural-Cleanse/ABS/STRIP
// weight-level backdoor detection is out of band, so these rules deliberately
// stop far short of it -- they are structural/statistical anomalies (a NaN
// storm, a duplicated row, an all-zero block, a magnitude spike, a low-entropy
// region), each of which has a benign explanation.
var (
	RuleWeightsNaN = report.DefineRule(report.Rule{
		ID:         "SC4N-WEIGHTS-NAN",
		Title:      "Tensor contains a high fraction of NaN or Inf values",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		Class:      "weights",
		Description: "More than the configured fraction of a tensor's sampled float values are NaN or +/-Inf. " +
			"NaN/Inf weights are a real failure mode of broken training and a documented carrier for " +
			"out-of-band signalling, but a freshly converted or partially written checkpoint can contain them " +
			"too. Informational, behind -deep-stats, never a gate.",
		Tags: []string{"weights", "statistics"},
	})

	RuleWeightsDuplicate = report.DefineRule(report.Rule{
		ID:         "SC4N-WEIGHTS-DUPLICATE",
		Title:      "Tensor has an unusually high fraction of duplicate values",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		Class:      "weights",
		Description: "More than the configured fraction of a tensor's sampled elements repeat a value seen " +
			"earlier in the sample. Duplicated rows/columns are how a naive backdoor injection copies a " +
			"trigger weight set; they are also what quantisation, padding and a broadcast constant produce. " +
			"Informational, behind -deep-stats, never a gate.",
		Tags: []string{"weights", "statistics"},
	})

	RuleWeightsAllZero = report.DefineRule(report.Rule{
		ID:         "SC4N-WEIGHTS-ALL-ZERO",
		Title:      "Tensor is entirely zero",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		Class:      "weights",
		Description: "Every sampled element of the tensor is zero. A zero tensor is legal (empty, masked or " +
			"uninitialised heads exist in real checkpoints) but it is also where a payload rides unnoticed, so " +
			"it is worth a human's eye. Informational, behind -deep-stats, never a gate.",
		Tags: []string{"weights", "statistics"},
	})

	RuleWeightsOutlier = report.DefineRule(report.Rule{
		ID:         "SC4N-WEIGHTS-OUTLIER",
		Title:      "Tensor has magnitude outliers far above its own mean",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		Class:      "weights",
		Description: "More than the configured fraction of a tensor's sampled float elements have a magnitude " +
			"larger than the configured multiple of the tensor's mean magnitude. A magnitude spike is the " +
			"crudest backdoor signature and also a normal property of an untrained or clipped tensor. " +
			"Informational, behind -deep-stats, never a gate.",
		Tags: []string{"weights", "statistics"},
	})

	RuleWeightsEntropy = report.DefineRule(report.Rule{
		ID:         "SC4N-WEIGHTS-ENTROPY",
		Title:      "Tensor byte entropy is outside the expected band",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		Class:      "weights",
		Description: "The Shannon entropy of the tensor's sampled bytes is either very low (a large constant or " +
			"zero region) or near the 8-bit maximum (compressed or encrypted data where weights should be). " +
			"Both have benign explanations (a bias vector is low-entropy by construction; a deliberately " +
			"encoded weight block is high-entropy). Informational, behind -deep-stats, never a gate.",
		Tags: []string{"weights", "statistics"},
	})
)
