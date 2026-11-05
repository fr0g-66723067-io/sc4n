package artifact

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleParseFailed fires when a format parser returned an error, which means the
// artifact's structures were not walked to the end. It lives here rather than in
// internal/scan because the container walkers in internal/archive, internal/numpy
// and internal/torch report a nested member's failure through it, and those
// packages cannot import internal/scan (which imports them).
var RuleParseFailed = report.DefineRule(report.Rule{
	ID:         "SC4N-PARSE-FAILED",
	Title:      "Format parser could not walk the artifact to the end",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-755"},
	Class:      "structure",
	Description: "The parser for this artifact's sniffed format returned an error part-way through, so " +
		"whatever lies past that point was not analysed. This is reported as a finding rather than as a " +
		"silent skip because a truncated walk is the classic way to make a scanner report CLEAN: modelscan " +
		"issue #354 is an unreadable ZIP entry placed before archive/data.pkl. Read the evidence for the " +
		"failing structure and treat the artifact as unscanned beyond that point.",
	Refs: []string{"https://github.com/protectai/modelscan/issues/354"},
	Tags: []string{"scanner-evasion"},
})

// RuleExtensionMismatch fires when the sniffed format contradicts the file's
// extension.
//
// This is a real detector rather than hygiene: the February 2025 Hugging Face
// campaign shipped .pt files that were 7z archives, and the entire reason the
// payloads reached users is that tooling trusted the extension. sc4n dispatches
// on content, so the file is still scanned — the finding tells the human that the
// file is not what its name says, which is the property a reviewer needs.
var RuleExtensionMismatch = report.DefineRule(report.Rule{
	ID:         "SC4N-FORMAT-EXTENSION-MISMATCH",
	Title:      "File content does not match its extension",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	Class:      "format",
	Description: "The bytes identify a different container than the file name implies. sc4n dispatched on " +
		"the content, so the real format was still scanned; the finding matters because every " +
		"extension-driven tool in the chain (and the human deciding whether to load the file) sees the " +
		"name first and the format second. A .safetensors that is a zip, a .npz that is a tar and a " +
		".gguf that is a zip are documented evasion shapes. Where the pair is a real convention the " +
		"extension is exempt and this rule stays silent: a .pt that is a 7z archive is the February 2025 " +
		"campaign, reported as SC4N-TORCH-7Z, and a .bin that is a pickle is an ordinary torch save.",
	Refs: []string{"https://huggingface.co/blog/notable-models-scanned"},
	Tags: []string{"evasion"},
})

// RuleAmbiguous fires when more than one sniffer recognised the content and the
// content heuristic had to choose.
//
// The two known ambiguities are .pt (TorchScript zip versus PyTorch Mobile
// flatbuffer) and protobuf-shaped files (ONNX versus TF SavedModel versus
// CoreML). Reporting which parser ran is the honest alternative to silently
// picking one.
var RuleAmbiguous = report.DefineRule(report.Rule{
	ID:         "SC4N-FORMAT-AMBIGUOUS",
	Title:      "Format is ambiguous; content heuristic chose a parser",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceLow,
	Class:      "format",
	Description: "More than one sniffer accepted this artifact's content, so the parser named in the " +
		"evidence ran and the others did not. The probe that emits this today is the protobuf-shaped " +
		"pair (ONNX, TF SavedModel, CoreML), where the wire format alone does not say which model " +
		"description it is. If the artifact is the other member of the pair, its format-specific rules " +
		"did not run.",
	Tags: []string{"format"},
})

// RulePartialSlice fires when the artifact is a known header slice of a larger
// file — the shape a campaign fetches under a per-file byte cap — and a parser had
// to stop at the slice boundary.
//
// It exists because the alternative is a medium-severity malformed-structure
// finding for every sliced weight file: on the 25 most-downloaded Hub models, 271
// of 1038 artifacts are slices and the safetensors parser alone reported 120
// SC4N-SAFETENSORS-TRUNCATED findings for them, none of which says anything
// about the model. The session knows which artifacts were fetched this way
// (Session.SetPartial), so a parser that would compare a declared extent against
// bytes it does not have can say "this is a slice" instead of "this is broken".
// Informational: the reviewer still learns that the artifact was not read in full.
var RulePartialSlice = report.DefineRule(report.Rule{
	ID:         "SC4N-PARTIAL-SLICE",
	Title:      "Artifact is a header slice, so declared extents run past its end",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-1059"},
	Class:      "structure",
	Description: "The scanner was given a byte prefix of a larger artifact (for example the first 2 MiB " +
		"of a multi-gigabyte checkpoint, fetched under a per-file budget), and the format's declared " +
		"extents therefore stop inside the slice. Nothing is wrong with the file: the structure was " +
		"followed as far as the bytes go. Informational, because the consequence for a reviewer is " +
		"coverage — what lies past the slice was not scanned, and a clean result for this artifact " +
		"does not describe the whole file.",
	Refs: []string{"https://huggingface.co/docs/hub/security"},
	Tags: []string{"coverage", "truncation"},
})
