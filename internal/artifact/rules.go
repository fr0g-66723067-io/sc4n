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
		"name first and the format second. A .pt that is a 7z archive, a .bin that is a pickle and a " +
		".safetensors that is a zip are all documented evasion shapes.",
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
