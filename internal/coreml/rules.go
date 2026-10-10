// The Core ML rule set.
//
// Core ML has no published "malicious model" advisory of the pickle kind, and the
// format is not designed to carry executable code. Its detector is about a
// *reference*: the model names a class the host must provide. That makes a Core ML
// package a coordination artifact rather than a self-contained payload, which is
// exactly why it is worth a finding -- an otherwise clean-looking `.mlpackage`
// becomes a code path once it is loaded by an application that ships a matching
// plugin.
package coreml

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleCustomLayer reports a CustomModel (ModelProto field 555) or a
// NeuralNetwork custom layer (NeuralNetworkLayer.custom=500) whose className names
// a host-supplied implementation.
var RuleCustomLayer = report.DefineRule(report.Rule{
	ID:         "SC4N-COREML-CUSTOM-LAYER",
	Title:      "Core ML model names a host-supplied custom class",
	Severity:   report.SeverityHigh,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-829", "CWE-494"},
	Class:      "format",
	Description: "A CustomModel (ModelProto field 555) or a NeuralNetwork layer's CustomLayerParams " +
		"(field 500) declares a className. The model file contains no implementation of that class: " +
		"Core ML asks the host application to supply one that conforms to MLCustomModel/MLCustomLayer and " +
		"to register it under that name. Loading the file therefore reaches whatever the host resolves " +
		"the name to. A poisoned package pairs with a host plugin, and the model itself can look like " +
		"ordinary weights, so the finding is about the pairing rather than the bytes.",
	Refs: []string{
		"https://apple.github.io/coremltools/mlmodel/Format/Model.html",
		"https://developer.apple.com/documentation/coreml/mlcustommodel",
	},
	Tags: []string{"coreml", "host-plugin"},
})

// RuleStruct reports a malformed ModelProto or a walk that could not be bounded.
var RuleStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-COREML-STRUCT",
	Title:      "Core ML model is structurally invalid or only partly walked",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "format",
	Description: "The protobuf could not be walked as a ModelProto: a field tag, length or fixed value " +
		"was truncated or malformed, a protobuf group wire type was used, or the model is larger than the " +
		"bounded walk window so only its head was inspected. Every length is validated by protowire before " +
		"use, so nothing is allocated from an attacker-controlled size; the finding tells the reviewer " +
		"that the declared Core ML structure and sc4n disagree about the document.",
	Refs: []string{"https://protobuf.dev/programming-guides/encoding/"},
	Tags: []string{"coreml", "malformed"},
})

// RuleProgramUnverified reports a MILSpec/ML Program model that v1 does not decode.
var RuleProgramUnverified = report.DefineRule(report.Rule{
	ID:         "SC4N-COREML-PROGRAM-UNVERIFIED",
	Title:      "Core ML ML Program graph is not decoded",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        nil,
	Class:      "format",
	Description: "Model.type is `mlProgram` (MILSpec.Program, field 502), the modern Core ML graph " +
		"representation. sc4n v1 recognises it but does not decode the MIL operator graph or its weight " +
		"blobs, so this model is reported as only shallowly analysed rather than silently treated as " +
		"clean. Custom layers named by an ML Program are not covered by SC4N-COREML-CUSTOM-LAYER.",
	Tags: []string{"coreml", "shallow"},
})
