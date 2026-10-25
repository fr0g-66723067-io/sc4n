package trt

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleUnverified is the mandatory depth statement for a recognized engine.
//
// There is deliberately no structural rule: TensorRT's serialization format is
// versioned and unpublished, so a validator would either accept everything or
// report every future engine version as malformed. Saying "recognised, not deeply
// parsed" is the accurate claim, and it is what keeps a shallow file from reading
// as a clean one.
var RuleUnverified = report.DefineRule(report.Rule{
	ID:         "SC4N-TRT-UNVERIFIED",
	Title:      "TensorRT engine is recognised but not deep-parsed",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	Class:      "format",
	Description: "The file starts with the `ftrt` magic of a TensorRT serialized engine. sc4n does not " +
		"interpret the section table (the format is versioned and NVIDIA does not publish a stable " +
		"specification), so the finding states the depth instead of implying the file is clean: the " +
		"indicator engine covered the first 4 MiB and the last 1 MiB only, and the serialized weights " +
		"between those windows were not scanned. A payload hidden in the weight region is out of scope.",
	Tags: []string{"tensorrt", "shallow"},
})
