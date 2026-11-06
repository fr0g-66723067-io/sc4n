package main

// op is one generator: it writes a mutant of a known-good artifact and declares
// what the scanner must say about it. The expectation is data, so a regression
// shows up as a matrix row rather than as prose that drifts away from the code.
type op struct {
	// Name is the matrix row key and the mutant subdirectory.
	Name string
	// Needs names the external tool this operator requires; empty means the
	// mutant is written with the standard library alone.
	Needs string
	// Build writes the mutant under out and returns its path relative to out.
	Build func(out string, seed int64) (string, error)
	// Oracle validates the mutant. A nil oracle reports the row unavailable.
	Oracle Oracle
	// Expected rule IDs must all be present.
	Expected []string
	// Forbid rule IDs must all be absent.
	Forbid []string
}

// graphOp is a graphs-profile operator. It is a distinct type because the edit
// happens inside the oracle container (onnx is not a Go library): the lab hands
// mutate.py the operator name and a seed and the container either writes a model
// the checker accepts or exits non-zero.
type graphOp struct {
	Name      string
	Mode      string // "checker" or "session"
	Expected  []string
	Forbidden []string
}

// graphOps is the mutation table. Traversal and custom-domain rows validate
// with the checker only: constructing an InferenceSession would resolve the
// external path (or reject an unknown domain), which is the runtime's behaviour
// rather than validity of the model document.
func graphOps() []graphOp {
	return []graphOp{
		{
			Name: "metadata-cmd", Mode: "session",
			Expected: []string{"SC4N-STRING-SHELL", "SC4N-STRING-RAW-IP-URL"},
		},
		{
			Name: "attr-shell-cmd", Mode: "session",
			Expected: []string{"SC4N-STRING-SHELL"},
		},
		{
			Name: "node-doc-traversal", Mode: "checker",
			Expected: []string{"SC4N-ONNX-EXTERNAL-TRAVERSAL"},
		},
		{
			Name: "if-subgraph-traversal", Mode: "checker",
			Expected: []string{"SC4N-ONNX-EXTERNAL-TRAVERSAL"},
		},
		{
			Name: "function-traversal", Mode: "checker",
			Expected: []string{"SC4N-ONNX-FUNCTION", "SC4N-ONNX-EXTERNAL-TRAVERSAL"},
		},
		{
			Name: "custom-domain", Mode: "checker",
			Expected: []string{"SC4N-ONNX-CUSTOM-DOMAIN"},
		},
	}
}
