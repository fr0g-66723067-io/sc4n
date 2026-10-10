package main

// coremlFixtures writes the Core ML fixtures.
//
// The security property being pinned is a *reference*, not bytes: a CustomModel
// (field 555) and a NeuralNetwork custom layer (field 500) each name a class the
// host application must supply. The protobufs are assembled from the field numbers
// in apple/coremltools mlmodel/format/Model.proto and NeuralNetwork.proto via the
// onnx fixture encoder, because the fixture's point is the field layout.
func init() {
	register(contributor{
		name:     "coreml",
		fixtures: coremlFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return coremlExpectations(), coremlBenignExpectations()
		},
	})
}

func coremlFixtures(f *fixtureSet) {
	// A CustomModel: Model.customModel = 555, CustomModel.className = 10.
	f.add("coreml_custom.mlmodel", pbCat(
		pbVar(1, 1), // specificationVersion
		pbBytes(2, pbCat(pbStr(1, "sc4n coreml fixture"))),
		pbBytes(555, pbCat(
			pbStr(10, "EvilCustomModel"),
			pbStr(40, "host must supply this class"),
		)),
	))

	// A NeuralNetwork custom layer: Model.neuralNetwork = 500,
	// NeuralNetwork.layers = 1, NeuralNetworkLayer.custom = 500,
	// CustomLayerParams.className = 10.
	f.add("coreml_custom_layer.mlmodel", pbCat(
		pbVar(1, 1),
		pbBytes(2, pbCat(pbStr(1, "sc4n coreml fixture"))),
		pbBytes(500, pbBytes(1, pbCat(
			pbStr(1, "layer0"),
			pbBytes(500, pbCat(pbStr(10, "EvilCustomLayer"))),
		))),
	))

	// Benign: a well-formed model with a description and a plain layer that names
	// no host class.
	f.add("benign/tiny.mlmodel", pbCat(
		pbVar(1, 1),
		pbBytes(2, pbCat(pbStr(1, "sc4n benign"), pbStr(2, "1.0"))),
		pbBytes(500, pbBytes(1, pbCat(
			pbStr(1, "conv0"),
			pbBytes(100, pbCat(pbVar(1, 3))), // a plain convolution layer
		))),
	))
}

func coremlExpectations() map[string]expectation {
	return map[string]expectation{
		"coreml_custom.mlmodel": {
			Expect: []string{"SC4N-COREML-CUSTOM-LAYER"},
			Forbid: []string{"SC4N-COREML-STRUCT", "SC4N-COREML-PROGRAM-UNVERIFIED", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "Model.customModel (field 555) naming a class the host must provide. The " +
				"implementation is not in the file, so a poisoned package pairs with a host plugin.",
		},
		"coreml_custom_layer.mlmodel": {
			Expect: []string{"SC4N-COREML-CUSTOM-LAYER"},
			Forbid: []string{"SC4N-COREML-STRUCT", "SC4N-COREML-PROGRAM-UNVERIFIED", "SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "NeuralNetwork.layers[].custom (NeuralNetworkLayer.custom = 500) naming a " +
				"host-supplied custom layer class.",
		},
	}
}

func coremlBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/tiny.mlmodel": {
			Forbid: []string{
				"SC4N-COREML-CUSTOM-LAYER",
				"SC4N-COREML-STRUCT",
				"SC4N-COREML-PROGRAM-UNVERIFIED",
				"SC4N-FORMAT-EXTENSION-MISMATCH",
			},
			Notes: "A well-formed model with a description and a neural-network layer that names no " +
				"host class. The false-positive gate for the Core ML walker.",
		},
	}
}
