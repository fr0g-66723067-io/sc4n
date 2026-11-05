package main

// onnxFixtures writes the ONNX fixtures.
//
// The protobufs are assembled byte by byte from the field numbers in
// onnx.proto3 at tag v1.21.0 rather than generated with protoc: the point of
// most of them is a property of the wire bytes (a `..` in a location string, a
// petabyte length, a key outside the loader whitelist), and a code generator
// would only add a toolchain dependency to express them. The encoder below is
// the whole wire format sc4n needs: tag = field<<3 | wiretype, varints base 128.
func init() {
	register(contributor{
		name:     "onnx",
		fixtures: onnxFixtures,
		expectations: func() (map[string]expectation, map[string]expectation) {
			return onnxExpectations(), onnxBenignExpectations()
		},
	})
}

func onnxFixtures(f *fixtureSet) {
	// A traversal location: the loader opens it relative to the model directory
	// and returns the bytes as tensor content (CVE-2022-25882, and CVE-2024-27318
	// for the bypass of its fix).
	f.add("onnx_external_traversal.onnx", pbCat(
		pbVar(1, 8), // ir_version
		pbStr(2, "sc4n-fixture"),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(5, pbTensorExternal("w", []int64{2, 2}, 1,
				pbEntry("location", "../../etc/passwd"),
				pbEntry("offset", "0"),
				pbEntry("length", "16"),
			)),
		)),
	))

	// An absolute location, the same primitive with the classic /etc/shadow
	// target.
	f.add("onnx_absolute_external.onnx", pbCat(
		pbVar(1, 8),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(5, pbTensorExternal("w", []int64{4}, 1,
				pbEntry("location", "/etc/shadow"),
				pbEntry("offset", "0"),
				pbEntry("length", "16"),
			)),
		)),
	))

	// Attribute injection: "__class__" is outside the loader's whitelist of
	// {location, offset, length, checksum, basepath} and reaches a setattr-shaped
	// sink (CVE-2026-34445 = GHSA-538c-55jv-c5g9). The length is 2^60, which is
	// petabyte-scale and was used as an allocation size before validation.
	f.add("onnx_external_attr_injection.onnx", pbCat(
		pbVar(1, 8),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(5, pbTensorExternal("w", []int64{2}, 1,
				pbEntry("location", "weights.bin"),
				pbEntry("offset", "0"),
				pbEntry("length", "1152921504606846976"),
				pbEntry("__class__", "Exploit"),
			)),
		)),
	))

	// A node in a runtime-supplied operator domain: the model file cannot contain
	// the implementation, so the behaviour is decided by the host's plugin set.
	f.add("onnx_custom_domain.onnx", pbCat(
		pbVar(1, 8),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(1, pbNode("evil", "CustomOp", "com.example")),
		)),
	))

	// A model-local function body: a subgraph supplied by the file rather than an
	// operator schema from the specification.
	f.add("onnx_functions.onnx", pbCat(
		pbVar(1, 8),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(pbStr(2, "g"))),
		pbBytes(25, pbCat(
			pbStr(1, "MyFn"),
			pbBytes(7, pbNode("n", "Identity", "")),
			pbBytes(9, pbOpset("", 17)),
		)),
	))

	// raw_data whose length disagrees with product(dims) x element size: dims
	// [2,3] of FLOAT is 24 bytes, and the tensor carries 8.
	f.add("onnx_dims_mismatch.onnx", pbCat(
		pbVar(1, 8),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(5, pbCat(
				pbVar(1, 2), pbVar(1, 3), // dims
				pbVar(2, 1),   // data_type FLOAT
				pbStr(8, "w"), // name
				pbBytes(9, []byte{0, 0, 0, 0, 0, 0, 0, 0}), // raw_data, 8 bytes
			)),
		)),
	))

	// The negative control for the CoreML description discriminator: a ModelProto
	// whose producer_name is the string "pytorch". It parses as a plausible tag
	// sequence for two bytes and then fails, so the CoreML sniffer must not claim
	// it, and the file keeps its ONNX dispatch.
	f.add("onnx_producer_name_string.onnx", pbCat(
		pbVar(1, 7),
		pbStr(2, "pytorch"),
	))

	// A ModelProto whose graph field declares more bytes than the file holds: the
	// shape of a header slice of a large model. nomic-embed-text-v1.5's
	// onnx/model.onnx is this shape, and before the sniffer accepted a truncated
	// walk it was dispatched as *text*, so every ONNX rule was skipped and the
	// tensor bytes produced a format-extension mismatch and Unicode findings.
	f.add("onnx_slice.onnx", pbCat(
		pbVar(1, 7),
		pbStr(2, "pytorch"),
		pbStr(3, "2.1.0"),
		pbTag(7, 2),
		pbVarint(1<<20),
		make([]byte, 64),
	))

	// The benign control: a well-formed model with a standard domain, one node
	// and one initializer whose raw_data length matches its dims exactly. It must
	// produce no high or critical finding, otherwise the ONNX rules are not usable
	// as a gate.
	f.add("benign/tiny.onnx", pbCat(
		pbVar(1, 8),
		pbStr(2, "sc4n-fixture"),
		pbBytes(8, pbOpset("", 17)),
		pbBytes(7, pbGraph(
			pbStr(2, "g"),
			pbBytes(1, pbNode("n", "Identity", "")),
			pbBytes(5, pbCat(
				pbVar(2, 1),              // data_type FLOAT
				pbStr(8, "w"),            // name
				pbVar(1, 2), pbVar(1, 2), // dims [2,2]
				pbBytes(9, make([]byte, 16)), // raw_data: 2*2*4 bytes
			)),
		)),
	))
}

func onnxExpectations() map[string]expectation {
	return map[string]expectation{
		"onnx_slice.onnx": {
			Expect: []string{"SC4N-ONNX-STRUCT"},
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "A ModelProto whose graph field declares 1 MiB and delivers 64 bytes: a header " +
				"slice of a larger model. The sniffer must claim it as ONNX (a truncated walk with an " +
				"ir_version opening) so the ONNX rules run and the parser says the stream stopped at " +
				"the slice boundary, instead of scanning the protobuf as text and reporting an " +
				"extension mismatch.",
		},
		"onnx_producer_name_string.onnx": {
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "The negative control for the CoreML description discriminator: field 2 " +
				"carries the string \"pytorch\", which is a well-formed-looking tag sequence " +
				"only until the third byte, so the file stays ONNX. It pins that a real " +
				"ModelProto's producer_name is not stolen by the CoreML sniffer.",
		},
		"onnx_external_traversal.onnx": {
			Expect: []string{"SC4N-ONNX-EXTERNAL-TRAVERSAL"},
			Forbid: []string{
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
				"SC4N-ONNX-EXTERNAL-SYMLINK",
				"SC4N-ONNX-CUSTOM-DOMAIN",
				"SC4N-ONNX-FUNCTION",
				"SC4N-ONNX-STRUCT",
				// The value fails the path-shape checks, so it is never resolved;
				// PATH-ESCAPE is for a path that passes them and is rejected by
				// os.Root.
				"SC4N-PATH-ESCAPE",
			},
			Notes: "external_data location '../../etc/passwd'. The loader resolves it relative to the " +
				"model directory and returns the file's bytes as tensor content: CVE-2022-25882, with " +
				"CVE-2024-27318 as the bypass of that fix.",
		},
		"onnx_absolute_external.onnx": {
			Expect: []string{"SC4N-ONNX-EXTERNAL-TRAVERSAL"},
			Forbid: []string{
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
				"SC4N-ONNX-EXTERNAL-SYMLINK",
				"SC4N-ONNX-STRUCT",
				"SC4N-PATH-ESCAPE",
			},
			Notes: "external_data location '/etc/shadow'. An absolute path needs no '..' at all and is " +
				"the most direct form of the arbitrary-read primitive.",
		},
		"onnx_external_attr_injection.onnx": {
			Expect: []string{
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
			},
			Forbid: []string{
				"SC4N-ONNX-EXTERNAL-TRAVERSAL",
				"SC4N-ONNX-EXTERNAL-SYMLINK",
				"SC4N-ONNX-STRUCT",
				"SC4N-PATH-ESCAPE",
			},
			Notes: "A '__class__' key plus length 2^60. The whitelist is exactly {location, offset, " +
				"length, checksum, basepath}; anything else is assigned onto an object, which is the " +
				"attribute-injection half of CVE-2026-34445 = GHSA-538c-55jv-c5g9 (NOT CVE-2026-34447, " +
				"which is the path-handling bug GHSA-p433-9wv8-28xj). The length is the OOM half.",
		},
		"onnx_custom_domain.onnx": {
			Expect: []string{"SC4N-ONNX-CUSTOM-DOMAIN"},
			Forbid: []string{
				"SC4N-ONNX-EXTERNAL-TRAVERSAL",
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
				"SC4N-ONNX-FUNCTION",
				"SC4N-ONNX-STRUCT",
			},
			Notes: "A node in domain 'com.example'. The operator has to come from a native extension " +
				"of the runtime, so the artifact's behaviour is a property of the host's plugin set.",
		},
		"onnx_functions.onnx": {
			Expect: []string{"SC4N-ONNX-FUNCTION"},
			Forbid: []string{
				"SC4N-ONNX-CUSTOM-DOMAIN",
				"SC4N-ONNX-EXTERNAL-TRAVERSAL",
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
				"SC4N-ONNX-STRUCT",
			},
			Notes: "A ModelProto.functions body: a subgraph supplied by the file. The runtime resolves " +
				"and executes it, so it is attacker-controlled code that the standard operator schemas " +
				"do not describe.",
		},
		"onnx_dims_mismatch.onnx": {
			Expect: []string{"SC4N-ONNX-STRUCT"},
			Forbid: []string{
				"SC4N-ONNX-EXTERNAL-TRAVERSAL",
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
				"SC4N-ONNX-CUSTOM-DOMAIN",
				"SC4N-ONNX-FUNCTION",
			},
			Notes: "dims [2,3] of FLOAT is 24 bytes of raw_data; the tensor carries 8. A loader that " +
				"trusts the shape and a scanner that trusts the length see different tensors.",
		},
	}
}

func onnxBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/tiny.onnx": {
			// The forbid list is the valuable half here: the benign fixture is the
			// false-positive gate for every ONNX rule, and it is evaluated by the
			// same TestFixtureExpectations as the malicious corpus.
			Forbid: []string{
				"SC4N-ONNX-EXTERNAL-TRAVERSAL",
				"SC4N-ONNX-EXTERNAL-KEY",
				"SC4N-ONNX-EXTERNAL-BOUNDS",
				"SC4N-ONNX-EXTERNAL-SYMLINK",
				"SC4N-ONNX-CUSTOM-DOMAIN",
				"SC4N-ONNX-FUNCTION",
				"SC4N-ONNX-STRUCT",
				"SC4N-PATH-ESCAPE",
			},
			Notes: "The smallest well-formed model: ir_version, one standard opset import, one node " +
				"in the default domain and one initializer whose raw_data length equals dims x element " +
				"size, with no external data at all. The correct output is no high or critical finding.",
		},
	}
}

// The encoder. Wire types: 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32.

// pbVarint encodes v as a base-128 varint.
func pbVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

// pbTag encodes a field tag: tag = field<<3 | wiretype.
func pbTag(field, wire int) []byte {
	return pbVarint(uint64(field)<<3 | uint64(wire))
}

// pbVar encodes a varint-valued field.
func pbVar(field int, v uint64) []byte {
	return append(pbTag(field, 0), pbVarint(v)...)
}

// pbBytes encodes a length-delimited field.
func pbBytes(field int, b []byte) []byte {
	return append(append(pbTag(field, 2), pbVarint(uint64(len(b)))...), b...)
}

// pbStr encodes a string field.
func pbStr(field int, s string) []byte {
	return pbBytes(field, []byte(s))
}

// pbCat concatenates the parts of one message.
func pbCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// pbEntry is a StringStringEntryProto (key=1, value=2), the shape ONNX uses for
// maps such as external_data.
func pbEntry(key, value string) []byte {
	return pbCat(pbStr(1, key), pbStr(2, value))
}

// pbOpset is an OperatorSetIdProto (domain=1, version=2).
func pbOpset(domain string, version uint64) []byte {
	return pbCat(pbStr(1, domain), pbVar(2, version))
}

// pbNode is a NodeProto (input=1, output=2, name=3, op_type=4, domain=7).
func pbNode(name, opType, domain string) []byte {
	out := pbCat(
		pbStr(1, "x"),
		pbStr(2, "y"),
		pbStr(3, name),
		pbStr(4, opType),
	)
	if domain != "" {
		out = append(out, pbStr(7, domain)...)
	}
	return out
}

// pbTensorExternal is a TensorProto whose data lives outside the protobuf
// (dims=1, data_type=2, name=8, external_data=13, data_location=14).
func pbTensorExternal(name string, dims []int64, dataType int64, entries ...[]byte) []byte {
	out := pbCat(pbStr(8, name), pbVar(2, uint64(dataType)))
	for _, d := range dims {
		out = append(out, pbVar(1, uint64(d))...)
	}
	for _, e := range entries {
		out = append(out, pbBytes(13, e)...)
	}
	return append(out, pbVar(14, 1)...) // data_location = EXTERNAL
}

// pbGraph is a GraphProto (node=1, name=2, initializer=5). The parts are the
// already-encoded fields.
func pbGraph(parts ...[]byte) []byte {
	return pbCat(parts...)
}
