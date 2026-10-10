package main

import (
	"archive/tar"
	"bytes"
	"time"
)

// torchFixtures writes the PyTorch checkpoint-family fixtures.
//
// Torch is the highest-value parser in sc4n: `torch.save` is a Python pickle, and
// each of its container shapes has its own evasion story. The fixtures therefore
// pin one shape each -- new zip, prefixed zip, TorchScript, legacy binary with a
// storage tail, legacy tar, 7z-disguised .pt, .pt2 -- and, for every one that
// reaches a pickle, a payload that only the pickle engine can see, so the
// expectation proves the engine ran *through* the torch path rather than beside it.
//
// References: torch/serialization.py (_save, _legacy_save, _legacy_load), the
// PyTorch serialization notes, the February 2025 Hugging Face 7z-in-.pt campaign,
// and arXiv 2508.19774 Appendix B2 (legacy tar loading paths).
func init() {
	register(contributor{
		name:     "torch",
		fixtures: torchFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return torchExpectations(), torchBenignExpectations()
		},
	})
	register(contributor{
		name:         "bin-zip",
		fixtures:     binZipFixtures,
		expectations: func() (malicious, benign map[string]expectation) { return binZipExpectations(), nil },
	})
}

func torchFixtures(f *fixtureSet) {
	// --- new-format zip, malicious data.pkl --------------------------------------
	// The default torch.save since 1.6: an uncompressed zip of data.pkl, byteorder
	// and data/<n>. data.pkl here calls os.system, so a scanner that reads the
	// member with the pickle engine reports it and one that only sniffs the zip
	// magic does not.
	f.add("torch_new_zip.pt", torchZipBytes(arcGadgetPickle()))

	// --- prefixed archive --------------------------------------------------------
	// A valid zip whose first local file header is preceded by arbitrary bytes.
	// Python's _is_zipfile only checks the current offset, while the C++
	// PyTorchStreamReader derives the archive base from the first record, so the
	// loader still opens it. The prefix is not PK so the magic table misses it and
	// only the torch sniffer's extension hint catches it.
	f.add("torch_prefixed_zip.pt", cat([]byte("sc4n-torch-prefix\x00\x01\x02"), torchZipBytes(arcGadgetPickle())))

	// --- TorchScript: code/*.py is attacker-controlled source stored as data -----
	// data.pkl carries a gadget; code/model.py reads input() into os.system. The
	// .py member must reach the Python analyser and data.pkl the pickle engine.
	script := []byte("import os\ncmd = input()\nos.system(cmd)\n")
	f.add("torch_script.pt", arcZip([]arcZipSpec{
		{name: "byteorder", data: []byte("little"), method: 0},
		{name: "data.pkl", data: arcGadgetPickle(), method: 0},
		{name: "constants.pkl", data: arcGadgetPickle(), method: 0},
		{name: "code/model.py", data: script, method: 0},
	}))

	// --- legacy binary with a storage tail ---------------------------------------
	// MAGIC_NUMBER (pickled), PROTOCOL_VERSION, sys_info, the object pickle, the
	// storage-key list, then raw storage. The object pickle is the gadget; the tail
	// is storage the loader appends, so it must NOT be reported as an attack suffix.
	f.add("torch_legacy.pt", torchLegacyBytes(arcGadgetPickle()))

	// --- legacy tar --------------------------------------------------------------
	// The old tar layout (arXiv 2508.19774 Appendix B2): a `pickle` member with the
	// object graph plus `storages` and `tensors` metadata members.
	pickleMember := arcGadgetPickle()
	storagesMember := cat(proto(2), []byte{bBININT1, 0x00}, stop())
	tensorsMember := cat(proto(2), []byte{bBININT1, 0x00}, stop())
	f.add("torch_legacy_tar.pt", torchTarBytes(pickleMember, storagesMember, tensorsMember))

	// --- 7z disguised as a .pt ---------------------------------------------------
	// The February 2025 Hugging Face campaign: a .pt whose bytes are a 7z archive.
	// An extension-driven scanner saw "not a zip"; sc4n cannot decode 7z and says so.
	f.add("torch_7z.pt", cat([]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, make([]byte, 64)))

	// --- .pt2 export archive -----------------------------------------------------
	// archive_format + models/<m>.json + data/weights + a sample_inputs/*.pt that is
	// itself a real torch.save pickle, so the payload is one recursion deep.
	inner := torchZipBytes(arcGadgetPickle())
	f.add("torch_pt2.pt2", arcZip([]arcZipSpec{
		{name: "archive_format", data: []byte("pt2"), method: 0},
		{name: "byteorder", data: []byte("little"), method: 0},
		{name: ".data/version", data: []byte("4"), method: 0},
		{name: "models/m.json", data: []byte(`{"name":"m"}`), method: 0},
		{name: "data/weights/w", data: make([]byte, 16), method: 0},
		{name: "data/sample_inputs/m.pt", data: inner, method: 0},
	}))

	// --- benign: a real-structure torch zip --------------------------------------
	// torch.save's own pickle for one F32 tensor plus an ordinary storage member.
	// The false-positive gate for the whole torch path: no finding above info.
	f.add("benign/torch_clean.pt", torchZipBytes(benignStateDict()))
}

// torchZipBytes builds a minimal new-format torch archive around a data.pkl.
func torchZipBytes(dataPkl []byte) []byte {
	return arcZip([]arcZipSpec{
		{name: "byteorder", data: []byte("little"), method: 0},
		{name: "data.pkl", data: dataPkl, method: 0},
		{name: "data/0", data: make([]byte, 64), method: 0},
	})
}

// torchMagic is MAGIC_NUMBER = 0x1950A86A20F9469CFC6C in little-endian byte order
// (10 bytes). _legacy_save pickles it, so torchLegacyBytes writes it as PROTO 2 +
// LONG1 + length 10 + these bytes + STOP.
var torchMagic = []byte{0x6C, 0xFC, 0x9C, 0x46, 0xF9, 0x20, 0x6A, 0xA8, 0x50, 0x19}

// torchLegacyBytes assembles the legacy binary layout with the given object pickle.
func torchLegacyBytes(obj []byte) []byte {
	magic := cat(proto(2), []byte{bLONG1, byte(len(torchMagic))}, torchMagic, stop())
	version := cat(proto(2), []byte{bBININT2}, u2(1001), stop())
	sysinfo := cat(proto(2), []byte{bEMPTY_DICT}, []byte{bMARK},
		binUnicode("protocol_version"), []byte{bBININT2}, u2(1001),
		[]byte{bSETITEMS}, stop())
	keys := cat(proto(2), []byte{bEMPTY_LIST}, stop())
	storage := make([]byte, 64) // raw storage appended after the last pickle
	return cat(magic, version, sysinfo, obj, keys, storage)
}

// torchTarBytes builds a ustar tar with the three legacy members.
func torchTarBytes(pickleMember, storagesMember, tensorsMember []byte) []byte {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	add := func(name string, body []byte) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}
		if err := w.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if _, err := w.Write(body); err != nil {
			panic(err)
		}
	}
	add("storages", storagesMember)
	add("tensors", tensorsMember)
	add("pickle", pickleMember)
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func torchExpectations() map[string]expectation {
	return map[string]expectation{
		"torch_new_zip.pt": {
			Expect: []string{"SC4N-TORCH-ZIP", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-TORCH-PREFIXED-ARCHIVE", "SC4N-TORCH-7Z", "SC4N-TORCH-STRUCT"},
			Notes: "The default torch.save shape (zip: data.pkl + byteorder + data/<n>) whose data.pkl " +
				"calls os.system. SC4N-PICKLE-REDUCE proves the pickle engine ran on the member.",
		},
		"torch_prefixed_zip.pt": {
			Expect: []string{"SC4N-TORCH-PREFIXED-ARCHIVE", "SC4N-TORCH-ZIP", "SC4N-PICKLE-REDUCE"},
			Notes: "A zip with bytes before its first local header. Python's _is_zipfile misses it, the C++ " +
				"PyTorchStreamReader still opens it; the members are still scanned.",
		},
		"torch_script.pt": {
			Expect: []string{"SC4N-TORCH-SCRIPT", "SC4N-PICKLE-REDUCE", "SC4N-CODE-TAINT-SHELL"},
			Notes: "TorchScript: code/model.py is Python stored as data and data.pkl is a pickle; both must " +
				"reach their engines.",
		},
		"torch_legacy.pt": {
			Expect: []string{"SC4N-TORCH-LEGACY", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-PICKLE-TRAILING"},
			Notes: "Legacy binary checkpoint: the object pickle is the gadget and the appended raw storage " +
				"is the container's payload, not an attack suffix.",
		},
		"torch_legacy_tar.pt": {
			Expect: []string{"SC4N-TORCH-LEGACY-TAR", "SC4N-PICKLE-REDUCE"},
			Notes: "Legacy tar checkpoint: the `pickle` member is the object graph and reaches the pickle " +
				"engine.",
		},
		"torch_7z.pt": {
			Expect: []string{"SC4N-TORCH-7Z", "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION"},
			Notes: "7z signature under a .pt name (the February 2025 Hugging Face campaign). sc4n names both " +
				"the disguise and the unreadable payload, and never claims the pickle inside was scanned.",
		},
		"torch_pt2.pt2": {
			Expect: []string{"SC4N-TORCH-PT2", "SC4N-PICKLE-REDUCE"},
			Notes: ".pt2 export archive whose data/sample_inputs/m.pt is a real torch.save pickle, one " +
				"recursion deep.",
		},
	}
}

func torchBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/torch_clean.pt": {
			Notes: "torch.save's own pickle for one F32 tensor plus a storage member. The false-positive " +
				"gate for the whole torch path: the shape rule is info, so nothing high or critical fires.",
		},
	}
}

// binZipFixtures writes the .bin/.pth container fixtures.
//
// HF's Trainer writes training_args.bin as torch.save's zip, with the members
// under a training_args/ prefix, and a torch-saved .pth dict of tensors is the
// same container. Both extensions now list a zip, so the file is read rather than
// reported as contradicting its name; the container the loader cannot read at all
// (a gzip stream named .bin) must still be reported.
func binZipFixtures(f *fixtureSet) {
	f.add("torchzip/training_args.bin", arcZip([]arcZipSpec{
		{name: "training_args/data.pkl", data: benignStateDict(), method: 0},
		{name: "training_args/byteorder", data: []byte("little"), method: 0},
	}))
	f.add("bin_gzip.bin", arcGzip([]byte("plain training args\n")))
}

func binZipExpectations() map[string]expectation {
	return map[string]expectation{
		"torchzip/training_args.bin": {
			Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH", "SC4N-PARSE-FAILED"},
			Notes: "The HF Trainer shape: a zip of training_args/{data.pkl,byteorder} named .bin. " +
				"torch.load reads it and the archive reader opens its members, so the extension " +
				"must not be reported as a mismatch. The member here is the benign state dict, so " +
				"the fixture is about the container and nothing else.",
		},
		"bin_gzip.bin": {
			Expect: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
			Notes: "The boundary of the same row: a gzip stream named .bin is not something torch.load " +
				"or any other .bin loader reads, so listing a zip for .bin must not excuse it.",
		},
	}
}
