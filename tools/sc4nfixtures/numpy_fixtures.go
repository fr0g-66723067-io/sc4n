package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"sort"
	"time"
)

// numpyFixtures writes the .npy/.npz/joblib fixtures.
//
// Each fixture pins one property of the format that the parser turns into a
// rule: the object-dtype detour into the pickle engine (the numpy.load
// allow_pickle=True path), a declared shape larger than the data, undeclared
// trailing bytes, a joblib array payload that disagrees with its wrapper, and a
// nested object-dtype pickle inside a joblib wrapper.
func init() {
	register(contributor{
		name:     "numpy",
		fixtures: numpyFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return numpyExpectations(), numpyBenignExpectations()
		},
	})
}

func numpyFixtures(f *fixtureSet) {
	// A protocol-4 os.system gadget, reused as the pickle payload of the object
	// array and of the nested joblib array.
	gadget := cat(
		proto(4),
		stackGlobal("os", "system"),
		shortBinUnicode("id"),
		[]byte{bTUPLE1},
		[]byte{bREDUCE},
		stop(),
	)

	// .npy with descr '|O': the data section is a pickle stream, so
	// numpy.load(allow_pickle=True) reaches the gadget. This is the documented
	// RCE path through an object array.
	f.add("numpy_object.npy", nfNPY("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", gadget))

	// A valid header whose declared shape needs more bytes than are present:
	// the parser must report it and must not allocate from the shape.
	f.add("numpy_shape_exceeds.npy",
		nfNPY("{'descr': '<f8', 'fortran_order': False, 'shape': (1024, 1024)}", make([]byte, 64)))

	// Bytes after the declared array.
	f.add("numpy_trailing.npy",
		nfNPY("{'descr': '<f8', 'fortran_order': False, 'shape': (2,)}",
			append(make([]byte, 16), []byte("PLANTED-TRAILING")...)))

	// .npz whose member is the object array above: the member must reach the
	// .npy parser through the container walk.
	f.add("numpy_object.npz", nfZip(map[string][]byte{
		"obj.npy": nfNPY("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", gadget),
	}))

	// A joblib array whose declared shape and payload length agree: the benign
	// array shape. Its wrapper globals are allowlisted (internal/numpy's init
	// registers them), so the wrapper's own REDUCE/BUILD do not fire and the
	// file is clean.
	f.add("benign/joblib_benign.joblib", nfJoblibP2("<f8", cat([]byte{bBININT1, 2}, []byte{bBININT1, 3}),
		nfPayload(make([]byte, 48))))

	// A joblib object-dtype array: the payload after the padding frame is a
	// nested protocol-4 pickle, which must reach the pickle engine.
	f.add("joblib_object_array.joblib", nfJoblib("|O", []byte{bBININT1, 2}, nfPayload(gadget)))

	// The wrapper declares 2x3 f8 = 48 bytes but the payload is 47: the gap a
	// second object can ride in.
	f.add("joblib_wrapper_mismatch.joblib", nfJoblib("<f8",
		cat([]byte{bBININT1, 2}, []byte{bBININT1, 3}), nfPayload(make([]byte, 47))))

	// Benign counterparts.
	f.add("benign/model.npy",
		nfNPY("{'descr': '<f8', 'fortran_order': False, 'shape': (4,)}", make([]byte, 32)))
	f.add("benign/model.npz", nfZip(map[string][]byte{
		"arr_0.npy": nfNPY("{'descr': '<f4', 'fortran_order': False, 'shape': (4,)}", make([]byte, 16)),
	}))
}

func numpyExpectations() map[string]expectation {
	return map[string]expectation{
		"numpy_object.npy": {
			Expect: []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-REDUCE", "SC4N-PICKLE-GLOBAL-CRITICAL"},
			Forbid: []string{"SC4N-NUMPY-STRUCT"},
			Notes:  "An object-dtype array whose data section is a pickle calling os.system: the numpy.load(allow_pickle=True) RCE path, dispatched to the pickle engine.",
		},
		"numpy_shape_exceeds.npy": {
			Expect: []string{"SC4N-NUMPY-STRUCT"},
			Forbid: []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-NUMPY-TRAILING"},
			Notes:  "A well-formed header declaring a 1M-element array in a 64-byte file: the shape is rejected, not trusted, and no bytes are allocated from it.",
		},
		"numpy_trailing.npy": {
			Expect: []string{"SC4N-NUMPY-TRAILING"},
			Forbid: []string{"SC4N-NUMPY-STRUCT"},
			Notes:  "A correct 2-element array with an undeclared tail: the format has no field for it, so it is a polyglot/steganography shape.",
		},
		"numpy_object.npz": {
			Expect: []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-NUMPY-STRUCT"},
			Notes:  "The object-array .npy above as a member of a .npz, reached through the container member dispatch.",
		},
		"joblib_object_array.joblib": {
			Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
			Forbid: []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"},
			Notes:  "A joblib object-dtype array whose padding-framed payload is a nested protocol-4 pickle calling os.system; the nested stream must be walked.",
		},
		"joblib_wrapper_mismatch.joblib": {
			Expect: []string{"SC4N-JOBLIB-WRAPPER-MISMATCH"},
			Notes:  "The wrapper declares 48 bytes of f8 but the payload carries 47, the gap SC4N-JOBLIB-WRAPPER-MISMATCH exists to expose.",
		},
	}
}

func numpyBenignExpectations() map[string]expectation {
	return map[string]expectation{
		"benign/model.npy": {
			Notes: "A correct 4-element f8 array with exact coverage; the correct output is no finding at all.",
		},
		"benign/model.npz": {
			Notes: "A .npz with one correct .npy member and no other content; the correct output is no finding at all.",
		},
		"benign/joblib_benign.joblib": {
			Forbid: []string{
				"SC4N-JOBLIB-WRAPPER-MISMATCH",
				"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-GLOBAL-HIGH", "SC4N-PICKLE-GLOBAL-UNKNOWN",
				"SC4N-PICKLE-REDUCE", "SC4N-PICKLE-BUILD-STATE",
				"SC4N-PICKLE-INST", "SC4N-PICKLE-OBJ", "SC4N-PICKLE-NEWOBJ", "SC4N-PICKLE-NEWOBJ_EX",
				"SC4N-PICKLE-SETITEM-TARGET", "SC4N-PICKLE-APPEND-TARGET", "SC4N-PICKLE-PERSID",
				"SC4N-PICKLE-EXT", "SC4N-PICKLE-MEMO-ALIAS", "SC4N-PICKLE-STRUCT",
				"SC4N-PICKLE-CODE-STRING", "SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
				"SC4N-PICKLE-PREFIX", "SC4N-PICKLE-TRAILING", "SC4N-PICKLE-SEGMENT",
				"SC4N-PICKLE-INCOMPLETE", "SC4N-PICKLE-OFFSET-ZERO", "SC4N-PICKLE-STACK",
				"SC4N-PICKLE-SAFE-GLOBALS",
			},
			Notes: "A joblib array (NumpyArrayWrapper + a correctly sized 2x3 f8 payload) with the wrapper " +
				"globals registered as allowlisted, so the wrapper's own REDUCE/BUILD do not fire and the " +
				"whole SC4N-PICKLE-* family and SC4N-JOBLIB-WRAPPER-MISMATCH are forbidden. The stream is " +
				"protocol 2 to isolate that property: a current joblib file defaulting to protocol 4/5 would " +
				"also, honestly, trip SC4N-PICKLE-REQUIRES-UNSAFE-LOADER at low confidence, which is the " +
				"rule's documented behaviour rather than a wrapper problem.",
		},
	}
}

// nfNPY builds a version-1.0 .npy prelude, the literal header and the data.
func nfNPY(header string, data []byte) []byte {
	out := []byte{0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0}
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(header)))
	out = append(out, l[:]...)
	out = append(out, header...)
	return append(out, data...)
}

// nfJoblib builds a joblib numpy_pickle stream: a NumpyArrayWrapper REDUCE with
// (dtype, shape, order, allow_mmap, subclass), a BUILD, a STOP, then the array
// payload tail.
func nfJoblib(dtype string, dims []byte, tail []byte) []byte {
	return cat(
		proto(4),
		globalText("joblib.numpy_pickle", "NumpyArrayWrapper"),
		[]byte{bMARK},
		shortBinUnicode(dtype),
		[]byte{bMARK},
		dims,
		[]byte{bTUPLE},
		shortBinUnicode("C"),
		[]byte{bNEWFALSE},
		[]byte{bNONE},
		[]byte{bTUPLE},
		[]byte{bREDUCE},
		[]byte{bNONE},
		[]byte{bBUILD},
		stop(),
		tail,
	)
}

// nfJoblibP2 builds the same joblib wrapper stream at protocol 2, using
// BINUNICODE instead of SHORT_BINUNICODE. It exists for the benign fixture so
// that no protocol-4 opcode is present and the whole SC4N-PICKLE-* family can be
// forbidden; a current joblib file defaulting to protocol 4/5 would honestly
// trip only SC4N-PICKLE-REQUIRES-UNSAFE-LOADER at low confidence.
func nfJoblibP2(dtype string, dims []byte, tail []byte) []byte {
	return cat(
		proto(2),
		globalText("joblib.numpy_pickle", "NumpyArrayWrapper"),
		[]byte{bMARK},
		binUnicode(dtype),
		[]byte{bMARK},
		dims,
		[]byte{bTUPLE},
		binUnicode("C"),
		[]byte{bNEWFALSE},
		[]byte{bNONE},
		[]byte{bTUPLE},
		[]byte{bREDUCE},
		[]byte{bNONE},
		[]byte{bBUILD},
		stop(),
		tail,
	)
}

// nfPayload frames an array payload with a zero-length padding run.
func nfPayload(data []byte) []byte {
	return cat([]byte{0x00}, data)
}

// nfZip builds a deterministic zip with the given members (deflate, a fixed
// modification time so regeneration is byte-identical).
func nfZip(members map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate, Modified: mod}
		w, err := zw.CreateHeader(h)
		if err != nil {
			panic("numpy fixtures: zip member " + n + ": " + err.Error())
		}
		if _, err := w.Write(members[n]); err != nil {
			panic("numpy fixtures: write " + n + ": " + err.Error())
		}
	}
	if err := zw.Close(); err != nil {
		panic("numpy fixtures: close zip: " + err.Error())
	}
	return buf.Bytes()
}
