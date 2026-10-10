package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
)

// joblibCompressionFixtures writes the fixture for the extension check's joblib
// exemption.
//
// joblib's loader accepts every single-stream compressor it ships, because
// joblib.dump's `compress` parameter is part of the format's API and
// _detect_compressor picks the decompressor from the file's magic prefix. A
// .joblib that is a zlib stream is therefore exactly what joblib.load reads, and
// reporting it as SC4N-FORMAT-EXTENSION-MISMATCH was a false positive on the
// format's own default (compress=3 is zlib) — one that fires at medium/high
// confidence and so trips `-fail-on medium` in CI.
//
// The fixture is benign on purpose: it sits under benign/, so the strengthened
// false-positive gate (any finding above info) is what keeps the exemption honest.
func init() {
	register(contributor{
		name:     "joblib-compression",
		fixtures: joblibCompressionFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"joblib_zstd.joblib": {
					Expect: []string{"SC4N-FORMAT-EXTENSION-MISMATCH", "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION"},
					Notes: "A zstd stream named .joblib. joblib ships no zstd compressor (its magic " +
						"table is \\x78, \\x1f\\x8b, BZ, \\xfd7zXZ, \\x5d\\x00, \\x04\\x22\\x4d\\x18 and ZF), so " +
						"joblib.load cannot read it and the name really does contradict the content. " +
						"This is the boundary of the .joblib exemption: the seven joblib accepts are " +
						"plausible, anything else still reports.",
				},
				"pickle_gzip.pkl": {
					Expect: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
					Notes: "A gzip stream named .pkl holding a pickle. pickle.load does not transparently " +
						"decompress, so the name lies about what a loader reading it gets — the same bytes " +
						"under .joblib would be loadable and exempt. The finding is the extension check's " +
						"purpose, not a false positive.",
				},
			}, map[string]expectation{
				"benign/joblib_compressed.joblib": {
					Forbid: []string{
						"SC4N-FORMAT-EXTENSION-MISMATCH",
						"SC4N-JOBLIB-WRAPPER-MISMATCH",
						"SC4N-PICKLE-REQUIRES-UNSAFE-LOADER",
						"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-GLOBAL-HIGH", "SC4N-PICKLE-GLOBAL-UNKNOWN",
						"SC4N-PICKLE-REDUCE", "SC4N-PICKLE-BUILD-STATE", "SC4N-PICKLE-MEMO-ALIAS",
						"SC4N-PICKLE-STRUCT", "SC4N-PICKLE-INCOMPLETE", "SC4N-PICKLE-TRAILING",
					},
					Notes: "A protocol-2 joblib array wrapped in zlib — the shape joblib.dump(compress=3) " +
						"writes, and the shape joblib.load reads back. The content is dispatched as zlib, " +
						"unwrapped, and the member is parsed by the joblib/pickle engine, so the correct " +
						"output is no finding at all: the extension check must treat joblib's own " +
						"compressors as plausible for .joblib, exactly as it treats the pre-0.10 ZF frame. " +
						"The pickle family is forbidden as well, so a regression in the unwrap/mask path " +
						"is caught by the benign gate rather than by the mismatch alone.",
				},
			}
		},
	})
}

func joblibCompressionFixtures(f *fixtureSet) {
	// The same benign wrapper stream as benign/joblib_benign.joblib (protocol 2,
	// NumpyArrayWrapper, a correctly sized 2x3 f8 payload), compressed.
	stream := nfJoblibP2("<f8", cat([]byte{bBININT1, 2}, []byte{bBININT1, 3}), nfPayload(make([]byte, 48)))
	f.add("benign/joblib_compressed.joblib", jcZlib(stream))

	// The other side of the boundary: joblib 1.4.2 ships no zstd compressor
	// (its magic table is \x78, \x1f\x8b, BZ, \xfd7zXZ, \x5d\x00, \x04\x22\x4d\x18
	// and ZF), so a .joblib that is a zstd stream is not loadable by joblib.load and
	// the mismatch is real. The fixture keeps the exemption from being widened to
	// "any compressor" by accident.
	f.add("joblib_zstd.joblib", cat(
		[]byte{0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x00, 0x00},
		bytes.Repeat([]byte{0x00}, 32),
	))

	// And the pickle side: pickle.load does not transparently decompress, so a .pkl
	// that is a gzip stream genuinely contradicts its name — the extension check's
	// purpose — while joblib.load would have accepted the same bytes under .joblib.
	f.add("pickle_gzip.pkl", jcGzip(cat(proto(2), globalText("posix", "system"), []byte{bNONE}, []byte{bTUPLE},
		[]byte{bREDUCE}, stop())))
}

// jcGzip wraps b in a gzip stream.
func jcGzip(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		panic("joblib fixture: gzip write: " + err.Error())
	}
	if err := w.Close(); err != nil {
		panic("joblib fixture: gzip close: " + err.Error())
	}
	return buf.Bytes()
}

// jcZlib wraps b in a zlib stream (RFC 1950), which is what joblib's default
// compress=3 produces.
func jcZlib(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		panic("joblib fixture: zlib write: " + err.Error())
	}
	if err := w.Close(); err != nil {
		panic("joblib fixture: zlib close: " + err.Error())
	}
	return buf.Bytes()
}
