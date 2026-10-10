package main

import (
	"bytes"
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
			return nil, map[string]expectation{
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
