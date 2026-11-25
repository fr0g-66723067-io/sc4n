// Package gguf parses GGUF model files (the llama.cpp / ggml on-device format).
//
// The parser is a total, bounds-checked walk of the metadata region: every
// declared count, key, value, tensor name, dimension, type id and offset is
// validated against the bytes actually present, and a violation is a finding
// rather than an abort. It reads only through source.Source, never allocates from
// an attacker-controlled length before validating it, validates executable magic
// with the standard library's debug/elf, debug/macho and debug/pe parsers, never
// extracts anything to disk and never executes the artifact.
//
// The tensor *data* is not read: this package validates geometry (offsets,
// alignment, extents) and scans metadata strings, which is what makes it cheap on
// a multi-gigabyte model. Chat templates are collected (see ChatTemplates) for
// the Jinja analyzer the format layer wires in; this package does not import it.
package gguf

import (
	"encoding/binary"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format: artifact.FormatGGUF,
		Magic:  "GGUF",
		Depth:  artifact.DepthDeep,
		Notes: "the metadata region is walked in full: magic, version (2 or 3, including the version 3 " +
			"big-endian variant), both counts, every KV pair and every tensor info record. Counts beyond the " +
			"file, illegal or duplicate keys, retired or out-of-range ggml types, a rank above 4, a zero " +
			"dimension, non-zero alignment padding, and misaligned, unsorted or overlapping tensor offsets " +
			"are reported; tensor extents are checked against a transcribed ggml type table, and a tensor " +
			"whose extent cannot be computed is reported as unverified rather than guessed at. Trailing " +
			"bytes after the last tensor, the llamafile/APE and embedded-native polyglot shapes, and " +
			"chat-template introspection or instruction-override text are reported too. The tensor data " +
			"itself is not read or decoded; string metadata is scanned at a sampled cap.",
	})
	artifact.RegisterSniffer("gguf-header", 100, sniff)
	artifact.RegisterParser(artifact.FormatGGUF, parser{})
}

// sniff claims a file whose first four bytes are the GGUF magic AND whose
// 4-byte version field is 2 or 3 in little- or big-endian. Checking the version
// keeps a source file starting with "GGUF=1" from being hijacked as GGUF.
func sniff(s source.Source, l limits.Limits) (artifact.Format, bool) {
	if s.Size() < 8 {
		return artifact.FormatUnknown, false
	}
	b, err := s.Bytes(0, 8)
	if err != nil && len(b) < 8 {
		return artifact.FormatUnknown, false
	}
	if string(b[:4]) != Magic {
		return artifact.FormatUnknown, false
	}
	le := binary.LittleEndian.Uint32(b[4:8])
	be := binary.BigEndian.Uint32(b[4:8])
	if le != 2 && le != 3 && be != 2 && be != 3 {
		return artifact.FormatUnknown, false
	}
	return artifact.FormatGGUF, true
}
