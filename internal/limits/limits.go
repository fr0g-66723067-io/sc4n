// Package limits holds the single resource-budget struct that every parser in
// sc4n is threaded with.
//
// The design rule for the whole tree: no parser may allocate from an
// attacker-controlled length before validating that length against the bytes
// actually remaining in the source and against the cap declared here. A budget
// that fires becomes a SC4N-LIMIT-* finding; it is never a silent skip, because
// a silent skip is exactly how modelscan's ZIP iterator reported CLEAN on an
// artifact it had failed to read (modelscan issue #354).
package limits

import "fmt"

// Limits is the decoded form of the `scan` flags. It is passed by value so that
// a parser cannot mutate the budget it was handed.
type Limits struct {
	// MaxArtifactBytes caps a single file (or a single -stdin stream) that sc4n
	// will map or read. Default 64 GiB: larger than any published single-file
	// checkpoint, small enough that a directory walk cannot be turned into a
	// disk-filling read by one path.
	MaxArtifactBytes int64

	// MaxHeaderBytes caps a format's *declared* header or metadata region, i.e.
	// any length field that precedes the payload. Default 100 MiB, mirroring the
	// safetensors reference implementation's own header cap; a header larger than
	// this is a finding, not a truncation.
	MaxHeaderBytes int64

	// MaxDepth caps container nesting (zip inside tar inside gzip …). Default 4:
	// the deepest legitimate nest observed in the wild is
	// joblib -> object-dtype pickle -> (nothing), and torch zip -> pickle.
	MaxDepth int

	// MaxEntries caps the member count of one archive. Default 100_000.
	MaxEntries int

	// MaxArrayElements caps the element count of one *metadata* array — a
	// tokenizer vocabulary, a UBJSON array, a MessagePack array. It is separate
	// from MaxEntries, which counts archive members: a 256 000-token vocabulary is
	// an ordinary file, while a 256 000-member archive is not. Default 1<<22,
	// which is above every published vocabulary (Llama-3 is 128 256, Qwen is
	// 151 936) with a wide margin and still bounds the work.
	MaxArrayElements int

	// MaxDecompressedBytes caps the cumulative decompressed output of one
	// archive (and, independently, of one compression layer). Default 8 GiB.
	MaxDecompressedBytes int64

	// MaxRatio caps decompressed:compressed for one layer. Default 200: above
	// real model compression (a bf16 tensor stream compresses far below 2:1 in
	// practice; tokenizer JSON reaches ~20:1) and far below a zip bomb.
	MaxRatio int64

	// MaxStringBlob caps a single string/blob a parser will materialise in
	// memory (metadata value, tokenizer vocab entry, notebook cell, embedded
	// JSON). Default 16 MiB.
	MaxStringBlob int64

	// MaxRetainedText caps the total text a single artifact's parse may keep
	// alive for matching and evidence. Default 64 MiB. Per-value retention is
	// already capped (MaxStringBlob, and the pickle engine's own 64 KiB per
	// constant), but a structure with a million small values would still retain
	// a gigabyte between them; this bounds the total. Past it, values keep their
	// length and kind and lose their text, and SC4N-LIMIT-RETAINED says so.
	MaxRetainedText int64

	// MaxHashBytes caps how much of an artifact the scan digests. Default
	// 256 MiB. The digest identifies an artifact and de-duplicates a blob
	// reachable from several cache revisions; it is not a provenance proof, and
	// `sc4n hash` is the command that computes a full sha256. The cap exists
	// because sha256 is CPU-bound (measured 0.35 GB/s on the reference host,
	// which has AVX2 but no SHA-NI), so a full digest of a 13 GiB checkpoint
	// would cost ~37 s — more than the whole scan budget — while the digest
	// itself is not what the scan is for. Above the cap the digest covers the
	// first MaxHashBytes and the report says so in sha256Scope.
	MaxHashBytes int64

	// MaxSpillBytes caps a single archive member that has to be materialised on
	// disk before it can be parsed — a compressed member far larger than memory,
	// such as the multi-gigabyte storage entries inside a torch archive. Default
	// 4 GiB: above every published single-member shape, and low enough that a
	// decompression bomb cannot fill the temporary filesystem. Members above it
	// are reported as SC4N-LIMIT-SPILL rather than parsed.
	MaxSpillBytes int64

	// MaxFindings caps the findings list so a crafted artifact with a million
	// trigger sites cannot exhaust memory. Default 100_000.
	MaxFindings int

	// MaxStackDepth caps the pickle operand stack. Default 1<<20: far above
	// anything a real torch state_dict builds (the deepest real value is a few
	// hundred) and far below an OOM.
	MaxStackDepth int

	// MmapThreshold is the file size at or above which source.Open memory-maps
	// instead of reading. Default 1 MiB.
	MmapThreshold int64
}

// Default returns the documented defaults. Every zero-valued Limits field is
// replaced, so a caller may set only the fields it cares about.
func Default() Limits {
	return Limits{
		MaxArtifactBytes:     64 << 30,
		MaxHeaderBytes:       100 << 20,
		MaxDepth:             4,
		MaxEntries:           100_000,
		MaxArrayElements:     1 << 22,
		MaxDecompressedBytes: 8 << 30,
		MaxRatio:             200,
		MaxStringBlob:        16 << 20,
		MaxRetainedText:      64 << 20,
		MaxHashBytes:         256 << 20,
		MaxSpillBytes:        4 << 30,
		MaxFindings:          100_000,
		MaxStackDepth:        1 << 20,
		MmapThreshold:        1 << 20,
	}
}

// RejectOnlyNegativeZero and the With* helpers keep the flag plumbing boring.
func (l Limits) withDefaults() Limits {
	d := Default()
	if l.MaxArtifactBytes == 0 {
		l.MaxArtifactBytes = d.MaxArtifactBytes
	}
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = d.MaxHeaderBytes
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxArrayElements == 0 {
		l.MaxArrayElements = d.MaxArrayElements
	}
	if l.MaxDecompressedBytes == 0 {
		l.MaxDecompressedBytes = d.MaxDecompressedBytes
	}
	if l.MaxRatio == 0 {
		l.MaxRatio = d.MaxRatio
	}
	if l.MaxStringBlob == 0 {
		l.MaxStringBlob = d.MaxStringBlob
	}
	if l.MaxRetainedText == 0 {
		l.MaxRetainedText = d.MaxRetainedText
	}
	if l.MaxHashBytes == 0 {
		l.MaxHashBytes = d.MaxHashBytes
	}
	if l.MaxSpillBytes == 0 {
		l.MaxSpillBytes = d.MaxSpillBytes
	}
	if l.MaxFindings == 0 {
		l.MaxFindings = d.MaxFindings
	}
	if l.MaxStackDepth == 0 {
		l.MaxStackDepth = d.MaxStackDepth
	}
	if l.MmapThreshold == 0 {
		l.MmapThreshold = d.MmapThreshold
	}
	return l
}

// Normalize fills zero fields from Default and reports the first negative field,
// which is a caller bug rather than an artifact property.
func (l Limits) Normalize() (Limits, error) {
	for _, f := range []struct {
		name string
		v    int64
	}{
		{"MaxArtifactBytes", l.MaxArtifactBytes},
		{"MaxHeaderBytes", l.MaxHeaderBytes},
		{"MaxDepth", int64(l.MaxDepth)},
		{"MaxEntries", int64(l.MaxEntries)},
		{"MaxArrayElements", int64(l.MaxArrayElements)},
		{"MaxDecompressedBytes", l.MaxDecompressedBytes},
		{"MaxRatio", l.MaxRatio},
		{"MaxStringBlob", l.MaxStringBlob},
		{"MaxRetainedText", l.MaxRetainedText},
		{"MaxHashBytes", l.MaxHashBytes},
		{"MaxSpillBytes", l.MaxSpillBytes},
		{"MaxFindings", int64(l.MaxFindings)},
		{"MaxStackDepth", int64(l.MaxStackDepth)},
		{"MmapThreshold", l.MmapThreshold},
	} {
		if f.v < 0 {
			return l, fmt.Errorf("limits: %s is negative (%d)", f.name, f.v)
		}
	}
	return l.withDefaults(), nil
}

// Descendant returns l with the depth reduced by one, for a nested container.
// ok is false when the depth budget is exhausted, in which case the caller MUST
// record a SC4N-LIMIT-DEPTH finding and stop descending — never continue with an
// unchanged depth, which would make the cap ineffective.
func (l Limits) Descendant() (Limits, bool) {
	if l.MaxDepth <= 0 {
		return l, false
	}
	l.MaxDepth--
	return l, true
}

// MaxArtifactBytes caps a single file (or a single -stdin stream) that sc4n
// will map or read.
func (l *Limits) SetMaxArtifactBytes(v int64) { l.MaxArtifactBytes = v }

// SetMaxDepth overrides the container depth cap.
func (l *Limits) SetMaxDepth(v int) { l.MaxDepth = v }

// SetMaxDecompressedBytes overrides the cumulative decompression cap.
func (l *Limits) SetMaxDecompressedBytes(v int64) { l.MaxDecompressedBytes = v }

// SetMaxRatio overrides the decompression ratio cap.
func (l *Limits) SetMaxRatio(v int64) { l.MaxRatio = v }

// SetMaxRetainedText overrides the retained-text cap.
func (l *Limits) SetMaxRetainedText(v int64) { l.MaxRetainedText = v }

// SetMaxHashBytes overrides the digest cap.
func (l *Limits) SetMaxHashBytes(v int64) { l.MaxHashBytes = v }

// SetMaxSpillBytes overrides the per-member spill cap.
func (l *Limits) SetMaxSpillBytes(v int64) { l.MaxSpillBytes = v }

// SetMaxEntries overrides the archive member cap.
func (l *Limits) SetMaxEntries(v int) { l.MaxEntries = v }

// SetMaxArrayElements overrides the metadata-array element cap.
func (l *Limits) SetMaxArrayElements(v int) { l.MaxArrayElements = v }
