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
		MaxDecompressedBytes: 8 << 30,
		MaxRatio:             200,
		MaxStringBlob:        16 << 20,
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
	if l.MaxDecompressedBytes == 0 {
		l.MaxDecompressedBytes = d.MaxDecompressedBytes
	}
	if l.MaxRatio == 0 {
		l.MaxRatio = d.MaxRatio
	}
	if l.MaxStringBlob == 0 {
		l.MaxStringBlob = d.MaxStringBlob
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
		{"MaxDecompressedBytes", l.MaxDecompressedBytes},
		{"MaxRatio", l.MaxRatio},
		{"MaxStringBlob", l.MaxStringBlob},
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

// SetMaxEntries overrides the archive member cap.
func (l *Limits) SetMaxEntries(v int) { l.MaxEntries = v }
