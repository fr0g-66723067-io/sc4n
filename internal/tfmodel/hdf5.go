package tfmodel

// hdf5.go is the shallow HDF5 (.h5/.hdf5) reader.
//
// v1 deliberately does NOT implement an HDF5 object-header reader. A correct one
// is a small filesystem of its own (superblock versions, fractal heaps, v1/v2
// B-trees, object-header continuation messages), and the plan chooses the bounded
// shallow path instead: find the JSON documents that hold a Keras model_config
// and the external-path-shaped strings that name a file the loader would open, and
// say plainly in `sc4n formats` that the object graph is not walked.
//
// What makes the shallow path worth having: Keras ignores safe_mode entirely for
// H5 (GHSA-36rr-ww3j-vrjv), so a Lambda in an .h5 is at least as dangerous as one
// in a .keras, and the class-allowlist rule applies unchanged.

import (
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// hdf5MaxPrefix bounds the shallow attribute scan from the start of the file: far
// larger than the object header of any real model, small enough that a
// multi-gigabyte weights file is not read end to end.
const hdf5MaxPrefix = 16 << 20

// hdf5MaxSuffix bounds the scan from the end, where a rewritten object header can
// land after the data section.
const hdf5MaxSuffix = 1 << 20

// hdf5MaxObjects caps the candidate JSON documents analysed per region.
const hdf5MaxObjects = 64

// hdf5Parser is the registered parser for HDF5.
type hdf5Parser struct{}

// Parse applies the shallow scan. It never returns an error: a malformed
// superblock is a finding, not a failure.
func (hdf5Parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	if size < 16 {
		ctx.Sink.Emit(ruleHDF5Struct, 0, "carries the HDF5 signature but is shorter than a superblock")
		return nil
	}
	prefix := size
	if prefix > hdf5MaxPrefix {
		prefix = hdf5MaxPrefix
	}
	region, err := s.Bytes(0, prefix)
	if err != nil && len(region) == 0 {
		ctx.Sink.Emit(ruleHDF5Struct, 0, "HDF5 signature present but the superblock region is unreadable")
		return nil
	}
	scanHDF5Region(ctx, 0, region)

	if size > hdf5MaxPrefix+hdf5MaxSuffix {
		suffix := size - hdf5MaxSuffix
		if tail, err := s.Bytes(suffix, hdf5MaxSuffix); err == nil && len(tail) > 0 {
			scanHDF5Region(ctx, suffix, tail)
		}
	}
	return nil
}

// scanHDF5Region recovers JSON documents and external-path strings from one
// region and applies the Keras class analysis to every document it finds.
func scanHDF5Region(ctx *artifact.Ctx, base int64, region []byte) {
	cap := ctx.Limits.MaxStringBlob
	blobs, spent, limit := extractJSONObjects(region, cap, hdf5MaxObjects)
	for _, blob := range blobs {
		analyzeKerasValue(ctx, base+blob.off, "hdf5 model_config", blob.doc, 0)
	}
	if limit > 0 {
		limits.Emit(ctx.Sink, limits.RuleEntries, "MaxRecoveryBytes", spent, limit,
			"HDF5 JSON recovery decode budget exhausted, so later objects in the region were not recovered")
	}
	scanExternalPaths(ctx, base, region)
}
