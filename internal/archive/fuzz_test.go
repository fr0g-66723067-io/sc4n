package archive_test

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// FuzzArchive asserts the container walk never panics, never allocates from a
// declared length without validating it against the bytes that exist, and always
// terminates. The seeds are the container fixtures plus the two crafted
// directories whose declared entry counts used to reach make() as a capacity
// (a negative zip64 count, and 0xffff entries in a file that cannot hold them).
//
// The limits are tightened so a fuzz input cannot make the target write to the
// temporary filesystem: MaxDecompressedBytes bounds the total decompressed
// output of the walk, and a spill above MaxSpillBytes is reported rather than
// materialised.
func FuzzArchive(f *testing.F) {
	f.Add(buildZip(f, []zspec{
		{name: "a.bin", data: []byte("a")},
		{name: "b.bin", data: make([]byte, 4096), method: 8},
	}, false))
	f.Add(patchZip64Entries(f, buildZip(f, []zspec{{name: "a.bin", data: []byte("a")}}, true), 1<<63))
	f.Add(patchEOCDEntries(f, buildZip(f, []zspec{{name: "a.bin", data: []byte("a")}}, false), 0xffff))
	f.Add(gzipBytes(f, gadgetPickle()))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		l := limits.Default()
		l.MaxEntries = 32
		l.MaxDepth = 3
		l.MaxStringBlob = 64 << 10
		l.MaxRatio = 20
		l.MaxDecompressedBytes = 4 << 20
		l.MaxSpillBytes = 1 << 20

		src := source.Mem("f.zip", data)
		defer src.Close()
		_, _ = archive.Collect(src, l)

		src2 := source.Mem("f.zip", data)
		defer src2.Close()
		ctx, _ := newCtx(t, "f.zip", l)
		_ = archive.Scan(ctx, src2)
	})
}
