package numpy

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// FuzzParseNPY asserts that the .npy parser never panics, never allocates from a
// declared length, and terminates on arbitrary bytes. The invariant checked is
// the one the parser owes the scanner: no panic, bounded work.
func FuzzParseNPY(f *testing.F) {
	f.Add(npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (2, 3)}", make([]byte, 48)))
	f.Add(npyV2("{'descr': '|O', 'fortran_order': True, 'shape': (1,)}", []byte{0x80, 0x05, 0x2e}))
	f.Add([]byte{0x93, 'N', 'U', 'M', 'P', 'Y'})
	f.Add([]byte("not an npy file at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := report.NewCollector(0)
		lim := limits.Default()
		sess := artifact.NewSession(c, "", lim)
		ctx := &artifact.Ctx{Session: sess, Sink: c.For("f.npy"), Limits: lim}
		src := source.Mem("f.npy", data)
		defer src.Close()
		_ = (npyParser{}).Parse(ctx, src)
	})
}

// FuzzParseJoblib asserts the joblib decoder and wrapper analysis never panic.
func FuzzParseJoblib(f *testing.F) {
	f.Add(joblibWrapperStream("<f8", []byte{0x4b, 2, 0x4b, 3}, append([]byte{0x00}, make([]byte, 48)...)))
	f.Add([]byte("joblib.numpy_pickle.NumpyArrayWrapper"))
	f.Add([]byte{0x80, 0x04, 0x2e})

	f.Fuzz(func(t *testing.T, data []byte) {
		c := report.NewCollector(0)
		lim := limits.Default()
		sess := artifact.NewSession(c, "", lim)
		ctx := &artifact.Ctx{Session: sess, Sink: c.For("f.joblib"), Limits: lim}
		src := source.Mem("f.joblib", data)
		defer src.Close()
		_ = (joblibParser{}).Parse(ctx, src)
	})
}
