package polyglot

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// FuzzPolyglot asserts the magic-window walk and the native-header validator
// never panic. This is the layer that scans every offset of every artifact for a
// second signature, so it runs on bytes no format sniffer claimed.
func FuzzPolyglot(f *testing.F) {
	f.Add("x.bin", tinyELF())
	f.Add("x.safetensors", safetensorsWithELF())
	f.Add("x.zip", zipWithTarAnchor())
	f.Add("x.bin", deterministicNoise(4096))
	f.Add("x.bin", []byte{})

	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		l := limits.Default()
		c := report.NewCollector(0)
		sess := artifact.NewSession(c, "", l)
		s := source.Mem(name, data)
		defer s.Close()
		Scan(sess.NewCtx(name, l), s, artifact.FormatUnknown)

		// The helpers behind Scan are exported and are the ones a future caller
		// reaches for; they must be total too.
		_ = MagicWindows(s, s.Size())
		EachValidatedNative(data, func(bytescan.NativeKind, int) {})
	})
}
