package msgpack

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// FuzzParseMsgpack asserts the bounded walker never panics and terminates on
// arbitrary bytes.
func FuzzParseMsgpack(f *testing.F) {
	f.Add(mmap(mstr("model"), mstr("bert"), mstr("layers"), append(append([]byte{0x92}, mstr("a")...), mstr("b")...)))
	f.Add([]byte{0x80 | 1, 0xc1, 0x01})
	f.Add([]byte{0xdf, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		c := report.NewCollector(0)
		lim := limits.Default()
		sess := artifact.NewSession(c, "", lim)
		ctx := &artifact.Ctx{Session: sess, Sink: c.For("f.msgpack"), Limits: lim}
		src := source.Mem("f.msgpack", data)
		defer src.Close()
		_ = (parser{}).Parse(ctx, src)
		// The sniffer must be equally total.
		s2 := source.Mem("f.msgpack", data)
		defer s2.Close()
		_, _ = sniff(s2, lim)
	})
}
