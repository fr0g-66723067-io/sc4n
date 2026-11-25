package msgpack

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func mext(typ byte, payload []byte) []byte {
	return append([]byte{0xc7, byte(len(payload)), typ}, payload...)
}

func TestMsgpackExtPayloadIsScanned(t *testing.T) {
	// 1. Embedded pickle inside an ext payload.
	gadget := []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85, 0x52, 0x2e,
	}
	fs := parse(t, mmap(mstr("e"), mext(1, gadget)))
	if !ids(fs)["SC4N-PICKLE-GLOBAL-CRITICAL"] || !ids(fs)["SC4N-PICKLE-REDUCE"] {
		t.Fatalf("pickle inside ext payload was missed: %v", ids(fs))
	}

	// 2. C2 string indicator inside an ext payload.
	c2 := []byte("https://discord.com/api/webhooks/123/abc")
	fs = parse(t, mmap(mstr("e"), mext(2, c2)))
	if !ids(fs)["SC4N-STRING-C2"] {
		t.Fatalf("string indicator inside ext payload was missed: %v", ids(fs))
	}

	// 3. NaN payload inside an ext payload.
	var nans bytes.Buffer
	for i := range 4 {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], 0x7ff8000000000001+uint64(i))
		nans.Write(b[:])
	}
	fs = parse(t, mmap(mstr("e"), mext(3, nans.Bytes())))
	if !ids(fs)["SC4N-MSGPACK-NAN-PAYLOAD"] {
		t.Fatalf("NaN run inside ext payload was missed: %v", ids(fs))
	}
}

func TestMsgpackNaNRunsFloat64LEBEAndFloat32(t *testing.T) {
	cases := []struct {
		name string
		blob []byte
		want bool
	}{
		{
			name: "float64-le NaNs",
			blob: func() []byte {
				var b bytes.Buffer
				for i := range 4 {
					var raw [8]byte
					binary.LittleEndian.PutUint64(raw[:], math.Float64bits(math.NaN())|uint64(i+1))
					b.Write(raw[:])
				}
				return b.Bytes()
			}(),
			want: true,
		},
		{
			name: "float64-be NaNs",
			blob: func() []byte {
				var b bytes.Buffer
				for i := range 4 {
					var raw [8]byte
					binary.BigEndian.PutUint64(raw[:], 0x7ff8000000000010+uint64(i))
					b.Write(raw[:])
				}
				return b.Bytes()
			}(),
			want: true,
		},
		{
			name: "float32-le NaNs",
			blob: func() []byte {
				var b bytes.Buffer
				for i := range 4 {
					var raw [4]byte
					binary.LittleEndian.PutUint32(raw[:], 0x7fc00001+uint32(i))
					b.Write(raw[:])
				}
				return b.Bytes()
			}(),
			want: true,
		},
		{
			name: "all-0xff int mask is not NaN payload",
			blob: bytes.Repeat([]byte{0xff}, 32),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := mmap(mstr("w"), mbin(tc.blob))
			fs := parse(t, doc)
			got := ids(fs)["SC4N-MSGPACK-NAN-PAYLOAD"]
			if got != tc.want {
				t.Fatalf("SC4N-MSGPACK-NAN-PAYLOAD = %v, want %v (findings=%v)", got, tc.want, ids(fs))
			}
		})
	}
}

func TestMsgpackBinScanningIsBoundedByMaxStringBlob(t *testing.T) {
	// Put a NaN run past MaxStringBlob: MaxStringBlob must be emitted and the
	// scanner must stop at the cap rather than scanning unboundedly.
	blob := make([]byte, 256)
	for i := range 4 {
		binary.LittleEndian.PutUint64(blob[128+i*8:], 0x7ff8000000000001+uint64(i))
	}
	doc := append([]byte{0x81}, mstr("w")...)
	doc = append(doc, 0xc5, 0x01, 0x00) // bin16 len=256
	doc = append(doc, blob...)

	c := report.NewCollector(0)
	lim := limits.Default()
	lim.MaxStringBlob = 64
	sess := artifact.NewSession(c, "", lim)
	ctx := &artifact.Ctx{Session: sess, Sink: c.For("m.msgpack"), Limits: lim, Format: artifact.FormatMsgpack}
	src := source.Mem("m.msgpack", doc)
	defer src.Close()
	_ = (parser{}).Parse(ctx, src)

	got := ids(c.Findings())
	if !got[limits.RuleString.ID] {
		t.Fatalf("expected %s, got %v", limits.RuleString.ID, got)
	}
	if got["SC4N-MSGPACK-NAN-PAYLOAD"] {
		t.Fatalf("bin scan ignored MaxStringBlob cap and scanned past offset 64: %v", got)
	}
}
