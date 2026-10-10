package msgpack

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// TestSniffRequiresCoverage pins the F31 invariant: a sniffer must not accept a
// document that its own parser reports as structurally invalid. `0x90` is a
// complete one-byte MessagePack value (an empty array), so the shape check alone
// claimed a ten-megabyte Chromium data table that happened to start with it.
func TestSniffRequiresCoverage(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		// A one-byte document is below the sniffer's size floor (a one-byte file
		// has nothing to analyse), so it is declined for that reason, not for
		// coverage.
		{"empty array alone is below the size floor", []byte{0x90}, false},
		{"small document that consumes both bytes", []byte{0x91, 0x90}, true},
		{"empty map alone is below the size floor", []byte{0x80}, false},
		{"empty array then padding", append([]byte{0x90}, make([]byte, 4096)...), false},
		{"one byte then other data", []byte{0x90, 0x00, 0x01, 0x02}, false},
		{"truncated map", []byte{0x82, 0xa1, 'a'}, true},
		{"invalid marker after a header", []byte{0x81, 0xc1, 0x01}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := source.Mem("f.msgpack", c.data)
			defer src.Close()
			f, ok := sniff(src, limits.Default())
			if ok != c.want {
				t.Fatalf("sniff(% x) = %v,%v, want %v", c.data, f, ok, c.want)
			}
		})
	}
}
