package cards

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// TestScanJSONFileIsLinear guards the document-level scan against the quadratic
// locate it replaced. A metadata document with 150000 keys took over 300 s to
// scan while every key and value was located with a whole-document search; with
// the offset index it takes under a second. The bound is deliberately generous
// so a slow machine does not flake, and a return to the search misses it by a
// wide margin.
func TestScanJSONFileIsLinear(t *testing.T) {
	var b strings.Builder
	b.WriteByte('{')
	const n = 150000
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\"key%06d\":\"value%06d\"", i, i)
	}
	b.WriteByte('}')
	data := []byte(b.String())

	c := report.NewCollector(0)
	start := time.Now()
	ScanJSONFile(c.For("config.json"), 0, "config.json", data)
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("scanning %d keys took %v; locating a value is a whole-document search again", n, d)
	}
}
