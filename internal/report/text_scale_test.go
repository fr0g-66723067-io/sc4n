package report

import (
	"io"
	"strconv"
	"testing"
	"time"
)

// TestTextEncoderScales checks that rendering the artifact table is roughly as
// cheap as the JSON encoder for the same report. The table used to rescan every
// distinct finding-artifact key for every row, which made it quadratic; this
// guards against that returning. Skipped under -short because it synthesises
// 20 000 artifacts and findings.
func TestTextEncoderScales(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const n = 20000
	arts := make([]ArtifactSummary, n)
	c := NewCollector(0)
	for i := range n {
		p := "art" + strconv.Itoa(i) + ".bin"
		arts[i] = ArtifactSummary{Path: p, Size: int64(i), Format: "test"}
		c.For(p).Emit(testRuleInfo, int64(i), "evidence")
	}
	rep := Build(Tool{Name: "sc4n", Version: "t"}, "", arts, c, Limits{}, nil, 0)

	text := func() time.Duration {
		st := time.Now()
		if err := rep.WriteText(io.Discard, TextOptions{}); err != nil {
			t.Fatal(err)
		}
		return time.Since(st)
	}
	js := func() time.Duration {
		st := time.Now()
		if err := rep.WriteJSON(io.Discard); err != nil {
			t.Fatal(err)
		}
		return time.Since(st)
	}
	// One warm-up each, then two measured runs of the text path.
	text()
	js()
	var textDur time.Duration
	for range 2 {
		textDur = text()
	}
	jsonDur := js()
	t.Logf("text=%v json=%v", textDur, jsonDur)
	if textDur > 3*jsonDur {
		t.Fatalf("text encoding is %.2fx the JSON encoding (%v vs %v)", float64(textDur)/float64(jsonDur), textDur, jsonDur)
	}
}
