package pickle

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func TestSniffClaimsLargeProtocolOneStream(t *testing.T) {
	data := []byte{opMARK}
	data = append(data, binUnicode(strings.Repeat("a", 300000))...)
	data = append(data, []byte("cos\nsystem\n(S'id'\ntR.")...)
	got, ok := sniff(source.Mem("large.pkl", data), limits.Default())
	if !ok || got != artifact.FormatPickle {
		t.Fatalf("sniff = %s, %v; want pickle", got, ok)
	}
}

func TestSniffClaimsProtocolZeroStreamWhoseFirstLineExceedsCap(t *testing.T) {
	data := append([]byte{opSTRING}, make([]byte, 300000)...)
	data = append(data, '\n')
	data = append(data, []byte("S'id'\n.")...)
	got, ok := sniff(source.Mem("zero.pkl", data), limits.Default())
	if !ok || got != artifact.FormatPickle {
		t.Fatalf("sniff = %s, %v; want pickle for a protocol-0 line past the probe", got, ok)
	}
}

func TestWalkOpBudgetIsReported(t *testing.T) {
	data := make([]byte, maxWalkOps+1)
	for i := range data {
		data[i] = opPOP
	}
	_, fs := walk(t, data)
	if !hasRule(fs, "SC4N-LIMIT-ENTRIES") {
		t.Fatalf("walk-op budget was silent; findings=%v", fs)
	}
}

func TestDistinctGlobalMetadataIsCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= maxDistinctGlobal; i++ {
		b.WriteString("cbuiltins\nname")
		b.WriteString(strconvItoa(i))
		b.WriteString("\n0\n") // GLOBAL then POP
	}
	b.WriteString("cos\nsystem\n(S'id'\ntR.")
	data := []byte(b.String())
	_, fs := walk(t, data)
	if !hasRule(fs, "SC4N-LIMIT-ENTRIES") || !hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("distinct-global cap did not report both the cap and the overflow global; findings=%v", fs)
	}
}

func TestMemoAliasSlotTrackingIsBounded(t *testing.T) {
	m := newMemo(100)
	g := &Global{Module: "m", Name: "n"}
	for i := 0; i < maxAliasSlots+5; i++ {
		m.noteGlobal(g, i)
	}
	b := m.byGlobal[g.QualName()]
	if len(b.slots) != maxAliasSlots || !b.slotsOverflow {
		t.Fatalf("memo slots=%d overflow=%v, want %d and true", len(b.slots), b.slotsOverflow, maxAliasSlots)
	}
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestRetainNeverExceedsMaxRetainedText(t *testing.T) {
	c := report.NewCollector(0)
	w := &walker{sink: c.For("x"), lim: limits.Limits{MaxRetainedText: 10}, once: map[string]bool{}}
	got := w.retain("abcdef")
	if len(got) != 6 || w.retained != 6 {
		t.Fatalf("first retain = %q/%d, want 6/6", got, w.retained)
	}
	got = w.retain("ghijkl")
	if len(got) != 4 || w.retained != 10 {
		t.Fatalf("second retain = %q/%d, want 4/10", got, w.retained)
	}
	got = w.retain("z")
	if got != "" || w.retained != 10 {
		t.Fatalf("exhausted retain = %q/%d, want empty/10", got, w.retained)
	}
}

func TestPerSiteFindingKeysAreBounded(t *testing.T) {
	c := report.NewCollector(0)
	w := &walker{sink: c.For("x"), siteOnce: map[string]bool{}, once: map[string]bool{}}
	for i := 0; i < maxOnceKeys+5; i++ {
		w.emitSiteOnce("site:"+strconvItoa(i), ruleIncomplete, int64(i), "x")
	}
	if len(w.siteOnce) != maxOnceKeys {
		t.Fatalf("site keys = %d, want %d", len(w.siteOnce), maxOnceKeys)
	}
	if !hasRule(c.Findings(), "SC4N-LIMIT-ENTRIES") {
		t.Fatal("site-key cap was silent")
	}
}

func TestCountedStringDoesNotDecodePastBlobCap(t *testing.T) {
	c := report.NewCollector(0)
	w := &walker{sink: c.For("x"), lim: limits.Limits{MaxStringBlob: 4}, data: []byte("abcdefghij"), once: map[string]bool{}, siteOnce: map[string]bool{}}
	v, next, err := w.countedString(opcodeInfo{name: "BINUNICODE", arg: argString4}, 0, 10, latin1String)
	if err != nil || next != 10 {
		t.Fatalf("countedString = %v, %d, %v", v, next, err)
	}
	if s, _ := v.(string); len(s) != 4 {
		t.Fatalf("decoded %d bytes, want 4", len(s))
	}
	if !hasRule(c.Findings(), "SC4N-LIMIT-STRING") {
		t.Fatal("blob cap was silent")
	}
}
