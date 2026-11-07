package tfmodel

import (
	"bytes"
	"encoding/json"
	"testing"
)

// collectObjects adapts the streaming recovery to a slice for the tests below,
// which pin the recovered set rather than the call order.
func collectObjects(data []byte, cap int64) (out []jsonBlob, st recoveryStats) {
	st = extractJSONObjects(data, cap, hdf5MaxObjects, func(b jsonBlob) { out = append(out, b) })
	return out, st
}

// hdf5JunkPrefix is the HDF5 signature plus the eight zero superblock bytes the
// fixture builder writes, so a recovery test sees the bytes a real shallow read
// would hand it.
func hdf5JunkPrefix() []byte {
	out := []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}
	return append(out, make([]byte, 8)...)
}

// TestExtractJSONObjectsUnterminatedNest pins the recovery against the shape that
// broke it: a deep unterminated nest (`{"a":{"a":…`, no closing brace) that used
// to make the walk advance one byte and re-decode the whole tail at every later
// '{'. The input is 100 KB and took ~50 s before the walk was single-pass.
//
// The assertion is the recovered set, not the time: a walk that finds an object
// in an unterminated nest is wrong however fast it is.
func TestExtractJSONObjectsUnterminatedNest(t *testing.T) {
	data := append(hdf5JunkPrefix(), bytes.Repeat([]byte(`{"a":`), 20000)...)
	out, _ := collectObjects(data, 0)
	if len(out) != 0 {
		t.Errorf("unterminated nest yielded %d objects, want 0", len(out))
	}
}

// TestExtractJSONObjectsBudget checks that a nest whose braces are matched but
// undecodable still stops at the decode budget rather than running away, and that
// the stop is reported (limit > 0) rather than silent.
func TestExtractJSONObjectsBudget(t *testing.T) {
	data := append(hdf5JunkPrefix(), bytes.Repeat([]byte(`{"a":`), 20000)...)
	data = append(data, bytes.Repeat([]byte(`}`), 20000)...)
	out, st := collectObjects(data, 0)
	if !st.overBudget {
		t.Fatalf("matched-but-undecodable nest did not hit the decode budget (spent=%d)", st.spent)
	}
	if st.spent <= st.budget {
		t.Errorf("budget stop reported spent=%d budget=%d, want spent > budget", st.spent, st.budget)
	}
	if len(out) != 0 {
		t.Errorf("undecodable nest yielded %d objects, want 0", len(out))
	}
}

// TestExtractJSONObjectsRecoversObjects pins the recovered set so the linear walk
// stays a drop-in replacement: separate objects, an object nested inside an
// unbalanced outer, a brace inside a string literal, and a region with no closing
// brace all keep the behaviour the previous walk had.
func TestExtractJSONObjectsRecoversObjects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "twoObjects",
			in:   `{"class_name":"Sequential"}{"class_name":"Dense"}`,
			want: []string{`{"class_name":"Sequential"}`, `{"class_name":"Dense"}`},
		},
		{
			name: "nestedInUnbalanced",
			in:   `{"a": {"b":1} , }`,
			want: []string{`{"b":1}`},
		},
		{
			name: "braceInsideString",
			in:   `{"s":"{"}`,
			want: []string{`{"s":"{"}`},
		},
		{
			name: "noClosingBrace",
			in:   `{"a":`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := append(hdf5JunkPrefix(), tc.in...)
			out, _ := collectObjects(data, 0)
			var got []string
			for _, b := range out {
				s, err := json.Marshal(b.doc)
				if err != nil {
					t.Fatalf("document did not marshal: %v", err)
				}
				got = append(got, string(s))
			}
			if len(got) != len(tc.want) {
				t.Fatalf("recovered %d objects %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("object %d = %s, want %s", i, got[i], tc.want[i])
				}
			}
		})
	}
}
