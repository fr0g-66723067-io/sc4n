package tfmodel

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// hdf5JunkPrefix is the HDF5 signature plus the eight zero superblock bytes the
// fixture builder writes, so a recovery test sees the bytes a real shallow read
// would hand it.
func hdf5JunkPrefix() []byte {
	out := []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}
	return append(out, make([]byte, 8)...)
}

// TestExtractJSONObjectsLinear pins the HDF5 JSON recovery against the quadratic
// walk it replaced: a deep unterminated nest (`{"a":{"a":…`, no closing brace)
// made the old walk advance one byte and re-decode the whole tail at every later
// '{'. The 100 KB input below took ~50 s then; the 2 s bound is deliberately
// loose so the test measures the complexity class, not the machine's speed.
func TestExtractJSONObjectsLinear(t *testing.T) {
	data := append(hdf5JunkPrefix(), bytes.Repeat([]byte(`{"a":`), 20000)...)
	start := time.Now()
	out, _, _ := extractJSONObjects(data, 0, hdf5MaxObjects)
	elapsed := time.Since(start)
	t.Logf("unterminated nest: %d bytes in %s, %d objects", len(data), elapsed, len(out))
	if len(out) != 0 {
		t.Errorf("unterminated nest yielded %d objects, want 0", len(out))
	}
	if elapsed > 2*time.Second {
		t.Errorf("unterminated nest took %s, want under 2s", elapsed)
	}
}

// TestExtractJSONObjectsBudget checks that a nest whose braces are matched but
// undecodable still stops at the decode budget rather than running away, and that
// the stop is reported (limit > 0) rather than silent.
func TestExtractJSONObjectsBudget(t *testing.T) {
	data := append(hdf5JunkPrefix(), bytes.Repeat([]byte(`{"a":`), 20000)...)
	data = append(data, bytes.Repeat([]byte(`}`), 20000)...)
	out, spent, limit := extractJSONObjects(data, 0, hdf5MaxObjects)
	if limit == 0 {
		t.Fatalf("matched-but-undecodable nest did not hit the decode budget (spent=%d)", spent)
	}
	if spent <= limit {
		t.Errorf("budget stop reported spent=%d limit=%d, want spent > limit", spent, limit)
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
			out, _, _ := extractJSONObjects(data, 0, hdf5MaxObjects)
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
