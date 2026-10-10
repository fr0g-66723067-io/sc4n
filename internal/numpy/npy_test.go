package numpy

import (
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// --- builders -----------------------------------------------------------------

// npyV1/npyV2/npyV3 build the 10-byte (v1.0) or 12-byte (v2.0/v3.0) prelude and
// the literal header. The header is written without the 64-byte space padding a
// producer adds, because the parser reads exactly the declared length; the
// padding path is covered by writing it explicitly in one case below.
func npyV1(header string, data []byte) []byte {
	out := []byte{0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0}
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(header)))
	out = append(out, l[:]...)
	out = append(out, header...)
	return append(out, data...)
}

func npyV2(header string, data []byte) []byte {
	out := []byte{0x93, 'N', 'U', 'M', 'P', 'Y', 2, 0}
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(header)))
	out = append(out, l[:]...)
	out = append(out, header...)
	return append(out, data...)
}

func npyV3(header string, data []byte) []byte {
	out := []byte{0x93, 'N', 'U', 'M', 'P', 'Y', 3, 0}
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(len(header)))
	out = append(out, l[:]...)
	out = append(out, header...)
	return append(out, data...)
}

func parse(t *testing.T, data []byte) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	lim := limits.Default()
	sess := artifact.NewSession(c, "", lim)
	ctx := &artifact.Ctx{Session: sess, Sink: c.For("a.npy"), Limits: lim, Format: artifact.FormatNPY}
	src := source.Mem("a.npy", data)
	defer src.Close()
	_ = (npyParser{}).Parse(ctx, src)
	return c.Findings()
}

func ids(fs []report.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func want(t *testing.T, fs []report.Finding, present, absent []string) {
	t.Helper()
	have := ids(fs)
	for _, id := range present {
		if !have[id] {
			t.Errorf("missing %s; got %v", id, have)
		}
	}
	for _, id := range absent {
		if have[id] {
			t.Errorf("unexpected %s; got %v", id, have)
		}
	}
}

// --- header literal parser ----------------------------------------------------

func TestParseHeaderLiteral(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		dtype string
		shape []int64
		ok    bool
	}{
		{"v1", "{'descr': '<f8', 'fortran_order': False, 'shape': (2, 3), }", "<f8", []int64{2, 3}, true},
		{"v2 spaces", `{"descr": "|O", "fortran_order": True, "shape": (4,)}`, "|O", []int64{4}, true},
		{"empty shape", "{'descr': '<i4', 'fortran_order': False, 'shape': ()}", "<i4", []int64{}, true},
		{"list shape", "{'descr': '<u2', 'fortran_order': False, 'shape': [1, 2, 3]}", "<u2", []int64{1, 2, 3}, true},
		{"trailing padding", "{'descr': '<f4', 'shape': (2,)}          \n", "<f4", []int64{2}, true},
		{"missing descr", "{'fortran_order': False, 'shape': (1,)}", "", nil, false},
		{"not a dict", "[1, 2, 3]", "", nil, false},
		{"eval attempt", "{'descr': __import__('os').system('id'), 'shape': (1,)}", "", nil, false},
		{"string shape", "{'descr': '<f8', 'shape': 'x'}", "", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := parseNPYHeader([]byte(tc.text))
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("expected error, got %+v", h)
				}
				return
			}
			if h.dtype != tc.dtype {
				t.Errorf("dtype = %q, want %q", h.dtype, tc.dtype)
			}
			if len(h.shape) != len(tc.shape) {
				t.Fatalf("shape = %v, want %v", h.shape, tc.shape)
			}
			for i := range tc.shape {
				if h.shape[i] != tc.shape[i] {
					t.Errorf("shape = %v, want %v", h.shape, tc.shape)
				}
			}
		})
	}
}

func TestDtypeSize(t *testing.T) {
	cases := []struct {
		dtype string
		size  int64
		ok    bool
	}{
		{"<f8", 8, true},
		{"|i4", 4, true},
		{">u1", 1, true},
		{"<c16", 16, true},
		{"|b1", 1, true},
		{"<U10", 40, true},
		{"<U2305843009213693952", 0, false},
		{"|S5", 5, true},
		{"|V8", 8, true},
		{"|O", 0, false},
		{"i4,i4", 0, false},
		{"<M8[ns]", 0, false},
	}
	for _, tc := range cases {
		got, ok := dtypeSize(tc.dtype)
		if ok != tc.ok || (ok && got != tc.size) {
			t.Errorf("dtypeSize(%q) = %d,%v want %d,%v", tc.dtype, got, ok, tc.size, tc.ok)
		}
	}
}

func TestDtypeSizeOverflow(t *testing.T) {
	if _, ok := dtypeSize("<U2305843009213693952"); ok {
		t.Error("dtypeSize accepted an overflowing U descriptor")
	}
	if !dtypeSizeOverflows("<U2305843009213693952") {
		t.Error("dtypeSizeOverflows missed a U count above MaxInt64/4")
	}
	for _, ok := range []string{"<U10", "<f8", "|S5", "i4,i4", ""} {
		if dtypeSizeOverflows(ok) {
			t.Errorf("dtypeSizeOverflows(%q) fired on a size that fits", ok)
		}
	}
}

// TestParseNPYStructuredDescr covers numpy's dtype.descr: a record dtype writes
// descr as a list, which the format docs define as "an object that can be passed
// as an argument to numpy.dtype". It is valid and must not be a header error.
func TestParseNPYStructuredDescr(t *testing.T) {
	hdr := "{'descr': [('a', '<i4')], 'fortran_order': False, 'shape': (3,), }"
	fs := parse(t, npyV1(hdr, make([]byte, 12)))
	want(t, fs, nil, []string{"SC4N-NUMPY-STRUCT", "SC4N-NUMPY-TRAILING"})

	// Sub-array fields and nested field lists are consumed as well.
	for _, h := range []string{
		"{'descr': [('a', '<i4', (2,))], 'shape': (3,)}",
		"{'descr': [('a', [('x', '<f4'), ('y', '<f4')])], 'shape': (3,)}",
		"{'descr': [('a', '<i4'), ('b', '<f8')], 'shape': (3,)}",
	} {
		hh, err := parseNPYHeader([]byte(h))
		if err != nil {
			t.Errorf("parseNPYHeader(%q) = %v, want nil", h, err)
			continue
		}
		if !hh.structured || hh.dtype != "" {
			t.Errorf("parseNPYHeader(%q) = dtype %q structured %v", h, hh.dtype, hh.structured)
		}
	}

	// A descr that is neither a string nor a list is still rejected.
	if _, err := parseNPYHeader([]byte("{'descr': 3, 'shape': (1,)}")); err == nil {
		t.Error("numeric descr accepted")
	}
	// A structured dtype with an unsizeable shape is still a structural finding.
	fs = parse(t, npyV1("{'descr': [('a', '<i4')], 'shape': (-1,)}", make([]byte, 4)))
	want(t, fs, []string{"SC4N-NUMPY-STRUCT"}, nil)
}

// TestParseNPYUnicodeSizeOverflow is the regression for the U descriptor whose
// byte size overflows int64: it must be reported as an overflow, and a
// zero-element shape must not turn it into a trailing-data claim.
func TestParseNPYUnicodeSizeOverflow(t *testing.T) {
	fs := parse(t, npyV1("{'descr': '<U2305843009213693952', 'shape': (2,)}", make([]byte, 16)))
	want(t, fs, []string{"SC4N-NUMPY-STRUCT"}, []string{"SC4N-NUMPY-TRAILING"})

	fs = parse(t, npyV1("{'descr': '<U2305843009213693952', 'shape': (0,)}", make([]byte, 16)))
	want(t, fs, []string{"SC4N-NUMPY-STRUCT"}, []string{"SC4N-NUMPY-TRAILING"})
}

// --- parseNPY ----------------------------------------------------------------

func TestParseNPYValid(t *testing.T) {
	data := npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (2, 3), }", make([]byte, 48))
	fs := parse(t, data)
	want(t, fs, nil, []string{"SC4N-NUMPY-STRUCT", "SC4N-NUMPY-OBJECT-ARRAY", "SC4N-NUMPY-TRAILING"})
}

func TestParseNPYVersion2And3(t *testing.T) {
	for _, b := range [][]byte{
		npyV2("{'descr': '<f4', 'fortran_order': False, 'shape': (4,)}", make([]byte, 16)),
		npyV3("{'descr': '<f4', 'fortran_order': False, 'shape': (4,)}", make([]byte, 16)),
	} {
		fs := parse(t, b)
		want(t, fs, nil, []string{"SC4N-NUMPY-STRUCT"})
	}
}

func TestParseNPYShapeExceedsData(t *testing.T) {
	// Declares 4 f8 elements (32 bytes) but carries 8.
	data := npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (4,)}", make([]byte, 8))
	fs := parse(t, data)
	want(t, fs, []string{"SC4N-NUMPY-STRUCT"}, nil)
}

func TestParseNPYTrailing(t *testing.T) {
	data := npyV1("{'descr': '<f8', 'fortran_order': False, 'shape': (2,)}", make([]byte, 16+9))
	fs := parse(t, data)
	want(t, fs, []string{"SC4N-NUMPY-TRAILING"}, []string{"SC4N-NUMPY-STRUCT"})
}

func TestParseNPYObjectArrayDispatchesPickle(t *testing.T) {
	// A protocol-4 os.system gadget as the object-array data section.
	gadget := []byte{
		0x80, 0x04,
		0x8c, 0x02, 'o', 's',
		0x8c, 0x06, 's', 'y', 's', 't', 'e', 'm',
		0x93,
		0x8c, 0x02, 'i', 'd',
		0x85,
		0x52,
		0x2e,
	}
	data := npyV1("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", gadget)
	fs := parse(t, data)
	want(t, fs, []string{"SC4N-NUMPY-OBJECT-ARRAY", "SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"}, nil)
}

func TestParseNPYMalformedNoPanic(t *testing.T) {
	cases := map[string][]byte{
		"empty":          {},
		"short magic":    {0x93, 'N', 'U'},
		"bad magic":      []byte("NOTNPYxxxx"),
		"bad major":      {0x93, 'N', 'U', 'M', 'P', 'Y', 9, 0, 0, 0},
		"huge hlen":      {0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0, 0xff, 0xff},
		"bad dict":       npyV1("garbage-not-a-dict", nil),
		"negative shape": npyV1("{'descr': '<f8', 'shape': (-1,)}", nil),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			fs := parse(t, data)
			if !ids(fs)["SC4N-NUMPY-STRUCT"] {
				t.Errorf("expected SC4N-NUMPY-STRUCT, got %v", ids(fs))
			}
		})
	}
}

func TestParseNPYDeterministic(t *testing.T) {
	data := npyV1("{'descr': '|O', 'fortran_order': False, 'shape': (1,)}", []byte{0x80, 0x05, 0x2e})
	a := parse(t, data)
	b := parse(t, data)
	if len(a) != len(b) {
		t.Fatalf("finding count differs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].RuleID != b[i].RuleID || a[i].Offset != b[i].Offset {
			t.Fatalf("finding %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}
