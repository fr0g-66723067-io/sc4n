package tfmodel

import (
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// pbVarint encodes a protobuf varint.
func pbVarint(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

// pbNodeDef encodes a NodeDef with a name (field 1) and an op (field 2).
func pbNodeDef(name, op string) []byte {
	out := append([]byte{0x0a}, pbVarint(len(name))...)
	out = append(out, name...)
	out = append(out, 0x12)
	out = append(out, pbVarint(len(op))...)
	return append(out, op...)
}

// pbSavedModel encodes a MetaGraphDef{graph_def{node*count}} as the top-level
// field 1, which is the shape a SavedModel on disk has.
func pbSavedModel(count int, lastName, lastOp string) []byte {
	node := pbNodeDef("n", "Add")
	last := pbNodeDef(lastName, lastOp)
	graph := make([]byte, 0, count*(len(node)+2))
	for i := 0; i < count-1; i++ {
		graph = append(graph, 0x0a)
		graph = append(graph, pbVarint(len(node))...)
		graph = append(graph, node...)
	}
	graph = append(graph, 0x0a)
	graph = append(graph, pbVarint(len(last))...)
	graph = append(graph, last...)

	g := append([]byte{0x12}, pbVarint(len(graph))...)
	g = append(g, graph...)
	m := append([]byte{0x0a}, pbVarint(len(g))...)
	return append(m, g...)
}

// TestSavedModelProbeAcceptsALargeGraph: the probe readers used to span a fixed
// window (2 KiB) while bytesValue refuses a nested length past the reader's end, so
// a MetaGraphDef whose graph_def exceeded the window failed the probe and the file
// was dispatched as text — i.e. no SavedModel rule ran on any realistic model. The
// probe now spans the declared body clamped to the source.
func TestSavedModelProbeAcceptsALargeGraph(t *testing.T) {
	l := limits.Default()
	for _, count := range []int{5, 500, 20000} {
		data := pbSavedModel(count, "payload", "PyFunc")
		s := source.Mem("saved_model.pb", data)
		f, _ := sniffSavedModel(s, l)
		s.Close()
		if f != artifact.FormatTFSavedModel {
			t.Errorf("%d nodes (%d bytes): sniffed %v, want tf-savedmodel", count, len(data), f)
		}
	}
}

// TestGraphNodeCapIsReported: the walk stops after maxGraphNodes NodeDefs, and that
// stop used to be silent — a GraphDef with more nodes than the cap reported clean.
// The cap now emits a limit finding, and because the walk stops the trailing PyFunc
// node is not claimed as seen.
func TestGraphNodeCapIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a million-node GraphDef")
	}
	data := pbSavedModel(maxGraphNodes+6, "payload", "PyFunc")
	c := parseBytes(t, savedModelParser{}, "saved_model.pb", data)
	got := ids(c)
	if !got["SC4N-LIMIT-ENTRIES"] {
		t.Fatalf("node cap not reported; got %v", got)
	}
	if got["SC4N-TF-PYFUNC"] {
		t.Fatalf("the walk claimed to see the node past the cap: %v", got)
	}
}
