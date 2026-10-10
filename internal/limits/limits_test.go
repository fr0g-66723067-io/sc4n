package limits

import "testing"

func TestDefaultNormalizeIsStableAndRejectsNegatives(t *testing.T) {
	d := Default()
	n, err := d.Normalize()
	if err != nil {
		t.Fatalf("Normalize(default): %v", err)
	}
	if n != d {
		t.Fatalf("Normalize changed the defaults: %+v != %+v", n, d)
	}

	zero, err := (Limits{}).Normalize()
	if err != nil {
		t.Fatalf("Normalize(zero): %v", err)
	}
	if zero != d {
		t.Fatal("a zero Limits must normalize to the documented defaults so a caller can set one field")
	}

	neg := Limits{MaxDepth: -1}
	if _, err := neg.Normalize(); err == nil {
		t.Fatal("Normalize accepted a negative MaxDepth")
	}
}

func TestDescendantDecrementsAndStops(t *testing.T) {
	l := Limits{MaxDepth: 2}
	l2, ok := l.Descendant()
	if !ok || l2.MaxDepth != 1 {
		t.Fatalf("first Descendant = %+v, %v", l2, ok)
	}
	l3, ok := l2.Descendant()
	if !ok || l3.MaxDepth != 0 {
		t.Fatalf("second Descendant = %+v, %v", l3, ok)
	}
	if _, ok := l3.Descendant(); ok {
		t.Fatal("Descendant must report exhaustion at MaxDepth 0")
	}
	if l.MaxDepth != 2 {
		t.Fatalf("Descendant mutated the receiver: %d", l.MaxDepth)
	}
}
