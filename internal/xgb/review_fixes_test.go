package xgb

import (
	"bytes"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func parseWithLimits(t *testing.T, name string, data []byte, l limits.Limits) []report.Finding {
	t.Helper()
	c := report.NewCollector(0)
	sess := artifact.NewSession(c, "", l)
	ctx := sess.NewCtx(name, l)
	s := source.Mem(name, data)
	defer s.Close()
	if err := (parser{}).Parse(ctx, s); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return c.Findings()
}

func TestMaxArrayElementsEnforcedInTypedContainersAndObjects(t *testing.T) {
	l := limits.Default()
	l.MaxArrayElements = 5

	// Typed object with 10 entries: { $ Z # i 10 <k0>...<k9> }
	obj := []byte{'{', '$', mNull, '#', mInt8, 10}
	for range 10 {
		obj = append(obj, ubjKey("k")...)
	}
	fs := parseWithLimits(t, "tobj.ubj", obj, l)
	if !hasRule(fs, limits.RuleEntries.ID) {
		t.Fatalf("typed object bypassed MaxArrayElements: %v", ids(fs))
	}

	// Nested typed string arrays whose cumulative elements exceed MaxArrayElements.
	var arr []byte
	arr = append(arr, '[')
	for range 3 {
		arr = append(arr, '[', '$', mString, '#', mInt8, 3)
		for range 3 {
			arr = append(arr, ubjLen(1)...)
			arr = append(arr, 'a')
		}
	}
	arr = append(arr, ']')
	fs = parseWithLimits(t, "tstr.ubj", arr, l)
	if !hasRule(fs, limits.RuleEntries.ID) {
		t.Fatalf("typed string arrays bypassed cumulative MaxArrayElements: %v", ids(fs))
	}

	// Strongly typed null array declaring more than MaxArrayElements.
	nulls := []byte{'[', '$', mNull, '#', mInt8, 20}
	fs = parseWithLimits(t, "tnull.ubj", nulls, l)
	if !hasRule(fs, limits.RuleEntries.ID) {
		t.Fatalf("typed null array bypassed MaxArrayElements: %v", ids(fs))
	}
}

func TestOversizedStringAndKeyStillScanPrefixAndZeroLimitDefaults(t *testing.T) {
	payload := "https://discord.com/api/webhooks/123/abc"
	padded := payload + string(bytes.Repeat([]byte("a"), 200))

	l := limits.Default()
	l.MaxStringBlob = 64

	// Oversized string value: must emit MaxStringBlob AND scan the first 64 bytes.
	docVal := append([]byte{'{'}, ubjKey("u")...)
	docVal = append(docVal, ubjStr(padded)...)
	docVal = append(docVal, '}')
	fsVal := parseWithLimits(t, "bigval.ubj", docVal, l)
	if !hasRule(fsVal, limits.RuleString.ID) || !hasRule(fsVal, "SC4N-STRING-C2") {
		t.Fatalf("oversized string value: got %v, want MaxStringBlob and SC4N-STRING-C2", ids(fsVal))
	}

	// Oversized object key: must emit MaxStringBlob AND scan the first 64 bytes.
	docKey := append([]byte{'{'}, ubjKey(padded)...)
	docKey = append(docKey, mNull, '}')
	fsKey := parseWithLimits(t, "bigkey.ubj", docKey, l)
	if !hasRule(fsKey, limits.RuleString.ID) || !hasRule(fsKey, "SC4N-STRING-C2") {
		t.Fatalf("oversized key: got %v, want MaxStringBlob and SC4N-STRING-C2", ids(fsKey))
	}

	// Zero MaxStringBlob must default to limits.Default().MaxStringBlob, not 0.
	docSmall := append([]byte{'{'}, ubjKey("u")...)
	docSmall = append(docSmall, ubjStr(payload)...)
	docSmall = append(docSmall, '}')
	fsZero := parseWithLimits(t, "zero.ubj", docSmall, limits.Limits{})
	if hasRule(fsZero, limits.RuleString.ID) || !hasRule(fsZero, "SC4N-STRING-C2") {
		t.Fatalf("zero MaxStringBlob did not default cleanly: got %v", ids(fsZero))
	}
}

func TestSniffAcceptsLengthStraddling64KiBBoundary(t *testing.T) {
	// Place a string length header ('L' + 8 bytes) straddling byte ubjSniffHead (65536).
	// Before the fix, readLength hitting io.ErrUnexpectedEOF called fail() (stopInvalid)
	// instead of failShort() (stopExhausted), making sniff reject valid large UBJSON.
	var doc []byte
	doc = append(doc, '{')
	// Compute first string length so second key's 'L'+8B length straddles 65536.
	k1 := ubjKey("pad")
	// '{' (1) + k1 + 'S' (1) + 'L'+8B (9) + padLen = 65532 -> next key 'L' at 65532..65540 straddles 65536.
	prefixLen := 1 + len(k1) + 1 + 9
	padLen := ubjSniffHead - prefixLen - 4
	doc = append(doc, k1...)
	doc = append(doc, mString)
	doc = append(doc, ubjLen(padLen)...)
	doc = append(doc, bytes.Repeat([]byte{'a'}, padLen)...)
	doc = append(doc, ubjKey("second")...)
	doc = append(doc, ubjStr("ok")...)
	doc = append(doc, '}')

	if _, ok := sniff(source.Mem("boundary.ubj", doc), limits.Default()); !ok {
		t.Fatal("valid UBJSON whose length integer straddles the 64 KiB sniff boundary was rejected")
	}
}
