package archive_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/report"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func findingsFor(t *testing.T, name string, data []byte, f artifact.Format, l limits.Limits) []report.Finding {
	t.Helper()
	col := report.NewCollector(0)
	sess := artifact.NewSession(col, "", l)
	ctx := sess.NewCtx(name, l)
	ctx.Format = f
	if err := archive.Scan(ctx, source.Mem(name, data)); err != nil {
		t.Fatalf("archive.Scan: %v", err)
	}
	return col.Findings()
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

func hasRule(fs []report.Finding, id string) bool { return countRule(fs, id) > 0 }

func TestNestedArchiveDecompressionBudgetIsShared(t *testing.T) {
	inner := buildZip(t, []zspec{
		{name: "first.bin", data: bytes.Repeat([]byte("a"), 2048)},
		{name: "second.bin", data: bytes.Repeat([]byte("b"), 1024)},
		{name: "archive/data.pkl", data: gadgetPickle()},
	}, false)
	middle := buildZip(t, []zspec{{name: "inner.zip", data: inner}}, false)
	outer := buildZip(t, []zspec{{name: "middle.zip", data: middle}}, false)
	l := limits.Default()
	l.MaxDecompressedBytes = 3 << 10
	fs := findingsFor(t, "outer.zip", outer, artifact.FormatZip, l)
	if got := countRule(fs, "SC4N-LIMIT-DECOMPRESSED"); got != 1 {
		t.Fatalf("decompression limits = %d, want exactly one; findings=%v", got, fs)
	}
	if hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatal("a member after the exhausted budget was scanned")
	}
}

func TestZipDirectoryModeWithPayloadIsScanned(t *testing.T) {
	payload := buildZip(t, []zspec{{name: "data.pkl", data: gadgetPickle(), mode: 0o040755}}, false)
	fs := findingsFor(t, "mode.zip", payload, artifact.FormatZip, limits.Default())
	if !hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("a data-bearing directory-mode member was skipped; findings=%v", fs)
	}
	empty := buildZip(t, []zspec{{name: "empty/", method: 0, mode: 0o040755}}, false)
	if fs := findingsFor(t, "empty.zip", empty, artifact.FormatZip, limits.Default()); hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatal("an empty directory member produced a payload finding")
	}
}

func TestPrefixedZip64DirectoryIsScanned(t *testing.T) {
	body := buildZip(t, []zspec{{name: "data.pkl", data: gadgetPickle(), method: 8}}, true)
	data := append(bytes.Repeat([]byte("prefix!"), 8), body...)
	fs := findingsFor(t, "prefix.zip64", data, artifact.FormatZip, limits.Default())
	if !hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("a prefixed zip64 member was skipped; findings=%v", fs)
	}
}

func TestConflictingZip64DirectoryIsRejected(t *testing.T) {
	data := buildZip(t, []zspec{{name: "a", data: []byte("a")}}, true)
	eocd := len(data) - 22
	binary.LittleEndian.PutUint32(data[eocd+12:], binary.LittleEndian.Uint32(data[eocd+12:])+1)
	col := report.NewCollector(0)
	sess := artifact.NewSession(col, "", limits.Default())
	ctx := sess.NewCtx("conflict.zip", limits.Default())
	ctx.Format = artifact.FormatZip
	if err := archive.Scan(ctx, source.Mem("conflict.zip", data)); err == nil {
		t.Fatal("a zip64 directory that conflicts with the EOCD was accepted")
	}
}

func TestPrefixedZipDecoyDirectoryDoesNotHideMembers(t *testing.T) {
	body := buildZip(t, []zspec{{name: "archive/data.pkl", data: gadgetPickle(), method: 8}}, false)
	eocd := len(body) - 22
	cdSize := int(binary.LittleEndian.Uint32(body[eocd+12:]))
	cdOff := int(binary.LittleEndian.Uint32(body[eocd+16:]))
	prefixLen := cdOff + cdSize + 32
	prefix := make([]byte, prefixLen)
	copy(prefix[cdOff:], body[cdOff:cdOff+cdSize])
	data := append(prefix, body...)
	fs := findingsFor(t, "decoy.zip", data, artifact.FormatZip, limits.Default())
	if !hasRule(fs, "SC4N-PICKLE-GLOBAL-CRITICAL") {
		t.Fatalf("the real member was hidden behind a decoy directory; findings=%v", fs)
	}
	if !hasRule(fs, "SC4N-ARCHIVE-DIRECTORY-AMBIGUOUS") {
		t.Fatalf("two valid directories were not reported; findings=%v", fs)
	}
}

func TestZipIncompleteLocalZip64ExtraIsReported(t *testing.T) {
	data := buildZip(t, []zspec{{name: "a", data: []byte("payload"), method: 8}}, false)
	binary.LittleEndian.PutUint32(data[18:], 0xffffffff)
	binary.LittleEndian.PutUint32(data[22:], 0xffffffff)
	binary.LittleEndian.PutUint16(data[28:], 0)
	fs := findingsFor(t, "badlocal.zip", data, artifact.FormatZip, limits.Default())
	if !hasRule(fs, "SC4N-ARCHIVE-NAME-MISMATCH") {
		t.Fatalf("a sentinel local size without a zip64 extra was not reported; findings=%v", fs)
	}
}

func TestZipNameRetentionIsCapped(t *testing.T) {
	data := buildZip(t, []zspec{{name: "a-very-long-member-name", data: []byte("a")}}, false)
	l := limits.Default()
	l.MaxRetainedText = 5
	fs := findingsFor(t, "names.zip", data, artifact.FormatZip, l)
	if !hasRule(fs, "SC4N-LIMIT-RETAINED") || !hasRule(fs, "SC4N-ARCHIVE-MEMBER-SKIPPED") {
		t.Fatalf("name retention cap was silent; findings=%v", fs)
	}
}

func TestKerasPrepassReportsTheDecompressionCap(t *testing.T) {
	data := buildZip(t, []zspec{
		{name: "config.json", data: []byte(`{"class_name":"Model","config":{}}`), method: 8},
		{name: "model.weights.h5", data: []byte("not really h5"), method: 8},
	}, false)
	l := limits.Default()
	l.MaxDecompressedBytes = 1
	fs := findingsFor(t, "model.keras", data, artifact.FormatKeras, l)
	if got := countRule(fs, "SC4N-LIMIT-DECOMPRESSED"); got != 1 {
		t.Fatalf("decompression limits = %d, want exactly one; findings=%v", got, fs)
	}
}
