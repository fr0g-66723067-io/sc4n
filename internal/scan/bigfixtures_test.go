//go:build bigfixtures

// Package scan's big-fixture benchmark generates a multi-gigabyte safetensors
// file, scans it through the real engine and asserts the wall-time and resident
// memory budget from docs/architecture.md.
//
// It is behind the `bigfixtures` build tag and never committed: the generator
// writes to $SC4N_BIG_DIR (default $TMPDIR) and deletes the file afterwards. The
// size is $SC4N_BIG_GB (default 13). The budget assertions are skipped, loudly,
// when the target filesystem cannot hold the file — a benchmark that silently
// shrinks its own input would be measuring the wrong thing.
package scan_test

import (
	"context"
	"encoding/binary"
	"fmt"
	rand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/scan"
)

// tensors is how many tensors the generated file declares. One tensor per
// ~130 MiB keeps the header small while still making the body the dominant cost.
const tensors = 100

func bigSize(tb testing.TB) int64 {
	gb := int64(13)
	if v := os.Getenv("SC4N_BIG_GB"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			tb.Fatalf("SC4N_BIG_GB=%q is not a positive integer", v)
		}
		gb = n
	}
	return gb << 30
}

// writeBigSafetensors writes a conforming F16 safetensors file of about size
// bytes and returns its path.
func writeBigSafetensors(tb testing.TB, dir string, size int64) string {
	tb.Helper()
	per := size / tensors
	per -= per % 2 // F16 elements are 2 bytes
	per -= per % 4096

	var header strings.Builder
	header.WriteString("{")
	header.WriteString(`"__metadata__":{"format":"pt","producer":"sc4n-bigfixtures"}`)
	off := int64(0)
	for i := 0; i < tensors; i++ {
		rows := per / (2 * 512)
		fmt.Fprintf(&header, `,"t%03d":{"dtype":"F16","shape":[%d,512],"data_offsets":[%d,%d]}`, i, rows, off, off+per)
		off += per
	}
	header.WriteString("}")
	// safetensors pads the header with spaces to an 8-byte boundary.
	for header.Len()%8 != 0 {
		header.WriteByte(' ')
	}

	path := filepath.Join(dir, "big-f16.safetensors")
	f, err := os.Create(path)
	if err != nil {
		tb.Fatalf("create: %v", err)
	}
	defer f.Close()
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(header.Len()))
	if _, err := f.Write(lenBuf[:]); err != nil {
		tb.Fatal(err)
	}
	if _, err := f.WriteString(header.String()); err != nil {
		tb.Fatal(err)
	}

	// The body is written in 8 MiB chunks of deterministic pseudo-random bytes:
	// real tensor data is incompressible, so this is the shape that exercises the
	// engine's worst case rather than a sparse file of zeros.
	r := rand.New(rand.NewPCG(0x5c4a, 0x9e37))
	chunk := make([]byte, 8<<20)
	for written := int64(0); written < off; {
		n := int64(len(chunk))
		if off-written < n {
			n = off - written
		}
		for i := range chunk[:n] {
			chunk[i] = byte(r.Uint32())
		}
		if _, err := f.Write(chunk[:n]); err != nil {
			tb.Fatal(err)
		}
		written += n
	}
	if err := f.Close(); err != nil {
		tb.Fatal(err)
	}
	return path
}

// rss reads the two resident-memory numbers that matter here.
//
// anon is the process's own memory (RssAnon): the slices it allocated, which is
// what "does the scanner materialise the artifact" means. hwm is the kernel's
// high-water mark for all resident pages, which for a memory-mapped artifact
// includes the clean, reclaimable page-cache pages the kernel is holding on the
// scanner's behalf — it grows to the artifact size even though the process never
// owns those bytes. Both are reported; the budget is asserted against anon, and
// docs/architecture.md says why.
func rss(tb testing.TB) (anon, hwm int64) {
	tb.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		var dst *int64
		switch {
		case strings.HasPrefix(line, "RssAnon:"):
			dst = &anon
		case strings.HasPrefix(line, "VmHWM:"):
			dst = &hwm
		default:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		*dst = kb << 10
	}
	return anon, hwm
}

func TestBigSafetensors(t *testing.T) {
	size := bigSize(t)
	dir := os.Getenv("SC4N_BIG_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("big fixture dir: %v", err)
	}
	if free := freeBytes(t, dir); free < size+size/10 {
		t.Skipf("skipping: %s has %d GiB free, need %d GiB for the fixture (set SC4N_BIG_DIR or SC4N_BIG_GB)",
			dir, free>>30, (size+size/10)>>30)
	}

	t.Log("generating the fixture (this is the slow part; the scan is timed separately)")
	start := time.Now()
	path := writeBigSafetensors(t, dir, size)
	if os.Getenv("SC4N_BIG_KEEP") == "" {
		defer os.Remove(path)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%.2f GiB) in %s", path, float64(st.Size())/(1<<30), time.Since(start).Round(time.Millisecond))

	l := limits.Default()
	l.MaxArtifactBytes = 1 << 40
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	runtime.GC()
	anonBefore, hwmBefore := rss(t)
	t0 := time.Now()
	res, err := scan.Run(ctx, scan.Config{Paths: []string{path}, Limits: l, Jobs: runtime.NumCPU()})
	if err != nil {
		t.Fatalf("scan.Run: %v", err)
	}
	elapsed := time.Since(t0)
	anonAfter, hwmAfter := rss(t)

	findings := 0
	if res.Collector != nil {
		findings = len(res.Collector.Findings())
	}
	rate := float64(st.Size()) / elapsed.Seconds() / (1 << 30)
	t.Logf("scan: %s wall (%.2f GiB/s), anon RSS %.1f MiB (was %.1f), VmHWM %.1f MiB (was %.1f), %d findings, %d artifact(s)",
		elapsed.Round(time.Millisecond), rate, float64(anonAfter)/(1<<20), float64(anonBefore)/(1<<20),
		float64(hwmAfter)/(1<<20), float64(hwmBefore)/(1<<20), findings, len(res.Artifacts))

	if testing.Short() {
		return
	}
	if elapsed > 20*time.Second {
		t.Errorf("wall time %s exceeds the 20 s budget in docs/architecture.md", elapsed.Round(time.Millisecond))
	}
	if anonAfter > 512<<20 {
		t.Errorf("anonymous RSS %.1f MiB exceeds the 512 MiB budget in docs/architecture.md", float64(anonAfter)/(1<<20))
	}
}

func freeBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var st syscallStatfs
	if err := statfs(dir, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
