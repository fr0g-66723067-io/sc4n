// Package native is the parser for FormatNative: an ELF, PE/DOS, Mach-O, ar
// object archive or OLE compound file, identified by magic in internal/artifact.
//
// It is deliberately shallow, and the capability row for FormatNative says so:
// no disassembly and no symbol-table walk, only header validation plus the shared
// string-indicator scan over the head and tail windows. What that buys is the two
// statements a scanner can make honestly about an executable it will not run:
// "this really is a program" (SC4N-NATIVE-VALID) and "there is a second program
// inside it" (SC4N-NATIVE-EMBEDDED-PAYLOAD). A native artifact that merely starts
// with a magic but does not validate is reported by the universal polyglot layer
// as SC4N-POLYGLOT-MAGIC-ONLY, so the invalid case is not silent.
//
// Header validation is delegated to polyglot.ValidateNativeHeader so that the
// layer that reports a validated header at high severity and the parser that
// reports it at info cannot disagree about what "valid" means.
package native

import (
	"strconv"
	"strings"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/polyglot"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
	"github.com/fr0g-66723067-io/sc4n/internal/stringscan"
)

// parser is the registered parser for a native artifact.
type parser struct{}

func init() {
	// The FormatNative capability row is registered by internal/artifact (which
	// owns the magic table); registering it here would panic on the duplicate.
	artifact.RegisterParser(artifact.FormatNative, parser{})
}

// Parse validates the artifact's own header, looks for a second validated header
// inside it, and runs the indicator engine over the head and tail windows.
func (parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	size := s.Size()
	if size <= 0 {
		return nil
	}

	hdr, _ := s.Bytes(0, min(size, 64))
	kind := bytescan.MagicAt(hdr)
	if kind == bytescan.NativeNone {
		// The sniffer dispatched on a magic we cannot re-read (a short file, a
		// truncated read). There is nothing to validate and the universal layer
		// already handles the magic-without-header case.
		return nil
	}

	if k, ok := polyglot.ValidateNativeHeader(s, size, 0); ok {
		ctx.Sink.EmitExtra(ruleNativeValid, 0,
			"the artifact is a valid "+k.String()+" executable; sc4n does not disassemble it, and does not run it",
			map[string]string{"kind": k.String()})
		// The symbol walk is ELF-only: debug/elf is the only stdlib header parser
		// that exposes imports, and a PE branch here would be code with no seed in
		// the validity-oracle lab to check it against.
		if kind == bytescan.NativeELF {
			if names := polyglot.ExecImportNames(s, size, 0); len(names) > 0 {
				ctx.Sink.EmitExtra(ruleNativeExecImports, 0,
					"ELF imports process-control symbols: "+strings.Join(names, ", "),
					map[string]string{"symbols": strings.Join(names, ","), "kind": k.String()})
			}
		}
	}

	emitEmbedded(ctx, s, size)

	// The indicator scan is bounded to the same two windows as every other magic
	// scan, so a multi-gigabyte .so costs at most 2 MiB of matching. Obvious
	// strings (a C2 URL, a credential path, a shell payload) in an embedded
	// binary are still surfaced from its head and tail.
	for _, w := range polyglot.MagicWindows(s, size) {
		// A compiled executable is not prose: its symbol table names libc functions
		// and its string table holds whatever the program ships. Only a reachable
		// secret or endpoint is a finding here.
		stringscan.EmitKind(ctx.Sink, w.Base, w.Data, stringscan.KindSecrets)
	}
	return nil
}

// emitEmbedded reports every validated native header inside the artifact other
// than the one at offset 0, deduplicated across the head and tail windows.
func emitEmbedded(ctx *artifact.Ctx, s source.Source, size int64) {
	seen := map[int64]bool{0: true}
	for _, w := range polyglot.MagicWindows(s, size) {
		base := w.Base
		polyglot.EachValidatedNative(w.Data, func(kind bytescan.NativeKind, off int) {
			abs := base + int64(off)
			if seen[abs] {
				return
			}
			seen[abs] = true
			region := "head"
			if base != 0 {
				region = "tail"
			}
			ctx.Sink.EmitExtra(ruleNativeEmbeddedPayload, abs,
				"a second validated "+kind.String()+" header sits at offset "+strconv.FormatInt(abs, 10)+
					" ("+region+" region) inside this native artifact",
				map[string]string{"kind": kind.String(), "region": region, "offset": strconv.FormatInt(abs, 10)})
		})
	}
}
