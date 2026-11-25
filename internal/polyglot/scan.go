// Package polyglot is a format-independent universal scan layer: it runs for
// every artifact and every nested member, before the format parser, and reports
// the signals that are meaningful whatever the artifact claims to be.
//
// Two properties of the layer matter:
//
//   - it is content-based and order-independent. It reads nothing another
//     universal layer wrote, and it decides from the artifact's own bytes, so
//     running it before or after the extension check cannot change its findings.
//   - it is bounded. Every magic scan looks at the first and last 1 MiB only
//     (see WindowBytes), so a 13 GB tensor file costs a couple of MiB of reads
//     and is never traversed twice.
//
// The layer owns three detections — a validated native executable inside an
// artifact that is not itself native (SC4N-POLYGLOT-NATIVE), a native magic that
// does not validate (SC4N-POLYGLOT-MAGIC-ONLY), a file that is two container
// formats at once (SC4N-POLYGLOT-CONTAINER) and a binary artifact that begins
// with an interpreter directive (SC4N-POLYGLOT-SHEBANG) — plus the emission of
// the already-defined artifact.RuleExtensionMismatch for the top-level file.
//
// A native artifact is handled by internal/native, which validates its own
// header and looks for a second one inside it; this layer only checks that a
// leading native magic it sees really does validate, so a file that merely
// starts with \x7fELF is not mistaken for a program.
package polyglot

import (
	"bytes"
	"strconv"

	"github.com/fr0g-66723067-io/sc4n/internal/archive"
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/bytescan"
	"github.com/fr0g-66723067-io/sc4n/internal/limits"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

func init() {
	artifact.RegisterUniversal("polyglot", Scan)
	// The magic sniffer must not claim a file as native on a bare magic: a chat
	// template that begins with "MZ" is still a template. This layer owns what
	// "the header validates" means, so it is the one that answers the question.
	artifact.RegisterNativeValidator(func(s source.Source, size, off int64) bool {
		_, ok := ValidateNativeHeader(s, size, off)
		return ok
	})
}

// Scan is the registered universal layer.
func Scan(ctx *artifact.Ctx, s source.Source, f artifact.Format) {
	if ctx == nil || s == nil {
		return
	}
	size := s.Size()
	if size <= 0 {
		return
	}

	checkExtension(ctx, f)

	if f == artifact.FormatNative {
		// The native parser owns everything about a native artifact. The only
		// thing this layer adds is the honest distinction between a leading magic
		// that is a real header and one that only looks like it, plus the zip a
		// native file can carry after its own bytes.
		checkLeadingMagicOnly(ctx, s, size)
		checkAppendedArchive(ctx, s, size)
		return
	}

	checkNative(ctx, s, f, size)
	checkContainers(ctx, s)
	checkShebang(ctx, s, f)
}

// checkExtension emits SC4N-FORMAT-EXTENSION-MISMATCH when the sniffed format has
// no plausible relationship with the file's extension.
//
// It fires only at the top level (ctx.Depth == 0): a nested member named
// model.bin inside a zip is the archive's business, and re-deriving the mismatch
// for it would report the same signal once per container level. A format that no
// sniffer identified (FormatUnknown) is not a contradiction — nothing was
// identified — so it is skipped, which keeps an ordinary random .bin clean.
func checkExtension(ctx *artifact.Ctx, f artifact.Format) {
	if ctx.Depth != 0 || f == artifact.FormatUnknown {
		return
	}
	name := ctx.Sink.Artifact()
	if name == "" || artifact.ExtensionPlausible(name, f) {
		return
	}
	ctx.Sink.EmitExtra(artifact.RuleExtensionMismatch, 0,
		"the file name claims one format; the content was dispatched as "+f.String()+" from its bytes",
		map[string]string{"sniffed": f.String()})
}

// checkLeadingMagicOnly reports a leading native magic when the standard
// library's header parser rejects it. Used for the FormatNative case, where the
// marker's job is to separate "this is an executable" from "this starts with four
// bytes that look like one".
func checkLeadingMagicOnly(ctx *artifact.Ctx, s source.Source, size int64) {
	hdr := readWindow(s, 0, 64)
	kind := bytescan.MagicAt(hdr.Data)
	if kind == bytescan.NativeNone {
		return
	}
	if _, ok := ValidateNativeHeader(s, size, 0); ok {
		return
	}
	emitMagicOnly(ctx, kind, 0, "the leading bytes match "+kind.String()+" but the header does not validate")
}

// checkNative reports validated native executables inside a non-native artifact,
// and a bare native magic at the artifact's head.
func checkNative(ctx *artifact.Ctx, s source.Source, f artifact.Format, size int64) {
	// The head, at offset 0: a model file that actually *is* a program (renamed
	// .so, an APE/llamafile without its GGUF trailer) lands here.
	hdr := readWindow(s, 0, 64)
	if kind := bytescan.MagicAt(hdr.Data); kind != bytescan.NativeNone {
		if _, ok := ValidateNativeHeader(s, size, 0); ok {
			emitPolyglotNative(ctx, kind, 0, "head")
		} else {
			emitMagicOnly(ctx, kind, 0, "the artifact begins with "+kind.String()+" but the header does not validate")
		}
	}

	// Anywhere in the head or tail window: a validated header buried in metadata
	// or appended after the model's own data.
	seen := map[int64]bool{0: true}
	for _, w := range MagicWindows(s, size) {
		base := w.Base
		EachValidatedNativeInWindow(s, size, w, func(kind bytescan.NativeKind, abs int64) {
			if seen[abs] {
				return
			}
			seen[abs] = true
			emitPolyglotNative(ctx, kind, abs, windowName(base))
		})
	}
}

// checkAppendedArchive scans a zip appended after a native executable. A
// native file's own parser never opens the trailing container, so a payload
// stored there was visible only to the head/tail magic window.
func checkAppendedArchive(ctx *artifact.Ctx, s source.Source, size int64) {
	if size <= 0 {
		return
	}
	tail := readWindow(s, max64(0, size-(64<<10)), 64<<10)
	if !bytes.Contains(tail.Data, []byte("PK\x05\x06")) &&
		!bytes.Contains(tail.Data, []byte("PK\x06\x06")) {
		return
	}
	if _, err := archive.Collect(s, ctx.Limits); err != nil {
		return
	}
	ctx.Sink.EmitExtra(rulePolyglotContainer, 0,
		"the file is both native (leading header) and zip (an end-of-central-directory record after it), so two readers open it two different ways",
		map[string]string{"container": "zip", "second": "native"})
	sub, ok := ctx.Member("!zip", artifact.FormatZip)
	if !ok {
		maxDepth := ctx.Depth
		if ctx.Session != nil {
			maxDepth = ctx.Session.TopLimits.MaxDepth
		}
		limits.Emit(ctx.Sink, limits.RuleDepth, "MaxDepth", int64(ctx.Depth+1), int64(maxDepth), "stopped at !zip")
		return
	}
	_ = archive.Scan(sub, s)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// checkContainers reports a file that is two container types at once, using only
// the canonical anchors (offset 0 and the tar ustar anchor at 257) so that a zip
// that merely stores a tar member is not a false positive.
func checkContainers(ctx *artifact.Ctx, s source.Source) {
	probe := readWindow(s, 0, 512)
	lead := leadingContainer(probe.Data)
	if lead == artifact.FormatUnknown || !hasTarAnchor(probe.Data) {
		return
	}
	ctx.Sink.EmitExtra(rulePolyglotContainer, 0,
		"the file is both "+lead.String()+" (leading magic) and tar (ustar anchor at offset 257), so two different readers open it two different ways",
		map[string]string{"container": lead.String(), "second": artifact.FormatTar.String()})
}

// checkShebang reports a binary artifact whose first line is an interpreter
// directive. Text-like formats are exempt because a shebang there is idiomatic.
func checkShebang(ctx *artifact.Ctx, s source.Source, f artifact.Format) {
	if textFormats[f] {
		return
	}
	head := readWindow(s, 0, 256)
	interp, ok := bytescan.ShebangAt(head.Data)
	if !ok {
		return
	}
	ctx.Sink.EmitExtra(rulePolyglotShebang, 0,
		"the artifact begins with #!"+interp+", so it is a script rather than the "+f.String()+" its bytes were dispatched as",
		map[string]string{"interpreter": interp})
}

// emitPolyglotNative emits the high finding with the offset and window that let a
// reviewer jump straight to the embedded executable.
func emitPolyglotNative(ctx *artifact.Ctx, kind bytescan.NativeKind, off int64, where string) {
	ctx.Sink.EmitExtra(rulePolyglotNative, off,
		"a validated "+kind.String()+" header sits at offset "+strconv.FormatInt(off, 10)+" ("+where+" region) inside an artifact that is not native",
		map[string]string{"kind": kind.String(), "region": where, "offset": strconv.FormatInt(off, 10)})
}

// emitMagicOnly emits the informational bare-magic finding.
func emitMagicOnly(ctx *artifact.Ctx, kind bytescan.NativeKind, off int64, why string) {
	ctx.Sink.EmitExtra(rulePolyglotMagicOnly, off, why,
		map[string]string{"kind": kind.String(), "validated": "false"})
}

// windowName names the region a window belongs to for the finding evidence.
func windowName(base int64) string {
	if base == 0 {
		return "head"
	}
	return "tail"
}
