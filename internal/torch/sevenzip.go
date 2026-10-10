package torch

import (
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// sevenZipUniversal emits SC4N-TORCH-7Z for a 7z archive named like a torch
// checkpoint.
//
// It is a universal layer rather than a sniffer because the built-in magic table
// claims the 7z signature (37 7A BC AF 27 1C) as FormatSevenZip at priority 100,
// and a format can have only one registered parser; there is no way for this
// package to own the SevenZip parse. A universal layer runs for every artifact
// before its parser and receives the sniffed format, which is exactly the hook
// needed to add the torch-specific verdict without stealing the format.
//
// The archive layer's own SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION finding for the
// format is emitted when its parser runs, so the two findings are complementary:
// one names the disguise, the other names the unreadable payload. sc4n does not
// decode 7z and does not shell out to a decompressor, so the pickle inside is
// never scanned; the rule text says so rather than implying a clean result.
func sevenZipUniversal(ctx *artifact.Ctx, s source.Source, f artifact.Format) {
	if ctx == nil || ctx.Sink == nil {
		return
	}
	if f != artifact.FormatSevenZip {
		return
	}
	if !isTorchExt(ctx.Sink.Artifact()) {
		return
	}
	ctx.Sink.Emit(ruleTorch7z, 0,
		"7z signature under a torch checkpoint name; the payload is NOT decoded by sc4n")
	_ = s
}
