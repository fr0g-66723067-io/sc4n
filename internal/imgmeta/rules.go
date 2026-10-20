// The image-metadata rule set.
//
// Two rules, one for each direction. SC4N-IMG-METADATA is informational and
// mandatory: it states which metadata was read and how many strings were handed to
// the indicator engine, so that an image with no findings is read as "metadata
// read, nothing in it" rather than "not recognised". SC4N-IMG-STRUCT is about
// framing that hides metadata: a chunk or segment whose declared length runs past
// the file, a compression method that is not deflate, or a zlib stream that does
// not inflate. Those are the shapes where a parser that trusted the length would
// read a different byte range than a viewer.
package imgmeta

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// RuleMetadata reports which image metadata was scanned.
var RuleMetadata = report.DefineRule(report.Rule{
	ID:         "SC4N-IMG-METADATA",
	Title:      "Image metadata was read and scanned",
	Severity:   report.SeverityInfo,
	Confidence: report.ConfidenceHigh,
	CWE:        nil,
	Class:      "format",
	Description: "The artifact is a PNG or JPEG image and sc4n read its text metadata (PNG tEXt, " +
		"zTXt, iTXt and eXIf chunks; JPEG APP1 Exif, APP1 XMP and COM segments) and ran every string " +
		"through the shared indicator engine and the invisible-character pass. The pixels and any " +
		"entropy-coded data are not decoded, so a payload hidden in pixel data (steganography) is not " +
		"covered. This finding is informational and exists so that a clean image report is read as " +
		"\"metadata read, nothing in it\" rather than \"not recognised\".",
	Refs: []string{
		"https://www.w3.org/TR/png-3/",
		"https://www.cipa.jp/std/documents/e/DC-008-Translation-2019-E.pdf",
	},
	Tags: []string{"image", "metadata"},
})

// RuleStruct reports image metadata framing that does not fit the file.
var RuleStruct = report.DefineRule(report.Rule{
	ID:         "SC4N-IMG-STRUCT",
	Title:      "Image metadata framing is invalid",
	Severity:   report.SeverityMedium,
	Confidence: report.ConfidenceHigh,
	CWE:        []string{"CWE-20"},
	Class:      "format",
	Description: "A PNG chunk or JPEG segment carrying metadata does not satisfy its own framing: " +
		"a declared length runs past the end of the file, the chunk list ends without an IEND, a " +
		"JPEG marker stream loses its alignment before SOS, an iTXt/zTXt compression method is not the " +
		"defined deflate, or a zlib stream does not inflate. A reader that trusts the declared length " +
		"reads a different byte range than sc4n inspected, so the mismatch is reported rather than " +
		"treated as a parse detail; the metadata that could be read before the break is still scanned.",
	Refs: []string{
		"https://www.w3.org/TR/png-3/",
		"https://www.cipa.jp/std/documents/e/DC-008-Translation-2019-E.pdf",
	},
	Tags: []string{"image", "malformed"},
})
