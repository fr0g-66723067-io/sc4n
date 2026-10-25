// Package archive walks zip, tar and single-stream compression wrappers without
// ever extracting a member to disk or running an external decompressor.
//
// The design rule that shapes every function here is fail-closed iteration: a
// member that cannot be read is reported as SC4N-ARCHIVE-MEMBER-ERROR and the
// walk continues, because a scanner that aborts on an unreadable entry and then
// reports "clean" is exactly how modelscan issue #354 turned a malicious
// `archive/data.pkl` into a CLEAN verdict. Only an unreadable *container* (a zip
// whose end-of-central-directory or central directory cannot be located) fails
// the artifact.
package archive

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The archive metrics that decision-9-1's calibration fixes to *high*, because a
// traversal or a link is a filesystem effect at extraction time, whereas a
// metadata disagreement is only evidence of intent.
var (
	// ruleArchivePath fires for an absolute, traversal, NUL-bearing, backslash or
	// drive-letter member name (the zip_slip class).
	ruleArchivePath = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-PATH",
		Title:      "Archive member name is an absolute or traversal path",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-22"},
		Class:      "archive",
		Description: "A member name is absolute, contains a '..' segment, a NUL byte, a backslash " +
			"separator, a Windows drive letter, or is longer than 4096 bytes. A loader that extracts without " +
			"normalising the name writes or reads outside the destination directory (zip_slip). sc4n never " +
			"extracts a member, so this is reported at the point the name is read, not at extraction time.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/22.html"},
		Tags: []string{"path-traversal"},
	})

	// ruleArchiveLink fires for symlink/hardlink/device members.
	ruleArchiveLink = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-LINK",
		Title:      "Archive contains a link or device member",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-59"},
		Class:      "archive",
		Description: "The archive declares a symbolic link, a hard link or a device node. Extracting it " +
			"creates a filesystem object whose target is chosen by the artifact rather than by the scanner, " +
			"which is the link-following primitive used to read or overwrite files outside the extraction " +
			"root (CWE-59). The link target is recorded in the evidence where the format carries it.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/59.html"},
		Tags: []string{"path-traversal"},
	})

	// ruleArchiveEncrypted fires for an encrypted member.
	ruleArchiveEncrypted = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-ENCRYPTED",
		Title:      "Archive member is encrypted and cannot be inspected",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-693"},
		Class:      "archive",
		Description: "The member is encrypted, so sc4n cannot read its content and the payload behind the " +
			"encryption was not analysed. This is reported rather than skipped because an encrypted member " +
			"is indistinguishable from a member whose scan failed: both mean \"not analysed\", never \"clean\".",
		Refs: []string{"https://cwe.mitre.org/data/definitions/693.html"},
	})

	// ruleArchiveCRC fires when a member's CRC-32 does not match its content.
	ruleArchiveCRC = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-CRC",
		Title:      "Archive member CRC-32 does not match its content",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-354"},
		Class:      "archive",
		Description: "The member's bytes do not hash to the CRC-32 recorded in the directory. Either the " +
			"archive is corrupt or it was edited after it was written, which is the shape a scanner using a " +
			"reader that validates CRC (and a loader that does not) would disagree about.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/354.html"},
	})

	// ruleArchiveNameMismatch fires when the local file header and the central
	// directory disagree about a member: its name, its compression method, its
	// CRC, or its sizes. The ID is historical (the name case came first); the
	// finding is "two records describe different bytes".
	ruleArchiveNameMismatch = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-NAME-MISMATCH",
		Title:      "Zip local header disagrees with the central directory",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-436"},
		Class:      "archive",
		Description: "A member's local file header and its central-directory record disagree about its " +
			"name, compression method, CRC-32 or sizes. A reader that trusts one record and a loader that " +
			"trusts the other see two different files — the classic way to show a scanner a benign member " +
			"and load a hostile one — and a method disagreement means the bytes sc4n read are not the bytes " +
			"a loader would decompress. The same rule reports a stored member whose central record declares " +
			"different compressed and uncompressed sizes, which cannot both be true.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/436.html"},
	})

	// ruleArchiveDuplicateName fires when two members share a name.
	ruleArchiveDuplicateName = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-DUPLICATE-NAME",
		Title:      "Archive contains duplicate member names",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-436"},
		Class:      "archive",
		Description: "Two members have the same name. Extractor behaviour then decides which copy wins: a " +
			"scanner may scan the first and a loader may use the last, so the artifact is not what the scan " +
			"described.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/436.html"},
	})

	// ruleArchiveMemberError fires when a member could not be read.
	ruleArchiveMemberError = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-MEMBER-ERROR",
		Title:      "Archive member could not be read",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-755"},
		Class:      "archive",
		Description: "A member's structure is malformed or its data is corrupt, so its content was not " +
			"analysed. A zip walk continues past the member (fail-closed iteration), so the rest of that " +
			"archive was still scanned; a tar walk cannot, because a tar is a forward stream and a header " +
			"that cannot be read ends the archive — so for a tar this finding means the members after it " +
			"were not visited either. The member itself is reported as not analysed rather than silently " +
			"skipped. modelscan issue #354 is exactly this: an unreadable entry before archive/data.pkl made " +
			"the whole scan report CLEAN.",
		Refs: []string{"https://github.com/protectai/modelscan/issues/354"},
	})

	// ruleArchiveUnsupportedCompression fires for a compressor sc4n recognises but
	// has no stdlib decoder for.
	ruleArchiveUnsupportedCompression = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-UNSUPPORTED-COMPRESSION",
		Title:      "Compression is recognised but cannot be decompressed",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-693"},
		Class:      "archive",
		Description: "The bytes are wrapped in a compression algorithm for which the Go standard library has " +
			"no decoder (xz, lzma, lz4, zstd, 7z, rar). sc4n does not shell out to a " +
			"decompressor, so the payload inside was NOT scanned. The algorithm and the offset are named in " +
			"the evidence. A 7z file named .pt is the February 2025 Hugging Face campaign: the loader still " +
			"deserialised it while every extension-driven scanner saw \"not a zip\".",
		Refs: []string{"https://huggingface.co/blog/notable-models-scanned"},
	})

	// ruleArchiveNestedCompression fires when a decompressed payload is itself
	// compressed.
	ruleArchiveNestedCompression = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-NESTED-COMPRESSION",
		Title:      "Compressed payload is wrapped in a second compression layer",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-409"},
		Class:      "archive",
		Description: "A payload decompressed cleanly and is itself compressed. sc4n recurses through " +
			"supported wrappers, but double wrapping is the published modelscan bypass (gzip of bzip2 of a " +
			"pickle) because a scanner that decompresses one layer and then classifies the result sees " +
			"compressed bytes, not a pickle. The finding records the inner algorithm.",
		Refs: []string{"https://github.com/protectai/modelscan/issues/354"},
	})

	// ruleArchiveNativeMember fires when a member is a validated native executable.
	ruleArchiveNativeMember = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-NATIVE-MEMBER",
		Title:      "Archive contains a native executable member",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "executable",
		Description: "A member's bytes validate as an ELF, PE, Mach-O or ar executable. A model archive has " +
			"no legitimate reason to carry native code, and the code runs as soon as anything executes the " +
			"member. High rather than critical: loading the model does not run it, so unlike a pickle " +
			"REDUCE there is no code execution on the normal load path — the same calibration the other " +
			"native-in-container rules use (SC4N-POLYGLOT-NATIVE, SC4N-TFLITE-NATIVE-MAGIC, " +
			"SC4N-NATIVE-EMBEDDED-PAYLOAD).",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"malicious-code"},
	})

	// ruleArchiveShebang fires for a member that starts with an interpreter line.
	ruleArchiveShebang = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-SHEBANG",
		Title:      "Archive member is an executable script",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-78"},
		Class:      "executable",
		Description: "A member starts with a '#!' interpreter line, so it is a script that becomes " +
			"executable when extracted with its mode bits intact. sc4n does not execute it; it reports the " +
			"interpreter name so the reader can see what the artifact intended to run.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/78.html"},
	})

	// ruleArchiveMemberSkipped fires for a member the walker did not read: a
	// typeflag it does not dispatch (a GNU sparse or contiguous member, or an
	// unknown type) or an empty name. It is medium and structural: the member's
	// bytes were not analysed, and a payload hidden in a sparse member's data
	// fragments is exactly what the universal head/tail windows do not see.
	ruleArchiveMemberSkipped = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-MEMBER-SKIPPED",
		Title:      "Archive member was not analysed",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-1059"},
		Class:      "structure",
		Description: "A member was not dispatched to any parser: its typeflag is not a regular file, " +
			"directory, link, device or fifo (a GNU sparse or contiguous member, or a type sc4n does not " +
			"know), or its name is empty. The member's bytes were therefore not scanned by anything but the " +
			"universal head/tail windows, and a payload can sit in the parts of it those windows do not " +
			"cover. The finding names the typeflag so the reader can see what the archive claimed.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/1059.html"},
		Tags: []string{"scanner-evasion", "structure"},
	})

	// ruleArchiveTrailingData fires when bytes follow the zip's
	// end-of-central-directory record. It is medium: appending to a zip is the
	// standard polyglot trick (a file that is both a zip and something else), and
	// the appended region is not described by the container's own directory, so a
	// reader that stops at the EOCD and a reader that scans to EOF disagree about
	// where the artifact ends.
	ruleArchiveTrailingData = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-TRAILING-DATA",
		Title:      "Bytes follow the end-of-central-directory record",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-436"},
		Class:      "structure",
		Description: "The zip's end-of-central-directory record does not end at the end of the file: a " +
			"region follows it. Appending bytes after the EOCD is the standard polyglot technique, and the " +
			"appended region is invisible to a reader that trusts the central directory while a reader that " +
			"scans the whole file sees it, so two tools can disagree about what the artifact contains. " +
			"sc4n still walks the central directory (the members it describes are analysed), and reports " +
			"the byte count so the appended region can be examined.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/436.html"},
		Tags: []string{"polyglot", "structure"},
	})

	// ruleArchiveTruncated fires when the members were recovered from local file
	// headers because the central directory is absent, which is the shape of a
	// header slice of a zip-backed checkpoint.
	ruleArchiveTruncated = report.DefineRule(report.Rule{
		ID:         "SC4N-ARCHIVE-TRUNCATED",
		Title:      "Zip has no central directory; members were recovered from local headers",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		Class:      "format",
		Description: "The file begins with zip local file headers but carries no end-of-central-directory " +
			"record, which is what a 2 MiB header slice of a torch checkpoint looks like. sc4n walked the " +
			"local headers forward and scanned every member they bound, so the findings under this artifact " +
			"come from the part of the archive that is present. Members after the last header are not " +
			"reachable and a member whose data descriptor is missing is bounded by the next header.",
		Tags: []string{"partial", "archive"},
	})
)

// algorithmName maps a zip compression method to the name used in evidence.
func algorithmName(method uint16) string {
	switch method {
	case 0:
		return "stored"
	case 8:
		return "deflate"
	case 12:
		return "bzip2"
	case 14:
		return "lzma"
	case 93:
		return "zstd"
	case 95:
		return "xz"
	case 99:
		return "AES"
	default:
		return "method-" + itoa(int(method))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
