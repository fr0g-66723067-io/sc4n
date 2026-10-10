package polyglot

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The polyglot rule set. Severity follows the plan's calibration: a validated
// native executable inside a model artifact is high (it is code, but its mere
// presence is not proof that a loader reaches it), a container that is two
// container types at once and a bare magic without a valid header are
// informational/medium (structural anomaly, no sink shown).
//
// SC4N-FORMAT-EXTENSION-MISMATCH deliberately lives in internal/artifact: it is
// emitted from here but its severity, description and evidence wording are owned
// by the dispatch package so the universal layer and the format table cannot
// disagree about what "the content contradicts the name" means.

var (
	// rulePolyglotNative fires when a *validated* native executable header is
	// found inside an artifact that is not itself native. "Validated" is the
	// whole point: the standard library's own header parser has to accept it, so
	// random tensor bytes that happen to contain 0x7f 'E' 'L' 'F' do not fire it
	// (that weaker signal is rulePolyglotMagicOnly). References: the February
	// 2025 Hugging Face campaign shipped .pt files that were 7z archives, and
	// "polyglot" model files that are also an executable are the same evasion
	// family one step further.
	rulePolyglotNative = report.DefineRule(report.Rule{
		ID:         "SC4N-POLYGLOT-NATIVE",
		Title:      "Validated native executable embedded in a non-native artifact",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506", "CWE-436"},
		Class:      "polyglot",
		Description: "A complete native executable header (ELF, PE/DOS, Mach-O, an ar object archive or an OLE " +
			"compound file) was found inside an artifact that was dispatched as something else. The header was " +
			"accepted by Go's own debug/elf, debug/macho or debug/pe parser, so this is real code, not four " +
			"bytes that happen to match a magic. Nothing in sc4n executes it; the finding is the statement that " +
			"the file carries a program alongside the model, which is the shape both a malicious repository and " +
			"a self-extracting single-file model (an APE/llamafile is exactly this) present to a loader.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/506.html",
			"https://cwe.mitre.org/data/definitions/436.html",
			"https://huggingface.co/blog/notable-models-scanned",
			"https://justine.lol/ape.html",
		},
		Tags: []string{"polyglot", "evasion"},
	})

	// rulePolyglotMagicOnly fires when the artifact *begins* with a native magic
	// or its container region carries one, but the header does not validate. It
	// is informational because the bytes are ordinary data: the value is that a
	// reviewer can see "this file was named like a model and starts with \x7fELF
	// but is not an ELF", which is how a truncated or hand-faked header looks.
	rulePolyglotMagicOnly = report.DefineRule(report.Rule{
		ID:         "SC4N-POLYGLOT-MAGIC-ONLY",
		Title:      "Native magic signature without a valid header",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-436"},
		Class:      "polyglot",
		Description: "The artifact carries a native-executable magic (ELF, PE/DOS, Mach-O, ar, OLE or an APE " +
			"sigil) but the standard library's header parser rejects it, so the magic is data that looks like a " +
			"header rather than a loadable program. Reported at info because a four-byte match is common in " +
			"binary tensor data; it is the validated match (SC4N-POLYGLOT-NATIVE) that means code. A leading " +
			"magic that does not validate is also how a truncated or deliberately malformed executable is " +
			"disguised as a model.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/436.html"},
		Tags: []string{"polyglot"},
	})

	// rulePolyglotContainer fires when the artifact is two container types at
	// once. The canonical case is a zip whose byte 257 (the tar ustar anchor) is
	// a real tar magic, so the same bytes are a zip to archive/zip and a tar
	// header to archive/tar; the same trick works with 7z, rar and the
	// single-stream compressors in front. It is medium because coexistence of
	// signatures does not by itself prove both loaders accept the file.
	rulePolyglotContainer = report.DefineRule(report.Rule{
		ID:         "SC4N-POLYGLOT-CONTAINER",
		Title:      "Artifact is more than one container format",
		Severity:   report.SeverityMedium,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-436"},
		Class:      "polyglot",
		Description: "Two container signatures occupy their canonical anchors in one file: a leading magic at " +
			"offset 0 (zip, 7z, rar, gzip, bzip2, xz, lz4, zstd or HDF5) together with the tar ustar anchor at " +
			"offset 257. A file both a zip and a tar is the classic container polyglot: two different readers " +
			"open it two different ways, so a scanner that only knows one container never sees what the other " +
			"one loads. sc4n reports the coexistence, not a loadability proof, because the second container's " +
			"checksum is not validated here.",
		Refs: []string{
			"https://cwe.mitre.org/data/definitions/436.html",
			"https://en.wikipedia.org/wiki/Polyglot_(computing)",
		},
		Tags: []string{"polyglot", "evasion"},
	})

	// rulePolyglotShebang fires when a binary artifact begins with an interpreter
	// directive. A shebang in a .py file is ordinary, so the rule is suppressed
	// for every text-like format; what it reports is a file whose bytes and
	// extension say "model" while its first line says "shell".
	rulePolyglotShebang = report.DefineRule(report.Rule{
		ID:         "SC4N-POLYGLOT-SHEBANG",
		Title:      "Binary artifact begins with an interpreter directive",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceMedium,
		CWE:        []string{"CWE-506"},
		Class:      "polyglot",
		Description: "The artifact's first two bytes are \"#!\", so the file is a script, not the binary " +
			"container or model its content was dispatched as. The rule is suppressed for text-like formats " +
			"(Python, notebook, Jinja, Markdown, YAML, JSON, plain text) where a shebang is idiomatic; it " +
			"reports the contradiction case, where a shell or interpreter line sits at the head of bytes that " +
			"were otherwise identified as a model artifact.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"polyglot"},
	})
)
