package native

import "github.com/fr0g-66723067-io/sc4n/internal/report"

// The native rule set. sc4n never disassembles and never executes, so these two
// rules are exactly what a header validator can honestly say: "this is a real
// executable" (info, because a .so in a model repository may be entirely
// expected) and "there is a second executable inside this one" (high, because an
// appended or embedded program is not something a linker produces).

var (
	// ruleNativeValid states the fact that the artifact is an executable. It is
	// informational: a doctor's model repository, a tokenizer's C extension and a
	// wheel's bundled .so are all legitimate. The value is that the verdict is
	// explicit, so "sc4n reported nothing about this file" is never read as "this
	// file is inert data".
	ruleNativeValid = report.DefineRule(report.Rule{
		ID:         "SC4N-NATIVE-VALID",
		Title:      "Artifact is a validated native executable",
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceHigh,
		Class:      "native",
		Description: "The artifact is a native executable whose header was accepted by Go's debug/elf, " +
			"debug/macho or debug/pe parser (ar archives and OLE compound files use the structural check in " +
			"internal/bytescan). sc4n does not disassemble or run it; the finding records that the bytes are " +
			"a program, which is the honest baseline for a repository that expects to ship weights. A native " +
			"binary inside a model artifact is worth an explicit decision, particularly when it arrives as an " +
			"archive member rather than a declared dependency.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"native"},
	})

	// ruleNativeExecImports fires when a validated ELF's dynamic symbol table
	// imports a process-control primitive. It is the one statement a symbol walk
	// can make that a header check cannot: not "this is a program" but "this
	// program will bind the calls that run another one".
	ruleNativeExecImports = report.DefineRule(report.Rule{
		ID:         "SC4N-NATIVE-EXEC-IMPORTS",
		Title:      "Native executable imports process-control symbols",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "executable",
		Description: "A validated ELF imports system, popen, an exec* variant, fork, dlopen or ptrace in its " +
			"dynamic symbol table. sc4n does not disassemble the binary: these are the names the dynamic " +
			"loader will bind when it is loaded, which is the loader's own statement that the program can " +
			"spawn a shell, execute a file or open another process's memory. A C extension that merely does " +
			"arithmetic imports none of them, so the set separates a numerical library from a dropper. It is " +
			"high rather than critical for the same reason SC4N-POLYGLOT-NATIVE is: loading the model does " +
			"not run the member.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"native", "exec"},
	})

	// ruleNativeEmbeddedPayload fires on a second validated native header inside
	// a native artifact. This is the self-extracting shape: one executable whose
	// body carries another, which the outer program can drop and run.
	ruleNativeEmbeddedPayload = report.DefineRule(report.Rule{
		ID:         "SC4N-NATIVE-EMBEDDED-PAYLOAD",
		Title:      "Native artifact embeds a second validated executable",
		Severity:   report.SeverityHigh,
		Confidence: report.ConfidenceHigh,
		CWE:        []string{"CWE-506"},
		Class:      "native",
		Description: "A second complete native header was found inside a native artifact. The header was " +
			"validated with Go's own executable-header parser, so this is a program embedded in a program, " +
			"not bytes that happen to match a magic. Legitimate linkers do not append a second executable to " +
			"their output, so the shape indicates a self-extracting or dropper payload carried inside an " +
			"otherwise ordinary-looking binary. sc4n reports the offset; it does not extract or run anything.",
		Refs: []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Tags: []string{"native", "evasion"},
	})
)
