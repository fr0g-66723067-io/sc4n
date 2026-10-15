package main

// claimFixtures writes the fixtures for the two dispatch defects fixed in the
// silent-miss round: an artifact whose content was never claimed, and a native
// magic that suppressed the format the file actually is.
//
//   - anytext_nul.json is a valid config.json document with one NUL byte appended.
//     The NUL disqualifies the text sniffer, so before the fix the artifact was
//     dispatched "unknown", which has no parser and no indicator pass: the finding
//     list was empty. The contract is now SC4N-CONTENT-NOT-UTF8 plus whatever the
//     byte-safe indicators find, and never an empty result.
//   - anytemplate_mz_prefix.jinja is a chat template with the two bytes "MZ" in
//     front of it. The magic sniffer claimed FormatNative from those two bytes, so
//     the Jinja analyser never ran and the template's __class__ escape produced no
//     finding; the file is now dispatched as the template it is, and the
//     unvalidated magic is reported at info instead.
//   - native_fat_magic_only.bin is a bare FAT_MAGIC followed by zeros: the
//     universal Mach-O magic the magic walk did not recognise, which made the file
//     produce no finding at all (a thin Mach-O from the same bytes produced one).
func init() {
	register(contributor{
		name:     "claim",
		fixtures: claimFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"anytext_nul.json": {
					Expect: []string{"SC4N-CONTENT-NOT-UTF8"},
					Notes: "A JSON document with a NUL appended. The bytes are a text document with " +
						"binary after it, which is how a padded or partially rewritten artifact looks; " +
						"the finding records that the text-only layers (cards, tokenizer, Jinja) did " +
						"not run, and the byte-safe indicators still did. Before this round the file " +
						"was dispatched unknown and reported NOTHING.",
				},
				"anytemplate_mz_prefix.jinja": {
					Expect: []string{"SC4N-JINJA-PY-OBJECT", "SC4N-POLYGLOT-MAGIC-ONLY"},
					Notes: "A Jinja template with \"MZ\" in front of it. The magic sniffer claimed the " +
						"bare PE magic and a native parser ran on a template, so the sandbox-escape " +
						"rule never fired on a file that is still a template to every reader that " +
						"looks past the first two bytes. The magic is still reported, at info.",
				},
				"native_fat_magic_only.bin": {
					Expect: []string{"SC4N-POLYGLOT-MAGIC-ONLY"},
					Notes: "A bare universal (fat) Mach-O magic. The dispatcher recognised the magic " +
						"but the magic walk did not, so the file produced no finding at all — not even " +
						"the informational one a thin Mach-O gets from the same bytes. FAT_MAGIC is " +
						"also the Java class-file magic, so the finding is informational, never " +
						"'validated executable'.",
				},
			}, map[string]expectation{}
		},
	})
}

func claimFixtures(f *fixtureSet) {
	f.addText("anytext_nul.json",
		"{\n"+
			"  \"architectures\": [\"LlamaForCausalLM\"],\n"+
			"  \"model_type\": \"llama\",\n"+
			"  \"auto_map\": {\"AutoModelForCausalLM\": \"modeling_x.CustomModel\"}\n"+
			"}\n\x00")

	f.addText("anytemplate_mz_prefix.jinja",
		"MZ{% for m in messages %}{{ m.__class__.__mro__ }}{% endfor %}\n")

	f.add("native_fat_magic_only.bin",
		append([]byte("\xca\xfe\xba\xbe"), make([]byte, 64)...))
}
