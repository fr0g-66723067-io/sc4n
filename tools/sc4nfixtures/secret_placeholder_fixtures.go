package main

// secretPlaceholderFixtures writes the two sides of the placeholder filter that
// keeps SC4N-STRING-SECRET-VALUE about secret material.
//
//   - secret_assignments.md is the positive side: two assignments whose values
//     could be credentials (a hex client secret, a password that is not a word the
//     document uses in place of one).
//   - secret_placeholders.md is the negative side, and it is the shape the
//     Hugging Face corpus actually contains: a local-server example naming
//     api_key="EMPTY", api_key="none", api_key="not-needed", api_key='your-api-key'
//     and password=password. Widening the assignment shapes to api_key/password/
//     secret turned 15 of those into high findings across the corpus before this
//     filter existed.
func init() {
	register(contributor{
		name:     "secret-placeholder",
		fixtures: secretPlaceholderFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"secret_assignments.md": {
					Expect: []string{"SC4N-STRING-SECRET-VALUE"},
					Notes: "Two assignment-shaped credentials with plausible values. The finding " +
						"redacts the value and names the shape it matched.",
				},
				"secret_placeholders.md": {
					Forbid: []string{"SC4N-STRING-SECRET-VALUE"},
					Notes: "The placeholder vocabulary a README uses instead of a credential: EMPTY, " +
						"none, not-needed, your-api-key, a shell expansion, a bracketed stand-in and " +
						"`password=password`. None of them is secret material, so the high finding " +
						"they used to produce was a false positive on documentation.",
				},
			}, map[string]expectation{}
		},
	})
}

func secretPlaceholderFixtures(f *fixtureSet) {
	f.addText("secret_assignments.md",
		"# Configuration\n\n"+
			"client_secret=Hunter2\n"+
			"password=hunter2\n")

	f.addText("secret_placeholders.md",
		"# Local server example\n\n"+
			"```python\n"+
			"client = OpenAI(base_url=\"http://localhost:8000/v1\", api_key=\"EMPTY\")\n"+
			"```\n\n"+
			"api_key=\"none\"  # any non-empty string works for a local server\n"+
			"api_key=\"not-needed\"\n"+
			"api_key='your-api-key'\n"+
			"api_key=<your-key>\n"+
			"token=${MY_TOKEN}\n"+
			"password=password\n")
}
