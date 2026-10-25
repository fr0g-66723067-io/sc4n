package hubcampaign

// The built-in universe of the 2026-10-24 unsafe round.
//
// The Hub exposes its security verdict only per repo (`/scan`) and has no listing
// filter for it: `expand[]` carries no security field and `filter=` matches tags,
// not verdicts (huggingface/hub-docs#1407). Enumerating candidates and probing
// each one is therefore the only complete method, and these three lists are the
// round's reproducible definition of "candidate". They are data, not defaults to
// grow casually: a new term changes what the campaign claims to have covered.
var (
	// DefaultTerms are the search terms, in the round's order.
	DefaultTerms = []string{
		"eicar", "malware", "malicious", "unsafe", "backdoor", "trojan", "ransomware",
		"keylogger", "exploit", "payload", "shellcode", "reverse-shell", "reverse_shell",
		"webshell", "rootkit", "spyware", "stealer", "botnet", "c2", "cobalt",
		"pickle", "picklescan", "pickle-exploit", "malicious-pickle", "unsafe-pickle",
		"trojaned", "poisoned", "infected", "virus", "worm", "hack", "poc-exploit",
		"cvss", "rce", "lfi", "sqli", "xxe", "deserialization", "gadget",
		"prompt-injection", "jailbreak", "abliterated", "uncensored",
	}

	// DefaultTags are the Hub tags that are supposed to mark a risky repo. The
	// round found them close to unused, which is itself a result worth keeping in
	// the universe rather than dropping.
	DefaultTags = []string{"unsafe", "malware", "security"}

	// DefaultAuthors are the accounts that published flagged repos in the round.
	DefaultAuthors = []string{
		"mcpotato", "kemalik", "ppradyoth", "mss-jpmc", "bitox76", "abrar0503", "mkiani",
	}
)
