package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fr0g-66723067-io/sc4n/internal/report"
)

// ruleJSON is the machine-readable catalogue entry. Its field set is the union of
// what the SARIF descriptor builder and `docs/threat-model.md` need, so a
// documentation generator can be built from the live rule tables rather than from
// a hand-maintained list that drifts.
type ruleJSON struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	CWE         []string `json:"cwe,omitempty"`
	Class       string   `json:"class"`
	Description string   `json:"description"`
	Refs        []string `json:"refs,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

func runRules(args []string, stdout, stderr io.Writer) int {
	var format string
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&format, "format", "md", "output format: md or json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "sc4n rules takes no positional arguments")
		return exitUsage
	}
	rules := report.Rules()
	switch format {
	case "json":
		out := make([]ruleJSON, 0, len(rules))
		for _, r := range rules {
			out = append(out, ruleJSON{
				ID:          r.ID,
				Title:       r.Title,
				Severity:    r.Severity.String(),
				Confidence:  r.Confidence.String(),
				CWE:         r.CWE,
				Class:       r.Class,
				Description: r.Description,
				Refs:        r.Refs,
				Tags:        r.Tags,
			})
		}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "sc4n: %v\n", err)
			return exitUsage
		}
		return exitClean
	case "md":
	default:
		fmt.Fprintf(stderr, "sc4n: unknown -format %q (want md or json)\n", format)
		return exitUsage
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSEVERITY\tCONFIDENCE\tCLASS\tCWE\tTITLE")
	for _, r := range rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Confidence, r.Class, r.CWEList(), r.Title)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", err)
		return exitUsage
	}
	// The detail block is what `docs/threat-model.md` quotes, so it carries the
	// full rationale and references rather than a one-line summary.
	for _, r := range rules {
		fmt.Fprintf(stdout, "\n### %s — %s\n\n%s\n", r.ID, r.Title, strings.TrimSpace(r.Description))
		if len(r.Refs) > 0 {
			fmt.Fprintln(stdout, "\nReferences:")
			for _, ref := range r.Refs {
				fmt.Fprintln(stdout, "- "+ref)
			}
		}
	}
	fmt.Fprintf(stdout, "\n%d rule(s)\n", len(rules))
	return exitClean
}
