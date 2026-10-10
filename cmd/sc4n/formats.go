package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
)

// runFormats prints the capability matrix. Its purpose is that a reader can tell
// "no findings" from "not analysed": every recognised format states how deep sc4n
// goes, and the formats that are deliberately recognised but not decompressed say
// so in the table rather than only in a report finding.
func runFormats(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "sc4n formats takes no arguments")
		return exitUsage
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FORMAT\tMAGIC\tDEPTH\tCONTAINER\tNOTES")
	for _, i := range artifact.AllFormats() {
		container := "-"
		if i.Container {
			container = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.Format, i.Magic, i.Depth, container, i.Notes)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "sc4n: %v\n", err)
		return exitUsage
	}
	fmt.Fprintln(stdout, `
depth legend:
  none        recognised and reported, payload NOT parsed (a finding says why)
  shallow     header/identifier validation plus native-magic and string scanning
  structural  the format's own structures are walked and validated
  deep        structures walked and any embedded code or pickle handed to its engine

Dispatch is by content, never by extension. A disagreement between the two is
reported as SC4N-FORMAT-EXTENSION-MISMATCH (medium).`)
	return exitClean
}
