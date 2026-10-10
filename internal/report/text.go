package report

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// TextOptions controls the human renderer.
type TextOptions struct {
	// Color enables ANSI severity colouring. The CLI sets it only when stdout is
	// a terminal, so a piped log never contains escape sequences.
	Color bool
	// Quiet prints only the summary line and the failing rules, not every
	// finding. It exists for pre-commit hooks that only care about the exit code.
	Quiet bool
	// EvidenceWidth truncates the evidence column. Zero means 120.
	EvidenceWidth int
}

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31;1m"
	ansiYellow = "\x1b[33;1m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
)

func severityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return ansiRed
	case SeverityHigh:
		return ansiRed
	case SeverityMedium:
		return ansiYellow
	case SeverityLow:
		return ansiCyan
	default:
		return ansiDim
	}
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer, o TextOptions) error {
	width := o.EvidenceWidth
	if width <= 0 {
		width = 120
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	if !o.Quiet {
		if _, err := io.WriteString(w, "ARTIFACT\tFORMAT\tSIZE\tFINDINGS\n"); err != nil {
			return err
		}
		// A finding inside a container is stamped "outer:member" (see Sink.Named),
		// so an exact match would show a container row with no findings while its
		// members carry them. Count both the row itself and anything nested in it.
		counts := map[string]int{}
		for _, f := range r.Findings {
			counts[f.Artifact]++
		}
		for _, a := range r.Artifacts {
			n := counts[a.Path]
			for k, v := range counts {
				if len(k) > len(a.Path) && strings.HasPrefix(k, a.Path) && k[len(a.Path)] == ':' {
					n += v
				}
			}
			line := []string{a.Path, a.Format, humanBytes(a.Size), strconv.Itoa(n)}
			if a.Error != "" {
				line[1] = "unreadable"
				line[3] = a.Error
			}
			if _, err := io.WriteString(tw, strings.Join(line, "\t")+"\n"); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}

		if len(r.Findings) > 0 {
			if _, err := io.WriteString(w, "\nSEVERITY\tCONFIDENCE\tRULE\tLOCATION\tEVIDENCE\n"); err != nil {
				return err
			}
			for _, f := range r.Findings {
				sev := f.Severity.String()
				if o.Color {
					sev = severityColor(f.Severity) + strings.ToUpper(sev) + ansiReset
				} else {
					sev = strings.ToUpper(sev)
				}
				loc := f.Artifact
				if f.Line != nil {
					loc += ":" + strconv.Itoa(*f.Line)
					if f.Col != nil {
						loc += ":" + strconv.Itoa(*f.Col)
					}
				} else if f.Offset > 0 {
					loc += "+0x" + strconv.FormatInt(f.Offset, 16)
				}
				ev := oneLine(f.Evidence, width)
				if _, err := io.WriteString(tw, strings.Join([]string{sev, f.Confidence.String(), f.RuleID, loc, ev}, "\t")+"\n"); err != nil {
					return err
				}
			}
			if err := tw.Flush(); err != nil {
				return err
			}
		}
	} else {
		ruleCounts := map[string]int{}
		for _, f := range r.Findings {
			ruleCounts[f.RuleID]++
		}
		ids := make([]string, 0, len(ruleCounts))
		for id := range ruleCounts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if _, err := io.WriteString(w, id+"\t"+strconv.Itoa(ruleCounts[id])+"\n"); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if _, err := io.WriteString(w, "\n"+r.SummaryLine()+"\n"); err != nil {
		return err
	}
	return nil
}

// SummaryLine is the single-line verdict, also used by -quiet and by the tests
// that assert the suppressed count.
func (r *Report) SummaryLine() string {
	counts := [5]int{}
	max := SeverityInfo
	for _, f := range r.Findings {
		if int(f.Severity) < len(counts) {
			counts[f.Severity]++
		}
		if f.Severity > max {
			max = f.Severity
		}
	}
	var b strings.Builder
	b.WriteString("sc4n: ")
	b.WriteString(strconv.Itoa(len(r.Artifacts)))
	b.WriteString(" artifact(s), ")
	b.WriteString(strconv.Itoa(len(r.Findings)))
	b.WriteString(" finding(s)")
	if len(r.Findings) > 0 {
		b.WriteString(" [")
		parts := make([]string, 0, 5)
		for i := len(counts) - 1; i >= 0; i-- {
			if counts[i] > 0 {
				parts = append(parts, strconv.Itoa(counts[i])+" "+Severity(i).String())
			}
		}
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString("], max severity ")
		b.WriteString(max.String())
	}
	if r.Suppressed > 0 {
		b.WriteString("; suppressed: ")
		b.WriteString(strconv.Itoa(r.Suppressed))
	}
	if r.Dropped > 0 {
		b.WriteString("; dropped: ")
		b.WriteString(strconv.Itoa(r.Dropped))
		b.WriteString(" (raise -max-findings)")
	}
	unreadable := 0
	for _, a := range r.Artifacts {
		if a.Error != "" {
			unreadable++
		}
	}
	if unreadable > 0 {
		b.WriteString("; unreadable paths: ")
		b.WriteString(strconv.Itoa(unreadable))
	}
	return b.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	v := float64(n)
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + " " + units[i]
}

// oneLine collapses whitespace and truncates, so one crafted string cannot
// reflow a terminal or a log.
func oneLine(s string, width int) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return '·'
		}
		return r
	}, s)
	if len(s) > width {
		s = s[:width] + "…"
	}
	return s
}
