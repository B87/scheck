package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/report"
)

// confirmProbes is how a site in confirm mode is asked: every request the
// plan listed is shown, and only a "y" sends them. With no terminal on
// standard input it returns nil, and the engagement reports those probes as
// not run (docs/spec/scope.md, "Running probes and scans").
func confirmProbes(cmd *cobra.Command) func(context.Context, []engagement.ProbePreviewSite) []string {
	in := cmd.InOrStdin()
	if !stdinIsTerminal(in) {
		return nil
	}
	rd := bufio.NewReader(in)
	out := cmd.ErrOrStderr()
	return func(_ context.Context, sites []engagement.ProbePreviewSite) []string {
		return askProbes(rd, out, sites)
	}
}

// askProbes shows each site's requests and reads one answer per site.
func askProbes(rd *bufio.Reader, out io.Writer, sites []engagement.ProbePreviewSite) []string {
	var approved []string
	fmt.Fprintln(out, "\nProbes are single GET requests for well-known sensitive files. Nothing is sent to a site until you approve it here.")
	for _, s := range sites {
		name := report.Sanitize(s.Site)
		fmt.Fprintf(out, "\n%s  (first-party evidence: %s)\n", name, report.Sanitize(s.Evidence))
		for _, r := range s.Requests {
			fmt.Fprintf(out, "  %s %s\n", r.Method, report.Sanitize(r.URL))
		}
		fmt.Fprintf(out, "Send these %d requests to %s? [y/N] ", len(s.Requests), name)
		line, err := rd.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a == "y" || a == "yes" {
			approved = append(approved, s.Site)
		}
		if err != nil {
			break
		}
	}
	fmt.Fprintln(out)
	return approved
}

// writeProbePlan prints one site's previewed requests (--stop-after plan).
func writeProbePlan(w io.Writer, p engagement.ProbePlan) {
	fmt.Fprintf(w, "\nProbes on %s  mode %s  first-party evidence: %s\n", report.Sanitize(p.Site), p.Mode, report.Sanitize(p.Evidence))
	if p.NotRun != "" {
		fmt.Fprintln(w, "  not run: the site answered neither over https nor over http")
		return
	}
	for _, r := range p.Requests {
		fmt.Fprintf(w, "  %s %s\n", r.Method, report.Sanitize(r.URL))
	}
	fmt.Fprintf(w, "  %d requests", p.Count)
	if n := len(p.FrameworkSkipped); n > 0 {
		fmt.Fprintf(w, "; %d for frameworks not declared are not sent", n)
	}
	if p.Mode == "confirm" {
		fmt.Fprint(w, "; Check asks before sending, and with no terminal does not run them")
	}
	fmt.Fprintln(w)
}
