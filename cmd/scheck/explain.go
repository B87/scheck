package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/runner"
)

func newExplainCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "explain CHECK-ID",
		Short: "Show exactly what a check runs, on which platform, and how it is parsed",
		Long: "explain prints one catalog entry verbatim: its description, the literal argv " +
			"with its typed placeholders, its parameters, whether it needs elevation, how " +
			"its output is parsed and which posture rules read the fact. A check id that is " +
			"defined per platform prints one section per platform.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			entries := explainEntries(id)
			if len(entries) == 0 {
				return usageErr("unknown check id %q: `scheck catalog --platform all` lists every id", id)
			}
			w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeOutput()
			if opts.Format == "json" {
				return writeDiscovery(w, "explain", "all", "", "", entries)
			}
			return writeExplain(w, id, entries, opts.textOptions(w))
		},
	}
}

// explainEntries returns every catalog entry registered under id, sorted so a
// platform-specific pair always prints in the same order.
func explainEntries(id string) []check.Check {
	var out []check.Check
	for _, c := range check.All() {
		if c.ID == id {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Platform < out[j].Platform })
	return out
}

func writeExplain(w io.Writer, id string, entries []check.Check, opt report.Options) error {
	var buf strings.Builder
	destination := w
	w = &buf
	fmt.Fprintf(w, "%s — %s\n", id, report.DomainLabel(entries[0].Domain))
	if len(entries) > 1 {
		plats := make([]string, 0, len(entries))
		for _, c := range entries {
			plats = append(plats, string(c.Platform))
		}
		fmt.Fprintf(w, "%d platform-specific definitions: %s. scheck runs the one matching the target.\n",
			len(entries), strings.Join(plats, ", "))
	}
	for _, c := range entries {
		fmt.Fprintln(w)
		if len(entries) > 1 {
			fmt.Fprintf(w, "on %s\n", c.Platform)
		}
		writeExplainEntry(w, c, opt)
	}
	_, err := io.WriteString(destination, buf.String())
	return err
}

func writeExplainEntry(w io.Writer, c check.Check, opt report.Options) {
	const labelWidth = 11
	indent := strings.Repeat(" ", labelWidth+3)
	field := func(name, value string) {
		avail := max(opt.Width-len(indent), 20)
		for i, l := range report.Wrap(value, avail) {
			if i == 0 {
				fmt.Fprintf(w, "  %-*s %s\n", labelWidth, name, l)
				continue
			}
			fmt.Fprintln(w, indent+l)
		}
	}
	if c.Description != "" {
		field("purpose", c.Description)
	}
	field("runs", argvString(c.Argv))
	field("platform", string(c.Platform))
	field("domain", fmt.Sprintf("%s (%s)", c.Domain, report.DomainLabel(c.Domain)))
	field("phase", explainPhase(c))
	field("elevation", explainElevation(c))
	field("parser", explainParser(c.Parser))
	// Which conclusions depend on this check, so an operator who sees it
	// skipped knows what went unassessed (docs/SPEC.md §7.5, §8).
	if rules := rulesFor(c); len(rules) > 0 {
		verb, them := "rules read", "them"
		if len(rules) == 1 {
			verb, them = "rule reads", "it"
		}
		field("rules", fmt.Sprintf("%d posture %s this fact; a skipped check leaves %s not assessed, never passed:",
			len(rules), verb, them))
		for _, r := range rules {
			def, _ := finding.Lookup(r.Finding)
			field("", fmt.Sprintf("%s (%s) when %s", r.Finding, def.BaseSeverity, r.When))
		}
	}
	field("exit codes", explainExitOK(c))
	if c.PathUse != check.PathNone {
		field("path use", explainPathUse(c.PathUse))
	}
	if c.Extract != "" {
		field("extract", "keeps only the capture of /"+c.Extract+"/ from the redacted output")
	}
	if c.Budget.Soft > 0 || c.Budget.Hard > 0 || c.Budget.Output > 0 {
		field("budget", explainBudget(c.Budget))
	}
	if c.Canary {
		field("canary", "the one entry whose literal contains shell metacharacters; it verifies "+
			"remote quoting before any other command runs (docs/SPEC.md §4.3)")
	}
	if len(c.Params) == 0 {
		field("params", "none — the argv above is the whole command")
		return
	}
	noun := "parameters"
	if len(c.Params) == 1 {
		noun = "parameter"
	}
	field("params", fmt.Sprintf("%d %s — each {name} token is bound to a typed value, never concatenated into a string",
		len(c.Params), noun))
	for _, p := range c.Params {
		field("  {"+p.Name+"}", explainParam(p))
	}
}

// rulesFor is the posture rules that read this catalog entry on its own
// platform.
func rulesFor(c check.Check) []finding.Rule {
	var out []finding.Rule
	for _, r := range finding.RulesFor(c.ID) {
		if r.Platform == check.Any || c.Platform == check.Any || r.Platform == c.Platform {
			out = append(out, r)
		}
	}
	return out
}

func explainPhase(c check.Check) string {
	if c.Baseline {
		return "baseline — runs in every phase 1 run on this platform"
	}
	return fmt.Sprintf("on-demand — offered to the model at profile %s and above", c.MinProfile)
}

func explainElevation(c check.Check) string {
	if !c.Elevated {
		return "not required"
	}
	return "required — prefixed with `" + strings.Join(runner.SudoPrefix, " ") +
		"` under --sudo, otherwise skipped as `requires elevated read`"
}

func explainParser(p check.ParserKind) string {
	switch p {
	case check.ParseRaw:
		return "raw — the output is kept as one string"
	case check.ParseLines:
		return "lines — non-empty lines, comments and marker lines dropped"
	case check.ParseKV:
		return "kv — key/value pairs, keys lower-cased"
	case check.ParseJSON:
		return "json — decoded as JSON"
	default:
		if check.IsTyped(p) {
			return string(p) + " — typed records with named fields, which a posture rule reads by name"
		}
		return string(p)
	}
}

func explainExitOK(c check.Check) string {
	if c.ExitOK == nil {
		return "0 only"
	}
	if c.ExitAllowed(-12345) {
		return "any — the exit code is itself the answer"
	}
	codes := make([]string, 0, len(c.ExitOK))
	for _, e := range c.ExitOK {
		codes = append(codes, fmt.Sprint(e))
	}
	return strings.Join(codes, ", ") + " count as a successful read"
}

func explainPathUse(u check.PathUse) string {
	switch u {
	case check.PathContent:
		return "content — reads the file's bytes; a sensitive path is answered with fs.stat instead"
	case check.PathMetadata:
		return "metadata — reads only the path's metadata, never its contents"
	default:
		return string(u)
	}
}

func explainBudget(b check.Budget) string {
	var parts []string
	if b.Soft > 0 {
		parts = append(parts, "soft "+b.Soft.String())
	}
	if b.Hard > 0 {
		parts = append(parts, "hard "+b.Hard.String())
	}
	if b.Output > 0 {
		parts = append(parts, fmt.Sprintf("output %d bytes", b.Output))
	}
	return strings.Join(parts, ", ") + " (clamped by the policy budgets, never widened)"
}

func explainParam(p check.Param) string {
	switch p.Kind {
	case check.KindPath:
		return "path — symlinks resolved, then checked against the path policy"
	case check.KindEnum:
		return "enum — one of: " + strings.Join(p.Enum, ", ")
	case check.KindInt:
		return fmt.Sprintf("int — %d..%d", p.Min, p.Max)
	case check.KindIdent:
		return "ident — a bare identifier, strict charset"
	default:
		return string(p.Kind)
	}
}
