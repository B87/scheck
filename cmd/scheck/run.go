package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/hostasset"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/state"
	"github.com/b87/scheck/internal/version"
)

// runFlags are the global flags `scheck run` reads. Every other flag is a
// usage error rather than a silent no-op.
var runFlags = []string{"format", "out", "verbose", "stop-after", "state-dir", "no-persist", "host", "write-engagement"}

// hostReachFlags are accepted only with --host, which writes them into the
// asset it builds: an engagement file holds its assets' settings
// (docs/spec/engagement.md, "One command, one file").
var hostReachFlags = []string{"identity", "known-hosts", "jump", "sudo", "elevate", "profile", "timeout"}

// runFlagHomes names where a 0.0.1 flag's meaning went, for the refusal.
var runFlagHomes = map[string]string{
	"context":         "context is assets.<name>.context in an engagement file; --write-engagement FILE writes one to start from",
	"ignore-context":  "an engagement's context is in its file; remove it there",
	"audit-log":       "the run directory holds audit.jsonl",
	"record-fixtures": "fixtures are recorded with scheck local or scheck ssh in this build",
}

// engagementOptions checks an engagement file against the compiled
// catalogs.
var engagementOptions = engagement.Options{
	KnownCheck: func(id string) bool {
		return slices.ContainsFunc(check.All(), func(c check.Check) bool { return c.ID == id })
	},
	KnownFinding: func(id string) bool { _, ok := finding.Lookup(id); return ok },
}

// collectHost reaches a host asset, and runClock names the run directory;
// tests replace both.
var (
	collectHost = hostasset.Collect
	runClock    = time.Now
)

type hostOpts struct {
	host, identity, knownHosts, jump, writeEngagement string
}

// newRunCmd is `scheck run`: an engagement file or --host, through the
// stages up to analyze in this build (docs/ROADMAP.md, E1b); the report
// arrives in E2.
func newRunCmd(opts *globalOpts) *cobra.Command {
	var ho hostOpts
	cmd := &cobra.Command{
		Use:   "run ENGAGEMENT.yaml | run --host LOCATOR",
		Short: "Run an engagement from its file, or on one host with --host",
		Long: "Run an engagement (docs/spec/engagement.md) through its stages: intake, scope, recon,\n" +
			"plan, check, analyze. The report stage arrives in 0.0.2 E2, so findings.json is the last\n" +
			"output in this build. --host LOCATOR (user@address[:port], or local) builds a one-host\n" +
			"engagement in memory from the reach flags. Each run writes its stage outputs to\n" +
			"<state-dir>/engagements/<name>/<started>/, created 0700 and locked; --stop-after intake\n" +
			"validates the file and contacts nothing. In this build a host root is collected; a root\n" +
			"of any other kind is recorded as not collected (collector_not_built).\n" +
			"Exit 0 no open finding at or above an asset's threshold (not a claim of full coverage),\n" +
			"1 findings, 2 incomplete (a root not read, a transport failure, a timeout), 3 usage,\n" +
			"validation, policy or canary error.",
		Example: "  scheck run engagement.yaml\n  scheck run engagement.yaml --stop-after intake --format json\n" +
			"  scheck run --host deploy@203.0.113.5 --identity ~/.ssh/deploy --sudo --profile hardened\n" +
			"  scheck run --host local\n  scheck run --host deploy@203.0.113.5 --write-engagement engagement.yaml",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageErr("scheck run takes one engagement file")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEngagementCmd(cmd, opts, &ho, args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&ho.host, "host", "", "run on one host: user@address[:port] or local")
	f.StringVar(&ho.identity, "identity", "", "with --host: private key file (otherwise ssh-agent)")
	f.StringVar(&ho.knownHosts, "known-hosts", "", "with --host: known_hosts file (default ~/.ssh/known_hosts)")
	f.StringVar(&ho.jump, "jump", "", "with --host: jump host (not available in this build)")
	f.StringVar(&ho.writeEngagement, "write-engagement", "", "with --host: write the engagement to FILE and contact nothing")
	return cmd
}

func runEngagementCmd(cmd *cobra.Command, opts *globalOpts, ho *hostOpts, args []string) error {
	if err := rejectRunFlags(cmd, ho.host != ""); err != nil {
		return err
	}
	switch {
	case opts.StopAfter == "", slices.Contains(engagement.Stages, opts.StopAfter):
	default:
		return usageErr("--stop-after must be one of %s", strings.Join(engagement.Stages, "|"))
	}
	if opts.StopAfter == "report" {
		return usageErr("--stop-after report is not available in this build: the report arrives in 0.0.2 E2; findings.json (--stop-after analyze) is the last output")
	}
	// A 0.0.1 configuration file stops any run that contacts a target. The
	// two paths that contact nothing are how its keys move into a file, so
	// there it is a warning.
	contactsNothing := ho.writeEngagement != "" || opts.StopAfter == "intake"
	if err := legacyConfig(); err != nil {
		if !contactsNothing {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", err)
	}
	res, raw, err := loadEngagement(opts, ho, args)
	if err != nil {
		return err
	}
	if ho.writeEngagement != "" {
		return writeEngagementFile(cmd.ErrOrStderr(), ho.writeEngagement, raw)
	}
	w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
	if err != nil {
		return err
	}
	defer closeOutput()
	if opts.StopAfter == "intake" {
		return writeIntake(w, opts.Format, res)
	}

	started := runClock()
	ro := engagement.RunOptions{Raw: raw, StopAfter: opts.StopAfter, Started: started, Version: version.Version,
		Collect: collectHost, Log: func(f string, a ...any) { opts.logf(1, f, a...) }}
	// Refuse what cannot be reached before a run directory exists, so a
	// refused run leaves nothing behind.
	if err := engagement.Preflight(res); err != nil {
		return usageErr("%v", err)
	}
	if !opts.NoPersist {
		stateDir, err := state.Dir(opts.StateDir)
		if err != nil {
			return usageErr("%v", err)
		}
		dir, err := engagement.CreateRunDir(stateDir, res.Engagement.Name, started)
		if err != nil {
			return usageErr("%v", err)
		}
		defer dir.Close()
		ro.Dir = dir
		opts.logf(1, "run directory: %s", dir.Path)
	}
	out, err := engagement.Run(cmd.Context(), res, ro)
	if err != nil {
		if _, ok := errors.AsType[*engagement.Refusal](err); ok {
			return usageErr("%v", err)
		}
		return incompleteErr("%v", err)
	}
	if err := writeStage(w, opts.Format, out, ro.Dir); err != nil {
		return err
	}
	for _, warn := range out.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn)
	}
	// Precedence is 3, 2, 1 (docs/spec/engagement.md, "Exit codes"): an
	// incomplete run's silence is not a clean bill of health. A host that
	// refused us is exit 3 once everything else was collected and written.
	if len(out.Refused) > 0 {
		return usageErr("refused:\n  %s", strings.Join(out.Refused, "\n  "))
	}
	if len(out.Incomplete) > 0 {
		return incompleteErr("run incomplete:\n  %s", strings.Join(out.Incomplete, "\n  "))
	}
	if out.Open > 0 {
		return findingsErr("%d open %s at or above an asset's threshold", out.Open, plural(out.Open, "finding"))
	}
	return nil
}

// loadEngagement reads the engagement file, or builds the --host one.
func loadEngagement(opts *globalOpts, ho *hostOpts, args []string) (*engagement.Resolved, []byte, error) {
	switch {
	case ho.host != "" && len(args) > 0:
		return nil, nil, usageErr("scheck run takes an engagement file or --host, not both")
	case ho.host == "" && len(args) == 0:
		return nil, nil, usageErr("scheck run takes one engagement file, or --host LOCATOR")
	case ho.host == "" && ho.writeEngagement != "":
		return nil, nil, usageErr("--write-engagement writes the engagement --host builds; it needs --host")
	case ho.host != "":
		if ho.jump != "" {
			return nil, nil, usageErr("--jump is not available in this build (0.0.2 E1c)")
		}
		elevate := opts.Elevate
		if opts.Sudo {
			if elevate != "" && elevate != "sudo" {
				return nil, nil, usageErr("--sudo and --elevate %s disagree", elevate)
			}
			elevate = "sudo"
		}
		timeout := ""
		if opts.Timeout > 0 {
			timeout = opts.Timeout.String()
		}
		res, raw, err := engagement.ForHost(ho.host, engagement.HostFlags{Identity: ho.identity, KnownHosts: ho.knownHosts,
			Timeout: timeout, Elevate: elevate, Profile: opts.Profile}, engagementOptions)
		if err != nil {
			return nil, nil, usageErr("%v", err)
		}
		return res, raw, nil
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return nil, nil, usageErr("%v", err)
	}
	res, err := engagement.Parse(args[0], raw, engagementOptions)
	if err != nil {
		if errs, ok := errors.AsType[engagement.Errors](err); ok {
			return nil, nil, usageErr("the engagement file is not valid (%d %s):\n%v", len(errs), plural(len(errs), "error"), errs)
		}
		return nil, nil, usageErr("%v", err)
	}
	return res, raw, nil
}

// writeEngagementFile writes the --host engagement as a starting point. It
// never overwrites a file.
func writeEngagementFile(stderr io.Writer, path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return usageErr("--write-engagement: %v", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return usageErr("--write-engagement: %v", err)
	}
	if err := f.Close(); err != nil {
		return usageErr("--write-engagement: %v", err)
	}
	fmt.Fprintf(stderr, "wrote %s; nothing contacted. Run it with: scheck run %s\n", path, path)
	return nil
}

// rejectRunFlags fails on any flag `scheck run` does not read, and on a
// reach flag without --host.
func rejectRunFlags(cmd *cobra.Command, withHost bool) error {
	var bad error
	cmd.Flags().Visit(func(f *pflag.Flag) {
		switch {
		case bad != nil, slices.Contains(runFlags, f.Name):
		case slices.Contains(hostReachFlags, f.Name):
			if !withHost {
				bad = usageErr("--%s is accepted only with --host: an engagement file sets its assets' reach (docs/spec/engagement.md, \"One command, one file\")", f.Name)
			}
		case runFlagHomes[f.Name] != "":
			bad = usageErr("--%s is not available for scheck run: %s", f.Name, runFlagHomes[f.Name])
		default:
			bad = usageErr("--%s is not available for scheck run in this build: an engagement's settings are in its file (docs/spec/engagement.md, \"One command, one file\")", f.Name)
		}
	})
	return bad
}

// writeIntake prints the resolved engagement: YAML for a person, JSON for a
// program. Neither carries a redact_extra pattern, only their count.
func writeIntake(w io.Writer, format string, res *engagement.Resolved) error {
	if format == "json" {
		return writeJSONDoc(w, res)
	}
	fmt.Fprintf(w, "# %s: valid; %d %s, %d %s, nothing contacted\n", res.Source.Path,
		len(res.Roots), plural(len(res.Roots), "root"), len(res.Assets), plural(len(res.Assets), "asset"))
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(res); err != nil {
		return err
	}
	return enc.Close()
}

func writeJSONDoc(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeStage prints the last stage's output: the document as written to the
// run directory for --format json, a summary for a person otherwise. Until
// the report (0.0.2 E2) the summary is the only text rendering; target text
// in it is control-character escaped.
func writeStage(w io.Writer, format string, out *engagement.Outcome, dir *engagement.RunDir) error {
	if format == "json" {
		return writeJSONDoc(w, out.Document)
	}
	where := "not persisted (--no-persist)"
	if dir != nil {
		where = dir.Path
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	switch doc := out.Document.(type) {
	case *engagement.ScopeDoc:
		fmt.Fprintf(w, "# %s: scope, %d %s; %s\n# run directory: %s\n", doc.Engagement, len(doc.Assets), plural(len(doc.Assets), "asset"), doc.Discovery, where)
		fmt.Fprintln(tw, "NAME\tID\tCOLLECTOR")
		for _, a := range doc.Assets {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Name, a.ID, or(a.Collector, "none in this build"))
		}
	case *engagement.ReconDoc:
		fmt.Fprintf(w, "# %s: recon\n# run directory: %s\n", doc.Engagement, where)
		fmt.Fprintln(tw, "NAME\tID\tSTATUS\tDETAIL")
		for _, a := range doc.Assets {
			detail := a.Detail
			if a.Facts != nil {
				detail = fmt.Sprintf("%d facts; %s", len(a.Facts), detail)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Name, a.ID, statusWord(a.Status, a.Reason), report.Sanitize(strings.TrimSuffix(detail, "; ")))
		}
	case *engagement.PlanDoc:
		fmt.Fprintf(w, "# %s: plan (%s): empty until 0.0.2 E9\n# run directory: %s\n", doc.Engagement, doc.Method, where)
	case *engagement.CheckDoc:
		fmt.Fprintf(w, "# %s: check: no follow-ups until 0.0.2 E9\n# run directory: %s\n", doc.Engagement, where)
	case *engagement.FindingsDoc:
		fmt.Fprintf(w, "# %s: analyze; %d open %s at or above threshold\n# run directory: %s\n", doc.Engagement, doc.Open, plural(doc.Open, "finding"), where)
		for _, a := range doc.Assets {
			fmt.Fprintf(w, "\n%s  %s  %s", a.Name, a.ID, statusWord(a.Status, a.Reason))
			if a.Threshold != "" {
				fmt.Fprintf(w, "  threshold %s, %d open at or above", a.Threshold, a.Open)
			}
			fmt.Fprintln(w)
			for _, f := range a.Findings {
				status := ""
				if f.Status != "open" {
					status = "  (" + f.Status + ")"
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s%s\n", f.Severity, f.ID, f.Title, status)
			}
			_ = tw.Flush()
		}
	}
	return tw.Flush()
}

func statusWord(status, reason string) string {
	if reason == "" {
		return status
	}
	return status + " (" + reason + ")"
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
