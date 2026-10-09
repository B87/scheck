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
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/engagement/hostasset"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/state"
	"github.com/b87/scheck/internal/version"
)

// runFlags are the global flags `scheck run` reads. Every other flag is a
// usage error rather than a silent no-op.
var runFlags = []string{"format", "out", "verbose", "stop-after", "state-dir", "no-persist", "host", "write-engagement", "include-evidence"}

// hostReachFlags are accepted only with --host, which writes them into the
// asset it builds: an engagement file holds its assets' settings
// (docs/spec/engagement.md, "One command, one file").
var hostReachFlags = []string{"identity", "known-hosts", "jump", "sudo", "elevate", "profile", "timeout", "record-fixtures"}

// runFlagHomes names where a 0.0.1 flag's meaning went, for the refusal.
var runFlagHomes = map[string]string{
	"context":        "context is assets.<name>.context in an engagement file; --write-engagement FILE writes one to start from",
	"ignore-context": "an engagement's context is in its file; remove it there",
	"audit-log":      "the run directory holds audit.jsonl",
}

// engagementOptions checks an engagement file against the compiled
// catalogs.
var engagementOptions = engagement.Options{
	KnownCheck: func(id string) bool {
		return slices.ContainsFunc(check.All(), func(c check.Check) bool { return c.ID == id })
	},
	KnownFinding:   finding.Known,
	FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) },
	HostFinding: func(id string) bool {
		d, ok := finding.Lookup(id)
		return ok && d.Area == finding.AreaHosts
	},
}

// collectHost reaches a host asset, newGate builds the scope gate, and
// runClock names the run directory; tests replace all three, so no test
// reaches a host, crt.sh or a resolver.
var (
	collectHost = hostasset.Collect
	newGate     = gate.New
	runClock    = time.Now
)

type hostOpts struct {
	host, identity, knownHosts, jump, writeEngagement string
}

// newRunCmd is `scheck run`: an engagement file or --host, through every
// stage to the engagement report (docs/spec/engagement.md, "The report").
func newRunCmd(opts *globalOpts) *cobra.Command {
	var ho hostOpts
	cmd := &cobra.Command{
		Use:   "run ENGAGEMENT.yaml | run RUN_DIRECTORY | run --host LOCATOR",
		Short: "Run an engagement from its file, or on one host with --host",
		Long: "Run an engagement (docs/spec/engagement.md) through its stages: intake, scope, recon,\n" +
			"plan, check, analyze, report. The report says what was checked and what was not, the\n" +
			"findings to fix first, and why the run exits as it does; --format json prints it as\n" +
			"docs/engagement-report-schema.json. --host LOCATOR (user@address[:port], or local) builds a one-host\n" +
			"engagement in memory from the reach flags. Each run writes its stage outputs to\n" +
			"<state-dir>/engagements/<name>/<started>/, created 0700 and locked; --stop-after intake\n" +
			"validates the file and contacts nothing. scheck run RUN_DIRECTORY resumes a run: it keeps\n" +
			"what earlier sessions read completely and reads everything else again. In this build a host root is collected;\n" +
			"a domain root's DNS, mail records and front pages are read but no rule judges them yet, and a root of any\n" +
			"other kind is not collected (both collector_not_built).\n" +
			"Exit 0 no open finding at or above an asset's threshold (not a claim of full coverage),\n" +
			"1 findings, 2 incomplete (a root not read, a transport failure, a timeout), 3 usage,\n" +
			"validation, policy or canary error.",
		Example: "  scheck run engagement.yaml\n  scheck run engagement.yaml --stop-after intake --format json\n" +
			"  scheck run --host deploy@203.0.113.5 --identity ~/.ssh/deploy --sudo --profile hardened\n" +
			"  scheck run --host local\n  scheck run --host deploy@203.0.113.5 --write-engagement engagement.yaml\n" +
			"  scheck run ~/.local/state/scheck/engagements/acme/2026-10-08T09:00:00Z",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageErr("scheck run takes one engagement file or run directory")
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
	f.StringVar(&ho.jump, "jump", "", "with --host: an SSH jump host, user@address[:port]; nothing runs on it")
	f.StringVar(&ho.writeEngagement, "write-engagement", "", "with --host: write the engagement to FILE and contact nothing")
	return cmd
}

func runEngagementCmd(cmd *cobra.Command, opts *globalOpts, ho *hostOpts, args []string) error {
	if err := rejectRunFlags(cmd, ho.host != ""); err != nil {
		return err
	}
	return executeEngagement(cmd, opts, ho, args)
}

// executeEngagement runs an engagement file or a --host one through its
// stages; `scheck run` and the 0.0.1 aliases both end here, so they give the
// same report and the same command trace.
func executeEngagement(cmd *cobra.Command, opts *globalOpts, ho *hostOpts, args []string) error {
	switch {
	case opts.StopAfter == "", slices.Contains(engagement.Stages, opts.StopAfter):
	default:
		return usageErr("--stop-after must be one of %s", strings.Join(engagement.Stages, "|"))
	}
	// --write-engagement writes FILE and contacts nothing: a flag that
	// shapes a run's output would be accepted and silently ignored.
	if ho.writeEngagement != "" && (opts.Out != "" || opts.StopAfter != "" || opts.StateDir != "" || opts.NoPersist ||
		opts.IncludeEvidence || opts.Format == "json") {
		return usageErr("--write-engagement writes FILE and contacts nothing: --out, --format json, --stop-after, " +
			"--state-dir, --no-persist and --include-evidence do not apply to it")
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
	// A run directory resumes that run (docs/spec/engagement.md, "Stop and
	// resume"): locked, its engagement file read again from where it was.
	var prior *engagement.Prior
	var res *engagement.Resolved
	var raw []byte
	if path, ok := runDirArg(args); ok {
		switch {
		case ho.host != "" || ho.writeEngagement != "":
			return usageErr("%s is a run directory, which scheck run resumes: --host and --write-engagement do not apply to it", path)
		case opts.NoPersist || opts.StateDir != "":
			return usageErr("a resume writes into the run directory it names: --no-persist and --state-dir do not apply to it")
		}
		dir, err := engagement.OpenRun(path)
		if err != nil {
			return usageErr("cannot resume: %v", err)
		}
		defer dir.Close()
		if prior, err = engagement.LoadPrior(dir); err != nil {
			return usageErr("cannot resume %s: %v", dir.Path, err)
		}
		// run.json says which file a resume reads, and whoever can write
		// the directory can change it: say which one, every time, by the
		// absolute path it was read from (the report and a parse error name
		// it as typed), even when it does not load.
		file := report.Sanitize(prior.Manifest.File)
		if prior.Manifest.Host {
			file = "the engagement --host built"
		}
		if res, raw, err = prior.LoadEngagement(engagementOptions); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "resuming %s with %s\n", report.Sanitize(dir.Path), file)
			return parseErr(err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "resuming %s with %s (sha256 %s)\n", report.Sanitize(dir.Path), file, res.Source.SHA256)
	} else {
		var err error
		if res, raw, err = loadEngagement(opts, ho, args); err != nil {
			return err
		}
	}
	for _, warn := range res.Warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", report.Sanitize(warn))
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
	ro := engagement.RunOptions{Raw: raw, StopAfter: opts.StopAfter, Started: started, Session: started, Version: version.Version,
		RecordFixtures: opts.RecordFixtures, Collect: collectHost, NewGate: newGate, Log: func(f string, a ...any) { opts.logf(1, f, a...) }}
	// Refuse what cannot be reached before a run directory exists, so a
	// refused run leaves nothing behind.
	if err := engagement.Preflight(res, !opts.NoPersist); err != nil {
		return usageErr("%v", err)
	}
	switch {
	case prior != nil:
		ro.Dir, ro.Resume, ro.Started = prior.Dir(), prior, prior.Manifest.Started
		opts.logf(1, "resuming the run in %s", ro.Dir.Path)
	case !opts.NoPersist:
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
	if err := writeStage(w, opts, out, ro.Dir); err != nil {
		return err
	}
	for _, warn := range out.Warnings {
		// A warning can quote the operator's file (an acceptance's
		// subject), which validation does not restrict to safe characters.
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", report.Sanitize(warn))
	}
	// Precedence is 3, 2, 1 (docs/spec/engagement.md, "Exit codes"): an
	// incomplete run's silence is not a clean bill of health. A host that
	// refused us is exit 3 once everything else was collected and written.
	describe := func(ss []ereport.Shortfall) string {
		lines := make([]string, len(ss))
		for i, s := range ss {
			lines[i] = report.Sanitize(engagement.Describe(s))
		}
		return strings.Join(lines, "\n  ")
	}
	switch out.ExitCode() {
	case 3:
		return usageErr("refused:\n  %s", describe(out.Refused))
	case 2:
		return incompleteErr("run incomplete:\n  %s", describe(out.Incomplete))
	case 1:
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
			Jump: ho.jump, Timeout: timeout, Elevate: elevate, Profile: opts.Profile}, engagementOptions)
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
		return nil, nil, parseErr(err)
	}
	return res, raw, nil
}

// parseErr is an engagement file that did not load, as exit 3.
func parseErr(err error) error {
	if errs, ok := errors.AsType[engagement.Errors](err); ok {
		return usageErr("the engagement file is not valid (%d %s):\n%v", len(errs), plural(len(errs), "error"), errs)
	}
	return usageErr("%v", err)
}

// runDirArg is the run directory `scheck run DIR` names, when its one
// argument is a directory.
func runDirArg(args []string) (string, bool) {
	if len(args) != 1 {
		return "", false
	}
	st, err := os.Stat(args[0])
	return args[0], err == nil && st.IsDir()
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

// writeStage prints the last stage's output: the engagement report, or for
// a run stopped earlier the document as written to the run directory for
// --format json and a summary for a person otherwise. Target text in the
// summaries is control-character escaped.
func writeStage(w io.Writer, opts *globalOpts, out *engagement.Outcome, dir *engagement.RunDir) error {
	if rep, ok := out.Document.(*ereport.Report); ok {
		if opts.Format == "json" {
			return ereport.WriteJSON(w, rep, opts.IncludeEvidence)
		}
		return ereport.WriteText(w, rep, opts.textOptions(w))
	}
	if opts.Format == "json" {
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
		fmt.Fprintln(tw, "NAME\tID\tCOLLECTOR\tFIRST-PARTY EVIDENCE")
		for _, a := range doc.Assets {
			evidence := "-"
			switch a.Kind {
			case engagement.KindDomain, engagement.KindURL, engagement.KindHost:
				evidence = a.FirstParty.String()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Name, a.ID, or(a.Collector, "none in this build"), evidence)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		for i, x := range doc.Exclude {
			if i == 0 {
				fmt.Fprintln(w, "\nExcluded (exclude always wins):")
			}
			what := "never contacted; dropped from every list that returns it"
			if x.OrgUnit != "" {
				what = "organizational unit " + report.Sanitize(x.OrgUnit) + " and every unit under it: " +
					"its users are dropped from every list and never read one by one"
			}
			fmt.Fprintf(w, "  exclude[%d]  %s  %s\n", i, x.ID, what)
		}
		writeScopeDiscovery(w, doc)
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

// writeScopeDiscovery prints what the Scope stage found under each domain root
// (docs/spec/scope.md, "Discovery"). Every name came from crt.sh or DNS,
// so every one is escaped.
func writeScopeDiscovery(w io.Writer, doc *engagement.ScopeDoc) {
	if doc.Resolver != nil {
		fmt.Fprintf(w, "\nDNS resolver: %s", or(report.Sanitize(doc.Resolver.Address), "none found in /etc/resolv.conf"))
		if doc.Resolver.Rewrites {
			fmt.Fprint(w, ". It answers names that do not exist with its own address, so discovered names were not checked; run from a network whose resolver does not do this")
		}
		fmt.Fprintln(w)
	}
	for _, d := range doc.Domains {
		fmt.Fprintf(w, "\nUnder %s: %d %s; certificate transparency %s", strings.TrimPrefix(d.Root, "domain:"),
			len(d.Names), plural(len(d.Names), "name"), d.CT)
		for _, dr := range d.Dropped {
			fmt.Fprintf(w, "; %d dropped (%s)", dr.Count, dr.Rule)
		}
		if len(d.Wildcard) > 0 {
			fmt.Fprintf(w, "; wildcard DNS (%s)", report.Sanitize(strings.Join(d.Wildcard, ", ")))
		}
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAME\tSTATUS\tPOINTS AT\tREAD\tFIRST-PARTY EVIDENCE\tDETAIL")
		for _, n := range d.Names {
			read := "no"
			if n.Read {
				read = "yes"
			}
			ev := "-"
			if n.Status == engagement.NameResolves {
				ev = n.FirstParty.String()
			}
			name := n.Name
			if n.ExpiredOnly {
				name += " (expired certificates only)"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", report.Sanitize(name), n.Status, or(report.Sanitize(n.Target), "-"), read,
				report.Sanitize(ev), report.Sanitize(n.Detail))
		}
		_ = tw.Flush()
		if len(d.WildcardCerts) > 0 {
			fmt.Fprintf(w, "  Wildcard certificates for: %s\n", report.Sanitize(strings.Join(d.WildcardCerts, ", ")))
		}
	}
	if len(doc.PointsAt) > 0 {
		fmt.Fprintln(w, "\nServices your names point at (outside every root; recorded, never contacted):")
		for _, p := range doc.PointsAt {
			fmt.Fprintf(w, "  %s  <- %s\n", report.Sanitize(p.Target), report.Sanitize(strings.Join(p.Names, ", ")))
		}
	}
	if len(doc.Domains) > 0 {
		fmt.Fprintln(w, "\n"+engagement.CTGaps)
		fmt.Fprintln(w, "First-party confirmations are written by hand in this version: an assets entry with "+
			"first_party: {confirmed_by, date, target}, the target as POINTS AT shows it; where it shows a "+
			"[REDACTED:...] marker, write the name the marker stands for.")
	}
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
