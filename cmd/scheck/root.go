package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/llm/openai"
	"github.com/b87/scheck/internal/version"
)

// globalOpts holds every flag from docs/SPEC.md §8. Flags that belong to a later
// milestone, or to a stage this build does not run, are registered so the
// surface is stable, and rejected at run time.
type globalOpts struct {
	IncludeEvidence bool
	Format          string
	Out             string
	Profile         string
	Elevate         string
	Sudo            bool
	Only            string
	Provider        string
	Model           string
	BaseURL         string
	LocalOnly       bool
	Effort          string
	Transcript      string
	MaxContext      int
	Context         []string
	IgnoreCtx       bool
	StopAfter       string
	AuditLog        string
	StateDir        string
	NoPersist       bool
	Timeout         time.Duration
	Verbose         int

	// RecordFixtures is a hidden developer flag: every exec of the run is written
	// to DIR as a fixture manifest usable by target/fixture.
	RecordFixtures string
}

// unavailableFlags lists the flags that exist for surface stability but
// have no implementation in this build (docs/SPEC.md §8). Setting any of
// them is a usage error, never a silent no-op.
var unavailableFlags = []string{"only", "local-only"}

// modelFlags select and configure an inference provider. The model-assessed
// pass did not earn its place in 0.0.1 (docs/SPEC.md §2.1, recorded in
// docs/eval/phase2-results.md), so `local` and `ssh` assess with the posture
// rules alone and reject these flags rather than accepting them and
// quietly ignoring them. They still configure `scheck providers` and the
// evaluation harness, which is the one remaining caller of phase 2.
var modelFlags = []string{"provider", "model", "base-url", "effort", "transcript", "max-context"}

// rejectUnimplemented fails a run that asked for something this build does
// not do, rather than doing something else instead.
func (o *globalOpts) rejectUnimplemented(cmd *cobra.Command) error {
	changed := func(name string) bool {
		f := cmd.Flags().Lookup(name)
		return f != nil && f.Changed
	}
	for _, name := range unavailableFlags {
		if changed(name) {
			return usageErr("--%s is not available in this build", name)
		}
	}
	for _, name := range modelFlags {
		if changed(name) {
			return usageErr("--%s selects a model, and no model assesses a host in this build: %s reports what the posture rules read from the facts (docs/eval/phase2-results.md). `scheck providers` and the evaluation harness still take it", name, cmd.Name())
		}
	}
	return nil
}

func newRootCmd() *cobra.Command {
	opts := &globalOpts{}
	root := &cobra.Command{
		Use:           "scheck",
		Short:         "Read-only security posture check of a macOS or Linux host",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&opts.Format, "format", "text", "report format: text|json|sarif")
	pf.BoolVar(&opts.IncludeEvidence, "include-evidence", false, "include redacted diagnostics in JSON facts (not persisted)")
	pf.StringVar(&opts.Out, "out", "", "write the report to FILE instead of stdout")
	pf.StringVar(&opts.Profile, "profile", "", "baseline|hardened (default baseline)")
	pf.StringVar(&opts.Elevate, "elevate", "", "elevation mechanism: none|sudo (default none)")
	pf.BoolVar(&opts.Sudo, "sudo", false, "shorthand for --elevate sudo")
	pf.StringVar(&opts.Only, "only", "", "category filter, comma-separated")
	pf.StringVar(&opts.Provider, "provider", "", "openai-compatible|mock (anthropic, ollama: post-v1)")
	pf.StringVar(&opts.Model, "model", "", "model name (default "+openai.DefaultModel+" on OpenAI's endpoint)")
	pf.StringVar(&opts.BaseURL, "base-url", "", "provider base URL")
	pf.BoolVar(&opts.LocalOnly, "local-only", false, "refuse any provider that leaves the machine")
	pf.StringVar(&opts.Effort, "effort", "", "low|medium|high|max")
	pf.StringVar(&opts.Transcript, "transcript", "", "mock provider: transcript file to replay")
	pf.IntVar(&opts.MaxContext, "max-context", 0, "declare the model's context window in tokens when the adapter cannot know it")
	pf.StringArrayVar(&opts.Context, "context", nil, "operator context: FILE | DIR | note:TEXT | target[:PATH] (repeatable)")
	pf.BoolVar(&opts.IgnoreCtx, "ignore-context", false, "read no operator context: no severity adjustment")
	pf.StringVar(&opts.StopAfter, "stop-after", "", "context|plan|facts: print that stage and exit")
	pf.StringVar(&opts.AuditLog, "audit-log", "", "append a JSONL audit line per attempted check to PATH")
	pf.StringVar(&opts.StateDir, "state-dir", "", "where run artifacts are persisted")
	pf.BoolVar(&opts.NoPersist, "no-persist", false, "do not persist the run envelope")
	pf.DurationVar(&opts.Timeout, "timeout", 0, "whole-run timeout (default 5m)")
	pf.CountVarP(&opts.Verbose, "verbose", "v", "verbose output (-v, -vv)")
	pf.StringVar(&opts.RecordFixtures, "record-fixtures", "", "developer: record every exec into DIR as a fixture")
	_ = pf.MarkHidden("record-fixtures")

	for _, name := range unavailableFlags {
		pf.Lookup(name).Usage += " (not available in this build)"
	}
	for _, name := range modelFlags {
		pf.Lookup(name).Usage += " (providers and the evaluation harness only in this build)"
	}
	pf.Lookup("format").Usage = "output format: text|json (sarif not available in this build)"
	pf.Lookup("stop-after").Usage = "context|plan|facts: print that stage and exit"
	root.Long = "Read-only host evidence collection, assessed by the compiled-in posture rules.\n" +
		"No model assesses a host in this build, so no API key is needed and nothing a check\n" +
		"observed leaves the machine (docs/SPEC.md §2.1).\n" +
		"Exit codes: 0 no finding at or above the profile threshold (not a claim of full\n" +
		"coverage — read the assessments and skipped checks), 1 findings, 2 incomplete run,\n" +
		"3 usage/policy error. JSON goes to stdout; diagnostics to stderr."
	root.Example = "  scheck local --format json --no-persist\n  scheck catalog --format json\n  scheck explain sshd.config --format json"
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if opts.Format != "text" && opts.Format != "json" {
			return usageErr("--format must be text|json; sarif is not available in this build")
		}
		if cmd.Name() == "sudoers" && opts.Format != "text" {
			return usageErr("sudoers emits a text fragment; --format json is not supported")
		}
		// The default run and --stop-after facts collect the same facts, so
		// both may carry the optional diagnostics; plan and context have none.
		if opts.IncludeEvidence && (opts.Format != "json" || (opts.StopAfter != "" && opts.StopAfter != "facts") || (cmd.Name() != "local" && cmd.Name() != "ssh")) {
			return usageErr("--include-evidence requires local or ssh with --format json, and no --stop-after other than facts")
		}
		return nil
	}
	root.AddCommand(
		newLocalCmd(opts),
		newSSHCmd(opts),
		newCatalogCmd(opts),
		newExplainCmd(opts),
		newSudoersCmd(opts),
		newProvidersCmd(opts),
		newConfigCmd(opts),
		newEvalCmd(opts),
	)
	return root
}

// logf prints to stderr when the verbosity level is at least lvl.
func (o *globalOpts) logf(lvl int, format string, args ...any) {
	if o.Verbose >= lvl {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}
