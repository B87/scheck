package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/version"
)

// globalOpts holds every flag from SPEC.md §8. Flags that belong to a later
// milestone are registered so the surface is stable, and rejected at run time.
type globalOpts struct {
	Format    string
	Out       string
	Profile   string
	Elevate   string
	Sudo      bool
	Only      string
	Provider  string
	Model     string
	BaseURL   string
	LocalOnly bool
	Effort    string
	Context   []string
	IgnoreCtx bool
	StopAfter string
	AuditLog  string
	StateDir  string
	NoPersist bool
	Timeout   time.Duration
	Verbose   int

	// RecordFixtures is a hidden developer flag: every exec of the run is written
	// to DIR as a fixture manifest usable by target/fixture.
	RecordFixtures string
}

// notInPhase1 lists the flags that exist for surface stability but have no
// implementation yet. Setting any of them is a usage error.
func (o *globalOpts) notInPhase1(cmd *cobra.Command) error {
	for _, name := range []string{"only", "provider", "model", "base-url", "local-only", "effort", "context", "ignore-context"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return usageErr("--%s is not available in this build (phase 1: baseline only)", name)
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
	pf.StringVar(&opts.Out, "out", "", "write the report to FILE instead of stdout")
	pf.StringVar(&opts.Profile, "profile", "", "baseline|hardened (default baseline)")
	pf.StringVar(&opts.Elevate, "elevate", "", "elevation mechanism: none|sudo (default none)")
	pf.BoolVar(&opts.Sudo, "sudo", false, "shorthand for --elevate sudo")
	pf.StringVar(&opts.Only, "only", "", "category filter, comma-separated")
	pf.StringVar(&opts.Provider, "provider", "", "anthropic|openai-compatible|ollama")
	pf.StringVar(&opts.Model, "model", "", "model name")
	pf.StringVar(&opts.BaseURL, "base-url", "", "provider base URL")
	pf.BoolVar(&opts.LocalOnly, "local-only", false, "refuse any provider that leaves the machine")
	pf.StringVar(&opts.Effort, "effort", "", "low|medium|high|max")
	pf.StringArrayVar(&opts.Context, "context", nil, "operator context: FILE | DIR | note:TEXT | target[:PATH] (repeatable)")
	pf.BoolVar(&opts.IgnoreCtx, "ignore-context", false, "no context in the prompt, no severity adjustment")
	pf.StringVar(&opts.StopAfter, "stop-after", "", "context|plan|facts: print that stage and exit")
	pf.StringVar(&opts.AuditLog, "audit-log", "", "append a JSONL audit line per attempted check to PATH")
	pf.StringVar(&opts.StateDir, "state-dir", "", "where run artifacts are persisted")
	pf.BoolVar(&opts.NoPersist, "no-persist", false, "do not persist the run envelope")
	pf.DurationVar(&opts.Timeout, "timeout", 0, "whole-run timeout (default 5m)")
	pf.CountVarP(&opts.Verbose, "verbose", "v", "verbose output (-v, -vv)")
	pf.StringVar(&opts.RecordFixtures, "record-fixtures", "", "developer: record every exec into DIR as a fixture")
	_ = pf.MarkHidden("record-fixtures")

	root.AddCommand(
		newLocalCmd(opts),
		newSSHCmd(opts),
		newCatalogCmd(opts),
		newSudoersCmd(opts),
	)
	return root
}

// logf prints to stderr when the verbosity level is at least lvl.
func (o *globalOpts) logf(lvl int, format string, args ...any) {
	if o.Verbose >= lvl {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}
