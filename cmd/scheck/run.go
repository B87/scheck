package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/finding"
)

// stages are the engagement's stage names for --stop-after
// (docs/spec/engagement.md, "Stages").
var stages = []string{"intake", "scope", "recon", "plan", "check", "analyze", "report"}

// runFlags are the global flags `scheck run` reads in this build. Every
// other flag is a usage error rather than a silent no-op: the host reach
// flags arrive with --host in 0.0.2 E1b.
var runFlags = []string{"format", "out", "verbose", "stop-after"}

// engagementOptions checks an engagement file against the compiled
// catalogs.
var engagementOptions = engagement.Options{
	KnownCheck: func(id string) bool {
		return slices.ContainsFunc(check.All(), func(c check.Check) bool { return c.ID == id })
	},
	KnownFinding: func(id string) bool { _, ok := finding.Lookup(id); return ok },
}

// newRunCmd is `scheck run`. In this build it reads an engagement file,
// validates it before any target contact and prints it resolved with
// --stop-after intake (docs/ROADMAP.md, E1a); the stages after intake arrive
// in E1b.
func newRunCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run ENGAGEMENT.yaml",
		Short: "Run an engagement (this build: validate the file with --stop-after intake)",
		Long: "Read an engagement file (docs/spec/engagement.md) and run its stages:\n" +
			"intake, scope, recon, plan, check, analyze, report.\n" +
			"This build runs intake only: --stop-after intake validates the file before any\n" +
			"target contact and prints it resolved, with canonical ids and defaults applied.\n" +
			"Every error names file:line:key and exits 3. scheck local and scheck ssh still run\n" +
			"the host collector.",
		Example: "  scheck run engagement.yaml --stop-after intake\n  scheck run engagement.yaml --stop-after intake --format json",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr("scheck run takes one engagement file")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rejectRunFlags(cmd); err != nil {
				return err
			}
			switch {
			case opts.StopAfter == "":
				return usageErr("scheck run runs only --stop-after intake in this build: the stages after intake arrive in 0.0.2 E1b; scheck local and scheck ssh still assess a host")
			case opts.StopAfter == "intake":
			case slices.Contains(stages, opts.StopAfter):
				return usageErr("--stop-after %s is not available in this build: scheck run stops after intake until 0.0.2 E1b", opts.StopAfter)
			default:
				return usageErr("--stop-after must be one of %s", strings.Join(stages, "|"))
			}
			res, err := engagement.Load(args[0], engagementOptions)
			if err != nil {
				if errs, ok := errors.AsType[engagement.Errors](err); ok {
					return usageErr("the engagement file is not valid (%d %s):\n%v", len(errs), plural(len(errs), "error"), errs)
				}
				return usageErr("%v", err)
			}
			w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeOutput()
			return writeIntake(w, opts.Format, res)
		},
	}
	return cmd
}

// rejectRunFlags fails on any flag `scheck run` does not read in this build.
func rejectRunFlags(cmd *cobra.Command) error {
	var bad error
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if bad == nil && !slices.Contains(runFlags, f.Name) {
			bad = usageErr("--%s is not available for scheck run in this build: an engagement's settings are in its file (docs/spec/engagement.md, \"One command, one file\")", f.Name)
		}
	})
	return bad
}

// writeIntake prints the resolved engagement: YAML for a person, JSON for a
// program. Neither carries a redact_extra pattern, only their count.
func writeIntake(w io.Writer, format string, res *engagement.Resolved) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
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
