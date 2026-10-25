package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/compare"
	hostreport "github.com/b87/scheck/internal/report"
)

// newDiffCmd is `scheck diff EARLIER LATER` (docs/spec/runs.md, "Comparing
// two runs"): two finished runs of one engagement, compared from their
// report.json files. It reads two files, sends nothing and runs nothing.
func newDiffCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "diff EARLIER LATER",
		Short: "Compare two runs of one engagement: fixed, still open, new, moved, not checked again",
		Long: `Compares two finished runs of the same engagement for remediation follow-up.
Each argument is a run directory or a report.json file; give the earlier run first.
It reads the two reports and nothing else: no target is contacted and nothing is
checked again.

A finding is called fixed only when the later run's rule decided on a complete read
of an asset that was collected, with the same release of scheck, the same access and
no declaration it reads changed. Anything less is "not confirmed" or "not checked
again", never fixed; a finding the later run could not look for is never fixed.

Exit codes: 0 nothing at or above the threshold is new, first reported, open again
or raised (not a clean result: findings may still be open), 1 something is, 2 the
later run did not read everything, 3 the pair cannot be compared (different
engagements, a report that was edited, a run still in progress, a schema this
build does not read).`,
		Example: "  scheck diff ~/.local/state/scheck/engagements/acme/2026-10-01T09:00:00Z ~/.local/state/scheck/engagements/acme/2026-10-22T09:00:00Z\n  scheck diff before.json after.json --format json",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.rejectUnimplemented(cmd); err != nil {
				return err
			}
			earlier, err := engagement.ReadReport(args[0])
			if err != nil {
				return usageErr("earlier run: %s", hostreport.Sanitize(err.Error()))
			}
			later, err := engagement.ReadReport(args[1])
			if err != nil {
				return usageErr("later run: %s", hostreport.Sanitize(err.Error()))
			}
			c, err := compare.Compare(
				compare.Input{Report: earlier.Report, SHA256: earlier.SHA256, Directory: earlier.Directory, RunRecordChecked: earlier.RunRecordChecked},
				compare.Input{Report: later.Report, SHA256: later.SHA256, Directory: later.Directory, RunRecordChecked: later.RunRecordChecked})
			if refusal, ok := errors.AsType[*compare.Refusal](err); ok {
				return usageErr("%s", refusal.Why)
			}
			if err != nil {
				return err
			}
			w, closeOutput, err := opts.commandOutput(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer closeOutput()
			if opts.Format == "json" {
				err = compare.WriteJSON(w, c)
			} else {
				err = compare.WriteText(w, c, opts.textOptions(w))
			}
			if err != nil {
				return err
			}
			switch c.Exit.Code {
			case exitFindings:
				return findingsErr("the later run has findings that are new, reported for the first time, open again or raised")
			case exitIncomplete:
				return incompleteErr("the later run did not read everything, so what is gone from it cannot be called fixed where it could not look")
			}
			return nil
		},
	}
}
