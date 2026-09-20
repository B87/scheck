package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/local"
)

func newLocalCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:     "local",
		Short:   "Collect facts from this machine (assessment not yet available)",
		Long:    "Collect read-only facts. This build requires --stop-after plan or facts; it does not assess security posture. JSON output is on stdout, diagnostics on stderr. Exit 0 means collection completed, 2 incomplete, 3 usage/policy error.",
		Example: "  scheck local --stop-after facts --format json --no-persist\n  scheck local --stop-after facts --format json --include-evidence --no-persist\n  scheck local --stop-after plan --format json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.notInPhase1(cmd); err != nil {
				return err
			}
			sess, err := opts.newSession(func(b policy.Budgets) (target.Target, error) {
				return local.New(b.CaptureLimit()), nil
			})
			if err != nil {
				return err
			}
			defer sess.close()
			return runStopAfter(cmd, sess)
		},
	}
}

// runStopAfter executes the stage selected by --stop-after for a built
// session. In phase 1 the only complete runs are plan and facts.
func runStopAfter(cmd *cobra.Command, sess *session) error {
	out, closeOutput, err := sess.opts.commandOutput(cmd.OutOrStdout())
	if err != nil {
		return err
	}
	defer closeOutput()
	switch sess.opts.StopAfter {
	case "plan":
		plan, err := sess.plan()
		if err != nil {
			return err
		}
		if sess.opts.Format == "json" {
			return writeDiscovery(out, "plan", string(sess.runner.Target.Platform()), sess.profile.String(), string(sess.elevate), plan)
		}
		printPlan(out, sess.runner.Target.Platform(), sess.elevate, plan)
		return nil
	case "facts":
		sheet, err := sess.runBaseline(cmd.Context())
		if err != nil {
			return err
		}
		env, err := sess.writeReport(out, sheet)
		if err != nil {
			return err
		}
		if env.Run.Status != "complete" {
			return incompleteErr("run incomplete: %s", strings.Join(env.Run.Warnings, "; "))
		}
		return nil
	case "context":
		return usageErr("--stop-after context is not available in this build (phase 1)")
	case "":
		fmt.Fprintln(os.Stderr, "scheck: agent mode is not available in this build; use --stop-after facts")
		return usageErr("no model in phase 1")
	default:
		return usageErr("--stop-after must be context|plan|facts")
	}
}
