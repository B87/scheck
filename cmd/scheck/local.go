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
		Use:   "local",
		Short: "Audit this machine",
		Args:  cobra.NoArgs,
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
	out, err := sess.opts.output()
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	switch sess.opts.StopAfter {
	case "plan":
		plan, err := sess.plan()
		if err != nil {
			return err
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
