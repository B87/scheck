package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/local"
)

func newLocalCmd(opts *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "local",
		Short: "Audit this machine with the posture rules (no model)",
		Long: "Collect read-only facts and assess them with the compiled-in posture rules. This build " +
			"requires --stop-after plan or facts; the agentic pass is not available. JSON output is on " +
			"stdout, diagnostics on stderr. Exit 0 no finding at or above the profile threshold, " +
			"1 findings, 2 incomplete, 3 usage/policy error.",
		Example: "  scheck local --stop-after facts --format json --no-persist\n  scheck local --stop-after facts --format json --include-evidence --no-persist\n  scheck local --stop-after plan --format json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.notInPhase1(cmd); err != nil {
				return err
			}
			sess, err := opts.newSession(cmd, func(b policy.Budgets) (target.Target, error) {
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

// reportAndExit renders the report and turns the run into an exit code. One
// meaning per code, and the more serious answer wins: 2 (the run could not
// finish) outranks 1 (it finished and found something), because an
// incomplete run's silence is not a clean bill of health (docs/SPEC.md §8).
func reportAndExit(sess *session, out io.Writer, sheet *baseline.FactSheet) error {
	env, err := sess.writeReport(out, sheet)
	if err != nil {
		return err
	}
	if env.Run.Status != "complete" {
		return incompleteErr("run incomplete: %s", strings.Join(env.Run.Warnings, "; "))
	}
	if n := env.OpenFindings(sess.profile); n > 0 {
		return findingsErr("%d open %s at or above the %s threshold (%s)",
			n, plural(n, "finding"), sess.profile, finding.Threshold(sess.profile))
	}
	return nil
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
		if err := sess.loadContext(cmd.Context()); err != nil {
			return err
		}
		sheet, err := sess.runBaseline(cmd.Context())
		if err != nil {
			return err
		}
		return reportAndExit(sess, out, sheet)
	case "context":
		if err := sess.loadContext(cmd.Context()); err != nil {
			return err
		}
		return writeContext(out, sess.context, sess.opts.Format)
	case "":
		fmt.Fprintln(os.Stderr, "scheck: agent mode is not available in this build; use --stop-after facts")
		return usageErr("no model in phase 1")
	default:
		return usageErr("--stop-after must be context|plan|facts")
	}
}
