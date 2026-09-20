package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all" // the complete catalog
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target"
)

// session is everything a run needs, built once from config + flags.
type session struct {
	opts     *globalOpts
	cfg      *config.Config
	profile  check.Profile
	elevate  runner.Elevation
	budgets  policy.Budgets
	audit    *policy.Audit
	redactor *policy.Redactor
	paths    *policy.PathPolicy
	runner   *runner.Runner
	started  time.Time
}

// newSession loads config, applies flags (last wins), and builds the policy
// objects. The target is constructed by the caller through mk because it
// needs the capture limit from the budgets.
func (o *globalOpts) newSession(mk func(policy.Budgets) (target.Target, error)) (*session, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, usageErr("%v", err)
	}
	if o.Profile != "" {
		cfg.Profile = o.Profile
	}
	if o.Sudo {
		cfg.Elevate = "sudo"
	}
	if o.Elevate != "" {
		cfg.Elevate = o.Elevate
	}
	if o.StateDir != "" {
		cfg.StateDir = o.StateDir
	}
	if err := cfg.Validate(); err != nil {
		return nil, usageErr("%v", err)
	}
	for _, src := range cfg.Sources {
		o.logf(1, "config: loaded %s", src)
	}
	if cfg.Provider != "" || cfg.Model != "" || !cfg.Context.IsZero() {
		o.logf(1, "config: provider/model/context are ignored in this build (phase 1)")
	}

	s := &session{opts: o, cfg: cfg, started: time.Now()}
	s.profile, _ = check.ParseProfile(cfg.Profile)
	s.elevate = runner.ElevateNone
	if cfg.Elevate == "sudo" {
		s.elevate = runner.ElevateSudo
	}
	s.budgets = policy.DefaultBudgets()
	if o.Timeout > 0 {
		s.budgets.RunTimeout = o.Timeout
	}
	if err := s.budgets.Validate(); err != nil {
		return nil, usageErr("%v", err)
	}
	if s.redactor, err = policy.NewRedactor(cfg.RedactExtra); err != nil {
		return nil, usageErr("%v", err)
	}
	s.paths = policy.NewPathPolicy(cfg.DenyPaths)
	if o.AuditLog != "" {
		if s.audit, err = policy.OpenAudit(o.AuditLog); err != nil {
			return nil, usageErr("%v", err)
		}
	}
	t, err := mk(s.budgets)
	if err != nil {
		return nil, err
	}
	s.runner = &runner.Runner{Target: t, Paths: s.paths, Redactor: s.redactor, Budgets: s.budgets,
		Audit: s.audit, Elevate: s.elevate, Log: func(f string, a ...any) { o.logf(1, f, a...) }}
	return s, nil
}

func (s *session) close() {
	if err := s.audit.Close(); err != nil {
		s.opts.logf(0, "audit log: %v", err)
	}
}

// plan returns the phase 1 check list for the target's platform.
func (s *session) plan() ([]check.Check, error) {
	p := s.runner.Target.Platform()
	if p == target.Unknown {
		return nil, incompleteErr("unsupported platform")
	}
	return baseline.Plan(p, s.cfg.DisableChecks), nil
}

// runBaseline detects root, then runs the plan under the run timeout.
func (s *session) runBaseline(ctx context.Context) (*baseline.FactSheet, error) {
	plan, err := s.plan()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.budgets.RunTimeout)
	defer cancel()
	if s.elevate == runner.ElevateNone && baseline.DetectRoot(ctx, s.runner) {
		s.runner.Elevate = runner.ElevateRoot
		s.elevate = runner.ElevateRoot
		s.opts.logf(1, "session runs as root; elevated checks need no prefix")
	}
	sheet := baseline.Run(ctx, s.runner, plan, func(r runner.Result) {
		s.opts.logf(1, "%-28s %-12s %6dms %s", r.CheckID, r.Status, r.Duration.Milliseconds(), r.Reason)
	})
	return sheet, nil
}

func printPlan(w io.Writer, platform check.Platform, elevate runner.Elevation, plan []check.Check) {
	fmt.Fprintf(w, "phase 1 plan: %d checks on %s (elevation: %s)\n", len(plan), platform, elevate)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tDOMAIN\tELEVATED\tARGV")
	for _, c := range plan {
		el := ""
		if c.Elevated {
			el = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Domain, el, argvString(c.Argv))
	}
	_ = tw.Flush()
}

func argvString(argv []string) string {
	out := ""
	for i, a := range argv {
		if i > 0 {
			out += " "
		}
		if a == "" {
			a = `""`
		}
		out += a
	}
	return out
}

// output opens --out or returns stdout.
func (o *globalOpts) output() (io.WriteCloser, error) {
	if o.Out == "" {
		return nopCloser{os.Stdout}, nil
	}
	f, err := os.OpenFile(o.Out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, usageErr("--out: %v", err)
	}
	return f, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// writeFactsJSON is the provisional --stop-after facts output until the
// full envelope lands (M1.4); it already uses the envelope's `facts` shape.
func writeFactsJSON(w io.Writer, sheet *baseline.FactSheet) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"facts": report.FactsFrom(sheet), "incomplete": sheet.Incomplete})
}
