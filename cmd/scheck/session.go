package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all" // the complete catalog
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/state"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/fixture"
	"github.com/b87/scheck/internal/version"
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
	canary   string // ok | fail | n/a
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

	s := &session{opts: o, cfg: cfg, started: time.Now(), canary: "n/a"}
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
	// A nil target is allowed for transports that need the session first
	// (ssh); the caller sets runner.Target before any check runs.
	s.runner = &runner.Runner{Target: s.wrapTarget(t), Paths: s.paths, Redactor: s.redactor, Budgets: s.budgets,
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
	var out strings.Builder
	for i, a := range argv {
		if i > 0 {
			out.WriteString(" ")
		}
		if a == "" {
			a = `""`
		}
		out.WriteString(a)
	}
	return out.String()
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

// nopCloser keeps stdout open when the report is not going to a --out file,
// while still exposing Fd() so the caller can ask whether it is a terminal.
type nopCloser struct{ *os.File }

func (nopCloser) Close() error { return nil }

// writeReport builds the envelope, persists it unless --no-persist, and
// renders it in --format.
func (s *session) writeReport(w io.Writer, sheet *baseline.FactSheet) (report.Envelope, error) {
	env := report.Build(sheet, report.Meta{
		Started:   s.started,
		Transport: string(s.runner.Target.Transport()),
		Canary:    s.canary,
		Elevation: string(s.elevate),
		Profile:   s.profile.String(),
		Version:   version.Version,
		Disabled:  s.cfg.DisableChecks,
	})
	if !s.opts.NoPersist {
		dir, err := state.Dir(s.cfg.StateDir)
		if err == nil {
			var path string
			path, err = state.Write(dir, &env)
			if err == nil {
				s.opts.logf(1, "persisted %s", path)
			}
		}
		if err != nil {
			env.Run.Warnings = append(env.Run.Warnings, "not persisted: "+err.Error())
			s.opts.logf(0, "warning: run not persisted: %v", err)
		}
	}
	switch s.opts.Format {
	case "json":
		return env, report.WriteJSONEvidence(w, env, s.opts.IncludeEvidence)
	case "text":
		return env, report.WriteText(w, env, s.opts.textOptions(w))
	case "sarif":
		return env, usageErr("--format sarif is not available in this build (phase 1)")
	default:
		return env, usageErr("--format must be text|json|sarif")
	}
}

// wrapTarget adds the fixture recorder when --record-fixtures is set. The
// recorder sees post-redaction bytes only.
func (s *session) wrapTarget(t target.Target) target.Target {
	if t == nil || s.opts.RecordFixtures == "" {
		return t
	}
	s.opts.logf(1, "recording fixtures into %s", s.opts.RecordFixtures)
	return &fixture.Recorder{Inner: t, Dir: s.opts.RecordFixtures, Redact: func(b []byte) []byte {
		out, _ := s.redactor.Redact(b)
		return out
	}}
}

func homeDir() (string, error) { return os.UserHomeDir() }
