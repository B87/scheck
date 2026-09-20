package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/b87/scheck/internal/agent"
	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all" // the complete catalog
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/operator"
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
	// context is the merged operator context once loadContext ran; nil
	// under --ignore-context or before loading.
	context *operator.Merged
	// provider is built before any target is contacted when the run will
	// reach phase 2; nil under --stop-after.
	provider llm.Provider
	effort   llm.Effort
	// phase2 and result are set once the agentic pass ran.
	phase2 *report.Phase2
	result *finding.Result
}

// defaultProvider is the v1 production adapter (docs/SPEC.md §5.2).
const defaultProvider = "openai-compatible"

// loadConfig resolves the effective configuration the way every command
// does (docs/SPEC.md §9): defaults, user file, project file, then the flags
// the operator explicitly set. It validates and returns the result with its
// provenance, so `config show` and a run cannot disagree.
func (o *globalOpts) loadConfig(cmd *cobra.Command) (*config.Config, error) {
	r, err := o.resolveConfig(cmd)
	if err != nil {
		return nil, err
	}
	if err := r.Config.Validate(); err != nil {
		return nil, usageErr("%v", err)
	}
	for _, src := range r.Config.Sources {
		o.logf(1, "config: loaded %s", src)
	}
	return r.Config, nil
}

// resolveConfig loads the file chain and applies explicitly set flags. It
// does not validate, so `config show` can display a broken configuration
// alongside the error `config validate` reports.
func (o *globalOpts) resolveConfig(cmd *cobra.Command) (*config.Resolved, error) {
	layers, err := config.LoadLayers(config.Paths()...)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	return config.Resolve(layers, o.overrides(cmd)), nil
}

// overrides collects the flags the operator set. A flag that was not given
// contributes nothing, so a registered default never overrides a file.
func (o *globalOpts) overrides(cmd *cobra.Command) config.Overrides {
	var ov config.Overrides
	changed := func(name string) bool {
		if cmd == nil {
			return false
		}
		f := cmd.Flags().Lookup(name)
		return f != nil && f.Changed
	}
	str := func(name string, v *string) *string {
		if changed(name) {
			return v
		}
		return nil
	}
	ov.Profile = str("profile", &o.Profile)
	ov.Elevate = str("elevate", &o.Elevate)
	if changed("sudo") && o.Sudo && ov.Elevate == nil {
		sudo := "sudo"
		ov.Elevate = &sudo
	}
	ov.StateDir = str("state-dir", &o.StateDir)
	ov.Provider = str("provider", &o.Provider)
	ov.Model = str("model", &o.Model)
	ov.BaseURL = str("base-url", &o.BaseURL)
	ov.Effort = str("effort", &o.Effort)
	if changed("max-context") {
		ov.MaxContext = &o.MaxContext
	}
	if changed("local-only") {
		ov.LocalOnly = &o.LocalOnly
	}
	return ov
}

// providerConfig is what an adapter is built from: the operator's selection,
// never a credential (docs/SPEC.md §9).
func (o *globalOpts) providerConfig(cfg *config.Config) llm.Config {
	effort, _ := llm.ParseEffort(cfg.Effort)
	return llm.Config{Model: cfg.Model, BaseURL: cfg.BaseURL, MaxContext: cfg.MaxContext,
		Transcript: o.Transcript, Effort: effort}
}

// newSession loads config, applies flags (last wins), and builds the policy
// objects. The target is constructed by the caller through mk because it
// needs the capture limit from the budgets.
func (o *globalOpts) newSession(cmd *cobra.Command, mk func(policy.Budgets) (target.Target, error)) (*session, error) {
	cfg, err := o.loadConfig(cmd)
	if err != nil {
		return nil, err
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
	// Phase 2 needs a provider; build it before any target is contacted so a
	// missing model, an unknown context limit or an unavailable adapter is a
	// usage error with nothing executed (docs/SPEC.md §5.2, §5.3).
	if o.StopAfter == "" {
		if err := s.buildProvider(); err != nil {
			return nil, err
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

// buildProvider selects and constructs the inference provider (docs/SPEC.md
// §5.2). Egress control and deferred adapters fail here, explicitly, before
// a single byte could leave the machine (§5.4).
func (s *session) buildProvider() error {
	cfg := s.cfg
	if s.opts.LocalOnly {
		return usageErr("--local-only is not available in this build (post-v1); it never silently enables egress")
	}
	if cfg.AllowEgress != nil && !*cfg.AllowEgress {
		return usageErr("allow_egress: false is not available in this build (post-v1); no provider can honour it yet")
	}
	name := cfg.Provider
	if name == "" {
		name = defaultProvider
	}
	if err := validateProvider(cfg); err != nil && (cfg.Model == "" && name != "mock") {
		return usageErr("%v", err)
	}
	p, err := llm.Build(name, s.opts.providerConfig(cfg))
	if err != nil {
		return usageErr("provider %s: %v", name, err)
	}
	if p.Limits().MaxContext <= 0 {
		return usageErr("provider %s: the context limit for model %q is unknown; set max_context: or --max-context (docs/SPEC.md §5.3)", name, cfg.Model)
	}
	s.provider, _ = p, name
	s.effort, _ = llm.ParseEffort(cfg.Effort)
	s.opts.logf(1, "provider %s, model %s, context limit %d tokens", name, cfg.Model, p.Limits().MaxContext)
	return nil
}

// runAgent is phase 2 (docs/SPEC.md §2.1, §5.6): the fact sheet and the
// rule findings go to the model through the closed tool surface, every
// execution through the same runner as phase 1, every finding through the
// store that grades it.
func (s *session) runAgent(ctx context.Context, sheet *baseline.FactSheet) {
	ctx, cancel := context.WithTimeout(ctx, s.budgets.RunTimeout)
	defer cancel()
	in := finding.Input{Sheet: sheet, Profile: s.profile, Disabled: s.cfg.DisableChecks}
	meta := s.meta()
	store := finding.NewStore(in)
	store.Grader = meta.Grader()
	store.Grader.EmulatedToolCalling = !s.provider.Native().ToolCalling
	sess := &agent.Session{
		Provider: s.provider, Runner: s.runner, Store: store, Sheet: sheet, Rules: finding.Evaluate(in),
		Profile: s.profile, Budgets: s.budgets, Context: s.context, Model: s.cfg.Model, Effort: s.effort,
		Log: func(f string, a ...any) { s.opts.logf(1, "agent: "+f, a...) },
	}
	if s.opts.Verbose >= 1 {
		sess.Progress = s.progress
	}
	out := sess.Run(ctx)
	res := store.Result()
	s.result = &res
	ended := "model stopped"
	if !out.Complete() {
		ended = out.Reason
	}
	s.phase2 = &report.Phase2{
		Provider: s.provider.Name(), Model: s.cfg.Model, Effort: string(s.effort),
		Native: s.provider.Native(), Limits: s.provider.Limits(), Usage: out.Usage,
		Mode: sess.Mode(), PromptVersion: agent.PromptVersion,
		Agent:    report.AgentRun{Iterations: out.Iterations, Checks: out.Checks, Reported: out.Reported, Ended: ended, Text: out.Text},
		Complete: out.Complete(), Reason: out.Reason, Warnings: out.Warnings,
	}
	s.opts.logf(1, "agent: %s after %d turns, %d checks, %d findings reported (%s)", out.Status, out.Iterations, out.Checks, out.Reported, ended)
}

// progress shows the model working on stderr: tool calls at -v, the text
// stream at -vv. Model text is escaped like target text before it reaches
// the terminal.
func (s *session) progress(ev llm.Event) {
	switch ev.Kind {
	case llm.EventToolCall:
		s.opts.logf(1, "model → %s %s", ev.ToolCall.Name, report.Sanitize(string(ev.ToolCall.Input)))
	case llm.EventText:
		if s.opts.Verbose >= 2 {
			fmt.Fprint(os.Stderr, report.Sanitize(ev.Text))
		}
	case llm.EventDone:
		if s.opts.Verbose >= 2 && ev.Response != nil && ev.Response.Text != "" {
			fmt.Fprintln(os.Stderr)
		}
	}
}

// loadContext reads every operator-context source (docs/SPEC.md §6.1). A
// target: source is read through the runner as the text.cat check, so it is
// subject to the path policy and appears in the audit log like any other
// binding — there is no second read path. --ignore-context reads nothing.
func (s *session) loadContext(ctx context.Context) error {
	if s.opts.IgnoreCtx {
		s.opts.logf(1, "context: ignored (--ignore-context)")
		return nil
	}
	read := func(path string) (string, error) {
		res := s.runner.Run(ctx, "text.cat", map[string]string{"path": path})
		if res.Status != runner.StatusOK {
			return "", fmt.Errorf("%s: %s", res.Status, res.Reason)
		}
		return res.Raw, nil
	}
	if s.runner.Target == nil {
		read = nil
	}
	m, err := operator.Load(operator.Options{
		ConfigContext: s.cfg.Context, ConfigSource: s.cfg.ContextSource,
		ImplicitDir: operator.DefaultImplicitDir, Flags: s.opts.Context,
		Budget: s.budgets.ContextBytes, ReadTarget: read, KnownFinding: config.KnownFinding,
	})
	if err != nil {
		return usageErr("%v", err)
	}
	s.context = m
	for _, w := range m.Warnings {
		s.opts.logf(0, "warning: %s", w)
	}
	s.opts.logf(1, "%s", m.Summary())
	return nil
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

// meta is what the envelope needs beyond the fact sheet.
func (s *session) meta() report.Meta {
	return report.Meta{
		Started:   s.started,
		Transport: string(s.runner.Target.Transport()),
		Canary:    s.canary,
		Elevation: string(s.elevate),
		Profile:   s.profile.String(),
		Version:   version.Version,
		Disabled:  s.cfg.DisableChecks,
		Context:   s.context,
		Result:    s.result,
		Phase2:    s.phase2,
	}
}

// writeReport builds the envelope, persists it unless --no-persist, and
// renders it in --format.
func (s *session) writeReport(w io.Writer, sheet *baseline.FactSheet) (report.Envelope, error) {
	env := report.Build(sheet, s.meta())
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
