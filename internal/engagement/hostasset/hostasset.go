// Package hostasset is the host collector as an engagement asset
// (docs/ROADMAP.md, E1b): it reaches one host, verifies the SSH canary,
// runs the baseline plan through the runner and assesses the facts with the
// posture rules, exactly as `scheck local` and `scheck ssh` do. It is the
// only engagement package that imports internal/runner or a target
// (AGENTS.md, "Layout"); the host collector's guarantees do not change by
// being reached from here (docs/spec/host-collector.md §1, §4).
package hostasset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/check/common"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target"
	"github.com/b87/scheck/internal/target/local"
	"github.com/b87/scheck/internal/target/ssh"
)

// Options is one host asset as the collector reads it: where it is, how to
// reach it, and the narrowing and context the engagement file declares for
// it. Nothing else reaches the collector (docs/spec/engagement.md, "Runs,
// state and configuration").
type Options struct {
	// Local reads the machine scheck runs on; otherwise Host is dialed.
	Local      bool
	Host       string
	Port       int
	User       string
	Identity   string
	KnownHosts string
	// Target, when set, replaces reaching the host, the canary included:
	// a fixture in tests. No production caller sets it.
	Target target.Target

	Elevate       string // none | sudo
	Profile       string // baseline | hardened
	DisableChecks []string
	DenyPaths     []string
	RedactExtra   []string
	// Context is the asset's context and the accepted risks that name it;
	// ContextSource names where it was declared, for attribution.
	Context       *operator.Structured
	ContextSource string
	// RunTimeout is the host collector's run timeout
	// (docs/spec/host-collector.md §4.4); 0 keeps the policy default.
	RunTimeout time.Duration

	Audit   *policy.Audit
	Log     func(format string, args ...any)
	Version string
}

// Error is a host that was not collected. Usage marks a refusal on a
// positive list: no SSH user, an unknown or changed host key, an unreadable
// identity or known_hosts file, failed authentication, a canary mismatch
// (target.ErrAccess, target.ErrCanary): exit 3, as in 0.0.1. Any other
// Error is a transport failure: the asset is recorded as failed and the run
// is incomplete. An unrecognized failure is never read as the operator's
// mistake (docs/spec/engagement.md, "Exit codes").
type Error struct {
	Usage bool
	Err   error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func usage(format string, args ...any) error {
	return &Error{Usage: true, Err: fmt.Errorf(format, args...)}
}

func failed(format string, args ...any) error {
	return &Error{Err: fmt.Errorf(format, args...)}
}

// Collection is a host's facts, ready for the posture rules.
type Collection struct {
	sheet   *baseline.FactSheet
	meta    report.Meta
	profile check.Profile
	env     *report.Envelope
}

// Collect reaches the host and runs the baseline plan. The run timeout
// bounds the plan; ctx bounds everything, and its end marks the collection
// incomplete like the run timeout does.
func Collect(ctx context.Context, o Options) (*Collection, error) {
	profile, ok := check.ParseProfile(o.Profile)
	if !ok {
		return nil, usage("profile %q is not baseline or hardened", o.Profile)
	}
	elevate := runner.ElevateNone
	switch o.Elevate {
	case "", "none":
	case "sudo":
		elevate = runner.ElevateSudo
	default:
		return nil, usage("elevate %q is not none or sudo", o.Elevate)
	}
	budgets := policy.DefaultBudgets()
	if o.RunTimeout > 0 {
		budgets.RunTimeout = o.RunTimeout
	}
	if err := budgets.Validate(); err != nil {
		return nil, usage("%v", err)
	}
	redactor, err := policy.NewRedactor(o.RedactExtra)
	if err != nil {
		// The redactor's error quotes the pattern, which is often the very
		// string it hides; validation already refused any that fail here.
		return nil, usage("redact_extra: a pattern does not compile")
	}
	logf := o.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	started := time.Now()
	r := &runner.Runner{Paths: policy.NewPathPolicy(o.DenyPaths), Redactor: redactor, Budgets: budgets,
		Audit: o.Audit, Elevate: elevate, Log: logf}
	canary := "n/a"
	switch {
	case o.Target != nil:
		r.Target = o.Target
	case o.Local:
		r.Target = local.New(budgets.CaptureLimit())
	default:
		st, err := dial(ctx, o, budgets.CaptureLimit(), logf)
		if err != nil {
			return nil, err
		}
		defer func() { _ = st.Close() }()
		r.Target = st
		if err := VerifyCanary(ctx, st, o.Audit, redactor, logf); err != nil {
			return nil, &Error{Usage: true, Err: err}
		}
		canary = "ok"
		logf("ssh: canary ok")
		if err := DetectPlatform(ctx, r, st); err != nil {
			return nil, &Error{Err: err}
		}
		logf("ssh: platform %s", st.Platform())
	}
	p := r.Target.Platform()
	if p == target.Unknown {
		return nil, failed("unsupported platform")
	}
	plan := baseline.Plan(p, o.DisableChecks)
	runCtx, cancel := context.WithTimeout(ctx, budgets.RunTimeout)
	defer cancel()
	if elevate == runner.ElevateNone && baseline.DetectRoot(runCtx, r) {
		r.Elevate, elevate = runner.ElevateRoot, runner.ElevateRoot
		logf("session runs as root; elevated checks need no prefix")
	}
	sheet := baseline.Run(runCtx, r, plan, func(res runner.Result) {
		logf("%-28s %-12s %6dms %s", res.CheckID, res.Status, res.Duration.Milliseconds(), res.Reason)
	})
	return &Collection{sheet: sheet, profile: profile, meta: report.Meta{
		Started:   started,
		Transport: string(r.Target.Transport()),
		Canary:    canary,
		Elevation: string(elevate),
		Profile:   profile.String(),
		Version:   o.Version,
		Disabled:  o.DisableChecks,
		Context:   merged(o.Context, o.ContextSource),
	}}, nil
}

// dial connects over SSH. An address that never answered is a transport
// failure; anything the operator's own configuration or the host refused
// is a usage error, as `scheck ssh` treats it.
func dial(ctx context.Context, o Options, maxOutput int, logf func(string, ...any)) (*ssh.Target, error) {
	if o.User == "" {
		return nil, usage("host %s has no SSH user: write it into the locator as user@%s", o.Host, o.Host)
	}
	identity := o.Identity
	if strings.HasPrefix(identity, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, usage("identity: %v", err)
		}
		identity = filepath.Join(home, identity[2:])
	}
	logf("ssh: connecting to %s@%s:%d", o.User, o.Host, o.Port)
	st, err := ssh.Dial(ctx, ssh.Options{Host: o.Host, Port: o.Port, User: o.User, Identity: identity,
		KnownHosts: o.KnownHosts, MaxOutput: maxOutput})
	if err != nil {
		return nil, &Error{Usage: errors.Is(err, target.ErrAccess), Err: err}
	}
	return st, nil
}

// VerifyCanary is the first command on a session
// (docs/spec/host-collector.md §4.3). Its outcome is audited like any
// check, and an audit write failure is logged as the runner logs one. Any
// failure returns target.ErrCanary and closes the session; what the remote
// shell echoed is quoted only after redaction, and cut short.
func VerifyCanary(ctx context.Context, st *ssh.Target, audit *policy.Audit, red *policy.Redactor, logf func(string, ...any)) error {
	c, ok := check.Lookup("sys.canary", check.Any)
	if !ok {
		return fmt.Errorf("%w: the catalog has no canary check", target.ErrCanary)
	}
	err := st.Verify(ctx, c.Argv, common.CanaryString)
	entry := policy.AuditEntry{CheckID: c.ID, Argv: c.Argv, Decision: "run"}
	if err != nil {
		entry.Decision = "denied:canary"
	}
	if aerr := audit.Log(entry); aerr != nil {
		logf("audit log: %v", aerr)
	}
	if err != nil && st.CanaryOutput != "" {
		out, _ := red.Redact([]byte(st.CanaryOutput))
		if len(out) > 120 {
			out = append(out[:120:120], "…"...)
		}
		err = fmt.Errorf("%w; it echoed %q", err, out)
	}
	return err
}

// DetectPlatform reads `uname -s` through the runner and records the
// platform on the SSH target.
func DetectPlatform(ctx context.Context, r *runner.Runner, st *ssh.Target) error {
	res := r.Run(ctx, "sys.platform", nil)
	if res.Status != runner.StatusOK {
		return fmt.Errorf("ssh: cannot detect platform: %s", res.Reason)
	}
	p := target.PlatformFromUname(strings.TrimSpace(res.Raw))
	if p == target.Unknown {
		return fmt.Errorf("ssh: unsupported platform %q", strings.TrimSpace(res.Raw))
	}
	st.SetPlatform(p)
	return nil
}

// Envelope is the host collector's report for this asset
// (docs/spec/host-collector.md §6.4): its facts, and the posture rules
// assessed over them and graded through the asset's context. It is built
// once.
func (c *Collection) Envelope() report.Envelope {
	if c.env == nil {
		env := report.Build(c.sheet, c.meta)
		c.env = &env
	}
	return *c.env
}

// Complete reports whether every planned check ran.
func (c *Collection) Complete() bool { return !c.sheet.Incomplete }

// Lost is the transport failure that cut the collection short, or "" when
// it was not cut or a timeout cut it.
func (c *Collection) Lost() string { return c.sheet.Lost }

// Threshold is the severity at or above which an open finding counts: the
// asset's profile sets it, as in 0.0.1 (docs/spec/engagement.md, "Exit
// codes").
func (c *Collection) Threshold() finding.Severity { return finding.Threshold(c.profile) }

// OpenFindings counts the open findings at or above Threshold.
func (c *Collection) OpenFindings() int { return c.Envelope().OpenFindings(c.profile) }

// merged turns the asset's declared context into the operator context the
// grader reads, every key attributed to source. It is one source, so no
// merging or budget applies.
func merged(s *operator.Structured, source string) *operator.Merged {
	if s == nil || s.IsZero() {
		return nil
	}
	m := &operator.Merged{Structured: *s, Origins: map[string]string{}, Prose: []operator.Prose{}, Warnings: []string{}}
	for key, set := range map[string]bool{
		"role": s.Role != "", "exposure": s.Exposure != "", "environment": s.Environment != "",
		"expected_services": len(s.ExpectedServices) > 0,
	} {
		if set {
			m.Origins[key] = source
		}
	}
	m.Structured.ExpectedServices = append([]operator.Service(nil), s.ExpectedServices...)
	for i := range m.Structured.ExpectedServices {
		m.Structured.ExpectedServices[i].Source = source
	}
	// An accepted risk names its own entry when the caller set one, so the
	// grade says which acceptance applied, not only which asset.
	m.Structured.AcceptedRisks = append([]operator.Risk(nil), s.AcceptedRisks...)
	var riskSources []string
	for i := range m.Structured.AcceptedRisks {
		r := &m.Structured.AcceptedRisks[i]
		if r.Source == "" {
			r.Source = source
		}
		if !slices.Contains(riskSources, r.Source) {
			riskSources = append(riskSources, r.Source)
		}
	}
	if len(riskSources) > 0 {
		m.Origins["accepted_risks"] = strings.Join(riskSources, ", ")
	}
	raw, _ := yaml.Marshal(m.Structured)
	sum := sha256.Sum256(raw)
	m.Sources = []operator.Source{{Name: source, Kind: "config", SHA256: hex.EncodeToString(sum[:]), Bytes: len(raw)}}
	m.Used = len(raw)
	return m
}
