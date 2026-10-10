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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	"github.com/b87/scheck/internal/target/fixture"
	"github.com/b87/scheck/internal/target/local"
	"github.com/b87/scheck/internal/target/ssh"
)

// Options is one host asset as the collector reads it: where it is, how to
// reach it, and the narrowing and context the engagement file declares for
// it. Nothing else reaches the collector (docs/spec/runs.md, "Runs,
// state and configuration").
type Options struct {
	// Local reads the machine scheck runs on; otherwise Host is dialed.
	Local      bool
	Host       string
	Port       int
	User       string
	Identity   string
	KnownHosts string
	// Jump, when set, is the SSH hop the connection goes through: a
	// connection setting, never an asset; nothing runs on it, and every
	// audit line records it (docs/ROADMAP.md, E1c).
	Jump *Hop
	// Allow refuses an address the host's or the hop's name resolves to
	// that an exclude covers, before the connection opens
	// (docs/spec/scope.md, "The scope gate").
	Allow func(netip.Addr) error
	// Reach, when set, is filled with how far reaching the host got,
	// whether or not the collection succeeds: what left this machine
	// (docs/spec/report.md, "What left this machine").
	Reach *Reach
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
	// RecordFixtures, when set, writes every exec of the run to that
	// directory as a fixture manifest (the hidden --record-fixtures flag);
	// the recorder sees post-redaction bytes only.
	RecordFixtures string
	// Now is the time accepted risks are graded at: an engagement's
	// collection time (docs/spec/engagement.md, "Accepted risks"); zero is
	// when the envelope is built.
	Now time.Time
}

// Hop is a jump host: who to log in as, where.
type Hop struct {
	User string
	Host string
	Port int
}

// String is the hop as an audit line and the report name it.
func (h Hop) String() string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return h.User + "@" + net.JoinHostPort(h.Host, strconv.Itoa(port))
}

// Error is a host that was not collected. Usage marks a refusal on a
// positive list: no SSH user, an unknown or changed host key, an unreadable
// identity or known_hosts file, failed authentication, a canary mismatch
// (target.ErrAccess, target.ErrCanary): exit 3, as in 0.0.1. Any other
// Error is a transport failure: the asset is recorded as failed and the run
// is incomplete. An unrecognized failure is never read as the operator's
// mistake (docs/spec/scope.md, "Exit codes").
type Error struct {
	Usage bool
	Err   error
	// Kind names a refusal for the report: host_key_unknown,
	// host_key_changed, access (identity, known_hosts, authentication) or
	// canary; "" for a transport failure.
	Kind string
	// Echo is what a remote shell returned in place of the canary,
	// redacted and cut, kept apart from Err so a report can carry it in
	// JSON and never print it (docs/spec/report.md, "Incompleteness
	// and refusals").
	Echo string
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func usage(format string, args ...any) error {
	return &Error{Usage: true, Err: fmt.Errorf(format, args...)}
}

// accessRefused is a host the operator's own access cannot reach: no SSH
// user, an unusable identity, known_hosts or credentials.
func accessRefused(format string, args ...any) error {
	return &Error{Usage: true, Kind: "access", Err: fmt.Errorf(format, args...)}
}

func failed(format string, args ...any) error {
	return &Error{Err: fmt.Errorf(format, args...)}
}

// Collection is a host's facts, ready for the posture rules.
type Collection struct {
	sheet   *baseline.FactSheet
	planned []string
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
	record := func(t target.Target) target.Target {
		if o.RecordFixtures == "" {
			return t
		}
		logf("recording fixtures into %s", o.RecordFixtures)
		return &fixture.Recorder{Inner: t, Dir: o.RecordFixtures, Redact: func(b []byte) []byte {
			out, _ := redactor.Redact(b)
			return out
		}}
	}
	switch {
	case o.Target != nil:
		// A fixture stands for a host reached directly.
		if o.Reach != nil {
			*o.Reach = Reach{Dialled: true, Connected: true}
		}
		r.Target = record(o.Target)
	case o.Local:
		r.Target = record(local.New(budgets.CaptureLimit()))
	default:
		if o.Jump != nil {
			// Every audit line names the hop; the hop itself never
			// appears as a target.
			o.Audit.SetVia(o.Jump.String())
		}
		st, err := dial(ctx, o, budgets.CaptureLimit(), logf)
		if err != nil {
			return nil, err
		}
		defer func() { _ = st.Close() }()
		r.Target = record(st)
		// The canary gets a check's own deadline: a login shell that never
		// answers is a host that could not be read, not one that altered
		// output.
		canaryCtx, cancel := context.WithTimeout(ctx, budgets.PerCheckHard)
		err = VerifyCanary(canaryCtx, st, o.Audit, redactor, logf)
		cancel()
		if err != nil {
			if errors.Is(err, target.ErrTransport) || errors.Is(err, target.ErrTimeout) || ctx.Err() != nil {
				// The session was lost, or never answered, while the canary
				// ran: nothing was shown to be altered, so this is a
				// transport failure (docs/spec/scope.md, "Exit codes").
				return nil, &Error{Err: err}
			}
			if ce, ok := errors.AsType[*CanaryError](err); ok {
				return nil, &Error{Usage: true, Kind: "canary", Err: ce.Err, Echo: ce.Echo}
			}
			return nil, &Error{Usage: true, Kind: "canary", Err: err}
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
		// A reason can carry the first line of a target's stderr: escaped
		// before it reaches a terminal (docs/spec/host-collector.md §6.6).
		logf("%-28s %-12s %6dms %s", res.CheckID, res.Status, res.Duration.Milliseconds(), report.Sanitize(res.Reason))
	})
	planned := make([]string, len(plan))
	for i, c := range plan {
		planned[i] = c.ID
	}
	return &Collection{sheet: sheet, planned: planned, profile: profile, meta: report.Meta{
		Started:   started,
		Transport: string(r.Target.Transport()),
		Canary:    canary,
		Elevation: string(elevate),
		Profile:   profile.String(),
		Version:   o.Version,
		Disabled:  o.DisableChecks,
		Context:   merged(o.Context, o.ContextSource),
		Now:       o.Now,
	}}, nil
}

// Reach is how far reaching a host over SSH got.
type Reach struct {
	// Resolved are the names this machine's resolver was asked for: the
	// host's, or its jump host's, when written as a name.
	Resolved []string
	// Dialled says a connection to the host was attempted, directly or
	// through its jump host; Connected says one opened. JumpDialled and
	// JumpConnected are the same for the jump host.
	Dialled, Connected, JumpDialled, JumpConnected bool
	// ByJump is the host name its jump host was asked to resolve, "" when
	// none was.
	ByJump string
}

// dial connects over SSH. An address that never answered is a transport
// failure; anything the operator's own configuration or the host refused
// is a usage error, as `scheck ssh` treats it.
func dial(ctx context.Context, o Options, maxOutput int, logf func(string, ...any)) (*ssh.Target, error) {
	if o.User == "" {
		return nil, accessRefused("host %s has no SSH user: write it into the locator as user@%s", o.Host, o.Host)
	}
	identity := o.Identity
	if strings.HasPrefix(identity, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, accessRefused("identity: %v", err)
		}
		identity = filepath.Join(home, identity[2:])
	}
	so := ssh.Options{Host: o.Host, Port: o.Port, User: o.User, Identity: identity, KnownHosts: o.KnownHosts, MaxOutput: maxOutput, Allow: o.Allow}
	if j := o.Jump; j != nil {
		if j.User == "" {
			return nil, accessRefused("jump host %s has no SSH user: write it as user@%s", j.Host, j.Host)
		}
		so.Jump = &ssh.Hop{Host: j.Host, Port: j.Port, User: j.User}
		logf("ssh: connecting to %s@%s:%d through %s", o.User, o.Host, o.Port, j)
	} else {
		logf("ssh: connecting to %s@%s:%d", o.User, o.Host, o.Port)
	}
	var p ssh.Progress
	so.Progress = &p
	st, err := ssh.Dial(ctx, so)
	if o.Reach != nil {
		*o.Reach = Reach{Resolved: p.Resolved, Dialled: p.Dialled, Connected: p.Connected, JumpDialled: p.JumpDialled,
			JumpConnected: p.JumpConnected}
		if _, err := netip.ParseAddr(o.Host); o.Jump != nil && p.Dialled && err != nil {
			o.Reach.ByJump = o.Host // a name; an address needs no resolving
		}
	}
	if err != nil {
		e := &Error{Usage: errors.Is(err, target.ErrAccess), Err: err}
		hop := ""
		if errors.Is(err, target.ErrJumpHost) {
			hop = "jump_"
		}
		switch {
		case errors.Is(err, target.ErrExcluded):
			e.Kind = hop + "excluded"
		case errors.Is(err, target.ErrHostKeyChanged):
			e.Kind = hop + "host_key_changed"
		case errors.Is(err, target.ErrHostKeyUnknown):
			e.Kind = hop + "host_key_unknown"
		case e.Usage:
			e.Kind = "access"
		}
		return nil, e
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
		return &CanaryError{Err: err, Echo: fmt.Sprintf("%q", out)}
	}
	return err
}

// CanaryError is a canary mismatch and what the remote shell echoed,
// redacted, cut and quoted. Collect keeps the two apart, so the echo
// reaches the report's JSON and never its text.
type CanaryError struct {
	Err  error
	Echo string
}

func (e *CanaryError) Error() string { return e.Err.Error() + "; it echoed " + e.Echo }
func (e *CanaryError) Unwrap() error { return e.Err }

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

// Restore is a collection an earlier session of the run completed, read
// back from the run directory: a resume keeps a completed host as a unit,
// never merging two sessions' commands (docs/spec/runs.md, "Stop and
// resume"). Nothing is regraded; the envelope is as that session wrote it.
func Restore(env report.Envelope, planned []string) (*Collection, error) {
	profile, ok := check.ParseProfile(env.Run.Profile)
	if !ok {
		return nil, fmt.Errorf("profile %q is not baseline or hardened", env.Run.Profile)
	}
	if env.Run.Status != "complete" {
		return nil, errors.New("only a complete collection is kept")
	}
	return &Collection{sheet: &baseline.FactSheet{}, planned: slices.Clone(planned), profile: profile, env: &env}, nil
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

// Planned is the plan's check ids, so the report counts the checks a cut
// collection never reached.
func (c *Collection) Planned() []string { return slices.Clone(c.planned) }

// Complete reports whether every planned check ran.
func (c *Collection) Complete() bool { return !c.sheet.Incomplete }

// Lost is the transport failure that cut the collection short, or "" when
// it was not cut or a timeout cut it.
func (c *Collection) Lost() string { return c.sheet.Lost }

// Threshold is the severity at or above which an open finding counts: the
// asset's profile sets it, as in 0.0.1 (docs/spec/scope.md, "Exit
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
