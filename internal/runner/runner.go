// Package runner is the single code path through which any check reaches a
// target. Phase 1 (baseline) and phase 2 (run_check / read_file) both call
// Run; there is no second command surface (docs/SPEC.md §2.1, §3).
//
// Run performs, in order: catalog lookup, typed parameter binding, symlink
// resolution and path policy for every Path param, elevation gating, budget-
// bounded execution, redaction, truncation, parsing and audit logging.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/target"
)

// Elevation is how elevated checks are run (docs/SPEC.md §8.1).
type Elevation string

// Elevation modes. Root means the session already runs as uid 0.
const (
	ElevateNone Elevation = "none"
	ElevateSudo Elevation = "sudo"
	ElevateRoot Elevation = "root"
)

// SudoPrefix is prepended to an elevated check's argv under ElevateSudo.
// Non-interactive only: scheck never prompts for, reads, or sends a password.
var SudoPrefix = []string{"sudo", "-n", "--"}

// Status of a check result.
type Status string

// Statuses.
const (
	StatusOK          Status = "ok"
	StatusUnavailable Status = "unavailable"
	StatusDenied      Status = "denied"
)

// Result is the outcome of one Run. Raw and Stderr are redacted and
// truncated; nothing downstream ever sees other bytes.
type Result struct {
	Observation string
	Occurrence  int
	CheckID     string
	// RanAs is the check actually executed, which differs from CheckID when
	// a content read of a sensitive path was substituted by fs.stat.
	RanAs      string
	Params     map[string]string
	Argv       []string
	Status     Status
	ReasonCode string
	Attempted  bool // execution was attempted; unavailable does not mean skipped
	Reason     string
	Raw        string
	Stderr     string
	Parsed     any
	Truncated  bool
	Redactions int
	ExitCode   int
	Duration   time.Duration
	Elevated   bool
	PathRule   string
	origin     Origin
}

// Runner composes a target with the policy. All fields but Log and Audit are
// required.
type Runner struct {
	Target   target.Target
	Paths    *policy.PathPolicy
	Redactor *policy.Redactor
	Budgets  policy.Budgets
	Audit    *policy.Audit
	Elevate  Elevation
	// Log, when set, receives verbose diagnostics (slow checks, substitutions).
	Log          func(format string, args ...any)
	observations Observations
}

// IDs of the catalog checks the runner itself depends on.
const (
	realpathCheck = "fs.realpath"
	statCheck     = "fs.stat"
)

// Origin says who asked for a check. Phase 1 leaves it zero. A model-
// initiated call (phase 2's run_check / read_file) names its tool and
// carries the model's rationale into the audit log, and is gated to the
// checks the model may see: the active profile's tier, never the canary
// (docs/SPEC.md §3 tiers, §4.3). The gate lives here, in the one
// enforcement point, not in the tool.
type Origin struct {
	Tool      string
	Rationale string
	// Profile bounds a model-initiated call; only read when Tool is set.
	Profile check.Profile
}

// Run executes the check with the given id on the runner's target platform.
func (r *Runner) Run(ctx context.Context, id string, params map[string]string) Result {
	return r.RunAs(ctx, id, params, Origin{})
}

// RunAs is Run with a stated origin.
func (r *Runner) RunAs(ctx context.Context, id string, params map[string]string, o Origin) Result {
	c, ok := check.Lookup(id, r.Target.Platform())
	if ok && o.Tool != "" && (c.Canary || c.MinProfile > o.Profile) {
		ok = false // outside the model's menu: same answer as an id that does not exist
	}
	if !ok {
		res := Result{CheckID: id, Params: params, Status: StatusDenied, Reason: "unknown check id", ReasonCode: "unknown_check", origin: o}
		res = r.record(res, "denied:unknown_check", nil)
		return res
	}
	return r.runCheck(ctx, c, params, o)
}

func (r *Runner) runCheck(ctx context.Context, c check.Check, params map[string]string, o Origin) Result {
	res := Result{CheckID: c.ID, RanAs: c.ID, Params: params, origin: o}
	argv, err := c.Bind(params)
	if err != nil {
		res.Status, res.Reason = StatusDenied, err.Error()
		res.ReasonCode = "invalid_params"
		res = r.record(res, "denied:param", nil)
		return res
	}

	res.Argv = argv // typed bindings are known, even if policy denies execution

	// Path policy on every Path param, on the resolved path.
	for _, p := range c.Params {
		if p.Kind != check.KindPath {
			continue
		}
		resolved := r.resolve(ctx, params[p.Name])
		verdict := r.Paths.Decide(policy.Canonical(resolved, r.Target.Platform() == check.MacOS))
		res.PathRule = verdict.Rule
		switch verdict.Decision {
		case policy.PathDeny:
			res.Status, res.Reason = StatusDenied, verdict.Rule+": "+params[p.Name]
			res.ReasonCode = "path_denied"
			res = r.record(res, "denied:"+verdict.Rule, nil)
			return res
		case policy.PathMetadataOnly:
			if c.PathUse == check.PathContent {
				stat, ok := check.Lookup(statCheck, r.Target.Platform())
				if !ok {
					res.Status, res.Reason = StatusUnavailable, "metadata-only path and no fs.stat check for platform"
					res.ReasonCode = "metadata_unavailable"
					res = r.record(res, "unavailable:no_stat_check", nil)
					return res
				}
				r.logf("check %s: %s is %s, substituting %s", c.ID, params[p.Name], verdict.Rule, statCheck)
				c = stat
				res.RanAs = stat.ID
				res.Reason = "metadata-only: " + verdict.Rule
				argv, err = c.Bind(map[string]string{"path": resolved})
				if err != nil {
					res.Status, res.Reason = StatusDenied, err.Error()
					res.ReasonCode = "invalid_params"
					res = r.record(res, "denied:param", nil)
					return res
				}
			}
		case policy.PathAllow:
		}
	}

	if c.Elevated {
		switch r.Elevate {
		case ElevateSudo:
			// sudo answers "a password is required" for a binary it cannot
			// find, which would misreport a missing tool as a policy refusal.
			if !r.installed(ctx, argv[0]) {
				res.Argv = argv
				res.Status, res.Reason = StatusUnavailable, "not found: "+argv[0]
				res.ReasonCode = "command_missing"
				res = r.record(res, "unavailable:"+res.Reason, nil)
				return res
			}
			argv = append(append([]string{}, SudoPrefix...), argv...)
			res.Elevated = true
		case ElevateRoot:
			res.Elevated = true
		default:
			res.Argv = argv
			res.Status, res.Reason = StatusUnavailable, "requires elevated read"
			res.ReasonCode = "requires_elevation"
			res = r.record(res, "unavailable:requires_elevation", nil)
			return res
		}
	}
	res.Argv = argv

	hard := r.Budgets.PerCheckHard
	if c.Budget.Hard > 0 && c.Budget.Hard < hard {
		hard = c.Budget.Hard
	}
	outCap := r.Budgets.PerCheckOutput
	if c.Budget.Output > 0 && c.Budget.Output < outCap {
		outCap = c.Budget.Output
	}
	cctx, cancel := context.WithTimeout(ctx, hard)
	defer cancel()
	res.Attempted = true
	exec, execErr := r.Target.Exec(cctx, argv)
	res.Duration = exec.Duration
	res.ExitCode = exec.Code

	// Redact before anything else can observe the bytes, then truncate.
	res.Raw, res.Truncated, res.Redactions = r.finish(exec.Stdout, exec.StdoutTruncated, outCap)
	stderr, _, n := r.finish(exec.Stderr, exec.StderrTruncated, 2<<10)
	res.Stderr = stderr
	res.Redactions += n

	// Extract is also an output minimization boundary (docs/SPEC.md §3). Failed commands
	// must not expose the full capture just because verbose diagnostics are enabled.
	if c.Extract != "" && (execErr != nil || !c.ExitAllowed(exec.Code)) {
		res.Raw = ""
	}
	if execErr != nil {
		res.Status = StatusUnavailable
		switch {
		case errors.Is(execErr, target.ErrNotFound):
			res.Reason = "not found: " + firstToken(argv, res.Elevated && r.Elevate == ElevateSudo)
			res.ReasonCode = "command_missing"
		case errors.Is(execErr, target.ErrTimeout):
			res.Reason = fmt.Sprintf("timeout after %s", hard)
			res.ReasonCode = "check_timeout"
			if ctx.Err() != nil {
				res.Reason, res.ReasonCode = "run deadline exceeded", "run_timeout"
				if errors.Is(ctx.Err(), context.Canceled) {
					res.Reason, res.ReasonCode = "run canceled", "canceled"
				}
			}
		default:
			res.Reason = "exec error: " + execErr.Error()
			res.ReasonCode = "exec_error"
		}
		res = r.record(res, "unavailable:"+res.Reason, &res.ExitCode)
		return res
	}
	if res.Elevated && r.Elevate == ElevateSudo && exec.Code == 1 && strings.HasPrefix(res.Stderr, "sudo:") {
		res.Status, res.Reason = StatusUnavailable, "sudo: "+firstLine(res.Stderr)+" (no NOPASSWD rule for this command, or "+firstToken(argv, true)+" is not installed)"
		res.ReasonCode = "sudo_refused"
		res = r.record(res, "unavailable:sudo", &res.ExitCode)
		return res
	}
	// For a check that accepts any exit code, the code carries no signal, so a
	// non-zero exit with nothing on stdout and a complaint on stderr is a
	// failure (systemctl on a host without systemd exits 1 exactly like
	// "disabled" does). Checks with an explicit ExitOK list are trusted.
	anyExit := len(c.ExitOK) > 0 && c.ExitOK[0] == check.AnyExit[0]
	if !c.ExitAllowed(exec.Code) || (anyExit && exec.Code != 0 && strings.TrimSpace(res.Raw) == "" && res.Stderr != "") {
		res.Status = StatusUnavailable
		res.Reason = fmt.Sprintf("exit %d", exec.Code)
		res.ReasonCode = "exit_error"
		if exec.Code == target.CodeNotFound {
			res.ReasonCode = "command_missing"
		}
		if l := firstLine(res.Stderr); l != "" {
			res.Reason += ": " + l
		}
		res = r.record(res, "unavailable:"+res.Reason, &res.ExitCode)
		return res
	}
	if c.Extract != "" {
		m := regexp.MustCompile(c.Extract).FindStringSubmatch(res.Raw)
		if m == nil {
			res.Status, res.Reason = StatusUnavailable, "extract: pattern not found in output"
			res.ReasonCode = "extract_error"
			res.Raw = ""
			res = r.record(res, "unavailable:extract", &res.ExitCode)
			return res
		}
		res.Raw = m[1]
	}
	parsed, perr := check.Parse(c, []byte(res.Raw))
	if perr != nil {
		res.Status, res.Reason = StatusUnavailable, "parse error: "+perr.Error()
		res.ReasonCode = "parse_error"
		res = r.record(res, "unavailable:parse_error", &res.ExitCode)
		return res
	}
	res.Parsed = parsed
	res.Status = StatusOK
	if res.Duration > r.Budgets.PerCheckSoft {
		r.logf("check %s: slow (%s > %s)", c.ID, res.Duration.Round(time.Millisecond), r.Budgets.PerCheckSoft)
	}
	res = r.record(res, "run", &res.ExitCode)
	return res
}

// installed reports whether bin is on the target's PATH, via the sys.which
// check; a path-qualified binary or a missing sys.which is assumed present
// and left for the exec itself to report.
func (r *Runner) installed(ctx context.Context, bin string) bool {
	if strings.HasPrefix(bin, "/") {
		return true
	}
	c, ok := check.Lookup("sys.which", r.Target.Platform())
	if !ok {
		return true
	}
	argv, err := c.Bind(map[string]string{"name": bin})
	if err != nil {
		return true
	}
	cctx, cancel := context.WithTimeout(ctx, r.Budgets.PerCheckHard)
	defer cancel()
	exec, execErr := r.Target.Exec(cctx, argv)
	sub := Result{CheckID: c.ID, RanAs: c.ID, Params: map[string]string{"name": bin}, Argv: argv, ExitCode: exec.Code, Duration: exec.Duration, Attempted: true, Status: StatusOK}
	sub.Raw, sub.Truncated, sub.Redactions = r.finish(exec.Stdout, exec.StdoutTruncated, 4<<10)
	sub.Stderr, _, _ = r.finish(exec.Stderr, exec.StderrTruncated, 2<<10)
	if execErr != nil || !c.ExitAllowed(exec.Code) {
		sub.Status, sub.ReasonCode, sub.Reason = StatusUnavailable, "exec_error", "availability probe failed"
		sub = r.record(sub, "unavailable:which", &sub.ExitCode)
	} else {
		sub.Parsed, _ = check.Parse(c, []byte(sub.Raw))
		sub = r.record(sub, "run", &sub.ExitCode)
	}
	if errors.Is(execErr, target.ErrNotFound) || exec.Code == target.CodeNotFound {
		// No `which` on this host (minimal images): assume present and let
		// sudo report; the sudo failure message carries the caveat.
		return true
	}
	return execErr == nil && exec.Code == 0
}

// resolve returns the symlink-resolved form of p via the fs.realpath check,
// or p itself when the check is missing or the path does not exist. Its
// execution is audited like any other.
func (r *Runner) resolve(ctx context.Context, p string) string {
	c, ok := check.Lookup(realpathCheck, r.Target.Platform())
	if !ok {
		return p
	}
	argv, err := c.Bind(map[string]string{"path": p})
	if err != nil {
		return p
	}
	cctx, cancel := context.WithTimeout(ctx, r.Budgets.PerCheckHard)
	defer cancel()
	exec, execErr := r.Target.Exec(cctx, argv)
	sub := Result{CheckID: c.ID, RanAs: c.ID, Params: map[string]string{"path": p}, Argv: argv, ExitCode: exec.Code, Duration: exec.Duration, Attempted: true, Status: StatusOK}
	sub.Raw, sub.Truncated, sub.Redactions = r.finish(exec.Stdout, exec.StdoutTruncated, 4<<10)
	sub.Stderr, _, _ = r.finish(exec.Stderr, exec.StderrTruncated, 2<<10)
	if execErr != nil || exec.Code != 0 {
		sub.Status, sub.ReasonCode, sub.Reason = StatusUnavailable, "exec_error", "path resolution failed"
		sub = r.record(sub, "unavailable:realpath", &sub.ExitCode)
		return p
	}
	sub.Parsed, _ = check.Parse(c, []byte(sub.Raw))
	sub = r.record(sub, "run", &sub.ExitCode)
	resolved := strings.TrimSpace(sub.Raw)
	if !strings.HasPrefix(resolved, "/") {
		return p
	}
	return resolved
}

// finish redacts b and then truncates it to capBytes with a marker.
func (r *Runner) finish(b []byte, targetTruncated bool, capBytes int) (string, bool, int) {
	red, hits := r.Redactor.Redact(b)
	truncated := targetTruncated
	if len(red) > capBytes {
		cut := capBytes
		// Never cut inside a redaction marker: the marker is what tells the
		// model something was there, so it stays whole even past the cap.
		if i := bytes.LastIndex(red[:cut], []byte("[REDACTED:")); i >= 0 && bytes.IndexByte(red[i:cut], ']') < 0 {
			if j := bytes.IndexByte(red[i:], ']'); j >= 0 {
				cut = i + j + 1
			}
		}
		dropped := len(red) - cut
		red = red[:cut]
		marker := fmt.Sprintf("\n[TRUNCATED:%d bytes]", dropped)
		if targetTruncated {
			marker = fmt.Sprintf("\n[TRUNCATED:%d+ bytes]", dropped)
		}
		red = append(red, marker...)
		truncated = true
	} else if targetTruncated {
		red = append(red, "\n[TRUNCATED:unknown bytes]"...)
	}
	return string(red), truncated, len(hits)
}

// record finalizes an outcome: retain a policy-safe snapshot and audit its reference.
func (r *Runner) record(res Result, decision string, code *int) Result {
	reasonDecision := decision == "unavailable:"+res.Reason
	res = r.retain(res)
	if reasonDecision {
		decision = "unavailable:" + res.Reason
	}
	e := policy.AuditEntry{
		Observation: res.Observation,
		CheckID:     res.RanAs,
		Params:      res.Params,
		Argv:        res.Argv,
		Decision:    decision,
		ExitCode:    code,
		DurationMS:  res.Duration.Milliseconds(),
		Elevated:    res.Elevated,
		Tool:        res.origin.Tool,
		Rationale:   res.origin.Rationale,
	}
	if e.CheckID == "" {
		e.CheckID = res.CheckID
	}
	if res.Raw != "" {
		e.OutputHash = policy.OutputHash([]byte(res.Raw))
	}
	if err := r.Audit.Log(e); err != nil {
		r.logf("audit log: %v", err)
	}
	return res
}

func (r *Runner) logf(format string, args ...any) {
	if r.Log != nil {
		message, _ := r.Redactor.RedactString(fmt.Sprintf(format, args...))
		r.Log("%s", message)
	}
}

func firstToken(argv []string, sudo bool) string {
	if sudo && len(argv) > len(SudoPrefix) {
		return argv[len(SudoPrefix)]
	}
	if len(argv) > 0 {
		return argv[0]
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
