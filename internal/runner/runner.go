// Package runner is the single code path through which any check reaches a
// target. Phase 1 (baseline) and phase 2 (run_check / read_file) both call
// Run; there is no second command surface (SPEC.md §2.1, §3).
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
	"strings"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/target"
)

// Elevation is how elevated checks are run (SPEC.md §8.1).
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
	CheckID string
	// RanAs is the check actually executed, which differs from CheckID when
	// a content read of a sensitive path was substituted by fs.stat.
	RanAs      string
	Params     map[string]string
	Argv       []string
	Status     Status
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
	Log func(format string, args ...any)
}

// IDs of the catalog checks the runner itself depends on.
const (
	realpathCheck = "fs.realpath"
	statCheck     = "fs.stat"
)

// Run executes the check with the given id on the runner's target platform.
func (r *Runner) Run(ctx context.Context, id string, params map[string]string) Result {
	c, ok := check.Lookup(id, r.Target.Platform())
	if !ok {
		res := Result{CheckID: id, Params: params, Status: StatusDenied, Reason: "unknown check id"}
		r.audit(res, "denied:unknown_check", nil)
		return res
	}
	return r.RunCheck(ctx, c, params)
}

// RunCheck executes an already-resolved catalog entry.
func (r *Runner) RunCheck(ctx context.Context, c check.Check, params map[string]string) Result {
	res := Result{CheckID: c.ID, RanAs: c.ID, Params: params}
	argv, err := c.Bind(params)
	if err != nil {
		res.Status, res.Reason = StatusDenied, err.Error()
		r.audit(res, "denied:param", nil)
		return res
	}

	// Path policy on every Path param, on the resolved path.
	for _, p := range c.Params {
		if p.Kind != check.KindPath {
			continue
		}
		resolved := r.resolve(ctx, params[p.Name])
		verdict := r.Paths.Decide(resolved)
		res.PathRule = verdict.Rule
		switch verdict.Decision {
		case policy.PathDeny:
			res.Status, res.Reason = StatusDenied, verdict.Rule+": "+params[p.Name]
			r.audit(res, "denied:"+verdict.Rule, nil)
			return res
		case policy.PathMetadataOnly:
			if c.PathUse == check.PathContent {
				stat, ok := check.Lookup(statCheck, r.Target.Platform())
				if !ok {
					res.Status, res.Reason = StatusUnavailable, "metadata-only path and no fs.stat check for platform"
					r.audit(res, "unavailable:no_stat_check", nil)
					return res
				}
				r.logf("check %s: %s is %s, substituting %s", c.ID, params[p.Name], verdict.Rule, statCheck)
				c = stat
				res.RanAs = stat.ID
				res.Reason = "metadata-only: " + verdict.Rule
				argv, err = c.Bind(map[string]string{"path": resolved})
				if err != nil {
					res.Status, res.Reason = StatusDenied, err.Error()
					r.audit(res, "denied:param", nil)
					return res
				}
			}
		case policy.PathAllow:
		}
	}

	if c.Elevated {
		switch r.Elevate {
		case ElevateSudo:
			argv = append(append([]string{}, SudoPrefix...), argv...)
			res.Elevated = true
		case ElevateRoot:
			res.Elevated = true
		default:
			res.Argv = argv
			res.Status, res.Reason = StatusUnavailable, "requires elevated read"
			r.audit(res, "unavailable:requires_elevation", nil)
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
	exec, execErr := r.Target.Exec(cctx, argv)
	res.Duration = exec.Duration
	res.ExitCode = exec.Code

	// Redact before anything else can observe the bytes, then truncate.
	res.Raw, res.Truncated, res.Redactions = r.finish(exec.Stdout, exec.StdoutTruncated, outCap)
	stderr, _, n := r.finish(exec.Stderr, exec.StderrTruncated, 2<<10)
	res.Stderr = stderr
	res.Redactions += n

	if execErr != nil {
		res.Status = StatusUnavailable
		switch {
		case errors.Is(execErr, target.ErrNotFound):
			res.Reason = "not found: " + firstToken(argv, res.Elevated && r.Elevate == ElevateSudo)
		case errors.Is(execErr, target.ErrTimeout):
			res.Reason = fmt.Sprintf("timeout after %s", hard)
		default:
			res.Reason = "exec error: " + execErr.Error()
		}
		r.audit(res, "unavailable:"+res.Reason, &res.ExitCode)
		return res
	}
	if res.Elevated && r.Elevate == ElevateSudo && exec.Code == 1 && strings.HasPrefix(res.Stderr, "sudo:") {
		res.Status, res.Reason = StatusUnavailable, "sudo: "+firstLine(res.Stderr)
		r.audit(res, "unavailable:sudo", &res.ExitCode)
		return res
	}
	if !c.ExitAllowed(exec.Code) {
		res.Status = StatusUnavailable
		res.Reason = fmt.Sprintf("exit %d", exec.Code)
		if l := firstLine(res.Stderr); l != "" {
			res.Reason += ": " + l
		}
		r.audit(res, "unavailable:"+res.Reason, &res.ExitCode)
		return res
	}
	parsed, perr := check.Parse(c.Parser, []byte(res.Raw))
	if perr != nil {
		res.Status, res.Reason = StatusUnavailable, "parse error: "+perr.Error()
		r.audit(res, "unavailable:parse_error", &res.ExitCode)
		return res
	}
	res.Parsed = parsed
	res.Status = StatusOK
	if res.Duration > r.Budgets.PerCheckSoft {
		r.logf("check %s: slow (%s > %s)", c.ID, res.Duration.Round(time.Millisecond), r.Budgets.PerCheckSoft)
	}
	r.audit(res, "run", &res.ExitCode)
	return res
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
	sub := Result{CheckID: c.ID, RanAs: c.ID, Params: map[string]string{"path": p}, Argv: argv, ExitCode: exec.Code, Duration: exec.Duration}
	if execErr != nil || exec.Code != 0 {
		r.audit(sub, "unavailable:realpath", &sub.ExitCode)
		return p
	}
	sub.Raw, _, _ = r.finish(exec.Stdout, false, 4<<10)
	r.audit(sub, "run", &sub.ExitCode)
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

func (r *Runner) audit(res Result, decision string, code *int) {
	e := policy.AuditEntry{
		CheckID:    res.RanAs,
		Params:     res.Params,
		Argv:       res.Argv,
		Decision:   decision,
		ExitCode:   code,
		DurationMS: res.Duration.Milliseconds(),
		Elevated:   res.Elevated,
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
}

func (r *Runner) logf(format string, args ...any) {
	if r.Log != nil {
		r.Log(format, args...)
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
