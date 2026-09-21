package bounded

import (
	"context"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// OriginTool names this arm in the audit log. Every follow-up read goes
// through runner.RunAs with it, so the menu gate (profile tier, never the
// canary), path policy, redaction, truncation and the audit trail apply
// exactly as they do to a model-initiated call (AGENTS.md rule 3).
const OriginTool = "bounded_followup"

// unitDir is where a host's own systemd units live. Vendor units under
// /lib/systemd are the platform's own and are not read: the question about
// them is answered by their name.
const unitDir = "/etc/systemd/system"

// resolver runs the fixed per-kind follow-up table and remembers what it
// already read, so one directory listing serves every unit of a run.
type resolver struct {
	opts  Options
	units map[string]bool // names present in unitDir; nil until listed
	reads int
}

// plan returns the one bounded read for an item, or ok=false when the kind
// has none. It is a table, not a decision: no model picks a check, a path or
// an argument. docs/ROADMAP-RESEARCH.md ("The follow-up table") carries the
// table and what was tried before it.
//
// Two kinds have no entry. A listener's owning process is not a file, and a
// SUID binary's own tree (/usr/bin, /opt/*/bin) is outside the path policy's
// readable prefixes, so there is nothing to read about it that the policy
// admits; the world-writable correlation it needs comes from code instead.
func (rv *resolver) plan(ctx context.Context, it Item) (checkID, path string, ok bool) {
	if it.Kind != KindPersistence {
		return "", "", false
	}
	switch it.Fields["entry_kind"] {
	case "systemd unit":
		if !rv.unitPresent(ctx, it.Fields["unit"]) {
			return "", "", false
		}
		return "text.cat", unitDir + "/" + it.Fields["unit"], true
	case "cron entry":
		if p, ok := scriptPath(it.Fields["command"]); ok {
			return "text.cat", p, true
		}
	case "launchd job":
		return "text.cat", it.Fields["path"], true
	}
	return "", "", false
}

// unitPresent lists unitDir once per run and answers from the listing, so a
// run reads one directory instead of attempting a file per enabled unit.
func (rv *resolver) unitPresent(ctx context.Context, unit string) bool {
	if rv.units == nil {
		rv.units = map[string]bool{}
		res := rv.run(ctx, "fs.list", unitDir, "bounded follow-up: units defined on this host")
		if res.Status == runner.StatusOK {
			for l := range strings.SplitSeq(res.Raw, "\n") {
				if check.IsMarkerLine(l) {
					continue
				}
				if f := strings.Fields(l); len(f) > 0 {
					rv.units[f[len(f)-1]] = true
				}
			}
		}
	}
	return rv.units[unit]
}

// scriptPath returns the absolute program a cron command runs, when the
// command starts with one. Anything else (a shell pipeline, a relative
// path, a variable) is not followed: the table reads one named file, it
// does not interpret a command line.
func scriptPath(command string) (string, bool) {
	f := strings.Fields(command)
	if len(f) == 0 || !strings.HasPrefix(f[0], "/") {
		return "", false
	}
	if strings.ContainsAny(f[0], "*?[]{}$`\"'\\") {
		return "", false
	}
	return f[0], true
}

func (rv *resolver) run(ctx context.Context, id, path, rationale string) runner.Result {
	rv.reads++
	return rv.opts.Runner.RunAs(ctx, id, map[string]string{"path": path}, runner.Origin{
		Tool:      OriginTool,
		Rationale: rationale,
		Profile:   rv.opts.Profile,
	})
}

// resolve runs the item's follow-up read, if the table has one, and records
// what happened. An unavailable or denied read is not an error: it becomes
// a definition_note in the state, and the affirmative-evidence rule then
// files nothing on its own.
func (rv *resolver) resolve(ctx context.Context, it *Item) bool {
	id, path, ok := rv.plan(ctx, *it)
	if !ok {
		return false
	}
	res := rv.run(ctx, id, path, "bounded follow-up for "+it.Key)
	fu := &FollowUp{Check: res.CheckID, Path: path, Observation: res.Observation, Status: string(res.Status), Reason: res.Reason}
	switch {
	case res.Status != runner.StatusOK:
	case res.Truncated || res.Redactions > 0:
		fu.Reason = "truncated or redacted capture"
	default:
		fu.Output = res.Raw
	}
	it.FollowUp = fu
	return true
}
