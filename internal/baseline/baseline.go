// Package baseline is phase 1: run the platform's Baseline checks through the
// runner and collect a fact sheet (docs/SPEC.md §2.1). No model is involved.
package baseline

import (
	"context"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// FactSheet is the ordered outcome of phase 1.
type FactSheet struct {
	Observations *runner.Observations
	Platform     check.Platform
	Order        []string // check ids in execution order
	Results      map[string]runner.Result
	// Incomplete is set when the run context ended before every check ran.
	Incomplete bool
}

// Get returns the result for id.
func (f *FactSheet) Get(id string) (runner.Result, bool) {
	r, ok := f.Results[id]
	return r, ok
}

// Raw returns the trimmed raw output of an ok check, or "".
func (f *FactSheet) Raw(id string) string {
	if r, ok := f.Results[id]; ok && r.Status == runner.StatusOK {
		return strings.TrimSpace(r.Raw)
	}
	return ""
}

// Plan lists the checks phase 1 will run on platform p, minus the ids in
// disabled (config `disable_checks`, which may only subtract).
func Plan(p check.Platform, disabled []string) []check.Check {
	skip := map[string]bool{}
	for _, id := range disabled {
		skip[id] = true
	}
	var out []check.Check
	for _, c := range check.Baseline(p) {
		if !skip[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

// Run executes plan sequentially. It stops early when ctx ends and marks the
// sheet incomplete; every check that did not run is absent from Results.
func Run(ctx context.Context, r *runner.Runner, plan []check.Check, progress func(runner.Result)) *FactSheet {
	fs := &FactSheet{Observations: r.Observations(), Platform: r.Target.Platform(), Results: map[string]runner.Result{}}
	for _, c := range plan {
		if ctx.Err() != nil {
			fs.Incomplete = true
			break
		}
		res := r.Run(ctx, c.ID, nil)
		fs.Order = append(fs.Order, c.ID)
		fs.Results[c.ID] = res
		if progress != nil {
			progress(res)
		}
	}
	return fs
}

// DetectRoot runs sys.uid and reports whether the session is uid 0, so the
// caller can switch the runner to ElevateRoot before the baseline runs.
func DetectRoot(ctx context.Context, r *runner.Runner) bool {
	res := r.Run(ctx, "sys.uid", nil)
	return res.Status == runner.StatusOK && strings.TrimSpace(res.Raw) == "0"
}
