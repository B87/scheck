package runner

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/b87/scheck/internal/check"
)

// Observations retains every policy-processed invocation for one run (§3, §7.4).
// Callers receive copies: neither a later call nor a consumer can change evidence.
// Collection is bounded by the baseline plan and the existing agent check budgets.
type Observations struct {
	mu      sync.Mutex
	results []Result
	byRef   map[string]int
	counts  map[string]int
}

// Observations is the shared evidence store for this runner's lifetime (one run).
func (r *Runner) Observations() *Observations { return &r.observations }

// Get resolves an exact run-local reference, never a check ID or latest result.
func (s *Observations) Get(ref string) (Result, bool) {
	if s == nil {
		return Result{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.byRef[ref]
	if !ok {
		return Result{}, false
	}
	return cloneResult(s.results[i]), true
}

// All returns observations in collection order, including prerequisite probes.
func (s *Observations) All() []Result {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Result, len(s.results))
	for i, r := range s.results {
		out[i] = cloneResult(r)
	}
	return out
}

func (r *Runner) retain(res Result) Result {
	// Request metadata is untrusted too. Redact before audit, storage, or return (§4.2).
	redact := func(s string) string { v, _ := r.Redactor.RedactString(s); return v }
	res.CheckID, res.RanAs = redact(res.CheckID), redact(res.RanAs)
	// Other reasons are static or derived from already-filtered captures. Applying
	// the redactor twice could consume an existing marker as a key/value secret.
	switch res.ReasonCode {
	case "invalid_params", "path_denied", "exec_error":
		res.Reason = redact(res.Reason)
	}
	params := make(map[string]string, len(res.Params))
	for k, v := range res.Params {
		key := redact(k)
		// Keep the parameter name beside its value for key/value secret rules.
		value := redact(k + "=" + v)
		params[key] = strings.TrimPrefix(value, key+"=")
	}
	res.Params = params
	res.Argv = slices.Clone(res.Argv)
	for i, v := range res.Argv {
		res.Argv[i] = redact(v)
	}
	res.origin.Rationale = redact(res.origin.Rationale)
	s := &r.observations
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byRef == nil {
		s.byRef = map[string]int{}
		s.counts = map[string]int{}
	}
	prefix := res.CheckID
	if _, ok := check.Lookup(prefix, r.Target.Platform()); !ok {
		prefix = "unknown"
	}
	s.counts[prefix]++
	res.Observation = fmt.Sprintf("%s#%d", prefix, s.counts[prefix])
	res.Occurrence = len(s.results) + 1
	s.byRef[res.Observation] = len(s.results)
	s.results = append(s.results, cloneResult(res))
	return res
}

func cloneResult(r Result) Result {
	r.Params = maps.Clone(r.Params)
	r.Argv = slices.Clone(r.Argv)
	r.Parsed = cloneParsed(r.Parsed)
	return r
}

// The parser's closed output shapes (§3); JSON recursively uses maps and slices.
func cloneParsed(v any) any {
	switch v := v.(type) {
	case check.Records:
		v.Items = slices.Clone(v.Items)
		for i, item := range v.Items {
			v.Items[i] = maps.Clone(item)
		}
		return v
	case map[string]string:
		return maps.Clone(v)
	case []string:
		return slices.Clone(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = cloneParsed(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = cloneParsed(x)
		}
		return out
	default:
		return v
	}
}
