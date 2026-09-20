package finding

import (
	"fmt"
	"strings"
	"time"

	"github.com/b87/scheck/internal/operator"
)

// Grader is the deterministic severity chain (docs/SPEC.md §7.2): base
// severity → structured-context adjustments (§6.3) → confidence cap (§5.3)
// → accepted-risk status → final severity. It is a table and a test; the
// model never touches it. A zero Grader grades every finding to its base.
type Grader struct {
	// Context is the merged structured context, or nil under
	// --ignore-context, in which case no adjustment is applied and
	// "unadjusted" is a precise claim (§6.4).
	Context *operator.Structured
	// Origins attributes each adjustment to the source that set the key.
	Origins map[string]string
	// EmulatedToolCalling caps a model finding's confidence at medium: a
	// parsed-from-text call is more error-prone (§5.3). Read from
	// Native.ToolCalling by the caller; the loop never branches on it.
	EmulatedToolCalling bool
	Now                 time.Time
}

// Step is one link of the chain, for `scheck explain FINDING-ID` (§8).
type Step struct {
	Stage  string `json:"stage"` // base | adjustment | cap | status | final
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

// Categories the exposure table applies to (§6.3).
const (
	CategoryRemoteAccess = "remote-access"
	CategoryNetwork      = "network"
	CategoryGovernance   = "governance"
)

// Grade returns the graded finding and the chain that produced it.
func (g Grader) Grade(f Finding) (Finding, []Step) {
	f.Adjustments = []Adjustment{}
	f.Severity = f.SeverityBase
	f.Status = StatusOpen
	f.AcceptedReason = ""
	steps := []Step{{Stage: "base", From: "", To: string(f.Severity), Reason: baseReason(f)}}
	if g.Context != nil {
		for _, adj := range g.adjustments(f) {
			next := shift(f.Severity, adj.delta)
			if f.Custom && next.Rank() > f.Severity.Rank() {
				// A custom finding is never adjusted upward (§7.1).
				steps = append(steps, Step{Stage: "adjustment", From: string(f.Severity), To: string(f.Severity),
					Reason: adj.rule + " ignored: custom findings are never escalated"})
				continue
			}
			if next == f.Severity {
				steps = append(steps, Step{Stage: "adjustment", From: string(f.Severity), To: string(next), Reason: adj.rule + " (already at the scale's end)"})
				continue
			}
			f.Adjustments = append(f.Adjustments, Adjustment{Rule: adj.rule, Source: adj.source, Delta: deltaString(adj.delta)})
			steps = append(steps, Step{Stage: "adjustment", From: string(f.Severity), To: string(next), Reason: adj.rule + " from " + adj.source})
			f.Severity = next
		}
	}
	if f.Custom && f.Severity.Rank() > SevMedium.Rank() {
		steps = append(steps, Step{Stage: "cap", From: string(f.Severity), To: string(SevMedium), Reason: "custom findings are capped at medium"})
		f.Severity = SevMedium
	}
	if g.EmulatedToolCalling && f.Source == SourceModel && f.Confidence == ConfidenceHigh {
		steps = append(steps, Step{Stage: "cap", From: "confidence high", To: "confidence medium", Reason: "tool calling was emulated (parsed from text)"})
		f.Confidence = ConfidenceMedium
	}
	if g.Context != nil {
		if r, ok := g.acceptance(f.ID); ok {
			if r.Expired(g.now()) {
				steps = append(steps, Step{Stage: "status", From: StatusOpen, To: StatusOpen,
					Reason: fmt.Sprintf("acceptance in %s expired on %s; it no longer suppresses this finding", r.Source, r.Expires)})
			} else {
				f.Status = StatusAccepted
				f.AcceptedReason = r.Reason
				steps = append(steps, Step{Stage: "status", From: StatusOpen, To: StatusAccepted, Reason: "accepted in " + r.Source + ": " + r.Reason})
			}
		}
	}
	steps = append(steps, Step{Stage: "final", From: "", To: string(f.Severity), Reason: f.Status})
	return f, steps
}

func (g Grader) now() time.Time {
	if g.Now.IsZero() {
		return time.Now()
	}
	return g.Now
}

func baseReason(f Finding) string {
	if f.Custom {
		return "proposed by the model for a custom finding, capped at medium"
	}
	return "catalog base severity for " + f.ID
}

type adjustment struct {
	rule   string
	source string
	delta  int
}

// adjustments is the fixed table of docs/SPEC.md §6.3, in the order it is
// applied: expected services first (they decide what a listener means),
// then exposure, then environment.
func (g Grader) adjustments(f Finding) []adjustment {
	var out []adjustment
	c := g.Context
	if f.Service != nil && len(c.ExpectedServices) > 0 {
		if svc, ok := g.expected(*f.Service); ok {
			// A declared listener is information, whatever the base says.
			out = append(out, adjustment{rule: "expected_service:" + svc.Key(), source: g.source("expected_services", svc.Source), delta: SevInfo.Rank() - f.SeverityBase.Rank()})
		} else if f.Category == CategoryNetwork {
			out = append(out, adjustment{rule: "unexpected_service:" + f.Service.Key(), source: g.source("expected_services", ""), delta: +1})
		}
	}
	switch c.Exposure {
	case "internet":
		if f.Category == CategoryRemoteAccess || f.Category == CategoryNetwork {
			out = append(out, adjustment{rule: "exposure:internet", source: g.source("exposure", ""), delta: +1})
		}
	case "airgapped":
		if f.Category == CategoryRemoteAccess {
			out = append(out, adjustment{rule: "exposure:airgapped", source: g.source("exposure", ""), delta: -2})
		}
	}
	if c.Environment == "dev" {
		out = append(out, adjustment{rule: "environment:dev", source: g.source("environment", ""), delta: -1})
	}
	return out
}

func (g Grader) expected(s ServiceRef) (operator.Service, bool) {
	for _, svc := range g.Context.ExpectedServices {
		if svc.Port == s.Port && strings.EqualFold(svc.Proto, s.Proto) {
			return svc, true
		}
	}
	return operator.Service{}, false
}

func (g Grader) acceptance(id string) (operator.Risk, bool) {
	for _, r := range g.Context.AcceptedRisks {
		if r.ID == id {
			return r, true
		}
	}
	return operator.Risk{}, false
}

// source attributes an adjustment: "<source>#context.<key>" (§6.4).
func (g Grader) source(key, entrySource string) string {
	src := entrySource
	if src == "" {
		src = g.Origins[key]
	}
	if src == "" {
		src = "context"
	}
	if strings.HasPrefix(src, "flag ") {
		return src // reproduced on the command line (`scheck explain`)
	}
	if strings.HasSuffix(src, "#context") {
		return src + "." + key
	}
	return src + "#context." + key
}

// shift moves a severity by delta steps, clamped to the scale.
func shift(s Severity, delta int) Severity {
	scale := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	r := s.Rank() + delta
	r = max(0, min(len(scale)-1, r))
	return scale[r]
}

func deltaString(d int) string {
	if d > 0 {
		return fmt.Sprintf("+%d", d)
	}
	return fmt.Sprint(d)
}

// ExpiredAcceptances turns every lapsed accepted_risks entry into a
// finding of its own (§6.3): the operator's record is out of date and the
// finding it named is no longer suppressed.
func (g Grader) ExpiredAcceptances(platform string) []Finding {
	if g.Context == nil {
		return nil
	}
	var out []Finding
	for _, r := range g.Context.AcceptedRisks {
		if !r.Expired(g.now()) {
			continue
		}
		def, _ := Lookup(IDAcceptanceExpired)
		out = append(out, Finding{
			ID: def.ID, Title: def.Title, Category: def.Category,
			SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity,
			Adjustments: []Adjustment{}, Status: StatusOpen, Source: SourceRule,
			Confidence: ConfidenceHigh, Platform: platform,
			Evidence: []Evidence{{Check: "context", Excerpt: fmt.Sprintf("%s: accepted_risks %s expired %s (%s)", r.Source, r.ID, r.Expires, r.Reason)}},
			Impact:   def.Impact, Remediation: def.Remediation,
			ContextNote: "acceptance of " + r.ID + " expired on " + r.Expires,
		})
	}
	return out
}
