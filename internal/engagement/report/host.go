package report

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
	hostreport "github.com/b87/scheck/internal/report"
)

// plumbing are the host domains that carry no rule by design: they say who
// the host is and how the session runs. They are not coverage
// (docs/spec/report.md, "Coverage").
var plumbing = []check.Domain{check.DomainHost, check.DomainOS, check.DomainSys, check.DomainText}

// hostView reads one collected host asset.
type hostView struct {
	a        AssetInput
	h        *HostInput
	env      hostreport.Envelope
	platform check.Platform
	// at is when each observation ran, and exit its exit code, from the
	// asset's trace.
	at   map[string]time.Time
	exit map[string]int
	// byID groups the envelope's assessments by finding id, in order.
	ids  []string
	byID map[string][]finding.Assessment
}

func newHostView(a AssetInput) *hostView {
	v := &hostView{a: a, h: a.Host, env: a.Host.Envelope, platform: check.Platform(a.Host.Envelope.Host.Platform),
		at: map[string]time.Time{}, exit: map[string]int{}, byID: map[string][]finding.Assessment{}}
	for _, e := range a.Trace {
		if e.Observation != "" {
			v.at[e.Observation] = e.Time
			if e.ExitCode != nil {
				v.exit[e.Observation] = *e.ExitCode
			}
		}
	}
	for _, as := range v.env.Assessments {
		if _, seen := v.byID[as.Finding]; !seen {
			v.ids = append(v.ids, as.Finding)
		}
		v.byID[as.Finding] = append(v.byID[as.Finding], as)
	}
	return v
}

func decided(a finding.Assessment) bool { return a.Status != finding.NotAssessed }

// answered is a rule that read its fact and judged it: matched or not.
// Not applicable is no answer about the host.
func answered(a finding.Assessment) bool {
	return a.Status == finding.Matched || a.Status == finding.NotMatched
}

// excused reports whether a rule that could not decide is an alternative
// to a sibling that did: rules sharing a finding id on one host are a
// family, and a package manager that is not installed does not lower the
// mark when another one answered (docs/spec/report.md, "Coverage").
func (v *hostView) excused(a finding.Assessment) bool {
	if decided(a) || a.Reason != "check-unavailable:command_missing" {
		return false
	}
	return slices.ContainsFunc(v.byID[a.Finding], answered)
}

// reason maps a rule that could not decide to the coverage reason list
// (docs/spec/report.md, "Coverage", the host mapping table).
func (v *hostView) reason(a finding.Assessment) ReasonDetail {
	// A reason prefixed "with-" is the rule's second check's: coverage names
	// that check, not the one that ran.
	if r, ok := strings.CutPrefix(a.Reason, finding.ReasonWith); ok && a.With != "" {
		a.Check, a.Observation, a.Reason = a.With, a.WithObservation, r
	}
	code, rc, _ := strings.Cut(a.Reason, ":")
	fact := v.env.Facts[a.Check]
	detail := a.Check
	if fact.Summary != "" {
		detail += ": " + fact.Summary
	}
	switch code {
	case "check-disabled-by-config":
		return ReasonDetail{"excluded_by_operator", a.Check + ": disable_checks"}
	case "check-not-run":
		if v.h.Lost != "" {
			return ReasonDetail{"failed", a.Check + ": not run, the connection was lost"}
		}
		return ReasonDetail{"limit_reached", a.Check + ": not run, the run timeout ended the collection"}
	case "check-unavailable", "check-denied":
		switch rc {
		case "requires_elevation", "sudo_refused":
			return ReasonDetail{"insufficient_permission:sudo", detail}
		case "run_timeout", "canceled":
			return ReasonDetail{"limit_reached", detail}
		case "path_denied":
			if strings.HasPrefix(fact.Reason, policy.RuleConfigDeny) {
				return ReasonDetail{"excluded_by_operator", detail}
			}
		case "":
			rc = "unknown"
		}
		return ReasonDetail{"unavailable:" + rc, detail}
	}
	// The check ran, but the rule could not read what it returned.
	return ReasonDetail{"unavailable:" + strings.ReplaceAll(code, "-", "_"), detail}
}

// assessments is one record per rule and asset: a family of rules sharing a
// finding id decides when any of them answered, and is complete when every
// member that is not an excused alternative or not applicable decided. A
// family with no member that answered is not assessed, unless every member
// is not applicable.
func (v *hostView) assessments() []Assessment {
	out := []Assessment{}
	for _, id := range v.ids {
		group := v.byID[id]
		ea := Assessment{ID: id, Asset: v.a.ID, Status: finding.NotAssessed, Complete: true, Reads: []string{}}
		notApplicable := 0
		for _, as := range group {
			ea.Reads = appendUnique(ea.Reads, "check:"+as.Check)
			if as.With != "" {
				ea.Reads = appendUnique(ea.Reads, "check:"+as.With)
			}
			for _, obs := range []string{as.Observation, as.WithObservation} {
				if obs != "" {
					ea.Observations = appendUnique(ea.Observations, obs)
				}
			}
			if answered(as) && !v.whole(as) {
				// It answered, but from part of what is there: an absence
				// here is not an absence on the host.
				ea.Complete = false
			}
			switch {
			case as.Status == finding.Matched:
				ea.Status, ea.Instances = finding.Matched, 1
			case as.Status == finding.NotMatched && ea.Status != finding.Matched:
				ea.Status = finding.NotMatched
			case as.Status == finding.NotApplicable:
				notApplicable++
			case !v.excused(as):
				ea.Complete = false
				if ea.Reason == "" {
					ea.Reason = v.reason(as).Reason
				}
			}
		}
		switch {
		case ea.Status == finding.NotAssessed && notApplicable == len(group):
			ea.Status = finding.NotApplicable
		case ea.Status == finding.NotAssessed:
			ea.Complete = false
		}
		out = append(out, ea)
	}
	return out
}

// whole reports whether a rule read its whole population: not a sampled
// check, not a truncated capture, not a command whose non-zero exit was
// tolerated (a find that could not enter some directories still answers).
func (v *hostView) whole(as finding.Assessment) bool {
	if !v.wholeCheck(as.Check, as.Observation) {
		return false
	}
	// A rule that joins a second check read it too (host-collector.md §6.5),
	// when that check gave a fact: a disproof that never needed it (no
	// account without a password) is not made partial by its failure.
	if as.WithObservation == "" || v.env.Facts[as.With].Status != "ok" {
		return true
	}
	return v.wholeCheck(as.With, as.WithObservation)
}

func (v *hostView) wholeCheck(id, observation string) bool {
	if c, ok := check.Lookup(id, v.platform); ok && c.Sampled {
		return false
	}
	if f, ok := v.env.Facts[id]; ok && f.Truncated {
		return false
	}
	if code, ok := v.exit[observation]; ok && code != 0 {
		return false
	}
	return true
}

// domains is the Hosts row's expansion for this host: one sub-item per
// host domain that carries a rule or that was read and no rule judges.
func (v *hostView) domains() []SubItem {
	type dom struct {
		rules         []finding.Assessment
		notApplicable int
		read          map[string]string // check id -> what it read, for checks that answered
		unread        []string
	}
	byDomain := map[check.Domain]*dom{}
	get := func(d check.Domain) *dom {
		if byDomain[d] == nil {
			byDomain[d] = &dom{read: map[string]string{}}
		}
		return byDomain[d]
	}
	for _, id := range v.ids {
		for _, as := range v.byID[id] {
			c, ok := check.Lookup(as.Check, v.platform)
			switch {
			case !ok || v.excused(as):
				continue
			case as.Status == finding.NotApplicable:
				get(c.Domain).notApplicable++
				continue
			}
			get(c.Domain).rules = append(get(c.Domain).rules, as)
		}
	}
	for _, id := range sortedKeys(v.env.Facts) {
		c, ok := check.Lookup(id, v.platform)
		if !ok || slices.Contains(plumbing, c.Domain) {
			continue
		}
		if f := v.env.Facts[id]; f.Status == "ok" {
			get(c.Domain).read[id] = f.Summary
		} else {
			get(c.Domain).unread = append(get(c.Domain).unread, id)
		}
	}
	var order []check.Domain
	for d := range byDomain {
		order = append(order, d)
	}
	slices.SortFunc(order, func(x, y check.Domain) int { return hostreport.DomainRank(x) - hostreport.DomainRank(y) })
	var out []SubItem
	for _, d := range order {
		dm := byDomain[d]
		si := SubItem{Name: hostreport.DomainLabel(d), Asset: v.a.ID, Reasons: []ReasonDetail{}}
		if len(dm.rules) == 0 && dm.notApplicable > 0 {
			si.Mark = "not_applicable"
			out = append(out, si)
			continue
		}
		// What was read that no rule here judges: a person can judge it,
		// and "checked" never stretches to cover it.
		judged := map[string]bool{}
		for _, as := range dm.rules {
			judged[as.Check] = true
			if as.With != "" {
				judged[as.With] = true
			}
		}
		var notJudged []string
		for _, id := range sortedKeys(dm.read) {
			if !judged[id] {
				notJudged = append(notJudged, dm.read[id])
			}
		}
		if len(dm.rules) == 0 {
			si.Mark = "not_assessed"
			// The detail is what was read, so a person can judge it, and
			// what was not.
			var detail []string
			if len(notJudged) > 0 {
				detail = append(detail, "read: "+strings.Join(notJudged, "; "))
			}
			if len(dm.unread) > 0 {
				detail = append(detail, "not read: "+strings.Join(dm.unread, ", "))
			}
			si.Reasons = append(si.Reasons, ReasonDetail{"no_rule", strings.Join(detail, "; ")})
			out = append(out, si)
			continue
		}
		n := 0
		for _, as := range dm.rules {
			si.Rules = appendUnique(si.Rules, as.Finding)
			if decided(as) {
				n++
				if def, ok := finding.Lookup(as.Finding); ok && def.Judges != "" {
					si.Judged = appendUnique(si.Judged, def.Judges)
				}
				continue
			}
			si.Reasons = appendReason(si.Reasons, v.reason(as))
		}
		si.ReadNotJudged = notJudged
		si.Population = &Population{Kind: "rules", InScope: len(dm.rules), Read: n}
		si.Mark = markOf(n, len(dm.rules))
		out = append(out, si)
	}
	return out
}

// checks counts the plan: what ran, what gave no usable answer, and what
// a cut collection never reached.
func (v *hostView) checks() Checks {
	c := Checks{}
	planned := map[string]bool{}
	for _, id := range v.h.Planned {
		planned[id] = true
	}
	for id, f := range v.env.Facts {
		planned[id] = true
		if f.Status == "ok" {
			c.Ran++
		} else {
			c.Unknown++
		}
	}
	c.Planned = len(planned)
	c.NotRun = c.Planned - c.Ran - c.Unknown
	return c
}

// principal is who an observation was read as.
func (v *hostView) principal(observation string) string {
	o, ok := v.env.Observations[observation]
	if ok && o.Elevated && v.env.Host.Elevation == "sudo" {
		return v.h.User + " (sudo -n)"
	}
	return v.h.User
}

// findings converts the host's graded findings. The host collector's chain
// is kept as the collector's; the engagement appends none of its own in
// 0.0.2 for a host (docs/spec/engagement.md, "Severity in context").
func (b *builder) hostFindings(v *hostView) []Finding {
	var out []Finding
	bound := v.env.Host.ID
	for _, f := range v.env.Findings {
		if f.ID == finding.IDAcceptanceExpired {
			// The lapsed entry is a record about the file, not the host:
			// the acceptance's outcome and the reopened finding say it.
			continue
		}
		def, _ := finding.Lookup(f.ID)
		area := string(def.Area)
		if area == "" {
			area = string(finding.AreaHosts)
		}
		ef := Finding{
			Key: Key{ID: f.ID, Asset: v.a.ID}, AssetName: v.a.Name, BoundID: &bound,
			ID: f.ID, Title: f.Title, Area: area, Category: f.Category,
			ExposureFinding: def.Exposure == finding.IsExposure,
			SeverityBase:    string(f.SeverityBase), Severity: string(f.Severity),
			Adjustments: []Adjustment{}, Status: f.Status,
			Rule:   Rule{Kind: "single_fact", Reads: []string{}},
			Impact: f.Impact, WhyHere: []string{}, NotChecked: []string{},
			Remediation: Remediation{Summary: f.Remediation.Summary, Commands: f.Remediation.Commands, Caveat: f.Remediation.Caveat},
		}
		for _, as := range v.byID[f.ID] {
			ef.Rule.Reads = appendUnique(ef.Rule.Reads, "check:"+as.Check)
			if as.With != "" {
				ef.Rule.Reads = appendUnique(ef.Rule.Reads, "check:"+as.With)
			}
		}
		for _, e := range f.Evidence {
			if e.Check != "context" {
				ef.Rule.Reads = appendUnique(ef.Rule.Reads, "check:"+e.Check)
			}
		}
		for _, adj := range f.Adjustments {
			src := sourceRef(adj.Source)
			ef.Adjustments = append(ef.Adjustments, Adjustment{Rule: adj.Rule, By: "collector", Delta: adj.Delta, Source: src})
			if line := whyHere(adj.Rule, v.a.Name, src); line != "" {
				ef.WhyHere = append(ef.WhyHere, line)
			}
		}
		for _, e := range f.Evidence {
			if e.Check == "context" {
				ef.Evidence = append(ef.Evidence, Evidence{Kind: "declared", Source: v.h.ExpectedSource, Excerpt: e.Excerpt})
				continue
			}
			at := v.collectedAt(e.Observation)
			ef.Evidence = append(ef.Evidence, Evidence{Kind: "observed", Asset: v.a.ID, Check: e.Check,
				Observation: e.Observation, CollectedAt: &at, Principal: v.principal(e.Observation), Excerpt: e.Excerpt})
		}
		if f.Status == finding.StatusAccepted {
			ef.Acceptance = b.findingAcceptance(v.a.ID, f.ID, f.AcceptedReason)
		} else {
			ef.AcceptTemplate = b.template(v.a, f.ID, f.Severity)
		}
		out = append(out, ef)
	}
	return out
}

func (v *hostView) collectedAt(observation string) time.Time {
	if t, ok := v.at[observation]; ok {
		return t.UTC()
	}
	return v.env.Run.Started.UTC()
}

// sourceRef reads the host grader's attribution, "<file> assets.<name>#context.<key>",
// as a declaration in the engagement file.
func sourceRef(src string) SourceRef {
	before, key, ok := strings.Cut(src, "#context.")
	if !ok {
		return SourceRef{File: src, Key: "context"}
	}
	if i := strings.LastIndex(before, " "); i >= 0 {
		return SourceRef{File: before[:i], Key: before[i+1:] + ".context." + key}
	}
	return SourceRef{File: before, Key: "context." + key}
}

// whyHere is the templated line a context adjustment prints, from the
// declaration only; no line is written from free text.
func whyHere(rule, asset string, src SourceRef) string {
	where := " (" + src.Key + ")."
	kind, arg, _ := strings.Cut(rule, ":")
	switch {
	case rule == "exposure:internet":
		return "You declared " + asset + " internet-facing" + where
	case rule == "exposure:airgapped":
		return "You declared " + asset + " air-gapped" + where
	case rule == "environment:dev":
		return "You declared " + asset + " a development host" + where
	case kind == "expected_service":
		return "You declared " + arg + " an expected service on " + asset + where
	case kind == "unexpected_service":
		return arg + " is not among the services you declared for " + asset + where
	}
	return ""
}

// markerRe finds a redaction marker (docs/spec/host-collector.md §4.2).
var markerRe = regexp.MustCompile(`\[REDACTED:([^\]]+):(\d+) bytes\]`)

// redactions counts the markers in this host's captures: built-in rules by
// rule, and the operator's redact_extra matches.
//
// The runner's count per observation is the total. The markers in a
// capture name the rules only when they account for exactly that total: a
// target can print a marker-shaped string, and a marker in stderr or cut by
// truncation is not in the capture. What they do not account for is counted
// as "unattributed", never invented.
func (v *hostView) redactions(builtin map[string]int) (operator int) {
	for _, o := range v.env.Observations {
		if o.Redactions == 0 {
			continue
		}
		ms := markerRe.FindAllStringSubmatch(o.Output, -1)
		if len(ms) != o.Redactions {
			builtin["unattributed"] += o.Redactions
			continue
		}
		for _, m := range ms {
			rule := m[1]
			if strings.HasPrefix(rule, "extra:") || strings.HasPrefix(rule, "redact_extra") {
				operator++
				continue
			}
			builtin[rule]++
		}
	}
	return operator
}

func markOf(read, of int) string {
	switch {
	case of > 0 && read == of:
		return "assessed"
	case read > 0:
		return "partial"
	}
	return "not_assessed"
}

func appendUnique[T comparable](s []T, v T) []T {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// appendReason keeps one entry per reason, joining the details.
func appendReason(rs []ReasonDetail, r ReasonDetail) []ReasonDetail {
	for i := range rs {
		if rs[i].Reason == r.Reason {
			if r.Detail != "" && !strings.Contains(rs[i].Detail, r.Detail) {
				rs[i].Detail = joinDetail(rs[i].Detail, r.Detail)
			}
			return rs
		}
	}
	return append(rs, r)
}

func joinDetail(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Checks counts a host's plan.
type Checks struct {
	Planned int `json:"planned"`
	Ran     int `json:"ran"`
	Unknown int `json:"unknown"`
	NotRun  int `json:"not_run"`
}
