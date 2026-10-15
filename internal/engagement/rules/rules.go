// Package rules is the engagement's multi-fact rules
// (docs/spec/engagement.md, "Multi-fact rules", "The multi-fact rules of
// 0.0.2"): rules over several facts of one host and its declared context,
// each reading only what it declares, each judgment fired, disproved or
// abstained. Analyze calls Judge; the verdicts are finding.Judgment, graded
// by internal/engagement/severity and rendered by the report like a network
// collector's. The package reads facts already collected and never runs
// anything.
package rules

import (
	"slices"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
)

// The verdicts of a judgment.
const (
	Fired     = "fired"
	Disproved = "disproved"
	Abstained = "abstained"
)

// ReasonIncomplete is a disproval the framework withdrew because a fact the
// rule read is known to be incomplete: it may show presence, never absence
// (docs/spec/scope.md, "Responses").
const ReasonIncomplete = "unavailable:incomplete_read"

// ReadKind is what a declared read names.
type ReadKind string

// The kinds of read.
const (
	// ReadCheck is a host check's fact, by catalog id.
	ReadCheck ReadKind = "check"
	// ReadDeclared is a declaration of the host's context, by its key
	// under the asset ("exposure", "expected_services").
	ReadDeclared ReadKind = "declared"
)

// Read is one thing a rule reads.
type Read struct {
	Kind ReadKind
	Name string
}

// DeclaredServices is the host's expected_services, the one declaration
// a rule reads in this build; the exposure raise is the severity table's.
const DeclaredServices = "expected_services"

// Rule is one multi-fact rule over a host.
type Rule struct {
	// ID is the finding it produces, a registered multi-fact definition.
	ID string
	// Platform is the host platform it judges; on another, it is not built
	// and the coverage says so (Unbuilt).
	Platform check.Platform
	Reads    []Read
	Judge    func(v *View) []Outcome
	// Group names the rule's coverage sub-item, and Unbuilt says why a host
	// of another platform is not judged.
	Group, Unbuilt string
	// Incomplete words the coverage of a host whose read the rule could
	// not complete.
	Incomplete finding.CoverageReason
	// HostDomain is the host area whose Hosts-row line also says what the
	// rule judged, in HostJudges words ("" for the definition's Judges).
	HostDomain check.Domain
	HostJudges string
}

// Facts are a host's facts as a rule reads them: finding.Facts.
type Facts interface {
	Fact(id string) (finding.Fact, string)
	Platform() check.Platform
}

// Host is one host asset as the rules read it.
type Host struct {
	Asset, Name string
	Facts       Facts
	Context     Context
}

// Context is the host's declared context the rules may read.
type Context struct {
	Services []Service
}

// Service is one expected_services entry.
type Service struct {
	Port            int
	Proto, Audience string
	Key             string
}

// Excerpt is what one fact shows that a judgment rests on.
type Excerpt struct{ Check, Text string }

// Outcome is a rule's verdict on one subject, or on the host when Subject
// is zero.
type Outcome struct {
	Subject    finding.Subject
	Verdict    string
	Reason     string
	Excerpts   []Excerpt
	Attributes []finding.Attribute
	NotChecked []string
	Why        string
	Details    map[string]any
	// Listed are the instances a judgment with no subject is about.
	Listed []string
	// Incomplete says the rule could not read the whole population the
	// verdict is about, so the host's coverage is partial.
	Incomplete bool
}

// Result is a host's judgments and the coverage they are marked against.
type Result struct {
	Judged   []finding.Judgment
	Coverage []finding.CoveragePlan
	// PopulationIncomplete says a rule could not read the whole of what it
	// judges on this host.
	PopulationIncomplete bool
}

// View is all a rule sees of a host: the reads it declared. A read it did
// not declare answers nothing and is recorded, so the invariants test
// rejects the rule.
type View struct {
	host       Host
	rule       Rule
	touched    []finding.Fact
	undeclared []string
	// used are the declared reads the rule made, for the invariants test.
	used []Read
}

func (v *View) declares(kind ReadKind, name string) bool {
	if slices.Contains(v.rule.Reads, Read{kind, name}) {
		if !slices.Contains(v.used, Read{kind, name}) {
			v.used = append(v.used, Read{kind, name})
		}
		return true
	}
	v.undeclared = append(v.undeclared, string(kind)+":"+name)
	return false
}

// Name is the host's name in the engagement file.
func (v *View) Name() string { return v.host.Name }

// Fact is a declared check's fact, or why there is none.
func (v *View) Fact(id string) (finding.Fact, string) {
	if !v.declares(ReadCheck, id) {
		return finding.Fact{Check: id}, "undeclared-read"
	}
	f, why := v.host.Facts.Fact(id)
	// An unusable fact is cited too: "not installed" is its observation's.
	if !slices.ContainsFunc(v.touched, func(t finding.Fact) bool { return t.Check == id }) {
		v.touched = append(v.touched, f)
	}
	return f, why
}

// Services are the host's expected services, if the rule declared them.
func (v *View) Services() []Service {
	if !v.declares(ReadDeclared, DeclaredServices) {
		return nil
	}
	return slices.Clone(v.host.Context.Services)
}

// registry is every multi-fact rule over a host, in order.
var registry []Rule

// All are the rules, in order.
func All() []Rule { return slices.Clone(registry) }

// Judge runs every rule over each host: its judgments, and one coverage
// plan per area the rules read, by asset id.
func Judge(hosts []Host) map[string]Result {
	out := map[string]Result{}
	for _, h := range hosts {
		out[h.Asset] = judgeHost(h, registry)
	}
	return out
}

func judgeHost(h Host, rules []Rule) Result {
	var res Result
	plans := map[finding.Area]*finding.CoveragePlan{}
	var areas []finding.Area
	for _, r := range rules {
		def, _ := finding.Lookup(r.ID)
		plan := plans[def.Area]
		if plan == nil {
			plan = &finding.CoveragePlan{Area: def.Area, Label: h.Name, Incomplete: r.Incomplete}
			plans[def.Area] = plan
			areas = append(areas, def.Area)
		}
		if r.Platform != check.Any && h.Facts.Platform() != r.Platform {
			plan.Unread = append(plan.Unread, finding.CoverageUnread{Name: r.Group, Detail: r.Unbuilt})
			continue
		}
		judges := r.HostJudges
		if judges == "" {
			judges = def.Judges
		}
		plan.Groups = append(plan.Groups, finding.CoverageGroup{Name: r.Group, Rules: []string{r.ID}, HostDomain: r.HostDomain, HostJudges: judges})
		js, incomplete := run(r, h)
		res.Judged = append(res.Judged, js...)
		res.PopulationIncomplete = res.PopulationIncomplete || incomplete
	}
	for _, a := range areas {
		res.Coverage = append(res.Coverage, *plans[a])
	}
	return res
}

// run is one rule over one host, its outcomes finished by the framework:
// a disproval resting on an incomplete fact is withdrawn, and each
// judgment names the facts and declarations the rule read.
func run(r Rule, h Host) ([]finding.Judgment, bool) {
	v := &View{host: h, rule: r}
	outcomes := r.Judge(v)
	partial := slices.ContainsFunc(v.touched, func(f finding.Fact) bool { return f.Partial })
	incomplete := false
	var out []finding.Judgment
	for _, o := range outcomes {
		if o.Verdict == Disproved && partial {
			o.Verdict, o.Reason = Abstained, ReasonIncomplete
		}
		incomplete = incomplete || o.Incomplete || o.Reason == ReasonIncomplete
		j := finding.Judgment{ID: r.ID, Asset: h.Asset, Subject: o.Subject, Verdict: o.Verdict, Reason: o.Reason,
			Reads: []string{}, NotChecked: o.NotChecked, Attributes: o.Attributes, Why: o.Why, Details: o.Details, Listed: o.Listed}
		for _, e := range o.Excerpts {
			obs := ""
			for _, t := range v.touched {
				if t.Check == e.Check {
					obs = t.Observation
				}
			}
			j.Facts = append(j.Facts, finding.FactRead{Check: e.Check, Observation: obs, Excerpt: e.Text})
		}
		for _, a := range o.Attributes {
			if a.Ref.Key != "" && !slices.Contains(j.Sources, a.Ref.Key) {
				j.Sources = append(j.Sources, a.Ref.Key)
			}
		}
		out = append(out, j)
	}
	return out, incomplete
}
