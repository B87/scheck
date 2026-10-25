package compare

import (
	"slices"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/report"
)

var t0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// lab builds a minimal report: enough for a comparison, not for the report
// schema.
type lab struct{ *report.Report }

func newLab(version string, started time.Time) *lab {
	return &lab{&report.Report{
		SchemaVersion: report.SchemaVersion, ScheckVersion: version, RulesVersion: version,
		Run: report.Run{Started: started, SessionStarted: started, Vantage: "internet"},
		Engagement: report.Engagement{Name: "acme", Timezone: "UTC", BuiltFrom: "file",
			Source:    report.Source{SHA256: "aaaa"},
			Collected: report.Span{From: started, To: started.Add(10 * time.Minute)}},
		Exit:      report.Exit{Code: 1, Thresholds: map[string]report.Threshold{}},
		Redaction: report.Redaction{Builtin: map[string]int{}},
	}}
}

func (l *lab) asset(id, name, kind, status, bound string) *report.Asset {
	a := report.Asset{Name: name, ID: id, Kind: kind, Status: status, Root: true}
	if bound != "" {
		a.BoundID = &bound
		a.BoundIDSource = "provider_id"
		if kind == "host" {
			a.BoundIDSource = "machine_id"
		}
	}
	l.Assets = append(l.Assets, a)
	return &l.Assets[len(l.Assets)-1]
}

func (l *lab) principal(id, identity string) {
	for i := range l.Assets {
		if l.Assets[i].ID == id {
			l.Assets[i].Principal = &report.Principal{Identity: identity, ScopesSource: "provider"}
		}
	}
}

// rule records a rule's decision on an asset.
func (l *lab) rule(id, asset, status string, complete bool, outcomes ...report.AssessmentOutcome) {
	l.Assessments = slices.DeleteFunc(l.Assessments, func(a report.Assessment) bool { return a.ID == id && a.Asset == asset })
	l.Assessments = append(l.Assessments, report.Assessment{ID: id, Asset: asset, Status: status, Complete: complete, Reads: []string{}, Outcomes: outcomes})
}

// notMatched records a rule that decided on a complete population and found
// nothing.
func (l *lab) notMatched(id, asset string) { l.rule(id, asset, "not_matched", true) }

// find records an open finding and the matched assessment that produced it.
func (l *lab) find(id, asset, subject, severity string, reads ...string) *report.Finding {
	name := asset
	for _, a := range l.Assets {
		if a.ID == asset {
			name = a.Name
		}
	}
	f := report.Finding{
		Key: report.Key{ID: id, Asset: asset}, AssetName: name, ID: id, Title: id + " title", Area: "hosts",
		SeverityBase: severity, Severity: severity, Status: "open", Adjustments: []report.Adjustment{},
		Rule: report.Rule{Kind: "single_fact", Reads: reads}, NotChecked: []string{},
	}
	if subject != "" {
		s := subject
		f.Key.Subject = &s
		f.Subject = &report.Subject{Kind: "account", Key: subject, Label: subject}
	}
	if b := l.bound(asset); b != nil {
		f.BoundID = b
	}
	l.Findings = append(l.Findings, f)
	if !slices.ContainsFunc(l.Assessments, func(a report.Assessment) bool { return a.ID == id && a.Asset == asset }) {
		l.rule(id, asset, "matched", true)
	}
	return &l.Findings[len(l.Findings)-1]
}

func (l *lab) bound(asset string) *string {
	for _, a := range l.Assets {
		if a.ID == asset {
			return a.BoundID
		}
	}
	return nil
}

func compareOK(t *testing.T, e, l *lab) *Comparison {
	t.Helper()
	c, err := Compare(Input{Report: e.Report, SHA256: "e", RunRecordChecked: true}, Input{Report: l.Report, SHA256: "l", RunRecordChecked: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// pairLab is the common starting point: the same release build, the same
// file, the same hosts, one weakness on each run's web host.
func pairLab() (e, l *lab) {
	e = newLab("0.0.3", t0)
	l = newLab("0.0.3", t0.Add(14*24*time.Hour))
	for _, r := range []*lab{e, l} {
		r.asset("host:203.0.113.6:22", "web", "host", "collected", "B-web")
	}
	return e, l
}

// category returns the category of the one instance of id on asset.
func category(c *Comparison, id string) Instance {
	for _, i := range c.Instances {
		if i.ID == id {
			return i
		}
	}
	return Instance{}
}

func adj(rule, delta, file, key string) report.Adjustment {
	return report.Adjustment{Rule: rule, By: "engagement", Delta: delta, Source: report.SourceRef{File: file, Key: key}}
}

func acceptance(by string, expires *string) *report.FindingAccept {
	return &report.FindingAccept{Entry: "engagement.yaml intent.accepted_risks[0]", Reason: "decided", AcceptedBy: by, Expires: expires}
}
