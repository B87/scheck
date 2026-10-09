package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/finding"
)

func restrictedReport(t *testing.T, v string, resumed bool) Input {
	t.Helper()
	in := Input{Version: "test", Name: "restricted-pages", Path: "engagement.yaml", SHA256: strings.Repeat("a", 64), Rerun: "scheck run engagement.yaml", Started: started, Finished: started.Add(time.Hour), Zone: time.UTC, Vantage: v, Resumed: resumed, LevelsUsed: []string{"passive", "observe"}}
	if resumed {
		in.Finished = started.Add(25 * time.Hour)
	}
	if v != "" {
		in.Rerun += " --vantage " + v
	}
	in.Observations = map[string]Observation{"admin1": {CollectedAt: started, Vantage: v}, "private1": {CollectedAt: started.Add(time.Hour), Vantage: v}}
	a := AssetInput{ID: "url:https://admin.example.com/", Name: "admin", Kind: "url", Root: true, Status: "collected", Collector: "web"}
	j := Judgment{ID: finding.IDWebRestrictedReachable, Asset: a.ID, Subject: Subject{Kind: "url", Key: "https://admin.example.com/", Label: "https://admin.example.com/"}, Verdict: verdictFired, Reads: []string{"admin1"}, Attributes: []string{"contradiction"}, Context: "intent.not_exposed[0]", Excerpt: "https://admin.example.com/ answered HTTP 401 from the declared internet vantage, outside every permitted source, including office allowlists and VPN; declared audience: vpn. Authentication was not tested", Details: map[string]any{"audience": "vpn", "vantage": v}}
	n := j
	n.Subject = Subject{Kind: "url", Key: "https://admin.example.com/private", Label: "https://admin.example.com/private"}
	n.Reads = []string{"private1"}
	n.Verdict = verdictDisproved
	n.Attributes = nil
	n.Excerpt = "did not answer from here; scheck cannot tell a firewall from a server that is down"
	switch v {
	case "":
		j.Verdict, n.Verdict = verdictAbstained, verdictAbstained
		j.Reason, n.Reason = "unavailable:vantage_unknown", "unavailable:vantage_unknown"
		a.WebNotes = []Note{{Kind: "web_context", Source: a.ID, Detail: "Pages you said are restricted were not checked for reachability: the run's vantage was not given (--vantage internet). internet means outside every permitted source, including office allowlists and VPN."}}
	case "vpn", "lan":
		j.Verdict, n.Verdict = verdictAbstained, verdictAbstained
		j.Reason, n.Reason = "unavailable:vantage_inside", "unavailable:vantage_inside"
		a.WebNotes = []Note{{Kind: "web_context", Source: a.ID, Detail: "Pages you said are restricted were not checked for outside reachability: you declared this run came from inside your network."}}
	}
	if j.Verdict == verdictAbstained {
		j.Attributes = nil
		j.Excerpt = ""
		n.Excerpt = ""
	}
	if n.Verdict == verdictDisproved {
		a.WebNotes = append(a.WebNotes, Note{Kind: "web_context", Source: n.Subject.Key, Detail: n.Excerpt})
	}
	a.Judged = []Judgment{j, n}
	in.Assets = []AssetInput{a}
	return in
}
func TestRestrictedReportSeverityAndObservedMetadata(t *testing.T) {
	in := restrictedReport(t, "internet", true)
	in.Exposures = []ExposureInput{{URL: "https://admin.example.com/", Reason: "must not lower contradiction"}}
	r := Build(in)
	validate(t, schema(t), r)
	if len(r.Findings) != 1 || r.Findings[0].Severity != "high" || r.Findings[0].ExposureFinding || r.Exit.Code != 1 {
		t.Fatal(r.Findings, r.Exit)
	}
	e := r.Findings[0].Evidence[len(r.Findings[0].Evidence)-1]
	if e.CollectedAt == nil || !e.CollectedAt.Equal(started) || e.Vantage != "internet" {
		t.Fatal(e)
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, r, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"outside every permitted source", "Authentication was not tested", "server that is down"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatal("missing", want)
		}
	}
}
func TestMissingAcceptanceSubjectNeedsCompletePopulation(t *testing.T) {
	in := restrictedReport(t, "", false)
	in.Acceptances = []AcceptanceInput{{ID: finding.IDWebRestrictedReachable, AssetID: in.Assets[0].ID, Subject: "https://admin.example.com/removed", Entry: "intent.accepted_risks[0]"}}
	if got := Build(in).Acceptances[0].Outcome; got != "rule_not_decided" {
		t.Fatal(got)
	}
	in.Assets[0].Judged = nil
	if got := Build(in).Acceptances[0].Outcome; got != "rule_not_decided" {
		t.Fatal(got)
	}
}

func TestMissingAcceptanceSubjectIgnoresUnrelatedPopulation(t *testing.T) {
	in := restrictedReport(t, "internet", false)
	in.Acceptances = []AcceptanceInput{{ID: finding.IDWebRestrictedReachable, AssetID: in.Assets[0].ID, Subject: "https://admin.example.com/removed", Entry: "intent.accepted_risks[0]"}}
	in.Assets = append(in.Assets, AssetInput{ID: "domain:other.example", Kind: "domain", Root: true, Collector: "web", Status: statusCollected, PopulationIncomplete: true})
	if got := Build(in).Acceptances[0].Outcome; got != "subject_not_found" {
		t.Fatal(got)
	}
	in.Assets[0].PopulationIncomplete = true
	if got := Build(in).Acceptances[0].Outcome; got != "rule_not_decided" {
		t.Fatal(got)
	}
}
