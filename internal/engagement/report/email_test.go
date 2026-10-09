package report

import (
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/finding"
)

func withEmailRoot(t *testing.T) Input {
	t.Helper()
	domain := Subject{Kind: "mail_domain", Key: "example.com", Label: "example.com (declared sending: google-workspace)"}
	return Input{LevelsUsed: []string{"passive", "observe"}, Version: "test", Name: "mail-review", Path: "engagement.yaml", SHA256: strings.Repeat("a", 64), Rerun: "scheck run engagement.yaml", Started: started, Zone: time.UTC,
		Egress: &EgressInput{Sources: []SourceInput{{Source: "dns", Host: "192.0.2.53:53", Requests: 12, RootControls: 1, InvalidControl: true}}},
		People: true, Candidates: []Candidate{{Handle: "alice", Why: "listed employee"}},
		Assets: []AssetInput{{ID: "domain:example.com", Name: "example.com", Kind: "domain", Root: true, Status: "collected", Collector: "web",
			MailNotes: []Note{
				{Kind: "mail_context", Source: "example.com", Detail: "You listed google-workspace as sending for example.com. DNS does not show whether it sends current mail"},
				{Kind: "mail_context", Source: "example.com", Detail: "adkim=r (default relaxed), aspf=r (default relaxed); whether your senders' mail actually aligns is not visible in DNS. Aggregate-report destination present: true"},
				{Kind: "mail_context", Source: "example.com", Detail: "DMARC coverage is limited to the DNS records read, including legacy pct percentages. Receivers may discover or apply policies differently; actual mail handling was not tested"},
				{Kind: "mail_context", Source: "example.com", Detail: "SPF term read, not compared with declared senders: ip4:192.0.2.0/24"},
				{Kind: "mail_context", Source: "news.example.com", Detail: "DKIM for sendgrid was not checked: no selector given. Find s= in the DKIM-Signature header of a recent message from this service"},
			}, Judged: []Judgment{
				{ID: finding.IDEmailDMARCNotEnforced, Subject: domain, Verdict: "disproved", Reads: []string{"dmarc1"}},
				{ID: finding.IDEmailDMARCPartial, Subject: domain, Verdict: "fired", Reads: []string{"dmarc1"}, Excerpt: "DMARC p=reject; legacy pct=25; test mode=false", Context: "You listed google-workspace as sending for example.com. DNS does not show whether it sends current mail.", NotChecked: []string{"Actual receiver enforcement and message alignment were not assessed"}},
				{ID: finding.IDEmailDMARCSubdomainsOpen, Subject: domain, Verdict: "disproved", Reads: []string{"dmarc1"}},
				{ID: finding.IDEmailSPFMissing, Subject: domain, Verdict: "disproved", Reads: []string{"spf1"}},
				{ID: finding.IDEmailSPFInvalid, Subject: domain, Verdict: "disproved", Reads: []string{"spf1", "spf2"}},
				{ID: finding.IDEmailSPFPermitsAnyone, Subject: domain, Verdict: "disproved", Reads: []string{"spf1", "spf2"}},
				{ID: finding.IDEmailSPFUndeclaredSender, Subject: Subject{Kind: "spf_mechanism", Key: "example.com/include:sendgrid.net", Label: "SPF include:sendgrid.net on example.com"}, Verdict: "fired", Reads: []string{"spf1", "spf2"}, Excerpt: "SPF includes senders through include:sendgrid.net maps to sendgrid, absent from declared senders", Context: "You listed google-workspace as sending for example.com."},
				{ID: finding.IDEmailSPFUndeclaredSender, Subject: Subject{Kind: "spf_mechanism", Key: "example.com/unmapped", Label: "SPF term ip4:192.0.2.0/24 has no service mapping"}, Verdict: "abstained", Reason: "no_rule", Reads: []string{"spf1"}},
				{ID: finding.IDEmailDKIMMissing, Subject: Subject{Kind: "dkim_selector", Key: "google._domainkey.example.com", Label: "selector google (google-workspace) on example.com"}, Verdict: "disproved", Reads: []string{"dkim1"}},
				{ID: finding.IDEmailDKIMKeyBreakable, Subject: Subject{Kind: "dkim_selector", Key: "google._domainkey.example.com", Label: "selector google (google-workspace) on example.com"}, Verdict: "fired", Reads: []string{"dkim1"}, Excerpt: "DKIM at google._domainkey.example.com; RSA modulus 512 bits", Context: "You declared selector google for google-workspace.", NotChecked: []string{"Whether this selector signs current mail and whether that mail aligns were not assessed"}},
				{ID: finding.IDEmailDKIMKey1024, Subject: Subject{Kind: "dkim_selector", Key: "google._domainkey.example.com", Label: "selector google (google-workspace) on example.com"}, Verdict: "disproved", Reads: []string{"dkim1"}},
				{ID: finding.IDEmailDKIMMissing, Subject: Subject{Kind: "dkim_selector", Key: "news.example.com/no-selector/sendgrid", Label: "DKIM for sendgrid on news.example.com: no selector given"}, Verdict: "abstained", Reason: "unavailable:dkim_selector"},
			}}}}
}

func TestEmailReportSubjectsCoverageAndAcceptances(t *testing.T) {
	in := withEmailRoot(t)
	in.DataMattersMost = []string{"domain:example.com"}
	r := Build(in)
	if r.Exit.Code != 1 || row(t, r, "email").Mark != "partial" {
		t.Fatalf("exit/coverage: %+v %+v", r.Exit, row(t, r, "email"))
	}
	for _, f := range r.Findings {
		if f.Subject == nil || f.Key.Asset != "domain:example.com" || f.Severity != f.SeverityBase || len(f.Adjustments) > 0 || f.AcceptTemplate.Subject != f.Subject.Key {
			t.Fatalf("email finding: %+v", f)
		}
	}
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", AssetID: "domain:example.com", Asset: "example.com", ID: finding.IDEmailDKIMKeyBreakable, Subject: "google._domainkey.example.com", Reason: "rotation in progress", AcceptedBy: "alice"}}
	r = Build(in)
	if len(r.Acceptances) != 1 || r.Acceptances[0].Outcome != "applied" {
		t.Fatal(r.Acceptances)
	}
	for _, f := range r.Findings {
		if f.ID == finding.IDEmailDKIMKeyBreakable && f.Status != finding.StatusAccepted {
			t.Fatal(f)
		}
	}
	if r.Exit.Code != 0 {
		t.Fatalf("only low findings remain open: %+v", r.Exit)
	}
	in.Acceptances[0].Subject = "other._domainkey.example.com"
	r = Build(in)
	if r.Acceptances[0].Outcome != "subject_not_found" {
		t.Fatal(r.Acceptances)
	}
	if !strings.Contains(r.Notes[1].Detail, "actually aligns") {
		t.Fatal(r.Notes)
	}
}
