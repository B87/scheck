package report

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

func withWebRoot(t *testing.T) Input {
	t.Helper()
	in := withEmailRoot(t)
	in.Name = "web-review"
	in.Exposures = []ExposureInput{{URL: "https://example.com/", Reason: "public build information", Source: "intent.exposed_on_purpose[0]"}}
	a := &in.Assets[0]
	a.Redactions = []policy.Hit{{Rule: "github-token", Bytes: 30}}
	in.Egress = &EgressInput{Sites: []SiteInput{{Name: "example.com", Requests: 3, FirstParty: true}}}
	a.WebNotes = []Note{{Kind: "web_context", Source: a.ID, Detail: "Entry points only: no authenticated login flow or loaded scripts were read."}}
	a.Judged = append(a.Judged,
		Judgment{ID: finding.IDWebSecretInResponse, Asset: a.ID, Verdict: verdictFired, Subject: Subject{Kind: "secret_location", Key: "github-token:https://example.com/", Label: "GitHub token in https://example.com/"}, Reads: []string{"page1"}, Excerpt: "One GitHub token match was removed from the captured response before reporting", Details: map[string]any{"detector": "github-token", "count": 1}, NotChecked: []string{"Credential validity was not tested"}},
		Judgment{ID: finding.IDWebPlaintextHTTP, Asset: a.ID, Verdict: verdictFired, Subject: Subject{Kind: "origin", Key: "http://example.com", Label: "http://example.com"}, Reads: []string{"http1"}, Attributes: []string{"password_form"}, Excerpt: "HTTP serves a page containing a password input"},
		Judgment{ID: finding.IDWebSessionCookieFlags, Asset: a.ID, Verdict: verdictFired, Reason: "unavailable:login_flow", Subject: Subject{Kind: "origin", Key: "https://example.com", Label: "https://example.com"}, Reads: []string{"page1"}, Listed: []string{"session"}, Excerpt: "Session cookie lacks HttpOnly"},
		Judgment{ID: finding.IDWebVersionDisclosed, Asset: a.ID, Verdict: verdictFired, Subject: Subject{Kind: "url", Key: "https://example.com/", Label: "https://example.com/"}, Reads: []string{"page1"}, Excerpt: "Server: nginx/1.24.0"},
		Judgment{ID: finding.IDTLSCertificateExpiring, Asset: a.ID, Verdict: verdictFired, Subject: Subject{Kind: "dns_name", Key: "example.com", Label: "example.com"}, Reads: []string{"page1"}, Details: map[string]any{"days_remaining": 6}, Excerpt: "Certificate expires in six days; confirm renewal is working"},
		Judgment{ID: finding.IDWebSecurityTXT, Asset: a.ID, Verdict: verdictAbstained, Reason: "unavailable:redirect_not_entry_point", Subject: Subject{Kind: "origin", Key: "https://example.com", Label: "https://example.com"}, Reads: []string{"contact1"}},
	)
	return in
}
func TestWebSeverityAndCoverage(t *testing.T) {
	r := Build(withWebRoot(t))
	for _, f := range r.Findings {
		switch f.ID {
		case finding.IDWebSecretInResponse:
			if f.Severity != "critical" {
				t.Fatal(f)
			}
		case finding.IDWebPlaintextHTTP:
			if f.Severity != "medium" || len(f.Adjustments) != 1 || f.Adjustments[0].Rule != "attribute:password_form" {
				t.Fatal(f)
			}
		case finding.IDWebVersionDisclosed:
			if f.Severity != "info" || !strings.Contains(strings.Join(f.WhyHere, " "), "public build") {
				t.Fatal(f)
			}
		}
	}
	if x := row(t, r, "web"); x.Mark != "partial" {
		t.Fatal(x)
	}
}
func TestUncollectedWebRuleHasNoInventedRequest(t *testing.T) {
	in := withWebRoot(t)
	in.Assets[0].Judged = append(in.Assets[0].Judged, Judgment{ID: finding.IDWebHSTSMissing, Asset: in.Assets[0].ID, Verdict: verdictAbstained, Reason: "unavailable:not_read", Subject: Subject{Kind: "origin", Key: "https://example.com", Label: "https://example.com"}})
	r := Build(in)
	validate(t, schema(t), r)
	for _, a := range r.Assessments {
		if a.ID == finding.IDWebHSTSMissing && (a.Complete || len(a.Reads) != 0) {
			t.Fatal(a)
		}
	}
}
