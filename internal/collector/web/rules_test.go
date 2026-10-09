package web

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func verdicts(js []Judgment) map[string]string {
	out := map[string]string{}
	for _, j := range js {
		out[j.ID+" "+j.Subject.Key] = j.Verdict
	}
	return out
}

var (
	ext  = finding.IDDNSDanglingExternal
	in   = finding.IDDNSDanglingInternal
	priv = finding.IDDNSPrivateAddress
)

func sent(outcome string) RecordRead {
	return RecordRead{RequestID: "g1", Decision: gate.DecisionSent, Outcome: outcome}
}

// Every rule fires, is disproved and abstains (AGENTS.md, "Adding a
// rule"): dns.dangling_* through a CNAME, an MX, an NS or an SPF include,
// and dns.private_address; and every finding id the collector defines is
// covered three ways.
func TestEveryRuleFiresDisprovesAndAbstains(t *testing.T) {
	names := []Name{
		{Name: "old.example.com", Status: StatusDangling, Outcome: "nxdomain", Chain: []string{"gone.saas.example"}},
		{Name: "stale.example.com", Status: StatusDangling, Outcome: "nodata", Chain: []string{"x.example.com"}, FinalInRoot: true},
		{Name: "www.example.com", Status: StatusResolves, Outcome: "addresses", Chain: []string{"edge.cdn.example"}, Addresses: []string{"198.51.100.7"}},
		{Name: "cname.example.com", Status: StatusResolves, Outcome: "addresses", Chain: []string{"in.example.com"}, FinalInRoot: true, Addresses: []string{"198.51.100.8"}},
		{Name: "flaky.example.com", Status: StatusInsufficient, Outcome: "servfail", Chain: []string{"a.saas.example"}},
		{Name: "vpn.example.com", Status: StatusResolves, Outcome: "addresses", Addresses: []string{"10.0.0.5", "fd00::5"}},
		{Name: "lost.example.com", Status: StatusInsufficient, Outcome: "timeout"},
		{Name: "gone.example.com", Status: StatusGone, Outcome: "nxdomain"},
		{Name: "far.example.com", Status: StatusNotChecked, Detail: "past the first 200 names under this root"},
		{Name: "late.example.com", Status: StatusNotChecked, Detail: "refused:deadline"},
		{Name: "legacy.example.com", Status: StatusExcluded},
		{Name: "any.example.com", Status: StatusWildcard, Outcome: "addresses", Addresses: []string{"10.9.9.9"}},
	}
	ev := Evidence{
		Mail: []MailEvidence{{Domain: "example.com", TXT: sent("records"), MX: sent("records"), SPFComplete: true,
			MXTargets: []TargetRead{
				{Owner: "example.com", Via: "mx", Name: "mx.gone-host.example", RecordRead: sent("nxdomain")},
				{Owner: "example.com", Via: "mx", Name: "mx.example.com", Decision: gate.DecisionSent, Outcome: "nodata", FinalInRoot: true},
				{Owner: "example.com", Via: "mx", Name: "mx.host.example", RecordRead: sent("addresses")},
				{Owner: "example.com", Via: "mx", Name: "mx.legacy.example.com", Decision: "refused:excluded"},
				{Owner: "example.com", Via: "mx", Name: "mx.slow.example", RecordRead: sent("deadline")},
			},
			SPF: []TargetRead{
				{Owner: "example.com", Via: "include", Name: "_spf.gone.example", RecordRead: sent("nxdomain")},
				{Owner: "example.com", Via: "include", Name: "_spf.empty.example", RecordRead: sent("nodata")},
				{Owner: "example.com", Via: "redirect", Name: "_spf.redirect.example", RecordRead: sent("nxdomain")},
				// One target two records include: one subject per record.
				{Owner: "a.vendor.example", Via: "include", Name: "gone.vendor.example", RecordRead: sent("nxdomain")},
				{Owner: "a.vendor.example", Via: "include", Name: "gone.vendor.example", RecordRead: sent("nxdomain")},
			}}},
		NS: sent("records"),
		NSTargets: []TargetRead{
			{Owner: "example.com", Via: "ns", Name: "ns1.dns.example", RecordRead: sent("servfail")},
			{Owner: "example.com", Via: "ns", Name: "ns.example.com", Decision: gate.DecisionSent, Outcome: "timeout", FinalInRoot: true},
		},
	}
	js := Judge(Input{Asset: "domain:example.com", Root: "example.com", Names: names, Evidence: ev})
	got := verdicts(js)
	want := map[string]string{
		ext + " old.example.com":                          Fired,
		in + " stale.example.com":                         Fired,
		ext + " www.example.com":                          Disproved,
		in + " cname.example.com":                         Disproved,
		ext + " flaky.example.com":                        Abstained,
		priv + " flaky.example.com":                       Abstained,
		priv + " www.example.com":                         Disproved,
		priv + " cname.example.com":                       Disproved,
		priv + " vpn.example.com":                         Fired,
		ext + " lost.example.com":                         Abstained,
		priv + " lost.example.com":                        Abstained,
		ext + " far.example.com":                          Abstained,
		priv + " far.example.com":                         Abstained,
		ext + " late.example.com":                         Abstained,
		priv + " late.example.com":                        Abstained,
		ext + " example.com/MX/mx.gone-host.example":      Fired,
		in + " example.com/MX/mx.example.com":             Fired,
		ext + " example.com/MX/mx.host.example":           Disproved,
		ext + " example.com/MX/mx.slow.example":           Abstained,
		ext + " example.com/TXT/_spf.gone.example":        Fired,
		ext + " example.com/TXT/_spf.empty.example":       Disproved,
		ext + " a.vendor.example/TXT/gone.vendor.example": Fired,
		ext + " example.com/NS/ns1.dns.example":           Abstained,
		in + " example.com/NS/ns.example.com":             Abstained,
	}
	for _, name := range []string{"flaky.example.com", "lost.example.com", "far.example.com", "late.example.com"} {
		want[finding.IDDNSTakeoverCandidate+" "+name] = Abstained
		want[finding.IDDNSUnclaimedAtProvider+" "+name] = Abstained
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok && !strings.HasPrefix(k, "email.") {
			t.Errorf("unexpected judgment %s: %s", k, got[k])
		}
	}
	reasons := map[string]string{}
	for _, j := range js {
		reasons[j.Subject.Key] = j.Reason
		if j.Subject.Key == "old.example.com" && j.Asset != "domain:old.example.com" ||
			strings.HasPrefix(j.Subject.Key, "example.com/") && j.Asset != "domain:example.com" {
			t.Errorf("%s filed under %s", j.Subject.Key, j.Asset)
		}
	}
	for key, want := range map[string]string{"far.example.com": "sampled", "late.example.com": "limit_reached",
		"lost.example.com": "unavailable:dns_timeout", "example.com/MX/mx.slow.example": "limit_reached"} {
		if reasons[key] != want {
			t.Errorf("%s abstained as %q, want %q", key, reasons[key], want)
		}
	}
	seen := map[string]map[string]bool{}
	for k, v := range want {
		id, _, _ := strings.Cut(k, " ")
		if seen[id] == nil {
			seen[id] = map[string]bool{}
		}
		seen[id][v] = true
	}
	for _, j := range append(takeoverOutcomes(t), emailOutcomes(t)...) {
		if seen[j.ID] == nil {
			seen[j.ID] = map[string]bool{}
		}
		seen[j.ID][j.Verdict] = true
	}
	for _, id := range finding.WebIDs() {
		if len(seen[id]) != 3 {
			t.Errorf("%s covered %v", id, seen[id])
		}
	}
}

// What the rules could not read is never counted as nothing found: a
// resolver that invents answers, names Scope could not list, a records
// read that said nothing, an SPF tree not read to its end.
func TestNothingUnreadCountsAsNothingFound(t *testing.T) {
	resolves := []Name{{Name: "old.example.com", Status: StatusResolves, Outcome: "addresses", Chain: []string{"gone.saas.example"},
		Addresses: []string{"198.51.100.250"}}}
	for name, tc := range map[string]Input{
		"a rewriting resolver":  {Names: resolves, Doubt: "unavailable:resolver_rewrites"},
		"an unchecked resolver": {Names: resolves, Doubt: "unavailable:resolver_unchecked"},
		"CT unavailable":        {Gaps: []Gap{{Reason: "unavailable:ct_source"}}},
		"MX read failed":        {Evidence: Evidence{Mail: []MailEvidence{{Domain: "example.com", TXT: sent("records"), SPFComplete: true, MX: sent("servfail")}}}},
		"NS read cut":           {Evidence: Evidence{NS: RecordRead{Decision: "refused:deadline"}}},
		"SPF tree incomplete":   {Evidence: Evidence{Mail: []MailEvidence{{Domain: "example.com", TXT: sent("records"), MX: sent("nodata")}}}},
	} {
		tc.Asset, tc.Root = "domain:example.com", "example.com"
		if tc.Evidence.NS.Decision == "" {
			tc.Evidence.NS = sent("records")
		}
		abstained := false
		for _, j := range Judge(tc) {
			if j.Verdict == Disproved {
				t.Errorf("%s: %s disproved on %s", name, j.ID, j.Subject.Key)
			}
			abstained = abstained || j.Verdict == Abstained && strings.HasPrefix(j.ID, "dns.dangling")
		}
		if !abstained {
			t.Errorf("%s: no dangling abstention", name)
		}
	}
}
