package web

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func restrictedOutcomes(t *testing.T) []Judgment {
	t.Helper()
	raw := "https://admin.example.com/private"
	var out []Judgment
	tests := []struct {
		name, vantage, audience, decision string
		status                            int
		location                          string
		invalid, blocked                  bool
		want                              string
	}{
		{name: "page", status: 200, want: Fired}, {name: "challenge", status: 401, want: Fired},
		{name: "login", status: 302, location: "/login", want: Fired},
		{name: "same host downgraded login", status: 302, location: "http://admin.example.com/login", want: Abstained},
		{name: "google", status: 302, location: "https://accounts.google.com/o/oauth2/v2/auth?client_id=not-retained", want: Fired},
		{name: "microsoft", status: 302, location: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", want: Fired},
		{name: "refused", decision: "unavailable:connection_refused", want: Disproved}, {name: "timeout", decision: "unavailable:timeout", want: Disproved},
		{name: "unknown vantage", vantage: "unknown", status: 200, want: Abstained}, {name: "vpn", vantage: "vpn", status: 200, want: Abstained}, {name: "lan", vantage: "lan", status: 200, want: Abstained},
		{name: "public audience", audience: "internet", status: 200, want: Abstained},
		{name: "scope refusal", decision: "refused:entry_point", want: Abstained}, {name: "dns timeout", decision: "unavailable:dns_timeout", want: Abstained},
		{name: "not found", status: 404, want: Abstained}, {name: "forbidden", status: 403, want: Abstained}, {name: "busy", status: 429, want: Abstained}, {name: "down", status: 503, want: Abstained},
		{name: "bad cert", status: 200, invalid: true, want: Abstained}, {name: "blocked", status: 503, blocked: true, want: Abstained},
		{name: "maintenance", status: 302, location: "/maintenance", want: Abstained}, {name: "logout", status: 302, location: "/logout", want: Abstained},
		{name: "unknown provider", status: 302, location: "https://accounts.google.com.evil.example/o/oauth2/auth", want: Abstained},
		{name: "microsoft encoded slash", status: 302, location: "https://login.microsoftonline.com/a%2fb/oauth2/authorize", want: Abstained},
		{name: "idp http", status: 302, location: "http://accounts.google.com/o/oauth2/auth", want: Abstained},
		{name: "idp other port", status: 302, location: "https://accounts.google.com:8443/o/oauth2/auth", want: Abstained},
		{name: "redacted location", status: 302, location: "/[REDACTED:x:3 bytes]/login", want: Abstained},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := goodPage(raw)
			p.Status = tc.status
			p.Header["Location"] = []string{tc.location}
			if tc.invalid {
				p.TLS.Verified = false
			}
			if tc.blocked {
				p.BlockedVendor = "Cloudflare"
			}
			if tc.decision != "" {
				p.Decision = tc.decision
				p.TLS = nil
			}
			v, a := tc.vantage, tc.audience
			if v == "" {
				v = "internet"
			}
			if v == "unknown" {
				v = ""
			}
			if a == "" {
				a = "vpn"
			}
			js := Judge(Input{Asset: "domain:example.com", Vantage: v, Restricted: []Restriction{{URL: raw, Audience: a}}, Evidence: Evidence{Sites: []Site{{Name: "admin.example.com", Pages: []Page{p}}}}})
			for _, j := range js {
				if j.ID == finding.IDWebRestrictedReachable {
					if j.Verdict != tc.want {
						t.Fatalf("%+v", j)
					}
					if tc.want == Disproved && !strings.Contains(j.Excerpt, "server that is down") {
						t.Fatal(j)
					}
					out = append(out, j)
					return
				}
			}
			t.Fatal("no reachability judgment")
		})
	}
	return out
}
func TestRestrictedReachability(t *testing.T) { restrictedOutcomes(t) }
func TestRestrictedURLRequiresExactOriginalResponse(t *testing.T) {
	raw := "https://admin.example.com/private"
	p := goodPage(raw)
	p.RedirectOf = "previous"
	js := Judge(Input{Vantage: "internet", Restricted: []Restriction{{URL: raw, Audience: "vpn"}}, Evidence: Evidence{Sites: []Site{{Pages: []Page{p, goodPage(raw + "/child")}}}}})
	for _, j := range js {
		if j.ID == finding.IDWebRestrictedReachable && (j.Verdict != Abstained || j.Reason != "unavailable:not_read") {
			t.Fatal(j)
		}
	}
}
