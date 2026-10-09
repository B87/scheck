package web

import (
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func providerInput(target, outcome string) Input {
	status := StatusResolves
	if outcome == "nxdomain" || outcome == "nodata" {
		status = StatusDangling
	}
	if outcome == "timeout" {
		status = StatusInsufficient
	}
	return Input{Asset: "domain:example.com", Root: "example.com", Names: []Name{{Name: "old.example.com", Request: "dns1", Status: status, Outcome: outcome, Chain: []string{target}}}, Evidence: Evidence{NS: sent("records")}}
}
func response(status int, body string) Page {
	return Page{RequestID: "http1", Decision: gate.DecisionSent, Status: status, Body: body}
}
func withPages(in Input, https, http Page) Input {
	in.Evidence.Sites = []Site{{Name: in.Names[0].Name, HTTPS: https, HTTP: http}}
	return in
}
func judgment(t *testing.T, js []Judgment, id string) Judgment {
	t.Helper()
	for _, j := range js {
		if j.ID == id {
			return j
		}
	}
	t.Fatalf("no %s in %+v", id, js)
	return Judgment{}
}

// The finding inventory's three-outcome check includes both new rule ids.
func takeoverOutcomes(t *testing.T) []Judgment {
	t.Helper()
	var out []Judgment
	for _, tc := range []struct{ target, id, marker string }{
		{"unused.github.io", finding.IDDNSTakeoverCandidate, "There isn't a GitHub Pages site here."},
		{"cname.vercel-dns.com", finding.IDDNSUnclaimedAtProvider, "DEPLOYMENT_NOT_FOUND"},
	} {
		for _, v := range []string{Fired, Disproved, Abstained} {
			p := response(404, tc.marker)
			if v == Disproved {
				p = response(200, "a site")
			}
			if v == Abstained {
				p = Page{RequestID: "http1", Decision: "unavailable:timeout"}
			}
			got := judgment(t, Judge(withPages(providerInput(tc.target, "addresses"), Page{}, p)), tc.id)
			if got.Verdict != v {
				t.Errorf("%s: got %+v, want %s", tc.id, got, v)
			}
			out = append(out, got)
		}
	}
	return out
}

func TestTakeoverEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, target, outcome string
		https, http           Page
		verdict, id           string
		dangling              bool
	}{
		{name: "GitHub http", target: "x.github.io", http: response(404, "There isn't a GitHub Pages site here."), verdict: Fired},
		{name: "GitHub https alone", target: "x.github.io", https: response(404, "There isn't a GitHub Pages site here."), verdict: Abstained},
		{name: "wrong status", target: "x.github.io", http: response(200, "There isn't a GitHub Pages site here."), verdict: Abstained},
		{name: "positive beats other protocol", target: "cname.vercel-dns.com", https: response(200, "site"), http: response(404, "DEPLOYMENT_NOT_FOUND"), id: finding.IDDNSUnclaimedAtProvider, verdict: Fired},
		{name: "404 not configured is not enough", target: "cname.vercel-dns-0.com", http: response(404, "not found"), id: finding.IDDNSUnclaimedAtProvider, verdict: Abstained},
		{name: "marked page", target: "x.github.io", http: response(200, "[REDACTED:extra:0:15 bytes]"), verdict: Abstained},
		{name: "blocked", target: "x.github.io", http: response(403, "blocked"), verdict: Abstained},
		{name: "429 marker", target: "x.github.io", http: response(429, "There isn't a GitHub Pages site here."), verdict: Abstained},
		{name: "503 marker", target: "x.github.io", http: response(503, "There isn't a GitHub Pages site here."), verdict: Abstained},
		{name: "body provider NXDOMAIN", target: "x.github.io", outcome: "nxdomain", verdict: Abstained, dangling: true},
		{name: "Azure NXDOMAIN", target: "x.azurewebsites.net", outcome: "nxdomain", verdict: Fired},
		{name: "Beanstalk NXDOMAIN", target: "x.eu-west-1.elasticbeanstalk.com", outcome: "nxdomain", verdict: Fired},
		{name: "Azure NODATA", target: "x.azurewebsites.net", outcome: "nodata", verdict: Abstained, dangling: true},
		{name: "Azure serving site", target: "x.azurewebsites.net", http: response(200, "site"), verdict: Disproved},
		{name: "known provider lookup failed", target: "x.azurewebsites.net", outcome: "timeout", verdict: Abstained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.outcome == "" {
				tc.outcome = "addresses"
			}
			if tc.id == "" {
				tc.id = finding.IDDNSTakeoverCandidate
			}
			input := withPages(providerInput(tc.target, tc.outcome), tc.https, tc.http)
			js := Judge(input)
			j := judgment(t, js, tc.id)
			if j.Verdict != tc.verdict {
				t.Fatalf("%+v", j)
			}
			firedDangling := false
			for _, x := range js {
				firedDangling = firedDangling || x.ID == ext && x.Verdict == Fired
			}
			if firedDangling != tc.dangling {
				t.Errorf("dangling=%v, judgments %+v", firedDangling, js)
			}
			if tc.dangling && tc.outcome == "nodata" && !strings.Contains(judgment(t, js, ext).Excerpt, "still knows this name") {
				t.Error("no NODATA explanation")
			}
			if j.Verdict == Fired && (len(j.NotChecked) == 0 || j.Subject.Kind != SubjectDNSName || !slices.Contains(j.Reads, "dns1")) {
				t.Errorf("missing context: %+v", j)
			}
		})
	}
}

func TestTakeoverTableBoundaries(t *testing.T) {
	for _, target := range []string{"github.io", "x.github.io.evil.example", "notgithub.io", "herokudns.com", "x.herokuapp.com", "x.bitbucket.io", "s3.amazonaws.com", "x.cloudfront.net", "x.elasticbeanstalk.com", "x.azurewebsites.net.evil.example"} {
		if provider(providerInput(target, "nxdomain").Names[0]) != nil {
			t.Errorf("matched %s", target)
		}
	}
	for _, target := range []string{"x.s3.amazonaws.com", "x.s3.eu-west-1.amazonaws.com", "x.s3-eu-west-1.amazonaws.com", "x.s3-website.eu-west-1.amazonaws.com", "x.s3-website-eu-west-1.amazonaws.com"} {
		for _, server := range []string{"AmazonS3", "other", ""} {
			p := response(404, "<Code>NoSuchBucket</Code>")
			p.Header = map[string][]string{"Server": {server}}
			j := judgment(t, Judge(withPages(providerInput(target, "addresses"), Page{}, p)), finding.IDDNSTakeoverCandidate)
			if (j.Verdict == Fired) != (server == "AmazonS3") {
				t.Errorf("%s server %s: %+v", target, server, j)
			}
		}
	}
	for _, p := range fingerprints {
		if p.Source == "" || (!p.NXDomain && (p.Status == 0 || p.Body == "")) {
			t.Errorf("incomplete fingerprint %+v", p)
		}
	}
	if TakeoverVersion == "" || !strings.Contains(takeoverSource, "5bd4e12837911c8475486f1da922c9b9c706e632") || takeoverSourceDate != "2025-02-08" {
		t.Fatal("missing provenance")
	}
}

func TestTakeoverInsufficientAndWildcard(t *testing.T) {
	p := response(200, "healthy")
	p.Truncated = true
	if j := judgment(t, Judge(withPages(providerInput("x.github.io", "addresses"), Page{}, p)), finding.IDDNSTakeoverCandidate); j.Verdict != Abstained {
		t.Fatal(j)
	}
	for _, doubt := range []string{"unavailable:resolver_rewrites", "unavailable:resolver_unchecked"} {
		input := providerInput("x.azurewebsites.net", "nxdomain")
		input.Doubt = doubt
		for _, j := range Judge(input) {
			if j.Verdict != Abstained || j.Reason != doubt {
				t.Fatal(j)
			}
		}
	}
	input := providerInput("x.azurewebsites.net", "nxdomain")
	ctl := input.Names[0]
	ctl.Name = "random.example.com"
	input.Wildcard = &ctl
	input.Names = []Name{{Name: "a.example.com", Status: StatusWildcard}, {Name: "b.example.com", Status: StatusWildcard}}
	input.Gaps = []Gap{{Reason: "unavailable:ct_source", Detail: "CT failed"}}
	js := Judge(input)
	j := judgment(t, js, finding.IDDNSTakeoverCandidate)
	if j.Verdict != Fired || j.Subject.Key != "*.example.com" || j.Asset != input.Asset || j.Reason != "unavailable:ct_source" || !slices.Equal(j.Members, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("wildcard %+v", j)
	}
	for _, j := range js {
		if j.Subject.Key != "*.example.com" && j.Subject.Kind == SubjectDNSName {
			t.Fatal(j)
		}
	}
	input.Wildcard = &Name{Name: "random.example.com", Status: StatusGone, Outcome: "nxdomain"}
	input.Gaps = nil
	if got := Judge(input); len(got) != 0 {
		t.Fatal(got)
	}
}
