package gate_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// This models the URL-only release review: a public page and an admin
// origin redirecting to an explicitly declared login entry, without an
// additional operator confirmation or a domain-discovery control.
func TestURLOnlyWebAssessmentAndDeclaredLogin(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.ResponseSite("www.example.page", "198.51.100.20", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/.well-known/security.txt" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="Astro v1.2.3"></head></html>`))
	})
	seen := h.ResponseSite("admin.example.page", "198.51.100.21", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/login")
			w.WriteHeader(302)
		case "/login":
			w.Header().Set("Server", "app/2.3.4")
			_, _ = w.Write([]byte(`<html><head></head><body><input type=password></body></html>`))
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Disallow: /never-read\n"))
		case "/.well-known/security.txt":
			w.WriteHeader(404)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	file := `schema: 1
engagement: {name: url-review, timezone: Europe/Madrid, trigger: routine}
roots:
 - {url: 'https://www.example.page/'}
 - {url: 'https://admin.example.page/'}
assets:
 login: {url: 'https://admin.example.page/login'}
`
	out := runWebFile(t, h, file)
	loginCount := 0
	for _, request := range seen() {
		if request == "https /login" {
			loginCount++
		}
		if strings.Contains(request, "never-read") {
			t.Fatal(request)
		}
	}
	if loginCount != 1 {
		t.Fatalf("declared login read %d times: %v", loginCount, seen())
	}
	statuses := map[string]bool{}
	for _, a := range out.Report.Assessments {
		if a.Reason == "unavailable:resolver_unchecked" {
			t.Fatal(a)
		}
		statuses[a.Status] = true
		if a.ID == finding.IDTLSCertificateInvalid && a.Status != finding.NotMatched {
			t.Fatal(a)
		}
		if a.ID == finding.IDWebSecurityHeaders && a.Asset == "url:https://admin.example.page/" && a.Status != finding.NotMatched {
			t.Fatal(a)
		}
	}
	for _, status := range []string{finding.Matched, finding.NotMatched, finding.NotAssessed} {
		if !statuses[status] {
			t.Fatalf("missing outcome %s", status)
		}
	}
	matched := map[string]bool{}
	loginVersion := false
	for _, f := range out.Report.Findings {
		matched[f.ID] = true
		if f.ID == finding.IDWebVersionDisclosed && f.Subject.Key == "https://admin.example.page/login" {
			loginVersion = true
			if f.Key.Asset != "url:https://admin.example.page/login" {
				t.Fatal(f)
			}
		}
	}
	if !loginVersion {
		t.Fatal("declared login response was not judged")
	}
	for _, id := range []string{finding.IDWebSecurityHeaders, finding.IDWebVersionDisclosed, finding.IDWebSecurityTXT} {
		if !matched[id] {
			t.Fatalf("no finding %s", id)
		}
	}
	for _, row := range out.Report.Coverage {
		if row.Area != "web" && row.Area != "external" && row.Area != "secrets" {
			continue
		}
		if row.Population == nil || row.Population.Read != 3 || row.Population.InScope != 3 {
			t.Fatal(row)
		}
		for _, reason := range row.Reasons {
			if reason.Reason == "collector_not_built" || reason.Reason == "unavailable:resolver_unchecked" {
				t.Fatal(reason)
			}
		}
	}
	for _, q := range h.Queries() {
		if strings.HasSuffix(q, ".invalid.") {
			t.Fatalf("URL-only response rules requested DNS control %s", q)
		}
	}
}

func runWebFile(t *testing.T, h *gate.Harness, file string) *engagement.Outcome {
	t.Helper()
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, KnownCheck: func(string) bool { return false }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Started: discoveryStart, Version: "test", NewGate: h.NewGate, Dir: runDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDeclaredURLEntryExclusionStillWins(t *testing.T) {
	h, g := harnessOf(t, `schema: 1
engagement: {name: url-exclusion, timezone: Europe/Madrid, trigger: routine}
roots: [{url: 'https://admin.example.com/app/'}]
assets:
 login: {url: 'https://admin.example.com/app/login'}
exclude: [{url: 'https://admin.example.com/app/login/private'}]
`)
	seen := h.ResponseSite("admin.example.com", "198.51.100.22", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("entry")) })
	send := func(path string) gate.Result {
		return g.Send(context.Background(), gate.Request{Op: "web.get", Asset: "url:https://admin.example.com/app/", Params: map[string]string{"scheme": "https", "host": "admin.example.com", "path": path}})
	}
	if x := send("/app/login"); x.Decision != gate.DecisionSent {
		t.Fatal(x)
	}
	if x := send("/app/login/private"); x.Decision != "refused:excluded" || x.Detail != "exclude[0]" {
		t.Fatal(x)
	}
	for _, request := range seen() {
		if strings.Contains(request, "private") {
			t.Fatalf("excluded path contacted: %s", request)
		}
	}
}

func TestDeclaredWebFailureExitSemantics(t *testing.T) {
	for _, tc := range []struct {
		name             string
		expired, private bool
		want             int
	}{{name: "transport", want: 2}, {name: "invalid certificate", expired: true, want: 0}, {name: "private address", private: true, want: 0}} {
		t.Run(tc.name, func(t *testing.T) {
			h := gate.NewHarness(t, nil)
			if tc.expired {
				h.ExpiredSite("admin.example.page", "198.51.100.60")
			} else if tc.private {
				h.Answer("admin.example.page", "10.0.0.4")
			} else {
				h.Answer("admin.example.page", "198.51.100.60")
			}
			file := `schema: 1
engagement: {name: failure-semantics, timezone: UTC, trigger: routine}
roots: [{url: 'https://admin.example.page/'}]
`
			out := runWebFile(t, h, file)
			if out.ExitCode() != tc.want {
				t.Fatal(out.ExitCode(), out.Report.Incomplete, out.Report.Findings)
			}
			if tc.expired {
				found := false
				for _, f := range out.Report.Findings {
					found = found || f.ID == finding.IDTLSCertificateInvalid
				}
				if !found {
					t.Fatal("expired certificate finding missing")
				}
			}
		})
	}
}

func TestDeclaredDomainNSFailureIsIncomplete(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[]`)
	h.DNS(map[string]string{})
	h.ResponseSite("example.com", "198.51.100.40", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello")) })
	h.TXT("example.com", "v=spf1 -all")
	h.TXT("_dmarc.example.com", "v=DMARC1; p=reject")
	h.FailNS("example.com")
	out := runWebFile(t, h, `schema: 1
engagement: {name: ns-failure, timezone: UTC, trigger: routine}
roots: [{domain: example.com}]
`)
	if out.Report.Exit.Code != 2 {
		t.Fatal(out.Report.Exit)
	}
	found := false
	for _, s := range out.Report.Incomplete {
		if s.Asset == "domain:example.com" && strings.Contains(s.Detail, "dns_servfail") {
			found = true
		}
	}
	if !found {
		t.Fatal(out.Report.Incomplete)
	}
}
