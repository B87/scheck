package web

import (
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

var webNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func goodPage(raw string) Page {
	return Page{URL: raw, RequestID: raw, Decision: gate.DecisionSent, Status: 200, Body: "<html><head></head><body>hello</body></html>", Header: map[string][]string{"Content-Type": {"text/html"}, "Strict-Transport-Security": {"max-age=31536000"}, "X-Content-Type-Options": {"nosniff"}, "X-Frame-Options": {"DENY"}, "Content-Security-Policy": {"default-src 'self'; frame-ancestors 'none'"}, "Referrer-Policy": {"strict-origin"}}, TLS: &gate.TLSInfo{Verified: true, Version: "TLS 1.3", Chain: []gate.Cert{{Issuer: "CN=Public CA", NotAfter: webNow.Add(60 * 24 * time.Hour)}}}}
}
func siteInput(host string, ps ...Page) Input {
	return Input{Asset: "domain:" + host, Root: host, Now: webNow, Evidence: Evidence{Sites: []Site{{Name: host, Declared: true, Pages: ps}}}}
}
func siteVerdict(t *testing.T, in Input, id, want string) Judgment {
	t.Helper()
	for _, x := range Judge(in) {
		if x.ID == id && (id != finding.IDWebSecretInResponse || strings.HasPrefix(x.Subject.Key, "github-token:")) {
			if x.Verdict != want {
				t.Fatalf("%s: %+v want %s", id, x, want)
			}
			return x
		}
	}
	t.Fatalf("no judgment %s", id)
	return Judgment{}
}
func httpOutcomes(t *testing.T) []Judgment {
	t.Helper()
	var out []Judgment
	ids := []string{finding.IDTLSCertificateInvalid, finding.IDTLSCertificateExpiring, finding.IDTLSLegacyOnly, finding.IDWebHSTSMissing, finding.IDWebPlaintextHTTP, finding.IDWebPlaintextHTTPClients, finding.IDWebSecurityHeaders, finding.IDWebVersionDisclosed, finding.IDWebSecretInResponse, finding.IDWebSecurityTXT}
	for _, id := range ids {
		for _, want := range []string{Fired, Disproved, Abstained} {
			host := "example.com"
			p := goodPage("https://" + host + "/")
			switch id {
			case finding.IDTLSCertificateInvalid:
				if want == Fired {
					p.TLS.Verified = false
					p.TLS.Class = gate.ClassHostnameMismatch
				}
			case finding.IDTLSCertificateExpiring:
				if want == Fired {
					p.TLS.Chain[0].NotAfter = webNow.Add(6 * 24 * time.Hour)
				}
			case finding.IDTLSLegacyOnly:
				if want == Fired {
					p.TLS = &gate.TLSInfo{Alert: "protocol_version"}
				}
			case finding.IDWebHSTSMissing:
				if want == Fired {
					delete(p.Header, "Strict-Transport-Security")
				}
			case finding.IDWebPlaintextHTTP, finding.IDWebPlaintextHTTPClients:
				if id == finding.IDWebPlaintextHTTPClients {
					host = "example.dev"
				}
				p = goodPage("http://" + host + "/")
				if want == Disproved {
					p.Status = 301
					p.Header["Location"] = []string{"https://" + host + "/"}
				}
			case finding.IDWebSecurityHeaders:
				if want == Fired {
					delete(p.Header, "X-Content-Type-Options")
				}
			case finding.IDWebVersionDisclosed:
				if want == Fired {
					p.Header["Server"] = []string{"nginx/1.24.0"}
				}
			case finding.IDWebSecretInResponse:
				if want == Fired {
					p.Redactions = []policy.Hit{{Rule: "github-token", Bytes: 30}}
					p.Body = "[REDACTED:github-token:30 bytes]"
				}
			case finding.IDWebSecurityTXT:
				p = goodPage("https://" + host + "/.well-known/security.txt")
				p.Header["Content-Type"] = []string{"text/plain"}
				p.Body = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"
				if want == Fired {
					p.Status = 404
				}
			}
			if want == Abstained {
				p.Decision = "unavailable:timeout"
				p.Status = 0
				p.Body = ""
				p.TLS = nil
				if id == finding.IDWebPlaintextHTTP {
					p.Decision = "unavailable:connection_reset"
				}
			}
			out = append(out, siteVerdict(t, siteInput(host, p), id, want))
		}
	}
	for _, want := range []string{Fired, Abstained} {
		p := goodPage("https://example.com/")
		p.Header["Set-Cookie"] = []string{"session=[REDACTED:cookie:12 bytes]; Secure; HttpOnly"}
		if want == Fired {
			p.Header["Set-Cookie"] = []string{"session=[REDACTED:cookie:12 bytes]; Secure"}
		}
		out = append(out, siteVerdict(t, siteInput("example.com", p), finding.IDWebSessionCookieFlags, want))
	}
	return out
}
func TestHTTPOutcomes(t *testing.T) { httpOutcomes(t) }
func TestHSTSGrammarAndFirstField(t *testing.T) {
	for _, tc := range []struct {
		s     string
		valid bool
	}{{"max-age=86400", true}, {"max-age=\"86400\"; includeSubDomains", true}, {"max-age=100", false}, {"max-age=86400; max-age=0", false}, {"max-age=+86400", false}, {"max-age=86400; includeSubDomains=1", false}, {"max-age=86400; foo=bar", true}} {
		if hstsValid(tc.s) != tc.valid {
			t.Errorf("%q", tc.s)
		}
	}
	p := goodPage("https://example.com/")
	p.Header["Strict-Transport-Security"] = []string{"max-age=0", "max-age=31536000"}
	siteVerdict(t, siteInput("example.com", p), finding.IDWebHSTSMissing, Fired)
}
func TestBlockedResponsesAndMarkerProvenance(t *testing.T) {
	p := goodPage("https://example.com/")
	p.Body = "[REDACTED:github-token:30 bytes]"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecretInResponse, Abstained)
	p.Redactions = []policy.Hit{{Rule: "github-token", Bytes: 30}}
	p.Status = 403
	p.Body = "Just a moment..."
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecretInResponse, Abstained)
	siteVerdict(t, siteInput("example.com", p), finding.IDWebHSTSMissing, Abstained)
	p.Status = 200
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecretInResponse, Fired)
}
func TestPreloadedOwnTLDAndCookieCoverage(t *testing.T) {
	if !strings.Contains(preloadData, "d5e6fd51b430fec89732a3976e666011ecffa0a2") {
		t.Fatal("no pin")
	}
	p := goodPage("http://example.dev/")
	p.Body = "<input type='password'>"
	x := siteVerdict(t, siteInput("example.dev", p), finding.IDWebPlaintextHTTP, Disproved)
	if len(x.Attributes) > 0 {
		t.Fatal(x)
	}
	siteVerdict(t, siteInput("example.dev", p), finding.IDWebPlaintextHTTPClients, Fired)
	p = goodPage("https://example.com/")
	p.Header["Set-Cookie"] = []string{"session=[REDACTED:cookie:3 bytes]; Secure; HttpOnly"}
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSessionCookieFlags, Abstained)
	in := siteInput("example.com", p)
	in.Names = []Name{{Name: "example.com", Status: StatusResolves, Outcome: "addresses", Chain: []string{"cdn.example.dev"}}}
	delete(p.Header, "Strict-Transport-Security")
	in.Evidence.Sites[0].Pages = []Page{p}
	siteVerdict(t, in, finding.IDWebHSTSMissing, Fired)
}
func TestContentRecognitionAndPartialEvidence(t *testing.T) {
	p := goodPage("https://example.com/")
	p.Body = "<!-- <meta name='generator' content='WordPress 6.4'> --><script>var x=\"<input type='password'>\"</script>"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Disproved)
	if passwordForm(p.Body) {
		t.Fatal("script counted")
	}
	p.Body = "<meta content='WordPress 6.4' NAME=generator>"
	p.Truncated = true
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Fired)
	p.Body = "<html><head>"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Abstained)
	p.Redactions = []policy.Hit{{Rule: "github-token", Bytes: 30}}
	x := siteVerdict(t, siteInput("example.com", p), finding.IDWebSecretInResponse, Fired)
	if !strings.Contains(x.Excerpt, "at least") {
		t.Fatal(x)
	}
	p = goodPage("https://example.com/")
	p.Header["Content-Type"] = []string{"application/json"}
	p.Body = `{"build":"2026-10-09T12:00:00Z"}`
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Disproved)
	p.Body = `{"version":"1.2.3"}`
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Fired)
}
func TestTLSUnclassifiedInterceptionAndTakeover(t *testing.T) {
	p := goodPage("https://example.com/")
	p.TLS.Verified = false
	p.TLS.Class = gate.ClassUnclassified
	siteVerdict(t, siteInput("example.com", p), finding.IDTLSCertificateInvalid, Abstained)
	p.TLS.Chain[0].Issuer = "O=Zscaler Inc, CN=Zscaler Intermediate"
	siteVerdict(t, siteInput("example.com", p), finding.IDTLSLegacyOnly, Abstained)
	p.TLS.Chain[0].Issuer = "CN=NotZscalerOther CA"
	if inspection(p.TLS) {
		t.Fatal("unbounded match")
	}
}
func TestSecurityTXTShape(t *testing.T) {
	p := goodPage("https://example.com/.well-known/security.txt")
	p.Header["Content-Type"] = []string{"text/html"}
	p.Body = "<html>login</html>"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityTXT, Abstained)
	p.Header["Content-Type"] = []string{"text/plain"}
	p.Body = "Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityTXT, Abstained)
	p.Body = "Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityTXT, Fired)
}
func TestHeadersNeverUnionProtectionAcrossPages(t *testing.T) {
	a, b := goodPage("https://example.com/"), goodPage("https://example.com/app")
	delete(a.Header, "Content-Security-Policy")
	delete(b.Header, "Referrer-Policy")
	siteVerdict(t, siteInput("example.com", a, b), finding.IDWebSecurityHeaders, Fired)
	a = goodPage("https://example.com/")
	delete(a.Header, "Content-Security-Policy")
	delete(a.Header, "X-Frame-Options")
	a.Header["Content-Security-Policy-Report-Only"] = []string{"frame-ancestors 'none'"}
	siteVerdict(t, siteInput("example.com", a), finding.IDWebSecurityHeaders, Fired)
}

func TestConsultantParserRegressions(t *testing.T) {
	if hstsValid("max-age=31536000;bad directive") {
		t.Fatal("invalid extension accepted")
	}
	if !hstsValid(`max-age=31536000;foo="a;b"`) {
		t.Fatal("valid quoted extension rejected")
	}
	p := goodPage("https://example.com/")
	p.Header["Set-Cookie"] = []string{"session=[REDACTED:cookie:1 bytes]; Secure=true; HttpOnly=true"}
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSessionCookieFlags, Abstained)
	p.Header["Content-Security-Policy"] = []string{"frame-ancestors ???"}
	delete(p.Header, "X-Frame-Options")
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityHeaders, Abstained)
	for _, s := range []string{`<textarea><input type=password></textarea>`, `<template><input type=password></template>`, `<noscript><input type=password></noscript>`, `< input type=password>`} {
		if passwordForm(s) {
			t.Fatalf("inert input %s", s)
		}
	}
	for _, s := range []string{`<textarea><meta name=generator content='WordPress 6.4'></textarea>`, `<title><meta name=generator content='WordPress 6.4'></title>`} {
		p = goodPage("https://example.com/")
		p.Body = s
		siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Disproved)
	}
	p = goodPage("https://example.com/.well-known/security.txt")
	p.Header["Content-Type"] = []string{"text/plain"}
	p.Body = "Contact: javascript:alert(1)\nExpires: 2027-01-01T00:00:00Z"
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityTXT, Abstained)
	p = goodPage("https://example.com/")
	p.Body = "[REDACTED:extra:0:400 bytes]"
	p.Redactions = []policy.Hit{{Rule: "extra:0", Bytes: 400}}
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSecretInResponse, Abstained)
}
func TestOriginAndURLAssetOwnership(t *testing.T) {
	p := goodPage("https://example.com/app")
	delete(p.Header, "Strict-Transport-Security")
	p.Header["Server"] = []string{"nginx/1.24.0"}
	in := siteInput("example.com", p)
	in.URLAssets = []URLAsset{{"url:https://example.com/app", "https://example.com/app"}}
	x := siteVerdict(t, in, finding.IDWebHSTSMissing, Fired)
	if x.Asset != "url:https://example.com/app" {
		t.Fatal(x)
	}
	in.URLAssets = append(in.URLAssets, URLAsset{"url:https://example.com/", "https://example.com/"})
	x = siteVerdict(t, in, finding.IDWebHSTSMissing, Fired)
	if x.Asset != "url:https://example.com/" {
		t.Fatal(x)
	}
	x = siteVerdict(t, in, finding.IDWebVersionDisclosed, Fired)
	if x.Asset != "url:https://example.com/app" {
		t.Fatal(x)
	}
}
func TestRemainingParserVariants(t *testing.T) {
	for _, v := range []string{"tel:garbage", "mailto:@", "https:"} {
		if contactURI(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"tel:+1-555-123-4567", "mailto:security@example.com", "https://example.com/contact"} {
		if !contactURI(v) {
			t.Fatal(v)
		}
	}
	if passwordForm(`<template><template></template><input type=password></template>`) {
		t.Fatal("nested template input")
	}
	p := goodPage("https://example.com/")
	p.Header["Set-Cookie"] = []string{"session=[REDACTED:cookie:1 bytes]; Secure =true; HttpOnly =true"}
	siteVerdict(t, siteInput("example.com", p), finding.IDWebSessionCookieFlags, Abstained)
	if !hstsValid("max-age=86400;") {
		t.Fatal("valid trailing semicolon")
	}
}
func TestPreloadCommentsAreNotTLDs(t *testing.T) {
	for _, name := range []string{"example.commit", "example.version", "example.snapshot", "example.com"} {
		if preloaded(name) != "" {
			t.Fatal(name)
		}
	}
	if preloaded("example.app") != "app" {
		t.Fatal("missing .app")
	}
}
func TestPasswordAttributeKeepsItsObservedPage(t *testing.T) {
	a, b := goodPage("http://example.com/"), goodPage("http://example.com/login")
	a.RequestID = "ordinary"
	b.RequestID = "password"
	b.Body = "<input type=password>"
	x := siteVerdict(t, siteInput("example.com", a, b), finding.IDWebPlaintextHTTP, Fired)
	if !strings.Contains(x.Excerpt, "password") || len(x.Reads) == 0 || x.Reads[0] != "password" {
		t.Fatal(x)
	}
}

func TestCodeReviewHTTPRegressions(t *testing.T) {
	for _, value := range []string{`max-age="\x38\x36\x34\x30\x30"`, `max-age="\u0038\u0036\u0034\u0030\u0030"`} {
		if hstsValid(value) {
			t.Fatalf("Go string escape accepted as HSTS: %s", value)
		}
	}
	if !hstsValid(`max-age="\8\6\4\0\0"`) {
		t.Fatal("literal HTTP quoted pairs rejected")
	}
	p := goodPage("https://example.com/.well-known/security.txt")
	p.Status = 404
	for _, decision := range []string{gate.DecisionSent, gate.DecisionReused} {
		p.Decision = decision
		siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityTXT, Fired)
	}
	for _, decision := range []string{"", "refused:exclude"} {
		p.Decision = decision
		siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityTXT, Abstained)
	}
	p = goodPage("https://example.com/")
	p.Body = `<template><noscript></noscript></template><meta name="generator" content="nginx/1.2.3">`
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Fired)
	for _, malformed := range []string{`<input "type=password">`, `<input @type=password>`, `<input xtype=password>`} {
		if passwordForm(malformed) {
			t.Fatalf("invented password attribute: %s", malformed)
		}
	}
	for _, valid := range []string{`<input type="password">`, `<input type=password>`, `<input disabled type=password>`, `<input type='password' type='text'>`} {
		if !passwordForm(valid) {
			t.Fatalf("missed password attribute: %s", valid)
		}
	}
	for _, source := range []string{"'nonce-@@@'", "'nonce-'", "'sha256-@@@'", "'sha256-'"} {
		p.Header["Content-Security-Policy"] = []string{"script-src " + source + "; frame-ancestors 'none'"}
		siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityHeaders, Abstained)
	}
	for _, source := range []string{"'nonce-YWJjZA=='", "'sha256-YWJjZA=='"} {
		p.Header["Content-Security-Policy"] = []string{"script-src " + source + "; frame-ancestors 'none'"}
		siteVerdict(t, siteInput("example.com", p), finding.IDWebSecurityHeaders, Disproved)
	}
}

func TestWildcardTakeoverSubsumesControlTLS(t *testing.T) {
	in := providerInput("unused.github.io", "addresses")
	control := in.Names[0]
	control.Name = "scheck-control.example.com"
	in.Wildcard, in.Names = &control, nil
	https := goodPage("https://" + control.Name + "/")
	https.TLS.Verified, https.TLS.Class = false, gate.ClassHostnameMismatch
	in.Evidence.Sites = []Site{{Name: control.Name, HTTPS: https, HTTP: response(404, "There isn't a GitHub Pages site here.")}}
	js := Judge(in)
	if x := judgment(t, js, finding.IDDNSTakeoverCandidate); x.Verdict != Fired || x.Subject.Key != "*.example.com" {
		t.Fatal(x)
	}
	for _, id := range []string{finding.IDTLSCertificateInvalid, finding.IDTLSCertificateExpiring, finding.IDTLSLegacyOnly} {
		if x := judgment(t, js, id); x.Verdict != Abstained || x.Reason != "unavailable:takeover" {
			t.Fatal(x)
		}
	}
}

func TestHTMLSlashDelimitedAttributes(t *testing.T) {
	for _, body := range []string{`<template/foo><input type=password></template>`, `<textarea/foo><input type=password></textarea>`, `<template/foo><noscript></noscript><input type=password></template/bar>`} {
		if passwordForm(body) {
			t.Fatalf("inert slash-delimited container: %s", body)
		}
		p := goodPage("http://example.com/")
		p.Body = body
		if x := siteVerdict(t, siteInput("example.com", p), finding.IDWebPlaintextHTTP, Fired); len(x.Attributes) != 0 {
			t.Fatal(x)
		}
	}
	if !passwordForm(`<input/type=password>`) {
		t.Fatal("active slash-delimited input missed")
	}
	http := goodPage("http://example.com/")
	http.Body = `<input/type=password>`
	if x := siteVerdict(t, siteInput("example.com", http), finding.IDWebPlaintextHTTP, Fired); strings.Join(x.Attributes, ",") != "password_form" {
		t.Fatal(x)
	}
	p := goodPage("https://example.com/")
	p.Body = `<template/foo><input type=password></template/bar><meta/name=generator content="nginx/1.2.3">`
	siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Fired)
}

func TestHTMLRawElementClosingTags(t *testing.T) {
	for _, prefix := range []string{`<script><!--</script>`, `<script>const s = '<';</script>`, `<style><!--</style>`, `<textarea><!--</textarea>`, `<script><!--<script></script>--></script>`, `<template><script><!--</script></template>`, `<template><textarea>'<';</textarea></template>`} {
		p := goodPage("https://example.com/")
		p.Body = prefix + `<meta name=generator content="nginx/1.2.3">`
		siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Fired)
		if !passwordForm(prefix + `<input type=password>`) {
			t.Fatalf("active input after raw text missed: %s", prefix)
		}
	}
	for _, body := range []string{`<script><!--<script></script><input type=password>--></script>`, `<template><script><!--</script><input type=password></template>`} {
		if passwordForm(body) {
			t.Fatalf("inert raw text became an input: %s", body)
		}
		p := goodPage("https://example.com/")
		p.Body = strings.ReplaceAll(body, `<input type=password>`, `<meta name=generator content="nginx/1.2.3">`)
		siteVerdict(t, siteInput("example.com", p), finding.IDWebVersionDisclosed, Disproved)
	}
}
