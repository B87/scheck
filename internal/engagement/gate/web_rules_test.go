package gate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func TestWebRulesThroughRun(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[{"name_value":"www.example.com"}]`)
	secret := "ghp_" + strings.Repeat("A", 30)
	seen := h.ResponseSite("www.example.com", "198.51.100.9", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Add("Set-Cookie", "session=never-retained; Secure")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/app")
			w.WriteHeader(302)
		case "/app":
			_, _ = w.Write([]byte("<html><head></head><body>" + secret + "</body></html>"))
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Disallow: /do-not-read\n"))
		case "/.well-known/security.txt":
			w.WriteHeader(404)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	file := `schema: 1
engagement: {name: web-review, timezone: Europe/Madrid, trigger: routine}
roots: [{domain: example.com}]
people: {alice: {kind: employee}}
assets:
 website: {url: 'https://www.example.com/app', first_party: {confirmed_by: alice, date: '2026-10-07', target: '198.51.100.9'}}
intent:
 exposed_on_purpose: [{url: 'https://www.example.com/app', audience: internet, reason: public version information}]
 accepted_risks:
  - {id: web.security_txt, asset: website, subject: 'https://www.example.com', reason: contact elsewhere, accepted_by: alice}
`
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, KnownCheck: func(string) bool { return false }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	dir := runDir(t)
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	var secretFound, versionFound bool
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDWebSecretInResponse {
			secretFound = true
			if f.Key.Asset != "url:https://www.example.com/app" || f.Severity != "critical" {
				t.Fatal(f)
			}
		}
		if f.ID == finding.IDWebVersionDisclosed && f.Subject.Key == "https://www.example.com/app" {
			versionFound = true
			if f.Severity != "info" {
				t.Fatal(f)
			}
		}
	}
	if len(out.Report.Acceptances) != 1 || out.Report.Acceptances[0].Outcome != "applied" {
		t.Fatal(out.Report.Acceptances)
	}
	if out.Report.Redaction.Builtin["github-token"] < 1 {
		t.Fatal(out.Report.Redaction)
	}
	if !secretFound || !versionFound {
		t.Fatalf("secret=%v version=%v", secretFound, versionFound)
	}
	for _, r := range seen() {
		if strings.Contains(r, "do-not-read") {
			t.Fatal(r)
		}
	}
	if !slices.Contains(seen(), "https /app") || !slices.Contains(seen(), "https /robots.txt") {
		t.Fatal(seen())
	}
	raw, _ := json.Marshal(out.Report)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "never-retained") {
		t.Fatal("secret escaped into report")
	}
	marker := false
	walkErr := filepath.WalkDir(dir.Path, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if strings.Contains(string(b), secret) || strings.Contains(string(b), "never-retained") {
			t.Errorf("secret in %s", path)
		}
		marker = marker || strings.Contains(string(b), "[REDACTED:github-token:")
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if !marker {
		t.Fatal("missing marker in persisted evidence")
	}
}
func TestURLRootCollector(t *testing.T) {
	h := gate.NewHarness(t, nil)
	seen := h.ResponseSite("url.example.com", "198.51.100.11", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	})
	file := `schema: 1
engagement: {name: url-read, timezone: Europe/Madrid, trigger: routine}
roots: [{url: 'https://url.example.com/status'}]
`
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, KnownCheck: func(string) bool { return false }, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Started: discoveryStart, Version: "test", NewGate: h.NewGate, Dir: runDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(seen(), "https /status") {
		t.Fatal(seen())
	}
	if len(out.Report.Assets) == 0 || out.Report.Assets[0].Status != "collected" {
		t.Fatal(out.Report.Assets)
	}
}

func TestIntentAloneDoesNotJudgeUnknownSite(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[{"name_value":"unknown.example.com"}]`)
	seen := h.Site("unknown.example.com", "198.51.100.13")
	file := `schema: 1
engagement: {name: unknown-site, timezone: Europe/Madrid, trigger: routine}
roots: [{domain: example.com}]
intent:
 exposed_on_purpose: [{url: 'https://unknown.example.com/app', audience: internet, reason: public}]
`
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, KnownCheck: func(string) bool { return false }, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Started: discoveryStart, Version: "test", NewGate: h.NewGate, Dir: runDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range out.Report.Findings {
		if slices.Contains([]string{finding.IDWebHSTSMissing, finding.IDWebPlaintextHTTP, finding.IDWebSecurityHeaders, finding.IDWebSessionCookieFlags, finding.IDWebSecurityTXT}, f.ID) {
			t.Fatal(f)
		}
	}
	for _, request := range seen() {
		if strings.Contains(request, "/app") || strings.Contains(request, "robots.txt") || strings.Contains(request, "security.txt") {
			t.Fatal(request)
		}
	}
}
func TestSharedOriginAcrossURLRoots(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.ResponseSite("shared.example.com", "198.51.100.17", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/status" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		_, _ = w.Write([]byte("<html><head></head><body>hello</body></html>"))
	})
	file := `schema: 1
engagement: {name: shared-origin, timezone: Europe/Madrid, trigger: routine}
roots: [{url: 'https://shared.example.com/app'}, {url: 'https://shared.example.com/status'}]
`
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, KnownCheck: func(string) bool { return false }, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Started: discoveryStart, Version: "test", NewGate: h.NewGate, Dir: runDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range out.Report.Findings {
		key := f.ID + f.Key.Asset + f.Subject.Key
		if seen[key] {
			t.Fatalf("duplicate %s", key)
		}
		seen[key] = true
		if f.ID == finding.IDWebHSTSMissing {
			t.Fatalf("valid HSTS on another entry was ignored: %+v", f)
		}
	}
}
