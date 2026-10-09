package gate_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func TestWildcardTakeoverThroughRun(t *testing.T) {
	for _, kind := range []string{"nxdomain", "body", "declared site"} {
		t.Run(kind, func(t *testing.T) {
			body := kind != "nxdomain"
			h := gate.NewHarness(t, nil)
			h.CrtSh(`[{"name_value":"a.example.com\nb.example.com","not_after":"2027-01-01T00:00:00"}]`)
			target := "unused.azurewebsites.net"
			dns := map[string]string{"example.com": "nodata"}
			seen := func() []string { return nil }
			if body {
				target = "unused.github.io"
				dns[target] = "addrs:198.51.100.77"
				seen = h.FingerprintSite("*.example.com", "198.51.100.77", 404, "There isn't a GitHub Pages site here. SECRET_SEEDED_VALUE", "www.example.com")
			}
			dns["*.example.com"] = "cname:" + target
			h.DNS(dns)
			file := `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
 - domain: example.com
redact_extra: [SECRET_SEEDED_.*]
`
			if kind == "declared site" {
				file += "assets:\n www: {domain: www.example.com}\n"
			}
			res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, KnownCheck: func(string) bool { return false }, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
			if err != nil {
				t.Fatal(err)
			}
			dir := runDir(t)
			out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, Started: discoveryStart, Version: "test", NewGate: h.NewGate})
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, f := range out.Report.Findings {
				if f.ID == finding.IDDNSTakeoverCandidate {
					n++
					if f.Subject.Key != "*.example.com" || f.Key.Asset != "domain:example.com" {
						t.Fatal(f)
					}
					if body && !strings.Contains(f.Evidence[0].Excerpt, "a.example.com, b.example.com") {
						t.Fatal(f)
					}
				}
				if f.ID == finding.IDDNSDanglingExternal && f.Subject.Kind == "dns_name" && f.Status == finding.StatusOpen {
					t.Fatalf("duplicate dangling %+v", f)
				}
			}
			if n != 1 {
				t.Fatalf("%d candidates: %+v", n, out.Report.Findings)
			}
			requests := seen()
			wantRequests := 0
			if body {
				wantRequests = 2
			}
			if kind == "declared site" {
				wantRequests = 4
			}
			if len(requests) != wantRequests {
				t.Fatal(requests)
			}
			for _, r := range requests {
				if strings.HasPrefix(r, "a.example.com") || strings.HasPrefix(r, "b.example.com") || strings.Contains(r, "*") {
					t.Errorf("member/wildcard read %s", r)
				}
			}
			raw, err := os.ReadFile(filepath.Join(dir.Path, "scope.json"))
			if err != nil {
				t.Fatal(err)
			}
			var sd engagement.ScopeDoc
			if err := json.Unmarshal(raw, &sd); err != nil {
				t.Fatal(err)
			}
			if kind == "declared site" {
				found := false
				for _, a := range out.Report.Assessments {
					if a.ID == finding.IDDNSTakeoverCandidate && a.Asset == "domain:www.example.com" {
						found = a.Status == finding.NotMatched
					}
				}
				if !found {
					t.Fatal("declared site was not judged on its own serving page")
				}
			}
			ctl := sd.Domains[0].Control
			if ctl == nil || ctl.RequestID == "" || len(ctl.Chain) != 1 {
				t.Fatal(ctl)
			}
			for _, name := range sd.Domains[0].Names {
				if name.Name == "a.example.com" || name.Name == "b.example.com" {
					if name.Status != engagement.NameMatchesWildcard || name.Read {
						t.Fatal(name)
					}
				}
			}
			if body {
				marked := false
				err = filepath.WalkDir(dir.Path, func(p string, e os.DirEntry, err error) error {
					if err != nil || e.IsDir() {
						return err
					}
					b, err := os.ReadFile(p)
					if strings.Contains(string(b), "SECRET_SEEDED_VALUE") {
						t.Errorf("seed leaked to %s", p)
					}
					marked = marked || strings.Contains(string(b), "[REDACTED:extra:")
					return err
				})
				if err != nil || !marked {
					t.Fatalf("redaction %v %v", marked, err)
				}
			}
		})
	}
}

func runTakeoverCase(t *testing.T, h *gate.Harness, extra string) (*engagement.Outcome, string) {
	t.Helper()
	file := `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots: [{domain: example.com}]
` + extra
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownCheck: func(string) bool { return false }, KnownFinding: finding.Known, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	dir := runDir(t)
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	return out, dir.Path
}

func TestWildcardDoesNotGroupSharedCDNAddresses(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[{"name_value":"real.example.com","not_after":"2027-01-01T00:00:00"}]`)
	seen := h.FingerprintSite("*.example.com", "198.51.100.77", 404, "There isn't a GitHub Pages site here.")
	h.DNS(map[string]string{"example.com": "nodata", "*.example.com": "cname:unused.github.io", "unused.github.io": "addrs:198.51.100.77", "real.example.com": "cname:customer.other-provider.example", "customer.other-provider.example": "addrs:198.51.100.77"})
	out, _ := runTakeoverCase(t, h, "")
	if len(seen()) != 4 {
		t.Fatalf("distinct binding was not read: %v", seen())
	}
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDDNSTakeoverCandidate {
			for _, e := range f.Evidence {
				if strings.Contains(e.Excerpt, "real.example.com") {
					t.Fatal("different provider attributed to wildcard")
				}
			}
		}
	}
	found := false
	for _, row := range out.Report.Coverage {
		for _, sub := range row.SubItems {
			for _, s := range sub.ReadNotJudged {
				found = found || strings.Contains(s, "real.example.com → customer.other-provider.example")
			}
		}
	}
	if !found {
		t.Fatal("distinct unknown provider missing from coverage")
	}
}

func TestUnknownWildcardProviderIsReportedWithoutCTMembers(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[]`)
	h.DNS(map[string]string{"example.com": "nodata", "*.example.com": "cname:service.unknown-provider.example", "service.unknown-provider.example": "addrs:198.51.100.77"})
	seen := h.Site("*.example.com", "198.51.100.77")
	out, _ := runTakeoverCase(t, h, "")
	found := false
	for _, row := range out.Report.Coverage {
		for _, sub := range row.SubItems {
			for _, s := range sub.ReadNotJudged {
				found = found || s == "*.example.com → service.unknown-provider.example"
			}
		}
	}
	if !found || len(seen()) != 0 {
		t.Fatalf("coverage %v, contacts %v", found, seen())
	}
}

func TestControlNameRedactedBeforePersistenceAndNeverSentAsHost(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[]`)
	h.DNS(map[string]string{"example.com": "nodata", "*.example.com": "cname:unused.github.io", "unused.github.io": "addrs:198.51.100.77"})
	seen := h.FingerprintSite("*.example.com", "198.51.100.77", 404, "There isn't a GitHub Pages site here.")
	out, dir := runTakeoverCase(t, h, "redact_extra: ['^[a-z0-9]{20}\\.example\\.com$']\n")
	var names []string
	for _, q := range h.Queries() {
		n := strings.TrimSuffix(q, ".")
		if len(n) == 32 && strings.HasSuffix(n, ".example.com") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		t.Fatal("no control queried")
	}
	if len(seen()) != 0 {
		t.Fatal("redacted control was used as HTTP target")
	}
	marked := false
	if err := filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		for _, n := range names {
			if strings.Contains(string(b), n) {
				t.Errorf("raw control name in %s", filepath.Base(p))
			}
		}
		marked = marked || strings.Contains(string(b), "[REDACTED:extra:")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("redaction marker missing")
	}
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDDNSTakeoverCandidate {
			t.Fatal("redacted identity supported a finding")
		}
	}
}

func TestResumeRetriesFailedWildcardControl(t *testing.T) {
	h := gate.NewHarness(t, nil)
	crt := h.CrtSh(`[]`)
	h.DNS(map[string]string{"example.com": "nodata", "*.example.com": "servfail"})
	path := filepath.Join(t.TempDir(), "e.yaml")
	file := []byte("schema: 1\nengagement: {name: acme, timezone: Europe/Madrid, trigger: routine}\nroots: [{domain: example.com}]\n")
	if err := os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "engagements", "acme", discoveryStart.UTC().Format(time.RFC3339))
	first := scopeRun(t, h, path, dir)
	if first.Domains[0].Control.Status != engagement.NameInsufficient {
		t.Fatal("control did not fail")
	}
	h.DNS(map[string]string{"example.com": "nodata", "*.example.com": "cname:unused.azurewebsites.net"})
	again := scopeRun(t, h, path, dir)
	if len(crt()) != 2 || again.Domains[0].Control.Status != engagement.NameDangling {
		t.Fatal("resume kept failed wildcard control")
	}
	scopeRun(t, h, path, dir)
	if len(crt()) != 2 {
		t.Fatal("complete control was unnecessarily repeated")
	}
}
