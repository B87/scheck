package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func TestSelectiveWebResume(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[]`)
	h.DNS(map[string]string{})
	reply := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>hello</html>"))
	}
	h.ResponseSite("example.com", "198.51.100.40", reply)
	h.ResponseSite("other.example", "198.51.100.41", reply)
	seen := h.ResponseSite("admin.example.page", "198.51.100.42", reply)
	for _, d := range []string{"example.com", "other.example"} {
		h.TXT(d, "v=spf1 include:_spf.vendor.example -all", "unrelated-DNS-verification-value")
		h.TXT("_dmarc."+d, "v=DMARC1; p=reject; rua=mailto:private-reports@"+d)
		h.TXT("s1._domainkey."+d, "v=DKIM1; k=rsa; p=MIGf; n=private-note")
	}
	h.TXT("_spf.vendor.example", "v=spf1 -all")
	h.TXT("s2._domainkey.example.com", "v=DKIM1; k=rsa; p=MIGf")
	file := filepath.Join(t.TempDir(), "e.yaml")
	state := t.TempDir()
	start := time.Now().UTC().Truncate(time.Second)
	var path string
	recons := map[*engagement.Outcome]*engagement.ReconDoc{}
	selector, audience, second := "s1", "vpn", true
	source := func() string {
		tail := ""
		if second {
			tail = "\n  - {url: 'https://admin.example.page/b', audience: vpn}"
		}
		return fmt.Sprintf(`schema: 1
engagement: {name: selective-resume, timezone: UTC, trigger: routine}
roots: [{domain: example.com}, {domain: other.example}, {url: 'https://admin.example.page/'}]
mail:
 senders:
  - {domain: example.com, service: google_workspace, dkim_selectors: [%s]}
  - {domain: other.example, service: google_workspace, dkim_selectors: [s1]}
intent:
 not_exposed:
  - {url: 'https://admin.example.page/a%%20b', audience: %s}%s
`, selector, audience, tail)
	}
	run := func(v string, resume bool) *engagement.Outcome {
		t.Helper()
		raw := []byte(source())
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		res, err := engagement.Parse(file, raw, engagement.Options{KnownCheck: func(string) bool { return false }, KnownFinding: finding.Known, FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
		if err != nil {
			t.Fatal(err)
		}
		var dir *engagement.RunDir
		var prior *engagement.Prior
		if resume {
			dir, err = engagement.OpenRun(path)
			if err == nil {
				prior, err = engagement.LoadPrior(dir)
			}
		} else {
			dir, err = engagement.CreateRunDir(state, res.Engagement.Name, start)
			if err == nil {
				path = dir.Path
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		defer dir.Close()
		out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: raw, Dir: dir, Resume: prior, Started: start, Session: time.Now(), Version: "v0.0.2-step5-test", Vantage: v, NewGate: h.NewGate})
		if err != nil {
			t.Fatal(err)
		}
		var recon engagement.ReconDoc
		data, err := os.ReadFile(filepath.Join(path, "recon.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &recon); err != nil {
			t.Fatal(err)
		}
		recons[out] = &recon
		return out
	}
	first := run("internet", false)
	foundRestricted := false
	for _, a := range recons[first].Assets {
		for _, j := range a.Judged {
			if j.ID == finding.IDWebRestrictedReachable && j.Subject.Key == "https://admin.example.page/a%20b" {
				foundRestricted = true
				if j.Verdict != "fired" {
					t.Fatal(j)
				}
			}
		}
	}
	if !foundRestricted {
		t.Fatal("escaped intent URL was not judged")
	}
	if len(first.Report.Engagement.Method.LevelsUsed) != 2 {
		t.Fatal(first.Report.Engagement.Method)
	}
	for _, a := range first.Report.Assets {
		if a.Root && len(a.Trace) == 0 {
			t.Fatal("network request trace missing", a.ID)
		}
	}
	assertMail := func(out *engagement.Outcome, d, decision string) {
		t.Helper()
		for _, a := range recons[out].Assets {
			if a.Web == nil {
				continue
			}
			for _, m := range a.Web.Mail {
				if m.Domain == d {
					if m.TXT.Decision != decision || m.DMARC.Decision != decision || m.MX.Decision != decision {
						t.Fatalf("%s: %+v", d, m)
					}
					for _, s := range m.DKIM {
						if s.Read.Decision != decision {
							t.Fatal(s)
						}
					}
					for _, f := range m.SPF {
						if f.Decision != decision {
							t.Fatal(f)
						}
					}
					return
				}
			}
		}
		t.Fatal("no mail domain", d)
	}
	assertEntry := func(out *engagement.Outcome, path, decision string) {
		t.Helper()
		for _, a := range recons[out].Assets {
			if a.Web == nil {
				continue
			}
			for _, s := range a.Web.Sites {
				for _, p := range s.Pages {
					if p.URL == "https://admin.example.page"+path {
						if p.Decision != decision {
							t.Fatalf("%s: %+v", path, p)
						}
						return
					}
				}
			}
		}
		t.Fatal("no page", path)
	}
	assertMail(first, "example.com", gate.DecisionSent)
	unchanged := run("internet", true)
	if len(unchanged.Report.Engagement.Method.LevelsUsed) != 2 {
		t.Fatal("retained observe level lost", unchanged.Report.Engagement.Method)
	}
	assertMail(unchanged, "example.com", gate.DecisionReused)
	assertMail(unchanged, "other.example", gate.DecisionReused)
	assertEntry(unchanged, "/a%20b", gate.DecisionReused)
	selector = "s2"
	mailChanged := run("internet", true)
	assertMail(mailChanged, "example.com", gate.DecisionSent)
	assertMail(mailChanged, "other.example", gate.DecisionReused)
	assertEntry(mailChanged, "/a%20b", gate.DecisionReused)
	for _, a := range recons[mailChanged].Assets {
		if a.Web != nil {
			for _, m := range a.Web.Mail {
				if m.Domain == "example.com" && (len(m.DKIM) != 1 || m.DKIM[0].Selector != "s2") {
					t.Fatal(m)
				}
			}
		}
	}
	before := len(seen())
	audience = "lan"
	intentChanged := run("internet", true)
	assertEntry(intentChanged, "/a%20b", gate.DecisionSent)
	assertEntry(intentChanged, "/b", gate.DecisionReused)
	assertMail(intentChanged, "other.example", gate.DecisionReused)
	if len(seen()) != before+1 {
		t.Fatalf("intent change sent %v; before %d", seen(), before)
	}
	second = false
	removed := run("internet", true)
	for _, a := range recons[removed].Assets {
		for _, j := range a.Judged {
			if j.ID == finding.IDWebRestrictedReachable && strings.HasSuffix(j.Subject.Key, "/b") {
				t.Fatal(j)
			}
		}
	}
	vantageChanged := run("vpn", true)
	assertMail(vantageChanged, "example.com", gate.DecisionSent)
	assertMail(vantageChanged, "other.example", gate.DecisionSent)
	assertEntry(vantageChanged, "/a%20b", gate.DecisionSent)
	// Reused evidence keeps the original observation time and declared vantage.
	for _, f := range unchanged.Report.Findings {
		for _, e := range f.Evidence {
			if e.Kind == "observed" && e.Vantage != "internet" {
				t.Fatal(e)
			}
		}
	}
	// The DNS ledger retains projections, never unrelated TXT/report destinations.
	files, err := filepath.Glob(filepath.Join(path, "evidence/requests/*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private-reports@", "private-note", "unrelated-DNS-verification-value"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("%s leaked %s", p, secret)
			}
		}
	}
}
