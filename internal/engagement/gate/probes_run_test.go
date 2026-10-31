package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	webc "github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

const probeSecret = "AKIA" + "ABCDEFGHIJKLMNOP"

// probeFile is an engagement with one url root probed in mode, framework
// none, inside a window that holds now.
func probeFile(mode string) string {
	now := time.Now()
	return fmt.Sprintf(`schema: 1
engagement: {name: probe-review, timezone: Europe/Madrid, trigger: routine}
roots: [{url: 'https://shop.example.com/'}]
defaults: {probe: %s, framework: [none]}
authorization:
  by: CTO, Example Ltd
  date: 2026-10-06
  windows:
    - {from: %s, to: %s}
`, mode, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
}

func probeSite(t *testing.T, h *gate.Harness) func() []string {
	t.Helper()
	return h.ResponseSite("shop.example.com", "198.51.100.12", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/.env":
			_, _ = w.Write([]byte("APP_NAME=shop\nAWS_ACCESS_KEY_ID=" + probeSecret + "\n"))
		case "/server-status":
			w.WriteHeader(http.StatusForbidden)
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>shop</html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func runProbes(t *testing.T, mode string, confirm func(context.Context, []engagement.ProbePreviewSite) []string) (*engagement.Outcome, *engagement.RunDir, func() []string) {
	t.Helper()
	h := gate.NewHarness(t, nil)
	seen := probeSite(t, h)
	file := probeFile(mode)
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{KnownFinding: finding.Known, KnownCheck: func(string) bool { return false },
		FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) }, HostFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	dir := runDir(t)
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, Started: discoveryStart,
		Version: "test", NewGate: h.NewGate, ConfirmProbes: confirm})
	if err != nil {
		t.Fatal(err)
	}
	return out, dir, seen
}

func probeHits(seen []string) []string {
	var out []string
	for _, s := range seen {
		if _, p, _ := strings.Cut(s, " "); p != "/" && p != "/robots.txt" && p != "/.well-known/security.txt" {
			out = append(out, s)
		}
	}
	return out
}

// Probes in mode all send exactly the list the plan previewed, once each;
// a file that matches is a finding with no value in the report, the run
// directory or the audit log.
func TestProbesRunInModeAll(t *testing.T) {
	out, dir, seen := runProbes(t, "all", nil)
	apply, _ := webc.SelectProbes([]string{"none"})
	if hits := probeHits(seen()); len(hits) != len(apply) {
		t.Errorf("%d probe requests for %d declared: %v", len(hits), len(apply), hits)
	}
	var env, status *finding.Finding
	for i, f := range out.Report.Findings {
		if f.ID == finding.IDWebConfigFileExposed && f.Subject.Key == "https://shop.example.com/.env" {
			env = &finding.Finding{Severity: finding.Severity(out.Report.Findings[i].Severity)}
		}
		if f.ID == finding.IDWebDebugInterfaceExposed {
			status = &finding.Finding{}
		}
	}
	if env == nil || env.Severity != finding.SevHigh || status != nil {
		t.Fatalf("env finding %+v, status finding %+v", env, status)
	}
	raw, _ := json.Marshal(out.Report)
	if strings.Contains(string(raw), probeSecret) || !strings.Contains(string(raw), "probe") {
		t.Error("the report holds the secret, or says nothing of probes")
	}
	if err := filepath.WalkDir(dir.Path, func(path string, d os.DirEntry, e error) error {
		if e != nil || d.IsDir() {
			return e
		}
		b, e := os.ReadFile(path)
		if strings.Contains(string(b), probeSecret) {
			t.Errorf("the secret is in %s", path)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	plan, _ := os.ReadFile(filepath.Join(dir.Path, "plan.json"))
	if !strings.Contains(string(plan), "https://shop.example.com/.env") || !strings.Contains(string(plan), `"count": 5`) {
		t.Errorf("plan.json does not preview the requests: %s", plan)
	}
	audit, _ := os.ReadFile(filepath.Join(dir.Path, "audit.jsonl"))
	if !strings.Contains(string(audit), `"level":"probe"`) || !strings.Contains(string(audit), `"window":0`) {
		t.Error("the audit log does not name the level and the window")
	}
}

// Confirm with no terminal runs nothing and says so; with an answer it runs
// only what was approved.
func TestProbesInModeConfirm(t *testing.T) {
	out, _, seen := runProbes(t, "confirm", nil)
	if hits := probeHits(seen()); len(hits) != 0 {
		t.Errorf("probes ran with nobody to ask: %v", hits)
	}
	var notRun int
	for _, f := range out.Report.Findings {
		if f.ID == finding.IDWebConfigFileExposed {
			t.Errorf("a probe that did not run found %+v", f)
		}
	}
	raw, _ := json.Marshal(out.Report)
	notRun = strings.Count(string(raw), "unavailable:probe_no_terminal")
	if notRun == 0 {
		t.Error("the report does not say the probes were not run")
	}

	var asked []engagement.ProbePreviewSite
	_, _, seen = runProbes(t, "confirm", func(_ context.Context, sites []engagement.ProbePreviewSite) []string {
		asked = sites
		return []string{"shop.example.com"}
	})
	if len(asked) != 1 || len(asked[0].Requests) != 5 || asked[0].Requests[0].Method != "GET" {
		t.Fatalf("%+v", asked)
	}
	if !slices.Contains(probeHits(seen()), "https /.env") {
		t.Errorf("an approved probe did not run: %v", seen())
	}

	_, _, seen = runProbes(t, "confirm", func(context.Context, []engagement.ProbePreviewSite) []string { return nil })
	if hits := probeHits(seen()); len(hits) != 0 {
		t.Errorf("a declined probe ran: %v", hits)
	}
}
