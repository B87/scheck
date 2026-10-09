package gate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

const inventoryFile = `schema: 1
engagement: {name: inventory, operator: alice, timezone: UTC, trigger: routine}
roots:
  - saas: github:acme
exclude:
  - repo: github:acme/excluded
`

func TestGitHubInventoryRunAndPrincipalResume(t *testing.T) {
	file := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(file, []byte(inventoryFile), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := engagement.Parse(file, []byte(inventoryFile), inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	token := "ghp_" + strings.Repeat("a", 36)
	h.Setenv("GITHUB_TOKEN", token)
	var mu sync.Mutex
	login, userID := "alice", 1
	hits := map[string]int{}
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != "GET" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
			t.Errorf("request %s version %s", r.Method, r.Header.Get("X-GitHub-Api-Version"))
		}
		hits[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		switch r.URL.Path {
		case "/user":
			fmt.Fprintf(w, `{"id":%d,"login":%q,"type":"User","email":%q}`, userID, login, "alice@example.test")
		case "/orgs/acme":
			fmt.Fprintf(w, `{"id":2,"login":"acme","type":"Organization","two_factor_requirement_enabled":false,"default_repository_permission":%q}`, token)
		case "/user/memberships/orgs/acme":
			fmt.Fprintf(w, `{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":%d,"login":%q,"type":"User"}}`, userID, login)
		case "/orgs/acme/members":
			fmt.Fprintf(w, `[{"id":%d,"login":%q,"type":"User"}]`, userID, login)
		case "/orgs/acme/outside_collaborators":
			fmt.Fprint(w, `[]`)
		case "/orgs/acme/invitations":
			fmt.Fprint(w, `[{"id":7,"login":null,"role":"direct_member","email":"do-not-persist@example.test"}]`)
		case "/orgs/acme/repos":
			fmt.Fprint(w, `[{"id":3,"name":"shop","full_name":"acme/shop","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"private"},{"id":4,"name":"excluded","full_name":"acme/excluded","owner":{"id":2,"login":"acme","type":"Organization"}}]`)
		default:
			t.Errorf("undeclared path %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	start := time.Now().UTC().Truncate(time.Second)
	dir, err := engagement.CreateRunDir(t.TempDir(), "inventory", start)
	if err != nil {
		t.Fatal(err)
	}
	path := dir.Path
	first, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(inventoryFile), Dir: dir, Started: start, Version: "v0.0.2", NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	if first.ExitCode() != 0 || len(first.Report.Findings) != 0 {
		t.Fatalf("first exit %d", first.ExitCode())
	}
	assertInventoryReport(t, first.Report)
	reconBytes, err := os.ReadFile(dir.File("recon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recon engagement.ReconDoc
	if err = json.Unmarshal(reconBytes, &recon); err != nil {
		t.Fatal(err)
	}
	ev := recon.Assets[0].GitHub
	if ev == nil || !ev.OwnerAuthority || len(ev.Repositories.Items) != 1 || ev.Repositories.Complete {
		t.Fatalf("evidence %+v", ev)
	}
	dir.Close()
	resume := func() *engagement.Outcome {
		d, err := engagement.OpenRun(path)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		p, err := engagement.LoadPrior(d)
		if err != nil {
			t.Fatal(err)
		}
		r, raw, err := p.LoadEngagement(inventoryOptions())
		if err != nil {
			t.Fatal(err)
		}
		out, err := engagement.Run(context.Background(), r, engagement.RunOptions{Raw: raw, Dir: d, Resume: p, Started: p.Manifest.Started, Session: time.Now(), Version: "v0.0.2", NewGate: h.Build})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	second := resume()
	if second.ExitCode() != 0 {
		t.Fatalf("same-principal exit %d", second.ExitCode())
	}
	mu.Lock()
	sameOrg, samePrincipal := hits["/orgs/acme"], hits["/user"]
	mu.Unlock()
	if sameOrg != 1 || samePrincipal != 2 {
		t.Fatalf("same identity should keep object but refresh principal: org=%d user=%d", sameOrg, samePrincipal)
	}
	mu.Lock()
	login = "alice-renamed"
	mu.Unlock()
	renamed := resume()
	if len(renamed.Report.Engagement.PrincipalChanges) != 0 {
		t.Fatal("login rename changed stable principal")
	}
	mu.Lock()
	login, userID = "bob", 9
	mu.Unlock()
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("b", 36))
	third := resume()
	if len(third.Report.Engagement.PrincipalChanges) != 1 || !strings.Contains(third.Report.Engagement.PrincipalChanges[0].To, "bob") {
		t.Fatalf("changes %+v", third.Report.Engagement.PrincipalChanges)
	}
	mu.Lock()
	changedOrg, changedPrincipal := hits["/orgs/acme"], hits["/user"]
	mu.Unlock()
	if changedOrg != 2 || changedPrincipal != 4 {
		t.Fatalf("changed identity must resend: org=%d user=%d", changedOrg, changedPrincipal)
	}
	var text bytes.Buffer
	if err = ereport.WriteText(&text, third.Report, ereport.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "principal changed") {
		t.Fatal("missing changed principal header")
	}
	marked := false
	if err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		for _, secret := range []string{token, "do-not-persist@example.test"} {
			if bytes.Contains(b, []byte(secret)) && !strings.HasSuffix(p, "engagement.yaml") && !strings.HasSuffix(p, "scope.json") {
				t.Errorf("%s exposed %s", p, secret)
			}
		}
		marked = marked || bytes.Contains(b, []byte("[REDACTED:"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("redacted marker missing from persisted evidence")
	}
}

func assertInventoryReport(t *testing.T, r *ereport.Report) {
	t.Helper()
	for _, row := range r.Coverage {
		if row.Area == "identity" || row.Area == "secrets" || row.Area == "cicd" {
			if row.Mark != "not_assessed" {
				t.Errorf("inventory judged security: %+v", row)
			}
			found := false
			for _, reason := range row.Reasons {
				found = found || reason.Reason == "no_rule"
			}
			if !found {
				t.Errorf("missing no_rule: %+v", row)
			}
		}
	}
	if r.Assets[0].Principal == nil || len(r.Assets[0].Trace) == 0 {
		t.Fatal("missing principal or request trace")
	}
}

func TestGitHubInventoryExecutionOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		token  string
		exit   int
	}{{"missing", 0, "", 2}, {"rejected", 401, "ghp_" + strings.Repeat("c", 36), 3}, {"permission", 403, "ghp_" + strings.Repeat("c", 36), 2}, {"server", 503, "ghp_" + strings.Repeat("c", 36), 2}, {"malformed", 200, "ghp_" + strings.Repeat("c", 36), 2}, {"content_type", 200, "ghp_" + strings.Repeat("c", 36), 2}, {"installation", 200, "ghs_" + strings.Repeat("c", 36), 0}} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := engagement.Parse("engagement.yaml", []byte(inventoryFile), inventoryOptions())
			if err != nil {
				t.Fatal(err)
			}
			h := gate.NewHarness(t, r.GateScope(time.Now()))
			h.Setenv("GITHUB_TOKEN", tc.token)
			var hits atomic.Int32
			h.GitHubHandler(func(w http.ResponseWriter, req *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if tc.name == "content_type" {
					w.Header().Set("Content-Type", "text/plain")
				}
				w.WriteHeader(tc.status)
				if tc.name == "malformed" {
					fmt.Fprint(w, "{")
					return
				}
				if tc.name == "content_type" {
					fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization"}`)
					return
				}
				if tc.name == "installation" {
					if req.URL.Path == "/user" {
						t.Error("installation principal contacted")
					}
					if req.URL.Path == "/orgs/acme" {
						fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization"}`)
					} else {
						fmt.Fprint(w, `[]`)
					}
				}
			})
			dir, err := engagement.CreateRunDir(t.TempDir(), "inventory", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			out, err := engagement.Run(context.Background(), r, engagement.RunOptions{Dir: dir, Raw: []byte(inventoryFile), Version: "v0.0.2", NewGate: h.Build})
			if err != nil {
				t.Fatal(err)
			}
			if out.ExitCode() != tc.exit {
				t.Fatalf("exit=%d want=%d: %+v %+v", out.ExitCode(), tc.exit, out.Report.Refused, out.Report.Incomplete)
			}
			if tc.status != 200 || tc.name == "malformed" || tc.name == "content_type" {
				for _, row := range out.Report.Coverage {
					if (row.Area == "identity" || row.Area == "cicd" || row.Area == "secrets") && row.Population.Read != 0 {
						t.Fatalf("failed inventory counted as read: %+v", row)
					}
				}
			}
			if tc.token == "" && hits.Load() != 0 {
				t.Fatal("missing credential contacted API")
			}
			if tc.name == "installation" && out.Report.Assets[0].Principal.Identity != "unknown" {
				t.Fatal("installation identity invented")
			}
		})
	}
}

func inventoryOptions() engagement.Options {
	return engagement.Options{KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }, FindingSubject: func(string) string { return "" }, HostFinding: func(string) bool { return false }}
}

func TestGitHubInventoryCapsAreIncomplete(t *testing.T) {
	for _, cap := range []string{"page", "body"} {
		t.Run(cap, func(t *testing.T) {
			res, err := engagement.Parse("engagement.yaml", []byte(inventoryFile), inventoryOptions())
			if err != nil {
				t.Fatal(err)
			}
			h := gate.NewHarness(t, res.GateScope(time.Now()))
			h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("d", 36))
			h.GitHubHandler(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch req.URL.Path {
				case "/user":
					fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
				case "/orgs/acme":
					fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization"}`)
				case "/orgs/acme/members":
					if cap == "body" {
						fmt.Fprintf(w, `[{"id":1,"login":"alice","type":"User","discarded":%q}]`, strings.Repeat("x", 512))
						return
					}
					w.Header().Set("Link", `<https://api.github.com/orgs/acme/members?per_page=100&page=2&role=all&filter=all>; rel="next"`)
					fmt.Fprint(w, `[{"id":1,"login":"alice","type":"User"}]`)
				default:
					fmt.Fprint(w, `[]`)
				}
			})
			ops := append([]gate.Op(nil), githubc.Ops...)
			for i := range ops {
				if ops[i].List != nil {
					cp := *ops[i].List
					cp.MaxPages = 1
					if cap == "body" && ops[i].ID == githubc.OpMembers {
						ops[i].MaxBytes = 128
					}
					ops[i].List = &cp
				}
			}
			registry, err := gate.NewRegistry(ops...)
			if err != nil {
				t.Fatal(err)
			}
			dir, err := engagement.CreateRunDir(t.TempDir(), "inventory", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: []byte(inventoryFile), NewGate: func(cfg gate.Config) (*gate.Gate, error) { cfg.Registry = registry; return h.Build(cfg) }})
			if err != nil {
				t.Fatal(err)
			}
			if out.ExitCode() != 2 {
				t.Fatalf("page cap exit %d", out.ExitCode())
			}
			if len(out.Report.Incomplete) == 0 || out.Report.Incomplete[0].Reason != "limit_reached" {
				t.Fatalf("cap not recorded: %+v", out.Report.Incomplete)
			}
		})
	}

}
