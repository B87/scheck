package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
)

// A refusal in Check is recorded with its kind even when Recon already
// left the root incomplete: the run exits 3, not 2.
func TestGitHubRefusalInCheckIsRecordedAfterAnIncompleteRecon(t *testing.T) {
	raw := []byte(`schema: 1
engagement: {name: refused, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}]
assets:
  shop: {repo: "github:acme/shop", deploys_to: production}
`)
	res, err := engagement.Parse("refused.yaml", raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("y", 36))
	repo := `{"id":10,"name":"shop","full_name":"acme/shop","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"private","default_branch":"main"}`
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case "/orgs/acme":
			fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization"}`)
		case "/user/memberships/orgs/acme":
			fmt.Fprint(w, `{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":1,"login":"alice","type":"User"}}`)
		case "/orgs/acme/invitations":
			w.WriteHeader(500)
		case "/orgs/acme/repos":
			fmt.Fprint(w, "["+repo+"]")
		case "/repos/acme/shop":
			fmt.Fprint(w, repo)
		case "/repos/acme/shop/keys":
			w.WriteHeader(401)
		case "/orgs/acme/actions/permissions/workflow", "/repos/acme/shop/actions/permissions/workflow":
			fmt.Fprint(w, `{"default_workflow_permissions":"read"}`)
		case "/orgs/acme/actions/secrets", "/repos/acme/shop/actions/secrets":
			fmt.Fprint(w, `{"secrets":[]}`)
		default:
			fmt.Fprint(w, `[]`)
		}
	})
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	dir, err := engagement.CreateRunDir(t.TempDir(), "refused", at)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, Started: at, Session: at, NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 3 || len(out.Report.Refused) != 1 || out.Report.Refused[0].Kind != "access" {
		t.Fatalf("exit %d refused %+v incomplete %+v", out.ExitCode(), out.Report.Refused, out.Report.Incomplete)
	}
	// Recon left the root incomplete before Check was refused.
	b, err := os.ReadFile(dir.File("recon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recon engagement.ReconDoc
	if err := json.Unmarshal(b, &recon); err != nil || recon.Assets[0].Status != engagement.StatusIncomplete {
		t.Fatalf("recon %v: %+v", err, recon.Assets)
	}
	for _, s := range out.Report.Incomplete {
		if s.Asset == "saas:github:acme" {
			t.Fatalf("refused root also incomplete: %+v", s)
		}
	}
}

// A provider's stop in Check leaves the declared repositories after it
// unread for the limit's reason, each named in incomplete: never "failed".
func TestGitHubStopInCheckLeavesLaterRepositoriesLimitReached(t *testing.T) {
	raw := []byte(`schema: 1
engagement: {name: stopped, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}]
assets:
  alpha: {repo: "github:acme/alpha", deploys_to: production}
  beta: {repo: "github:acme/beta", deploys_to: production}
  gamma: {repo: "github:acme/gamma", deploys_to: production}
`)
	res, err := engagement.Parse("stopped.yaml", raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("w", 36))
	repo := func(name string) string {
		return fmt.Sprintf(`{"id":%d,"name":%q,"full_name":"acme/%s","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"private","default_branch":"main"}`, 10+len(name), name, name)
	}
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case "/orgs/acme":
			fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization"}`)
		case "/user/memberships/orgs/acme":
			fmt.Fprint(w, `{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":1,"login":"alice","type":"User"}}`)
		case "/orgs/acme/repos":
			fmt.Fprint(w, "["+repo("alpha")+","+repo("beta")+","+repo("gamma")+"]")
		case "/repos/acme/alpha", "/repos/acme/gamma":
			fmt.Fprint(w, repo(strings.TrimPrefix(r.URL.Path, "/repos/acme/")))
		case "/repos/acme/beta":
			w.Header().Set("Retry-After", "86400")
			w.WriteHeader(429)
		case "/orgs/acme/actions/permissions/workflow", "/repos/acme/alpha/actions/permissions/workflow":
			fmt.Fprint(w, `{"default_workflow_permissions":"read"}`)
		case "/orgs/acme/actions/secrets", "/repos/acme/alpha/actions/secrets":
			fmt.Fprint(w, `{"secrets":[]}`)
		case "/repos/acme/alpha/branches/main":
			fmt.Fprintf(w, `{"name":"main","protected":true,"commit":{"sha":%q}}`, strings.Repeat("a", 40))
		default:
			fmt.Fprint(w, `[]`)
		}
	})
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	dir, err := engagement.CreateRunDir(t.TempDir(), "stopped", at)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, Started: at, Session: at, NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Report.Assets {
		if a.ID == "repo:github:acme/gamma" && (a.Reason != "limit_reached" || a.Status == "failed") {
			t.Fatalf("gamma: %+v", a)
		}
	}
	listed := false
	for _, s := range out.Report.Incomplete {
		listed = listed || s.Asset == "repo:github:acme/gamma" && s.Reason == "limit_reached"
	}
	if !listed || out.ExitCode() != 2 {
		t.Fatalf("exit %d incomplete %+v", out.ExitCode(), out.Report.Incomplete)
	}
}
