package gate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func TestGitHubAccessRunPersistsSubjectFindings(t *testing.T) {
	raw := []byte(`schema: 1
engagement: {name: access, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}]
assets:
  shop: {repo: "github:acme/shop", deploys_to: production, public: false}
people:
  alice: {kind: employee, github: [alice]}
  carol: {kind: employee, github: [carol], left: "2026-10-09"}
  ops: {kind: shared, github: [ops], used_by: [carol]}
access:
  admins: {"github:acme": [alice]}
  mfa: [{where: "github:acme", enforced: everyone}]
`)
	opts := inventoryOptions()
	opts.KnownFinding = finding.Known
	opts.FindingSubject = func(id string) string { return string(finding.SubjectOf(id)) }
	res, err := engagement.Parse("access.yaml", raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("z", 36))
	accounts := `[{"id":1,"login":"alice","type":"User"},{"id":4,"login":"carol","type":"User"},{"id":5,"login":"ops","type":"User"},{"id":7,"login":"ghost","type":"User"}]`
	owners := `[{"id":1,"login":"alice","type":"User"},{"id":5,"login":"ops","type":"User"},{"id":7,"login":"ghost","type":"User"}]`
	repo := `{"id":10,"name":"shop","full_name":"acme/shop","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"public"}`
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("write %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case "/orgs/acme/actions/permissions/workflow", "/repos/acme/shop/actions/permissions/workflow":
			fmt.Fprint(w, `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`)
		case "/orgs/acme":
			fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization","two_factor_requirement_enabled":false,"default_repository_permission":"write"}`)
		case "/user/memberships/orgs/acme":
			fmt.Fprint(w, `{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":1,"login":"alice","type":"User"}}`)
		case "/orgs/acme/members":
			if r.URL.Query().Get("filter") == "2fa_disabled" {
				fmt.Fprint(w, `[{"id":1,"login":"alice","type":"User"}]`)
			} else if r.URL.Query().Get("role") == "admin" {
				fmt.Fprint(w, owners)
			} else {
				fmt.Fprint(w, accounts)
			}
		case "/orgs/acme/outside_collaborators":
			fmt.Fprint(w, `[{"id":3,"login":"bob","type":"User"}]`)
		case "/orgs/acme/invitations":
			fmt.Fprint(w, `[{"id":6,"login":"carol","role":"direct_member"}]`)
		case "/orgs/acme/repos":
			fmt.Fprint(w, "["+repo+"]")
		case "/repos/acme/shop":
			fmt.Fprint(w, repo)
		case "/repos/acme/shop/collaborators":
			fmt.Fprint(w, `[{"id":3,"login":"bob","type":"User","role_name":"admin","permissions":{"admin":true,"pull":true,"push":true,"triage":true,"maintain":true}}]`)
		case "/repos/acme/shop/keys":
			fmt.Fprint(w, `[{"id":8,"read_only":false,"key":"discarded-public-key"}]`)
		case "/orgs/acme/actions/secrets", "/repos/acme/shop/actions/secrets", "/repos/alice/shop/actions/secrets":
			fmt.Fprint(w, `{"secrets":[]}`)
		case "/repos/acme/shop/dependabot/alerts", "/repos/acme/shop/secret-scanning/alerts", "/repos/alice/shop/dependabot/alerts", "/repos/alice/shop/secret-scanning/alerts":
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	dir, err := engagement.CreateRunDir(t.TempDir(), "access", at)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, Started: at, Session: at, NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 1 {
		t.Fatalf("exit%d incomplete%+v refused%+v", out.ExitCode(), out.Report.Incomplete, out.Report.Refused)
	}
	for _, row := range out.Report.Coverage {
		if (row.Area == string(finding.AreaIdentity) || row.Area == string(finding.AreaCICD)) && !slices.Contains(row.AssetsCovered, "repo:github:acme/shop") {
			t.Fatalf("read repository absent from covered assets: %+v", row)
		}
		for _, item := range row.SubItems {
			if item.Asset == "repo:github:acme/shop" && item.Name == "GitHub security controls" {
				t.Fatalf("judged repository mislabeled inventory-only: %+v", item)
			}
		}
	}
	found := map[string]bool{}
	for _, f := range out.Report.Findings {
		found[f.ID] = true
		if f.Subject != nil && f.Subject.ProviderID == "" {
			t.Errorf("no provider id: %+v", f)
		}
		if f.ID == finding.IDGitHubMFANotRequired && (f.Key.Subject != nil || f.Subject != nil || f.Severity != "critical") {
			t.Errorf("org subject/contradiction: %+v", f)
		}
		if f.ID == finding.IDGitHubWritableDeployKey && (f.Key.Asset != "repo:github:acme/shop" || f.Severity != "high") {
			t.Errorf("key ownership/grading: %+v", f)
		}
		for _, e := range f.Evidence {
			if e.Kind == "observed" && (e.Principal == "anonymous" || e.CollectedAt == nil) {
				t.Errorf("missing principal/time %+v", e)
			}
		}
	}
	for _, id := range []string{finding.IDGitHubMFANotRequired, finding.IDGitHubOwnerWithoutMFA, finding.IDIdentitySharedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityFormerPersonHasAccess, finding.IDIdentityFormerPersonInvited, finding.IDGitHubTooManyOwners, finding.IDGitHubUndeclaredPublicRepository, finding.IDGitHubBroadDefaultMemberPermission, finding.IDGitHubOutsideAdminOnProduction, finding.IDGitHubWritableDeployKey} {
		if !found[id] {
			t.Errorf("missing %s", id)
		}
	}
	b, err := os.ReadFile(dir.File("recon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recon engagement.ReconDoc
	if err = json.Unmarshal(b, &recon); err != nil {
		t.Fatal(err)
	}
	if len(recon.Attribution) == 0 || len(recon.PeopleCandidates) == 0 || len(recon.Assets[0].GitHub.Judgments) == 0 {
		t.Fatal("missing persisted attribution/candidates/judgments")
	}
	if strings.Contains(string(b), "discarded-public-key") {
		t.Fatal("public key persisted")
	}
	sharedNote := false
	for _, note := range out.Report.Notes {
		sharedNote = sharedNote || strings.Contains(note.Detail, "Rotate the shared account")
	}
	if !sharedNote {
		t.Fatal("shared rotation note absent")
	}
}

func TestGitHubRepositoryRootCollectsWithoutOrganizationAuthority(t *testing.T) {
	raw := []byte("schema: 1\nengagement: {name: repo, operator: alice, timezone: UTC, trigger: routine}\nroots: [{repo: 'github:alice/shop'}]\nassets:\n  shop: {repo: 'github:alice/shop', public: true}\n")
	res, err := engagement.Parse("repo.yaml", raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("x", 36))
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case "/repos/alice/shop/actions/permissions/workflow":
			fmt.Fprint(w, `{"default_workflow_permissions":"read"}`)
		case "/repos/alice/shop":
			fmt.Fprint(w, `{"id":10,"name":"shop","full_name":"alice/shop","owner":{"id":1,"login":"alice","type":"User"},"visibility":"public"}`)
		case "/repos/alice/shop/keys", "/repos/alice/shop/collaborators":
			fmt.Fprint(w, `[]`)
		case "/orgs/acme/actions/secrets", "/repos/acme/shop/actions/secrets", "/repos/alice/shop/actions/secrets":
			fmt.Fprint(w, `{"secrets":[]}`)
		case "/repos/acme/shop/dependabot/alerts", "/repos/acme/shop/secret-scanning/alerts", "/repos/alice/shop/dependabot/alerts", "/repos/alice/shop/secret-scanning/alerts":
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("root escaped to %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	dir, err := engagement.CreateRunDir(t.TempDir(), "repo", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 0 || len(out.Report.Findings) != 0 {
		t.Fatalf("exit%d findings%+v incomplete%+v", out.ExitCode(), out.Report.Findings, out.Report.Incomplete)
	}
	if out.Report.Assets[0].Collector == nil || *out.Report.Assets[0].Collector != "github" {
		t.Fatal("repository collector omitted")
	}
}
