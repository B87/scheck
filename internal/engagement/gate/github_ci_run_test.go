package gate_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

func TestGitHubCIRunPinsGETsAndNeverPersistsEncodedSecrets(t *testing.T) {
	raw := []byte("schema: 1\nengagement: {name: ci, operator: alice, timezone: UTC, trigger: routine}\nroots: [{saas: 'github:acme'}]\nassets:\n  shop: {repo: 'github:acme/shop', deploys_to: production, public: true}\npeople:\n  alice: {kind: employee, github: [alice]}\naccess:\n  admins: {'github:acme': [alice]}\n")
	opts := inventoryOptions()
	opts.KnownFinding = finding.Known
	opts.FindingSubject = func(id string) string { return string(finding.SubjectOf(id)) }
	res, err := engagement.Parse("ci.yaml", raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("t", 36))
	commit := strings.Repeat("a", 40)
	blob := strings.Repeat("b", 40)
	secret := "ghp_" + strings.Repeat("s", 36)
	workflow := "on: pull_request_target\npermissions: write-all\njobs:\n  build:\n    runs-on: [self-hosted, linux]\n    steps:\n    - uses: actions/checkout@v4\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n        allow-unsafe-pr-checkout: true\n    - run: npm ci\n    env:\n      SEED: " + secret + "\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(workflow))
	repo := `{"id":10,"name":"shop","full_name":"acme/shop","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"public","default_branch":"Release/v1"}`
	hits := []string{}
	h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.RequestURI())
		if r.Method != "GET" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
			t.Errorf("request changed %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
		case "/orgs/acme":
			fmt.Fprint(w, `{"id":2,"login":"acme","type":"Organization","two_factor_requirement_enabled":true,"default_repository_permission":"read"}`)
		case "/user/memberships/orgs/acme":
			fmt.Fprint(w, `{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":1,"login":"alice","type":"User"}}`)
		case "/orgs/acme/members":
			if r.URL.Query().Get("filter") == "2fa_disabled" {
				fmt.Fprint(w, `[]`)
			} else {
				fmt.Fprint(w, `[{"id":1,"login":"alice","type":"User"}]`)
			}
		case "/orgs/acme/outside_collaborators", "/orgs/acme/invitations", "/repos/acme/shop/collaborators", "/repos/acme/shop/keys":
			fmt.Fprint(w, `[]`)
		case "/orgs/acme/repos":
			fmt.Fprint(w, "["+repo+"]")
		case "/repos/acme/shop":
			fmt.Fprint(w, repo)
		case "/orgs/acme/actions/permissions/workflow", "/repos/acme/shop/actions/permissions/workflow":
			fmt.Fprint(w, `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}`)
		case "/repos/acme/shop/branches/Release/v1":
			fmt.Fprintf(w, `{"name":"Release/v1","protected":false,"commit":{"sha":%q}}`, commit)
		case "/repos/acme/shop/rules/branches/Release/v1":
			fmt.Fprint(w, `[]`)
		case "/repos/acme/shop/contents/.github/workflows":
			if r.URL.Query().Get("ref") != commit {
				t.Error("directory unpinned")
			}
			fmt.Fprintf(w, `[{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":%d,"download_url":"https://outside.example/steal"}]`, blob, len(workflow))
		case "/repos/acme/shop/contents/.github/workflows/ci.yml":
			if r.URL.Query().Get("ref") != commit {
				t.Error("file unpinned")
			}
			fmt.Fprintf(w, `{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":%d,"encoding":"base64","content":%q,"download_url":"https://outside.example/steal"}`, blob, len(workflow), encoded)
		case "/orgs/acme/actions/secrets", "/repos/acme/shop/actions/secrets":
			fmt.Fprint(w, `{"secrets":[]}`)
		case "/repos/acme/shop/dependabot/alerts", "/repos/acme/shop/secret-scanning/alerts":
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("uncompiled path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	dir, err := engagement.CreateRunDir(t.TempDir(), "ci", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, NewGate: h.Build, Version: "step4"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 1 {
		t.Fatalf("exit%d incomplete%+v refused%+v", out.ExitCode(), out.Report.Incomplete, out.Report.Refused)
	}
	found := map[string]bool{}
	for _, f := range out.Report.Findings {
		found[f.ID] = true
		if f.ID == finding.IDGitHubPRTargetUnsafe && f.Severity != "high" {
			t.Fatalf("PR-target rating %+v", f)
		}
		if f.ID == finding.IDGitHubMutableActionWrite && f.Severity != "high" {
			t.Fatal("dependency double raised")
		}
		if f.ID == finding.IDGitHubDefaultBranchUnprotected && (f.Subject == nil || f.Subject.Key != "Release/v1") {
			t.Fatal("branch case lost")
		}
		if strings.Contains(f.ID, "workflow") || f.ID == finding.IDGitHubDefaultBranchUnprotected || f.ID == finding.IDGitHubPRTargetUnsafe {
			if f.ID != finding.IDGitHubOrganizationWorkflowWrite && f.Key.Asset != "repo:github:acme/shop" {
				t.Fatal("wrong report asset")
			}
		}
	}
	for _, id := range finding.GitHubCIIDs() {
		if id == finding.IDGitHubMutableAction {
			if found[id] {
				t.Fatal("duplicate pinning finding")
			}
			continue
		}
		if !found[id] {
			t.Fatalf("missing%s findings%+v", id, out.Report.Findings)
		}
	}
	for _, row := range out.Report.Coverage {
		if row.Area == "cicd" && !slices.Contains(row.AssetsCovered, "repo:github:acme/shop") {
			t.Fatal("CI coverage omitted repo")
		}
	}
	var reportText bytes.Buffer
	if err = ereport.WriteText(&reportText, out.Report, ereport.Options{Verbose: 1}); err != nil {
		t.Fatal(err)
	}
	reportJSON, _ := json.Marshal(out.Report)
	for _, output := range [][]byte{reportText.Bytes(), reportJSON} {
		if bytes.Contains(output, []byte(secret)) || bytes.Contains(output, []byte(encoded)) {
			t.Fatal("report exposed seeded secret")
		}
	}
	if !strings.Contains(reportText.String(), "not assessed") || !strings.Contains(reportText.String(), "self-hosted") {
		t.Fatal("missing runtime/runner limitations")
	}
	if !bytes.Contains(reportJSON, []byte("[REDACTED:")) {
		t.Fatal("report marker absent")
	}
	audit, _ := os.ReadFile(filepath.Join(dir.Path, "audit.jsonl"))
	if bytes.Contains(audit, []byte(secret)) || bytes.Contains(audit, []byte(encoded)) {
		t.Fatal("audit exposed secret")
	}
	marked := false
	err = filepath.WalkDir(dir.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(encoded)) {
			t.Errorf("secret persisted in %s", path)
		}
		marked = marked || bytes.Contains(b, []byte("[REDACTED:"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("persisted marker absent")
	}
	if len(hits) != 23 {
		t.Fatalf("request trace count %d %v", len(hits), hits)
	}
}

// Every CI rule is also driven through real gate decoding/projection, not only
// neutral-document fixtures. Unknown responses never become negative verdicts.
func TestGitHubCIFakeAPIThreeOutcomes(t *testing.T) {
	for _, verdict := range []string{githubc.Fired, githubc.Disproved, githubc.Abstained} {
		t.Run(verdict, func(t *testing.T) {
			res, err := engagement.Parse("ci.yaml", []byte(inventoryFile), inventoryOptions())
			if err != nil {
				t.Fatal(err)
			}
			h := gate.NewHarness(t, res.GateScope(time.Now()))
			h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("x", 36))
			sha := strings.Repeat("a", 40)
			blob := strings.Repeat("b", 40)
			setting, trigger, reference, permissions, protected := "write", "pull_request_target", "v4", "write-all", false
			if verdict == githubc.Disproved {
				setting, trigger, reference, permissions, protected = "read", "push", sha, "read-all", true
			}
			source := "on: " + trigger + "\npermissions: " + permissions + "\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@" + reference + "\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n    - run: npm test\n"
			if verdict == githubc.Abstained {
				source = "on: push\non: pull_request_target\n"
			}
			hits := []string{}
			h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
				hits = append(hits, r.URL.Path)
				if r.Method != "GET" {
					t.Error("write")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/orgs/acme/actions/permissions/workflow", "/repos/acme/shop/actions/permissions/workflow":
					if verdict == githubc.Abstained {
						w.WriteHeader(403)
						fmt.Fprint(w, `{"message":"permission denied"}`)
					} else {
						fmt.Fprintf(w, `{"default_workflow_permissions":%q}`, setting)
					}
				case "/repos/acme/shop/branches/main":
					if verdict == githubc.Abstained {
						fmt.Fprintf(w, `{"name":"main","commit":{"sha":%q}}`, sha)
					} else {
						fmt.Fprintf(w, `{"name":"main","protected":%t,"commit":{"sha":%q}}`, protected, sha)
					}
				case "/repos/acme/shop/rules/branches/main":
					if verdict == githubc.Abstained {
						w.WriteHeader(403)
						fmt.Fprint(w, `{"message":"permission denied"}`)
					} else {
						fmt.Fprint(w, `[]`)
					}
				case "/repos/acme/shop/contents/.github/workflows":
					if r.URL.Query().Get("ref") != sha {
						t.Error("unpinned")
					}
					fmt.Fprintf(w, `[{"name":"ci.yml","path":".github/workflows/ci.yml","sha":%q,"type":"file","size":%d}]`, blob, len(source))
				case "/repos/acme/shop/contents/.github/workflows/ci.yml":
					if r.URL.Query().Get("ref") != sha {
						t.Error("unpinned")
					}
					fmt.Fprintf(w, `{"name":"ci.yml","path":".github/workflows/ci.yml","sha":%q,"type":"file","size":%d,"encoding":"base64","content":%q}`, blob, len(source), base64.StdEncoding.EncodeToString([]byte(source)))
				case "/orgs/acme/actions/secrets", "/repos/acme/shop/actions/secrets":
					fmt.Fprint(w, `{"secrets":[]}`)
				case "/repos/acme/shop/dependabot/alerts", "/repos/acme/shop/secret-scanning/alerts":
					fmt.Fprint(w, `[]`)
				default:
					t.Errorf("unexpected%s", r.URL.Path)
					w.WriteHeader(404)
				}
			})
			registry, err := gate.NewRegistry(githubc.Ops...)
			if err != nil {
				t.Fatal(err)
			}
			g, err := h.Build(gate.Config{Registry: registry, Scope: res.GateScope(time.Now()), Audit: policy.NewAudit(&bytes.Buffer{})})
			if err != nil {
				t.Fatal(err)
			}
			e := githubc.Evidence{Organization: &githubc.OrganizationObject{ID: 2, Login: "acme", Type: "Organization"}, RepositoriesAccess: []githubc.RepositoryAccess{{Asset: "repo:github:acme/shop", Repository: &githubc.Repository{ID: 10, Name: "shop", FullName: "acme/shop", Owner: githubc.Account{ID: 2, Login: "acme", Type: "Organization"}, DefaultBranch: new("main")}}}}
			e = githubc.CollectCI(context.Background(), g, e, githubc.Organization{Asset: "saas:github:acme", Name: "acme", Stage: "recon"})
			judgments := githubc.JudgeCI(e, githubc.Context{OrganizationAsset: "saas:github:acme"})
			for _, id := range finding.GitHubCIIDs() {
				if !slices.ContainsFunc(judgments, func(j githubc.Judgment) bool { return j.ID == id && j.Verdict == verdict }) {
					t.Fatalf("%s want %s: %+v", id, verdict, judgments)
				}
			}
			if len(hits) != 6 {
				t.Fatalf("unexpected surface%v", hits)
			}
		})
	}
}
