package gate_test

import (
	"bytes"
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

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

func TestGitHubAlertsRunOutcomesProjectionAndScope(t *testing.T) {
	for _, verdict := range []string{githubc.Fired, githubc.Disproved, githubc.Abstained} {
		t.Run(verdict, func(t *testing.T) {
			raw := []byte("schema: 1\nengagement: {name: alerts, operator: alice, timezone: UTC, trigger: routine}\nroots: [{saas: 'github:acme'}]\nexclude: [{repo: 'github:acme/excluded'}]\nassets:\n  shop: {repo: 'github:acme/shop', public: true}\npeople:\n  alice: {kind: employee, github: [alice]}\naccess:\n  admins: {'github:acme': [alice]}\n")
			opts := inventoryOptions()
			opts.KnownFinding = finding.Known
			opts.FindingSubject = func(id string) string { return string(finding.SubjectOf(id)) }
			res, err := engagement.Parse("alerts.yaml", raw, opts)
			if err != nil {
				t.Fatal(err)
			}
			h := gate.NewHarness(t, res.GateScope(time.Now()))
			h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("t", 36))
			opaque := "opaque-provider-value-without-local-detector"
			known := "ghp_" + strings.Repeat("s", 36)
			unsupported := "discard-unknown-location-secret"
			commit := strings.Repeat("a", 40)
			repo := `{"id":10,"name":"shop","full_name":"acme/shop","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"public"}`
			hits := []string{}
			h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
					t.Error("request surface")
				}
				hits = append(hits, r.URL.RequestURI())
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
					fmt.Fprint(w, `{"default_workflow_permissions":"read"}`)
				case "/orgs/acme/actions/secrets":
					v := "all"
					if verdict == githubc.Disproved {
						v = "private"
					}
					if verdict == githubc.Abstained {
						v = "future"
					}
					fmt.Fprintf(w, `{"secrets":[{"name":"PROD_KEY","visibility":%q},{"name":"SHARED","visibility":"selected"}]}`, v)
				case "/orgs/acme/actions/secrets/SHARED/repositories":
					fmt.Fprint(w, `{"repositories":[{"id":11,"name":"excluded","full_name":"acme/excluded","owner":{"id":2,"login":"acme","type":"Organization"}},{"id":12,"name":"alien","full_name":"other/alien","owner":{"id":3,"login":"other","type":"Organization"}}]}`)
				case "/repos/acme/shop/actions/secrets":
					fmt.Fprint(w, `{"secrets":[{"name":"REPO_KEY","updated_at":"2026-10-01T00:00:00Z","value":"discard-metadata-value"}]}`)
				case "/repos/acme/shop/dependabot/alerts":
					if r.URL.Query().Has("page") {
						t.Error("Dependabot used page instead of cursor")
					}
					state := "open"
					if verdict == githubc.Disproved {
						state = "dismissed"
					}
					if verdict == githubc.Abstained {
						state = "future"
					}
					fmt.Fprintf(w, `[{"number":1,"state":%q,"dependency":{"manifest_path":"App/package-lock.json","scope":"runtime"},"security_vulnerability":{"severity":"critical"}},{"number":2,"state":%q,"dependency":{"manifest_path":"App/package-lock.json"},"security_vulnerability":{"severity":"medium"}},{"number":3,"state":%q,"dependency":{"manifest_path":"App/package-lock.json"},"security_vulnerability":{"severity":"low"}}]`, state, state, state)
				case "/repos/acme/shop/secret-scanning/alerts":
					if r.URL.Query().Get("hide_secret") != "true" {
						t.Error("raw secret not suppressed")
					}
					state := "open"
					resolution := ""
					validity := "unknown"
					if verdict == githubc.Disproved {
						state = "resolved"
						resolution = "revoked"
					}
					if verdict == githubc.Abstained {
						validity = "inactive"
					}
					fmt.Fprintf(w, `[{"number":7,"state":%q,"resolution":%q,"secret_type":"stripe_secret_key","validity":%q,"secret":%q,"metadata":{"opaque":%q},"locations_url":"https://outside.example/steal"},{"number":8,"state":%q,"resolution":%q,"secret_type":"github_pat","validity":%q,"secret":%q}]`, state, resolution, validity, opaque, opaque, state, resolution, validity, known)
				case "/repos/acme/shop/secret-scanning/alerts/7/locations", "/repos/acme/shop/secret-scanning/alerts/8/locations":
					fmt.Fprintf(w, `[{"type":"commit","details":{"commit_sha":%q,"path":"config/Prod.env","start_line":2,"end_line":2,"start_column":1,"end_column":12,"blob_url":"https://outside.example/steal"}}]`, commit)
				default:
					t.Errorf("outside compiled requests %s", r.URL.Path)
					fmt.Fprint(w, unsupported)
					w.WriteHeader(500)
				}
			})
			dir, err := engagement.CreateRunDir(t.TempDir(), "alerts", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Dir: dir, Raw: raw, NewGate: h.Build, Version: "step5"})
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, a := range out.Report.Assessments {
				if slices.Contains(finding.GitHubAlertIDs(), a.ID) {
					for _, v := range a.Outcomes {
						seen[a.ID+":"+v.Outcome] = true
					}
				}
			}
			for _, id := range finding.GitHubAlertIDs() {
				if !seen[id+":"+verdict] {
					t.Fatalf("outcome missing %s %s; seen=%v incomplete=%+v hits=%v", id, verdict, seen, out.Report.Incomplete, hits)
				}
			}
			if verdict == githubc.Fired {
				for _, f := range out.Report.Findings {
					if f.ID == finding.IDGitHubSecretScanningOpen && (f.Severity != "critical" || f.Subject == nil || !strings.Contains(f.Subject.Key, "config%2FProd.env")) {
						t.Fatalf("secret severity/subject %+v", f)
					}
				}
			}
			encoded, _ := json.Marshal(out.Report)
			if bytes.Contains(encoded, []byte(opaque)) || bytes.Contains(encoded, []byte(known)) || !bytes.Contains(encoded, []byte("[REDACTED:")) {
				t.Fatal("report redaction")
			}
			marker := false
			err = filepath.WalkDir(dir.Path, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				for _, seed := range []string{opaque, known, unsupported, "discard-metadata-value", "https://outside.example/steal"} {
					if bytes.Contains(b, []byte(seed)) {
						t.Errorf("unretained data in %s: %s", p, seed)
					}
				}
				marker = marker || bytes.Contains(b, []byte("[REDACTED:"))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !marker {
				t.Fatal("marker missing")
			}
			// Exclude declarations are legitimately persisted; inspect collected Recon separately.
			var recon engagement.ReconDoc
			b, _ := os.ReadFile(dir.File("recon.json"))
			if bytes.Contains(b, []byte("other/alien")) || bytes.Contains(b, []byte("acme/excluded")) {
				t.Fatal("excluded repository metadata persisted in recon")
			}
			if json.Unmarshal(b, &recon) != nil {
				t.Fatal("recon")
			}
			if len(hits) != 22 {
				t.Fatalf("trace %d %v", len(hits), hits)
			}
		})
	}
}

func TestMetadataGateErrorsCapsAndCursor(t *testing.T) {
	for _, mode := range []string{"cursor", "page_cap", "body_cap", "structure_cap", "error", "malformed", "unexpected_type", "unsupported_location"} {
		t.Run(mode, func(t *testing.T) {
			res, err := engagement.Parse("e.yaml", []byte(inventoryFile), inventoryOptions())
			if err != nil {
				t.Fatal(err)
			}
			h := gate.NewHarness(t, res.GateScope(time.Now()))
			h.Setenv("GITHUB_TOKEN", "ghp_"+strings.Repeat("t", 36))
			secret := "opaque-value-with-no-detector"
			hits := []string{}
			h.GitHubHandler(func(w http.ResponseWriter, r *http.Request) {
				hits = append(hits, r.URL.RequestURI())
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/user" {
					fmt.Fprint(w, `{"id":1,"login":"alice","type":"User"}`)
					return
				}
				if r.Method != "GET" {
					t.Error("write")
				}
				switch mode {
				case "cursor", "page_cap":
					if r.URL.Query().Has("page") {
						t.Error("page sent")
					}
					if r.URL.Query().Get("after") == "" {
						w.Header().Set("Link", `<https://evil.example/elsewhere?after=next_cursor>; rel="next"`)
						fmt.Fprint(w, `[{"number":1}]`)
					} else if r.URL.Path == "/repos/acme/shop/dependabot/alerts" && r.URL.Query().Get("after") == "next_cursor" {
						fmt.Fprint(w, `[{"number":2}]`)
					} else {
						t.Error("cursor URL followed")
						fmt.Fprint(w, `[]`)
					}
				case "body_cap":
					fmt.Fprintf(w, `[{"number":7,"secret":%q,"metadata":%q}]`, secret, strings.Repeat("x", 500))
				case "structure_cap":
					fmt.Fprint(w, strings.Repeat("[", 42)+"0"+strings.Repeat("]", 42))
				case "error":
					w.WriteHeader(403)
					fmt.Fprintf(w, `{"message":%q,"secret":%q}`, secret, secret)
				case "malformed":
					fmt.Fprintf(w, `[{"secret":%q,"number":7,"number":8}]`, secret)
				case "unexpected_type":
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprint(w, secret)
				case "unsupported_location":
					fmt.Fprintf(w, `[{"type":"issue_title","details":{"path":%q,"body":%q,"commit_sha":"%s"}}]`, secret, secret, strings.Repeat("a", 40))
				}
			})
			ops := slices.Clone(githubc.Ops)
			for i := range ops {
				if ops[i].ID == githubc.OpDependabotAlerts && mode == "page_cap" {
					cp := *ops[i].List
					cp.MaxPages = 1
					ops[i].List = &cp
				}
				if ops[i].ID == githubc.OpSecretAlerts && mode == "body_cap" {
					ops[i].MaxBytes = 128
				}
			}
			reg, err := gate.NewRegistry(ops...)
			if err != nil {
				t.Fatal(err)
			}
			var audit bytes.Buffer
			g, err := h.Build(gate.Config{Registry: reg, Scope: res.GateScope(time.Now()), Audit: policy.NewAudit(&audit)})
			if err != nil {
				t.Fatal(err)
			}
			githubc.ResolvePrincipal(context.Background(), g, "saas:github:acme", "recon")
			op := githubc.OpSecretAlerts
			if mode == "cursor" || mode == "page_cap" {
				op = githubc.OpDependabotAlerts
			}
			params := map[string]string{"owner": "acme", "repo": "shop"}
			if mode == "unsupported_location" {
				op = githubc.OpSecretLocations
				params["alert_number"] = "7"
			}
			req := gate.Request{Op: op, Asset: "repo:github:acme/shop", Stage: "recon", Exists: true, Params: params}
			r := g.Send(context.Background(), req)
			if mode == "cursor" {
				if r.Response == nil || r.Response.Population == nil || !r.Response.Population.More {
					t.Fatal("missing cursor")
				}
				req.NextOf = r.RequestID
				next := g.Send(context.Background(), req)
				if next.Reason != "" || !bytes.Contains(next.Response.Body, []byte(`"number":2`)) {
					t.Fatalf("cursor did not reconstruct %+v", next)
				}
				if len(hits) != 3 || strings.Contains(hits[2], "evil") {
					t.Fatal("contact count", hits)
				}
			}
			if mode == "page_cap" && (r.Response.Population == nil || !slices.Contains(r.Response.Population.Incomplete, "page_limit")) {
				t.Fatal("missing page cap")
			}
			if (mode == "body_cap" || mode == "structure_cap") && r.Reason != "limit_reached" {
				t.Fatal("cap mislabeled", r.Reason)
			}
			if r.Response != nil && bytes.Contains(r.Response.Body, []byte(secret)) {
				t.Fatal("secret response retained")
			}
			b, _ := json.Marshal(g.Entries())
			if bytes.Contains(b, []byte(secret)) || bytes.Contains(audit.Bytes(), []byte(secret)) {
				t.Fatal("secret in trace/audit")
			}
			if mode == "unsupported_location" && strings.Contains(string(r.Response.Body), "details") {
				t.Fatal("unsupported details kept")
			}
		})
	}
}
