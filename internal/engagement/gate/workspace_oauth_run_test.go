package gate_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
)

const workspaceOAuthFile = `schema: 1
engagement: {name: workspace-oauth, operator: Dani, timezone: UTC, trigger: routine}
roots:
  - saas: google-workspace:example.com
exclude:
  - {saas: google-workspace:example.com, org_unit: /board}
people:
  alice: {kind: employee, workspace: [alice@example.com]}
`

// OAuth grants travel from fake Directory responses through the gate and
// the collector to the report: the optional token is asked for once with
// its one scope and used only for grant reads, an excluded account is
// never read, a suspended account's grant does not fire, a seeded secret
// in an app's name never reaches the run directory yet does not hide the app, and a super
// administrator's broad grant raises its app
// (docs/spec/workspace-collector.md, "OAuth scope interpretation").
func TestWorkspaceOAuthThroughGateAndReport(t *testing.T) {
	raw := []byte(workspaceOAuthFile)
	res, err := engagement.Parse("engagement.yaml", raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	credential := filepath.Join(t.TempDir(), "adc.json")
	const token, optional = "opaque-access-seeded-oauth-1234567890", "opaque-optional-seeded-oauth-1234567890"
	const seeded = "ghp_0123456789abcdefABCDEF0123456789abcd"
	if err := os.WriteFile(credential, []byte(`{"type":"authorized_user","client_id":"assessment.apps.googleusercontent.com","client_secret":"fake-client-secret","refresh_token":"private-refresh-oauth-1234567890"}`), 0600); err != nil {
		t.Fatal(err)
	}
	h.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credential)
	h.Setenv("SCHECK_WORKSPACE_PROFILE", "directory_oauth")
	var mu sync.Mutex
	var scopes []string
	h.GoogleTokenHandler(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		scopes = append(scopes, r.PostForm.Get("scope"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Has("scope") {
			fmt.Fprint(w, `{"access_token":"`+optional+`","token_type":"Bearer","expires_in":3600}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"`+token+`","token_type":"Bearer","expires_in":3600}`)
	})
	user := func(id, email, unit, extra string) string {
		return `{"id":"` + id + `","primaryEmail":"` + email + `","customerId":"C123","orgUnitPath":"` + unit + `","archived":false,"isEnforcedIn2Sv":true,"isEnrolledIn2Sv":true` + extra + `}`
	}
	alice := user("1", "alice@example.com", "/Sales", `,"suspended":false,"isAdmin":true`)
	gone := user("2", "gone@example.com", "/Sales", `,"suspended":true,"isAdmin":false`)
	carol := user("4", "carol@example.com", "/Sales", `,"suspended":false,"isAdmin":false`)
	board := user("3", "board@example.com", "/Board", `,"suspended":false,"isAdmin":true`)
	grants := map[string]string{
		"1": `{"clientId":"app.apps.googleusercontent.com","scopes":["https://www.googleapis.com/auth/drive","openid"],"userKey":"1","displayText":"Shiny Docs"},{"clientId":"assessment.apps.googleusercontent.com","scopes":["https://www.googleapis.com/auth/admin.directory.user.security"],"userKey":"1","displayText":"scheck"}`,
		"2": `{"clientId":"old.apps.googleusercontent.com","scopes":["https://www.googleapis.com/auth/cloud-platform"],"userKey":"2","displayText":"Old Tool"}`,
		"4": `{"clientId":"leaky.apps.googleusercontent.com","scopes":["openid"],"userKey":"4","displayText":"` + seeded + `"}`,
	}
	var tokensRead []string
	h.WorkspaceHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/tokens") {
			if auth != "Bearer "+optional {
				t.Error("grants read without the optional token")
			}
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/directory/v1/users/"), "/tokens")
			mu.Lock()
			tokensRead = append(tokensRead, id)
			mu.Unlock()
			fmt.Fprint(w, `{"kind":"admin#directory#tokenList","items":[`+grants[id]+`]}`)
			return
		}
		if auth != "Bearer "+token {
			t.Error("a baseline read used another token", r.URL.Path)
		}
		switch r.URL.Path {
		case "/admin/directory/v1/customers/my_customer":
			fmt.Fprint(w, `{"id":"C123"}`)
		case "/admin/directory/v1/customer/C123/domains":
			fmt.Fprint(w, `{"kind":"admin#directory#domains","domains":[{"domainName":"example.com","verified":true}]}`)
		case "/admin/directory/v1/customer/C123/domainaliases":
			fmt.Fprint(w, `{"kind":"admin#directory#domainAliases"}`)
		case "/admin/directory/v1/customer/C123/orgunits":
			fmt.Fprint(w, `{"kind":"admin#directory#orgUnits","organizationUnits":[{"orgUnitId":"id:root","orgUnitPath":"/"},{"orgUnitId":"id:sales","orgUnitPath":"/Sales","parentOrgUnitPath":"/"},{"orgUnitId":"id:board","orgUnitPath":"/Board","parentOrgUnitPath":"/"}]}`)
		case "/admin/directory/v1/users":
			fmt.Fprint(w, `{"kind":"admin#directory#users","users":[`+alice+`,`+gone+`,`+carol+`,`+board+`]}`)
		case "/admin/directory/v1/users/1":
			fmt.Fprint(w, alice)
		case "/admin/directory/v1/users/4":
			fmt.Fprint(w, carol)
		case "/admin/directory/v1/customer/C123/roles", "/admin/directory/v1/customer/C123/roles/ALL/privileges", "/admin/directory/v1/customer/C123/roleassignments":
			w.WriteHeader(403)
		default:
			t.Error("undeclared or excluded path", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	start := time.Now().UTC().Truncate(time.Second)
	dir, err := engagement.CreateRunDir(t.TempDir(), "workspace-oauth", start)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: raw, Dir: dir, Started: start, Version: "e6-step5", NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(scopes, "|") != "|https://www.googleapis.com/auth/admin.directory.user.security" {
		t.Fatalf("token requests asked for %q", scopes)
	}
	if strings.Join(tokensRead, ",") != "1,4,2" {
		t.Fatalf("grants read for %v", tokensRead)
	}
	apps := map[string]string{}
	for _, f := range out.Report.Findings {
		if f.ID == "workspace.oauth_broad_scope" && f.Subject != nil {
			apps[f.Subject.Key] = f.Severity
		}
	}
	// The assessment client is not set aside on an incomplete population.
	if len(apps) != 2 || apps["app.apps.googleusercontent.com"] != "high" || apps["assessment.apps.googleusercontent.com"] != "high" {
		t.Fatalf("app findings %v", apps)
	}
	outcomes := map[string]string{}
	for _, a := range out.Report.Assessments {
		for _, o := range a.Outcomes {
			if o.Subject != nil {
				outcomes[o.Subject.Key] = o.Outcome
			}
		}
	}
	if outcomes["old.apps.googleusercontent.com"] != "abstained" {
		t.Fatalf("a suspended grantor's app on a partial population: %v", outcomes)
	}
	// A name that trips a redaction rule does not hide the app's grants.
	if outcomes["leaky.apps.googleusercontent.com"] != "abstained" {
		t.Fatalf("an app with a redacted name was not judged: %v", outcomes)
	}
	if out.ExitCode() != 2 {
		t.Fatalf("an exclusion and denied role reads leave the run incomplete, got exit %d", out.ExitCode())
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
		marked = marked || strings.Contains(string(b), `"label": "\"[REDACTED:`) || strings.Contains(string(b), `"label":"[REDACTED:`)
		for _, s := range []string{token, optional, seeded, "board@example.com", "private-refresh-oauth"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s leaked %s", path, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("the seeded secret's redaction marker is not in the run directory")
	}
}
