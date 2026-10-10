package gate_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
)

const workspaceTwoStepFile = `schema: 1
engagement: {name: workspace-two-step, operator: Dani, timezone: UTC, trigger: routine}
roots:
  - saas: google-workspace:example.com
exclude:
  - {saas: google-workspace:example.com, org_unit: /board}
people:
  alice: {kind: employee, workspace: [alice@example.com]}
access:
  mfa:
    - {where: google-workspace:example.com, enforced: everyone}
`

// Observed 2-step flags travel from fake Directory responses through the
// gate and the collector to the report: an excluded unit's account never
// appears, a fresh detail with a null flag leaves its account unknown, and
// the everyone declaration raises the fired unit
// (docs/spec/workspace-collector.md, "Observed 2-step verification").
func TestWorkspaceTwoStepThroughGateAndReport(t *testing.T) {
	raw := []byte(workspaceTwoStepFile)
	res, err := engagement.Parse("engagement.yaml", raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	credential := filepath.Join(t.TempDir(), "adc.json")
	const token = "opaque-access-seeded-2sv-1234567890"
	if err := os.WriteFile(credential, []byte(`{"type":"authorized_user","client_id":"assessment.apps.googleusercontent.com","client_secret":"fake-client-secret","refresh_token":"private-refresh-2sv-1234567890"}`), 0600); err != nil {
		t.Fatal(err)
	}
	h.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credential)
	h.GoogleTokenHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"`+token+`","token_type":"Bearer","expires_in":3600}`)
	})
	user := func(id, email, unit, extra string) string {
		return `{"id":"` + id + `","primaryEmail":"` + email + `","customerId":"C123","orgUnitPath":"` + unit + `","suspended":false,"archived":false` + extra + `}`
	}
	alice := user("1", "alice@example.com", "/Sales", `,"isAdmin":true,"isEnforcedIn2Sv":false,"isEnrolledIn2Sv":false`)
	bob := user("2", "bob@example.com", "/Eng", `,"isAdmin":false,"isEnforcedIn2Sv":false,"isEnrolledIn2Sv":true`)
	board := user("3", "board@example.com", "/Board", `,"isAdmin":true,"isEnforcedIn2Sv":false,"isEnrolledIn2Sv":false`)
	h.WorkspaceHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/directory/v1/customers/my_customer":
			fmt.Fprint(w, `{"id":"C123"}`)
		case "/admin/directory/v1/customer/C123/domains":
			fmt.Fprint(w, `{"kind":"admin#directory#domains","domains":[{"domainName":"example.com","verified":true}]}`)
		case "/admin/directory/v1/customer/C123/domainaliases":
			fmt.Fprint(w, `{"kind":"admin#directory#domainAliases"}`)
		case "/admin/directory/v1/customer/C123/orgunits":
			fmt.Fprint(w, `{"kind":"admin#directory#orgUnits","organizationUnits":[{"orgUnitId":"id:root","orgUnitPath":"/"},{"orgUnitId":"id:sales","orgUnitPath":"/Sales","parentOrgUnitPath":"/"},{"orgUnitId":"id:eng","orgUnitPath":"/Eng","parentOrgUnitPath":"/"},{"orgUnitId":"id:board","orgUnitPath":"/Board","parentOrgUnitPath":"/"}]}`)
		case "/admin/directory/v1/users":
			fmt.Fprint(w, `{"kind":"admin#directory#users","users":[`+alice+`,`+bob+`,`+board+`]}`)
		case "/admin/directory/v1/users/2":
			// A present null flag in fresh detail is unknown, never the list's value.
			fmt.Fprint(w, user("2", "bob@example.com", "/Eng", `,"isAdmin":false,"isEnforcedIn2Sv":null,"isEnrolledIn2Sv":true`))
		case "/admin/directory/v1/users/1":
			fmt.Fprint(w, alice)
		case "/admin/directory/v1/customer/C123/roles", "/admin/directory/v1/customer/C123/roles/ALL/privileges", "/admin/directory/v1/customer/C123/roleassignments":
			w.WriteHeader(403)
		default:
			t.Error("undeclared or excluded path", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	start := time.Now().UTC().Truncate(time.Second)
	dir, err := engagement.CreateRunDir(t.TempDir(), "workspace-two-step", start)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: raw, Dir: dir, Started: start, Version: "e6-step4", NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	units, admins := map[string]string{}, map[string]string{}
	for _, f := range out.Report.Findings {
		if f.Subject == nil {
			continue
		}
		switch f.ID {
		case "workspace.two_step_not_enforced":
			units[f.Subject.Key] = f.Severity
		case "workspace.admin_without_two_step":
			admins[f.Subject.Key] = f.Severity
		}
	}
	if len(units) != 1 || units["/sales"] != "critical" {
		t.Fatalf("unit findings %v", units)
	}
	if len(admins) != 1 || admins["alice@example.com"] != "high" {
		t.Fatalf("admin findings %v", admins)
	}
	engJudged := false
	for _, a := range out.Report.Assessments {
		for _, o := range a.Outcomes {
			if o.Subject != nil && (strings.Contains(o.Subject.Key, "board") || o.Subject.Key == "/eng" && o.Outcome != "abstained") {
				t.Fatalf("excluded or unknown account judged: %+v", o)
			}
			engJudged = engJudged || o.Subject != nil && o.Subject.Key == "/eng"
		}
	}
	if !engJudged {
		t.Fatal("the unit with an unreadable fresh flag has no explicit abstention")
	}
	if out.ExitCode() != 2 {
		t.Fatalf("an exclusion and denied role reads leave the run incomplete, got exit %d", out.ExitCode())
	}
	err = filepath.WalkDir(dir.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, seed := range []string{token, "board@example.com", "private-refresh-2sv"} {
			if strings.Contains(string(b), seed) {
				t.Errorf("%s leaked %s", path, seed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
