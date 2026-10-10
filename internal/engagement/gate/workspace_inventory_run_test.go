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
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

const workspaceInventoryFile = `schema: 1
engagement: {name: workspace-inventory, operator: Dani, timezone: UTC, trigger: routine}
roots:
  - saas: google-workspace:example.com
exclude:
  - {saas: google-workspace:example.com, org_unit: /board}
people:
  alice: {kind: employee, workspace: [alice@secondary.example]}
`

func TestWorkspaceInventoryPersistResumePrivacyAndCoverage(t *testing.T) {
	raw := []byte(workspaceInventoryFile)
	file := filepath.Join(t.TempDir(), "engagement.yaml")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	res, err := engagement.Parse(file, raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	credential := filepath.Join(t.TempDir(), "adc.json")
	const token = "opaque-access-seeded-1234567890"
	const secret = "private-refresh-seeded-1234567890"
	if err := os.WriteFile(credential, []byte(`{"type":"authorized_user","client_id":"assessment.apps.googleusercontent.com","client_secret":"fake-client-secret","refresh_token":"`+secret+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	h.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credential)
	var mu sync.Mutex
	hits := map[string]int{}
	h.GoogleTokenHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/token" {
			t.Error("wrong credential endpoint")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"`+token+`","token_type":"Bearer","expires_in":3600}`)
	})
	h.WorkspaceHandler(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("read/auth changed")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/directory/v1/customers/my_customer":
			fmt.Fprint(w, `{"id":"C123","postalAddress":"private-bootstrap-contact"}`)
		case "/admin/directory/v1/customer/C123/domains":
			fmt.Fprint(w, `{"kind":"admin#directory#domains","domains":[{"domainName":"example.com","verified":true},{"domainName":"secondary.example","verified":true}]}`)
		case "/admin/directory/v1/customer/C123/domainaliases":
			fmt.Fprint(w, `{"kind":"admin#directory#domainAliases"}`)
		case "/admin/directory/v1/customer/C123/orgunits":
			fmt.Fprint(w, `{"kind":"admin#directory#orgUnits","organizationUnits":[{"orgUnitId":"id:root","orgUnitPath":"/"},{"orgUnitId":"id:board","orgUnitPath":"/Board","parentOrgUnitPath":"/"}]}`)
		case "/admin/directory/v1/users":
			if r.URL.Query().Get("customer") != "C123" || r.URL.Query().Has("domain") {
				t.Error("not customer inventory")
			}
			fmt.Fprint(w, `{"kind":"admin#directory#users","users":[{"id":"123","primaryEmail":"alice@secondary.example","customerId":"C123","orgUnitPath":"/","isAdmin":false,"name":{"fullName":"`+token+`"},"recoveryEmail":"private-recovery@example.net"},{"id":"456","primaryEmail":"excluded@example.com","customerId":"C123","orgUnitPath":"/Board","isAdmin":true}]}`)
		default:
			t.Error("undeclared or excluded account path", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	start := time.Now().UTC().Truncate(time.Second)
	dir, err := engagement.CreateRunDir(t.TempDir(), "workspace-inventory", start)
	if err != nil {
		t.Fatal(err)
	}
	runPath := dir.Path
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: raw, Dir: dir, Started: start, Version: "e6-step2", NewGate: h.Build})
	if err != nil {
		dir.Close()
		t.Fatal(err)
	}
	if out.ExitCode() != 2 || len(out.Report.Findings) != 0 {
		t.Fatalf("inventory-only partial exit=%d", out.ExitCode())
	}
	identityFound := false
	for _, row := range out.Report.Coverage {
		if row.Area == "identity" {
			identityFound = true
			if row.Mark != "not_assessed" || row.Population == nil || row.Population.Read != 1 {
				t.Fatal(row)
			}
		}
	}
	if !identityFound {
		t.Fatal("identity coverage absent")
	}
	reconRaw, err := os.ReadFile(dir.File("recon.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recon engagement.ReconDoc
	if err = json.Unmarshal(reconRaw, &recon); err != nil {
		t.Fatal(err)
	}
	if len(recon.Assets) != 1 || recon.Assets[0].Workspace == nil || len(recon.Assets[0].Workspace.Users.Items) != 1 || len(recon.Attribution) != 1 || recon.Attribution[0].ProviderID != "123" {
		t.Fatal(recon)
	}
	var reportText bytes.Buffer
	if err = ereport.WriteText(&reportText, out.Report, ereport.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(reportText.String()), " "), "Inventory alone does not assess account security") {
		t.Fatal("inventory warning missing")
	}
	dir.Close()
	err = filepath.WalkDir(runPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, seed := range []string{token, secret, "fake-client-secret", "excluded@example.com", "private-recovery@example.net", "private-bootstrap-contact"} {
			if strings.Contains(string(b), seed) {
				t.Errorf("%s leaked %s", path, seed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reconRaw), "[REDACTED:") {
		t.Fatal("retained seeded secret has no marker")
	}
	reopened, err := engagement.OpenRun(runPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	prior, err := engagement.LoadPrior(reopened)
	if err != nil {
		t.Fatal(err)
	}
	again, againRaw, err := prior.LoadEngagement(inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := engagement.Run(context.Background(), again, engagement.RunOptions{Raw: againRaw, Dir: reopened, Resume: prior, Started: start, Session: time.Now(), Version: "e6-step2", NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ExitCode() != 2 {
		t.Fatal("resume lost partial inventory")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/admin/directory/v1/customers/my_customer", "/admin/directory/v1/customer/C123/orgunits", "/admin/directory/v1/users"} {
		if hits[path] != 2 {
			t.Fatal("resume reused Workspace admission", path, hits[path])
		}
	}
}
