package gate_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
)

const workspaceMailFile = `schema: 1
engagement: {name: workspace-mail, operator: Dani, timezone: UTC, trigger: routine}
roots:
  - saas: google-workspace:example.com
  - domain: acquired.example
%s
people:
  alice: {kind: employee, workspace: [alice@example.com]}
`

type mailRun struct {
	out       *engagement.Outcome
	dir       string
	file      string
	impersona []string
	paths     []string
	h         *gate.Harness
}

func mailboxAuthYAML(date, expires, by string) string {
	if by == "" {
		return ""
	}
	return fmt.Sprintf("authorization:\n  mailboxes:\n    - {asset: google-workspace:example.com, by: %s, date: %s, expires: %s}\n", by, date, expires)
}

func currentMailboxAuth() string {
	now := time.Now().UTC()
	return mailboxAuthYAML(now.AddDate(0, 0, -1).Format("2006-01-02"), now.AddDate(0, 0, 30).Format("2006-01-02"), "CTO")
}

// runMail runs the mail profile end to end against fake Google servers.
func runMail(t *testing.T, exclude bool) *mailRun {
	t.Helper()
	return runMailAuth(t, exclude, currentMailboxAuth())
}

func runMailAuth(t *testing.T, exclude bool, auth string) *mailRun {
	t.Helper()
	return runMailNamed(t, "engagement.yaml", exclude, auth)
}

func runMailNamed(t *testing.T, name string, exclude bool, auth string) *mailRun {
	t.Helper()
	excludes := ""
	if exclude {
		excludes = "exclude:\n  - {saas: google-workspace:example.com, org_unit: /board}"
	}
	raw := []byte(fmt.Sprintf(workspaceMailFile, excludes) + auth)
	if filepath.IsAbs(name) {
		if err := os.WriteFile(name, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := engagement.Parse(name, raw, inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	credential := filepath.Join(t.TempDir(), "sa.json")
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "scheck@project.iam.gserviceaccount.com", "private_key_id": "kid1", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if err := os.WriteFile(credential, sa, 0600); err != nil {
		t.Fatal(err)
	}
	h.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credential)
	h.Setenv("SCHECK_WORKSPACE_PROFILE", "directory_mail")
	h.Setenv("SCHECK_WORKSPACE_SUBJECT", "alice@example.com")
	const base = "opaque-access-seeded-mail-1234567890"
	const seeded = "ghp_0123456789abcdefABCDEF0123456789abcd"
	var mu sync.Mutex
	run := &mailRun{}
	h.GoogleTokenHandler(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims := map[string]any{}
		if parts := strings.Split(r.PostForm.Get("assertion"), "."); len(parts) == 3 {
			body, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(body, &claims)
		}
		w.Header().Set("Content-Type", "application/json")
		if claims["scope"] == "https://www.googleapis.com/auth/gmail.readonly" {
			sub, _ := claims["sub"].(string)
			mu.Lock()
			run.impersona = append(run.impersona, sub)
			mu.Unlock()
			fmt.Fprint(w, `{"access_token":"mail-`+strings.Split(sub, "@")[0]+`-opaque-1234567890","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if strings.Contains(fmt.Sprint(claims["scope"]), "gmail") || claims["sub"] != "alice@example.com" {
			t.Error("the baseline exchange asked for mail or acted as someone else", claims)
		}
		fmt.Fprint(w, `{"access_token":"`+base+`","token_type":"Bearer","expires_in":3600}`)
	})
	user := func(id, email, unit, extra string) string {
		return `{"id":"` + id + `","primaryEmail":"` + email + `","customerId":"C123","orgUnitPath":"` + unit + `","archived":false,"isEnforcedIn2Sv":true,"isEnrolledIn2Sv":true` + extra + `}`
	}
	alice := user("1", "alice@example.com", "/Sales", `,"suspended":false,"isAdmin":true`)
	carol := user("4", "carol@example.com", "/Sales", `,"suspended":false,"isAdmin":false`)
	erin := user("5", "erin@example.com", "/Sales", `,"suspended":false,"isAdmin":false`)
	gone := user("2", "gone@example.com", "/Sales", `,"suspended":true,"isAdmin":false`)
	board := user("3", "board@example.com", "/Board", `,"suspended":false,"isAdmin":true`)
	h.WorkspaceHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+base {
			t.Error("a Directory read used another token", r.URL.Path)
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
			fmt.Fprint(w, `{"kind":"admin#directory#users","users":[`+alice+`,`+gone+`,`+carol+`,`+erin+`,`+board+`]}`)
		case "/admin/directory/v1/users/1":
			fmt.Fprint(w, alice)
		case "/admin/directory/v1/users/4":
			fmt.Fprint(w, carol)
		case "/admin/directory/v1/users/5":
			fmt.Fprint(w, erin)
		case "/admin/directory/v1/users/3":
			fmt.Fprint(w, board)
		case "/admin/directory/v1/customer/C123/roles":
			fmt.Fprint(w, `{"kind":"admin#directory#roles","items":[]}`)
		case "/admin/directory/v1/customer/C123/roles/ALL/privileges":
			fmt.Fprint(w, `{"kind":"admin#directory#privileges","items":[]}`)
		case "/admin/directory/v1/customer/C123/roleassignments":
			fmt.Fprint(w, `{"kind":"admin#directory#roleAssignments","items":[]}`)
		default:
			t.Error("undeclared path", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	h.GmailHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		who := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer mail-"), "-opaque-1234567890")
		mu.Lock()
		run.paths = append(run.paths, who+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.URL.Path == "/gmail/v1/users/me/settings/autoForwarding" && who == "alice":
			fmt.Fprint(w, `{"enabled":true,"emailAddress":"alice.home@gmail.com","disposition":"leaveInInbox"}`)
		case r.URL.Path == "/gmail/v1/users/me/settings/autoForwarding" && who == "erin":
			fmt.Fprint(w, `{"enabled":true,"emailAddress":"`+seeded+`@leak.example"}`)
		case r.URL.Path == "/gmail/v1/users/me/settings/autoForwarding":
			fmt.Fprint(w, `{"enabled":false}`)
		case r.URL.Path == "/gmail/v1/users/me/settings/filters" && who == "carol":
			fmt.Fprint(w, `{"filter":[{"id":"ANe1","criteria":{"query":"`+seeded+` PRIVATE_QUERY","subject":"PRIVATE_SUBJECT"},"action":{"forward":"books@acquired.example","removeLabelIds":["INBOX"]}}]}`)
		case r.URL.Path == "/gmail/v1/users/me/settings/filters":
			fmt.Fprint(w, `{}`)
		default:
			t.Error("undeclared mail path", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	start := time.Now().UTC().Truncate(time.Second)
	dir, err := engagement.CreateRunDir(t.TempDir(), "workspace-mail", start)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: raw, Dir: dir, Started: start, Version: "e6-step6", NewGate: h.Build})
	if err != nil {
		t.Fatal(err)
	}
	run.out, run.dir, run.file, run.h = out, dir.Path, name, h
	// Nothing in the run directory holds a token, a seeded secret, filter
	// criteria or an excluded account; the redacted destination is marked.
	marked := false
	err = filepath.WalkDir(dir.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		marked = marked || strings.Contains(string(b), "[REDACTED:")
		never := []string{base, "-opaque-1234567890", seeded, "PRIVATE_SUBJECT", "PRIVATE_QUERY", "BEGIN PRIVATE KEY"}
		if exclude {
			never = append(never, "board@example.com")
		}
		for _, s := range never {
			if strings.Contains(string(b), s) {
				t.Errorf("%s leaked %s", path, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.impersona) > 0 && !marked {
		t.Fatal("the seeded destination's redaction marker is not in the run directory")
	}
	return run
}

// Gmail forwarding travels from fake Gmail settings through the gate and
// the collector to the report: the gate signs in as each active admitted
// mailbox with gmail.readonly only, reads only the two settings of that
// mailbox, never an excluded or suspended account's; a super administrator's
// forward is raised, a filter's criteria never leave the gate, and a seeded
// secret in a destination is redacted and leaves that mailbox unjudged
// (docs/spec/workspace-collector.md, "Forwarding interpretation").
func TestWorkspaceMailThroughGateAndReport(t *testing.T) {
	run := runMail(t, true)
	slices.Sort(run.impersona)
	if strings.Join(run.impersona, ",") != "alice@example.com,carol@example.com,erin@example.com" {
		t.Fatalf("signed in as %v", run.impersona)
	}
	for _, p := range run.paths {
		if !strings.HasSuffix(p, "/gmail/v1/users/me/settings/autoForwarding") && !strings.HasSuffix(p, "/gmail/v1/users/me/settings/filters") {
			t.Fatal("an undeclared mail path was requested", p)
		}
	}
	if len(run.paths) != 6 {
		t.Fatal(run.paths)
	}
	found := map[string]string{}
	for _, f := range run.out.Report.Findings {
		if f.ID == "workspace.external_forwarding" && f.Subject != nil {
			found[f.Subject.Key] = f.Severity
		}
	}
	if len(found) != 2 || found["alice@example.com -> alice.home@gmail.com"] != "high" || found["carol@example.com -> books@acquired.example"] != "medium" {
		t.Fatalf("forwarding findings %v", found)
	}
	outcomes := map[string]string{}
	for _, a := range run.out.Report.Assessments {
		for _, o := range a.Outcomes {
			if o.Subject != nil && strings.Contains(o.Subject.Key, " -> ") {
				outcomes[o.Subject.Key] = o.Outcome
			}
		}
	}
	if outcomes["erin@example.com -> none"] != "abstained" {
		t.Fatalf("a redacted destination was judged: %v", outcomes)
	}
	// The exclusion leaves the account list incomplete: exit 2.
	if run.out.ExitCode() != 2 {
		t.Fatalf("exit %d", run.out.ExitCode())
	}
	audit, err := os.ReadFile(filepath.Join(run.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	exchanges := 0
	for line := range strings.SplitSeq(string(audit), "\n") {
		if strings.Contains(line, `"workspace.credential_exchange_gmail_forwarding"`) && strings.Contains(line, `"user"`) {
			exchanges++
		}
		if strings.Contains(line, "workspace.mail_") && strings.Contains(line, "@example.com") {
			t.Fatal("a mail audit line names an address", line)
		}
	}
	if exchanges < 3 {
		t.Fatalf("%d mailbox exchanges audited with their account id", exchanges)
	}
	if !strings.Contains(string(audit), `"mailbox_authorization"`) || !strings.Contains(string(audit), `"by":"CTO"`) {
		t.Fatal("the audit does not record who approved mailbox sign-in")
	}
}

func TestWorkspaceMailRunWithoutApprovalSignsInAsNobody(t *testing.T) {
	run := runMailAuth(t, false, "")
	if len(run.impersona) != 0 || len(run.paths) != 0 {
		t.Fatal("signed in without an approval", run.impersona, run.paths)
	}
	body, err := json.Marshal(run.out.Report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "unavailable:mailbox_authorization_missing") || !strings.Contains(string(body), "records no approval") {
		t.Fatal("the report does not name the missing approval")
	}
}

func TestWorkspaceMailRunWithExpiredApprovalSignsInAsNobody(t *testing.T) {
	run := runMailAuth(t, false, mailboxAuthYAML("2020-01-01", "2020-03-01", "CEO"))
	if len(run.impersona) != 0 {
		t.Fatal("signed in under an expired approval", run.impersona)
	}
	if len(run.out.Report.Engagement.Authorization.Mailboxes) != 1 || run.out.Report.Engagement.Authorization.Mailboxes[0].Used {
		t.Fatalf("header %+v", run.out.Report.Engagement.Authorization)
	}
	body, err := json.Marshal(run.out.Report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "unavailable:mailbox_authorization_expired") || !strings.Contains(string(body), `ended on 2020-03-01`) {
		t.Fatal("the report does not name the expired approval")
	}
}

func TestWorkspaceMailCompleteRunExitsOnFindings(t *testing.T) {
	run := runMail(t, false)
	if run.out.ExitCode() != 1 {
		t.Fatalf("a complete run with forwarding findings exits %d", run.out.ExitCode())
	}
	if !slices.Contains(run.impersona, "board@example.com") {
		t.Fatal("an included administrator mailbox was not read")
	}
}

func TestWorkspaceMailResumeStopsWhenTheApprovalIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engagement.yaml")
	run := runMailNamed(t, path, false, currentMailboxAuth())
	if len(run.impersona) == 0 {
		t.Fatal("the first session did not sign in")
	}
	manifest, err := os.ReadFile(filepath.Join(run.dir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `"mailbox_approvals"`) || !strings.Contains(string(manifest), `"by": "CTO"`) {
		t.Fatal("the session did not record the approval it acted under")
	}
	before := len(run.impersona)
	if err := os.WriteFile(path, []byte(fmt.Sprintf(workspaceMailFile, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	reopened, err := engagement.OpenRun(run.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	prior, err := engagement.LoadPrior(reopened)
	if err != nil {
		t.Fatal(err)
	}
	again, raw, err := prior.LoadEngagement(inventoryOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engagement.Run(context.Background(), again, engagement.RunOptions{
		Raw: raw, Dir: reopened, Resume: prior, Started: prior.Manifest.Started,
		Session: time.Now(), Version: "e6-step6", NewGate: run.h.Build,
	}); err != nil {
		t.Fatal(err)
	}
	if len(run.impersona) != before {
		t.Fatalf("resume signed in as %v", run.impersona[before:])
	}
}
