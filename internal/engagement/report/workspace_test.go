package report

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// workspacePlan sets the collector's coverage plan for a fixture's
// judgments: a bound tenant on the default profile with complete
// administrative evidence unless change says otherwise.
func workspacePlan(a *AssetInput, change func(*workspace.Evidence)) {
	workspacePlanFor(a, change, workspace.Context{})
}

// workspacePlanFor is workspacePlan with the declarations c gives it.
func workspacePlanFor(a *AssetInput, change func(*workspace.Evidence), c workspace.Context) {
	e := workspace.Evidence{Binding: workspace.Binding{CustomerID: "C123", Profile: "directory"}}
	e.Access.AdministrationComplete = true
	if change != nil {
		change(&e)
	}
	a.Coverage = e.Coverage(a.Judged, c)
}

func workspaceInventoryReport(_ *testing.T) Input {
	const asset = "saas:google-workspace:example.com"
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	return Input{Version: "test", Name: "Workspace inventory review", Operator: "Dani", Trigger: "routine", Zone: time.UTC, Path: "engagement.yaml", SHA256: strings.Repeat("a", 64), Started: at, Finished: at.Add(time.Minute), Rerun: "scheck run engagement.yaml", LevelsUsed: []string{"observe"},
		Assets: []AssetInput{{Name: "Workspace", ID: asset, Kind: "saas", Root: true, Status: "collected", Collector: "workspace", InventoryRead: true, Detail: "Workspace tenant inventory collected. Account security and administrator-access rules are not implemented in this build.", NetworkPrincipal: &Principal{Identity: "unknown", ScopesSource: "unknown"}, InventoryNotes: []Note{
			{Kind: "workspace_credential", Source: asset, Detail: "Returned credential permissions are unknown; effective permissions were not tested."},
			{Kind: "workspace_inventory", Source: asset, Detail: "domains: observed 2; organizational units: observed 3; accounts: observed 6. Inventory alone does not assess account security or administrator access."},
			{Kind: "workspace_inventory", Source: asset, Detail: "scheck could not identify the Google account used for this run. Information from earlier Workspace reads was not used in this report."},
		}}}, Egress: &EgressInput{Sources: []SourceInput{{Source: "google", Operator: "Google", Host: "admin.googleapis.com", Requests: 7, Sent: []string{asset}, Credentials: []string{"GOOGLE_APPLICATION_CREDENTIALS"}}, {Source: "google", Operator: "Google", Host: "oauth2.googleapis.com", Requests: 1, Sent: []string{asset}, Credentials: []string{"GOOGLE_APPLICATION_CREDENTIALS"}}}, Tenants: []string{asset}}}
}

func workspacePartialInventoryReport(t *testing.T) Input {
	in := workspaceInventoryReport(t)
	a := &in.Assets[0]
	a.Status, a.Reason, a.Detail = "incomplete", "failed", "Workspace inventory is incomplete; inventory notes show what was read and what remains unknown."
	a.PopulationIncomplete = true
	a.InventoryNotes[1].Detail = "domains: observed 2; organizational units: at least 2; accounts: at least 5. Inventory alone does not assess account security or administrator access."
	a.InventoryNotes = append(a.InventoryNotes, Note{Kind: "workspace_inventory", Source: a.ID, Detail: "workspace.users: inventory incomplete (dropped). Counts are lower bounds."})
	return in
}

func TestWorkspaceInventoryDoesNotClaimSecurityAssessment(t *testing.T) {
	for _, partial := range []bool{false, true} {
		in := workspaceInventoryReport(t)
		if partial {
			in = workspacePartialInventoryReport(t)
		}
		r := build(in)
		want := 0
		if partial {
			want = 2
		}
		if r.Exit.Code != want || len(r.Findings) != 0 {
			t.Fatal(r.Exit)
		}
		identity := row(t, r, "identity")
		if identity.Mark != "not_assessed" || identity.Population == nil || identity.Population.Read != 1 {
			t.Fatal(identity)
		}
		if !strings.Contains(identity.Reasons[0].Detail, "no Workspace security control") {
			t.Fatal(identity)
		}
		var b bytes.Buffer
		if err := WriteText(&b, r, Options{}); err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(b.String()), " ")
		if partial && (strings.Contains(text, "Nothing was read") || strings.Contains(text, "connection to the host") || strings.Contains(text, "could not be reached")) {
			t.Fatal(text)
		}
		if !strings.Contains(text, "Inventory alone does not assess") || !strings.Contains(text, "permissions are unknown") {
			t.Fatal(text)
		}
	}
	in := githubAccessDisprovedReport(t)
	in.Assets = append(in.Assets, workspaceInventoryReport(t).Assets...)
	if row(t, build(in), "identity").Mark == "assessed" {
		t.Fatal("GitHub controls masked unassessed Workspace")
	}
}

func workspaceIdentityReport(t *testing.T) Input {
	in := workspaceInventoryReport(t)
	a := &in.Assets[0]
	a.Detail = "Workspace inventory and identity/administrator checks collected; unresolved evidence is listed in coverage."
	a.InventoryNotes[1].Detail = "Observed 6 accounts. Administrative scope is limited to accounts included in these reads; group membership paths, effective permissions and application activity were not tested."
	a.Judged = []Judgment{
		{ID: "identity.unexpected_admin", Asset: a.ID, Subject: finding.Subject{Kind: "account", Key: "admin@example.com", Label: "admin@example.com", ProviderID: "123", Person: "alice"}, Verdict: "fired", Reads: []string{"g000008"}, Sources: []string{"access.admins"}, Excerpt: "admin@example.com is a super administrator attributed to declared person alice, who is absent from the expected administrator list"},
		{ID: "workspace.stale_account", Asset: a.ID, Subject: finding.Subject{Kind: "account", Key: "admin@example.com", Label: "admin@example.com", ProviderID: "123", Person: "alice"}, Verdict: "fired", Reads: []string{"g000014"}, Excerpt: "Google reports no sign-in since 2026-01-01T00:00:00Z. Sessions and application activity were not reviewed."},
		{ID: "workspace.too_many_super_admins", Asset: a.ID, Verdict: "disproved", Reads: []string{"g000008"}, Excerpt: "Two retained super-administrator flags were observed."},
		{ID: "workspace.suspended_admin_assignment", Asset: a.ID, Subject: finding.Subject{Kind: "account", Key: "old@example.com", Label: "old@example.com", ProviderID: "456"}, Verdict: "fired", Reads: []string{"g000008", "g000010", "g000012"}, Excerpt: "suspended:true; supported Directory USERS_RESET_PASSWORD (password-reset administrator permission) assignment. The account is suspended, so this assignment does not establish usable access. Review and remove it if no longer needed."},
		{ID: "identity.unattributed_admin", Asset: a.ID, Subject: finding.Subject{Kind: "account", Key: "unknown@example.com", Label: "unknown@example.com", ProviderID: "789"}, Verdict: "abstained", Reason: "unavailable:workspace_evidence", Reads: []string{"g000008"}, NotChecked: []string{"Assignment read was denied."}},
	}
	workspacePlan(a, nil)
	return in
}
func TestWorkspaceIdentityCoverageAndSubjectAcceptances(t *testing.T) {
	in := workspaceIdentityReport(t)
	r := build(in)
	if r.Exit.Code != 1 || len(r.Findings) != 3 || row(t, r, "identity").Mark != "partial" {
		t.Fatal(r.Exit, r.Findings, row(t, r, "identity"))
	}
	workspacePlan(&in.Assets[0], func(e *workspace.Evidence) { e.Access.AdministrationComplete = false })
	r = build(in)
	found := false
	for _, si := range row(t, r, "identity").SubItems {
		if si.Name == "Workspace administrator assignments and counts" {
			found = true
			if si.Mark != "partial" {
				t.Fatal(si)
			}
		}
	}
	if !found {
		t.Fatal("assignment coverage absent")
	}
	for _, f := range r.Findings {
		if f.Subject == nil || f.Subject.Key == "" {
			t.Fatal("account subject missing", f)
		}
	}
}

// workspaceTwoStepReport renders what the collector judges for observed
// 2-step flags, with an everyone declaration raising the unit findings.
func workspaceTwoStepReport(t *testing.T) Input { return workspaceTwoStepInput(t, "") }

// workspaceSignInReport declares sign_in: another_provider and adds a root
// unit of non-administrators without the requirement: /sales keeps its
// raise for its super administrator, / is reported but not raised.
func workspaceSignInReport(t *testing.T) Input { return workspaceTwoStepInput(t, "another_provider") }

func workspaceTwoStepInput(t *testing.T, signIn string) Input {
	in := workspaceInventoryReport(t)
	a := &in.Assets[0]
	a.Detail = "Workspace inventory, identity/administrator and 2-step verification checks collected; notes and coverage show any unresolved evidence."
	a.InventoryNotes[1].Detail = "domains: observed 2; organizational units: observed 3; accounts: observed 5. Account security conclusions appear separately; inventory alone proves no security control."
	user := func(id, unit string, enforced, enrolled *bool) workspace.User {
		return workspace.User{ID: id, Primary: id + "@example.com", Customer: "C123", Unit: unit, Suspended: new(false), Archived: new(false), IsAdmin: new(false), Enforced: enforced, Enrolled: enrolled}
	}
	admin := user("admin", "/Sales", new(false), new(false))
	admin.IsAdmin = new(true)
	users := []workspace.User{admin, user("carol", "/Sales", new(false), new(true)), user("dan", "/", new(true), new(true)), user("erin", "/Eng", nil, new(true)), user("new", "/", new(true), new(false))}
	if signIn != "" {
		users = append(users, user("gina", "/", new(false), new(true)))
	}
	read := []workspace.Read{{Op: workspace.OpUsers, RequestID: "g000008", Decision: "sent", Status: 200}}
	e := workspace.Evidence{Users: workspace.Population[workspace.User]{Items: users, Complete: true, Reads: read}, Units: workspace.Population[workspace.Unit]{Complete: true, Items: []workspace.Unit{{ID: "root", Path: "/"}, {ID: "sales", Path: "/Sales"}, {ID: "eng", Path: "/Eng"}}}}
	e.Access.Roles.Complete, e.Access.Privileges.Complete = true, true
	for i, u := range users {
		e.Access.Accounts = append(e.Access.Accounts, workspace.AccountAccess{ID: u.ID, Assignments: workspace.Population[workspace.Assignment]{Complete: true, Items: []workspace.Assignment{}, Reads: []workspace.Read{{Op: workspace.OpUserAssignments, RequestID: fmt.Sprintf("g%06d", 10+i), Decision: "sent", Status: 200}}}})
	}
	c := workspace.Context{Zone: time.UTC, MFA: "everyone", MFASource: "access.mfa[0]"}
	if signIn != "" {
		c.SignIn, c.SignInSource = signIn, "access.mfa[0].sign_in"
	}
	for _, j := range workspace.Judge(e, a.ID, c) {
		if j.ID == workspace.IDTwoStepNotEnforced || j.ID == workspace.IDAdminWithoutTwoStep {
			a.Judged = append(a.Judged, j)
		}
	}
	for _, n := range workspace.Readout(e, a.ID, c) {
		a.InventoryNotes = append(a.InventoryNotes, Note{Kind: n.Kind, Source: n.Source, Detail: n.Detail})
	}
	workspacePlanFor(a, nil, c)
	return in
}

// Under another_provider the unit with a super administrator stays
// critical and the unit without one stays high, with the declaration as
// evidence on both (docs/spec/workspace-collector.md, "Observed 2-step
// verification").
func TestWorkspaceSignInWithholdsTheRaise(t *testing.T) {
	r := build(workspaceSignInReport(t))
	got := map[string]string{}
	for _, f := range r.Findings {
		if f.ID != "workspace.two_step_not_enforced" {
			continue
		}
		got[f.Subject.Key] = f.Severity
		declared := 0
		for _, e := range f.Evidence {
			if e.Kind == "declared" {
				declared++
			}
		}
		if declared != 2 || !slices.Contains(f.Rule.Reads, "declared:access.mfa[0].sign_in") {
			t.Fatalf("declaration evidence %+v", f)
		}
	}
	if got["/sales"] != "critical" || got["/"] != "high" {
		t.Fatalf("severities %v", got)
	}
}

func TestWorkspaceTwoStepContradictionAndCoverage(t *testing.T) {
	r := build(workspaceTwoStepReport(t))
	raised, admin := false, false
	for _, f := range r.Findings {
		switch f.ID {
		case "workspace.two_step_not_enforced":
			if f.Subject == nil || f.Subject.Kind != "org_unit" || f.Subject.Key != "/sales" || f.Severity != "critical" || len(f.Adjustments) != 1 || f.Adjustments[0].Rule != "contradiction" || f.Adjustments[0].By != "engagement" || f.Adjustments[0].Source.Key != "access.mfa[0]" {
				t.Fatalf("%+v", f)
			}
			raised = f.Affected != nil && f.Affected.Count == 2
		case "workspace.admin_without_two_step":
			admin = f.Severity == "high" && len(f.Adjustments) == 0
		}
	}
	if !raised || !admin {
		t.Fatal(r.Findings)
	}
	var twoStep, oauth, delegation *SubItem
	for _, si := range row(t, r, "identity").SubItems {
		switch {
		case strings.HasPrefix(si.Name, "Workspace 2-step verification"):
			twoStep = &si
		case si.Name == "Workspace OAuth grants (third-party app access)":
			oauth = &si
		case si.Name == "Workspace domain-wide delegation":
			delegation = &si
		}
	}
	if twoStep == nil || twoStep.Mark != "partial" || oauth == nil || oauth.Mark != "not_assessed" || oauth.Reasons[0].Reason != "not_on_plan:profile=directory" || delegation == nil || delegation.Mark != "not_assessed" || delegation.Reasons[0].Reason != "no_rule" {
		t.Fatal(twoStep, oauth, delegation)
	}
	if !slices.ContainsFunc(twoStep.Reasons, func(d ReasonDetail) bool {
		return strings.Contains(d.Detail, "Not checked: organizational-unit policy")
	}) {
		t.Fatal("2-step limits missing from coverage", twoStep.Reasons)
	}
}

func TestWorkspaceTwoStepWithoutOutcomesIsNotAssessed(t *testing.T) {
	r := build(workspaceIdentityReport(t))
	found := false
	for _, si := range row(t, r, "identity").SubItems {
		if !strings.HasPrefix(si.Name, "Workspace 2-step verification") {
			continue
		}
		found = true
		if si.Mark != "not_assessed" || !slices.ContainsFunc(si.Reasons, func(d ReasonDetail) bool {
			return d.Reason == "unavailable:workspace_evidence" && strings.HasPrefix(d.Detail, "No 2-step verification outcome")
		}) {
			t.Fatal("2-step coverage without outcomes", si)
		}
	}
	if !found {
		t.Fatal("2-step coverage sub-item missing")
	}
}

// workspaceOAuthReport renders the optional OAuth grant surface: a broad app
// a super administrator granted, an unclassified app, a narrow app and a
// label carrying a terminal escape.
func workspaceOAuthReport(t *testing.T) Input {
	in := workspaceInventoryReport(t)
	a := &in.Assets[0]
	a.Detail = "Workspace inventory, identity/administrator, 2-step verification and OAuth grant checks collected; notes and coverage show any unresolved evidence."
	user := func(id string, admin bool) workspace.User {
		return workspace.User{ID: id, Primary: id + "@example.com", Customer: "C123", Unit: "/", Suspended: new(false), Archived: new(false), IsAdmin: new(admin), Enforced: new(true), Enrolled: new(true)}
	}
	users := []workspace.User{user("admin", true), user("carol", false), user("dan", false)}
	e := workspace.Evidence{Binding: workspace.Binding{CustomerID: "C123", Domain: "example.com", Profile: "directory_oauth", Surfaces: []gate.WorkspaceSurface{gate.WorkspaceOAuthGrants}, Offers: map[gate.WorkspaceSurface]string{gate.WorkspaceGmailForwarding: "directory_oauth_mail"}}, Users: workspace.Population[workspace.User]{Items: users, Complete: true, Reads: []workspace.Read{{Op: workspace.OpUsers, RequestID: "g000008", Decision: "sent", Status: 200}}}, Units: workspace.Population[workspace.Unit]{Complete: true, Items: []workspace.Unit{{ID: "root", Path: "/"}}}}
	e.Access.Roles.Complete, e.Access.Privileges.Complete = true, true
	e.OAuth = workspace.OAuthEvidence{Selected: true, Complete: true}
	const p = "https://www.googleapis.com/auth/"
	grants := map[string][]workspace.Grant{
		"admin": {{ClientID: "123456789012-k3v9qz7x2m4n8p1r5t6w0y3b7d9f2h4j.apps.googleusercontent.com", Label: "Shiny \x1b[31mDocs", Scopes: []string{p + "drive", "openid"}, ScopesKnown: true}},
		"carol": {{ClientID: "123456789012-k3v9qz7x2m4n8p1r5t6w0y3b7d9f2h4j.apps.googleusercontent.com", Label: "Shiny \x1b[31mDocs", Scopes: []string{p + "drive.readonly"}, ScopesKnown: true}, {ClientID: "77185425430.apps.googleusercontent.com", Label: "Google Chrome", Scopes: []string{"https://www.google.com/accounts/OAuthLogin"}, ScopesKnown: true, NativeApp: new(true)}},
		"dan":   {{ClientID: "555555555555-sso0login0only0q2w3e4r5t6y7u8i9o0p.apps.googleusercontent.com", Label: "Team Chat", Scopes: []string{"email", "openid", "profile"}, ScopesKnown: true}},
	}
	for i, u := range users {
		e.Access.Accounts = append(e.Access.Accounts, workspace.AccountAccess{ID: u.ID, Assignments: workspace.Population[workspace.Assignment]{Complete: true, Items: []workspace.Assignment{}, Reads: []workspace.Read{{Op: workspace.OpUserAssignments, RequestID: fmt.Sprintf("g%06d", 10+i), Decision: "sent", Status: 200}}}})
		e.OAuth.Accounts = append(e.OAuth.Accounts, workspace.AccountGrants{ID: u.ID, Read: workspace.Read{Op: workspace.OpUserTokens, RequestID: fmt.Sprintf("g%06d", 20+i), Decision: "sent", Status: 200}, Grants: grants[u.ID], Usable: true, Complete: true})
	}
	c := workspace.Context{Zone: time.UTC}
	for _, j := range workspace.Judge(e, a.ID, c) {
		if j.ID == workspace.IDOAuthBroadScope {
			a.Judged = append(a.Judged, j)
		}
	}
	for _, n := range workspace.Readout(e, a.ID, c) {
		if strings.Contains(n.Detail, "app") || strings.Contains(n.Detail, "credential") {
			a.InventoryNotes = append(a.InventoryNotes, Note{Kind: n.Kind, Source: n.Source, Detail: n.Detail})
		}
	}
	workspacePlan(a, func(w *workspace.Evidence) { w.Binding, w.OAuth.Selected = e.Binding, true })
	return in
}

func TestWorkspaceOAuthRaiseCoverageAndAcceptance(t *testing.T) {
	r := build(workspaceOAuthReport(t))
	var app *Finding
	for i, f := range r.Findings {
		if f.ID == "workspace.oauth_broad_scope" {
			app = &r.Findings[i]
		}
	}
	if app == nil || app.Severity != "high" || len(app.Adjustments) != 1 || app.Adjustments[0].Rule != "attribute:admin_grantor" || app.Subject == nil || app.Subject.Kind != "oauth_app" ||
		app.AcceptTemplate == nil || !app.AcceptTemplate.BySubject || app.AcceptTemplate.Subject != "123456789012-k3v9qz7x2m4n8p1r5t6w0y3b7d9f2h4j.apps.googleusercontent.com" {
		t.Fatalf("%+v", app)
	}
	if len(app.WhyHere) != 1 || !strings.HasPrefix(app.WhyHere[0], "admin@example.com is a super administrator and granted this app the scope drive") {
		t.Fatal(app.WhyHere)
	}
	var oauth *SubItem
	for _, si := range row(t, r, "identity").SubItems {
		if si.Name == "Workspace OAuth grants (third-party app access)" {
			oauth = &si
		}
	}
	if oauth == nil || oauth.Mark != "partial" || !slices.ContainsFunc(oauth.Reasons, func(d ReasonDetail) bool {
		return d.Reason == "unavailable:oauth_unclassified" && strings.HasPrefix(d.Detail, "1 app holds scopes scheck does not classify")
	}) {
		t.Fatal(oauth)
	}
	var b bytes.Buffer
	if err := WriteText(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatal("a label's terminal escape reached the text report")
	}
	// An acceptance by client id accepts that app only.
	in := workspaceOAuthReport(t)
	in.Acceptances = []AcceptanceInput{
		{Entry: "engagement.yaml intent.accepted_risks[0]", ID: "workspace.oauth_broad_scope", Asset: "Workspace", AssetID: in.Assets[0].ID, Subject: "210987654321-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com", Reason: "r", AcceptedBy: "dani", Expires: "2027-01-01"},
	}
	if f := build(in).Findings[0]; f.Status != finding.StatusOpen {
		t.Fatal("another app's acceptance accepted this one", f)
	}
	in.Acceptances[0].Subject = app.Subject.Key
	if f := build(in).Findings[0]; f.Status != finding.StatusAccepted || f.Acceptance == nil || f.Acceptance.CoversEveryInstance {
		t.Fatal("the app's own acceptance did not apply", f)
	}
}

// workspaceMailReport renders the optional forwarding surface: a super
// administrator forwarding everything to a personal address, a filter
// forwarding to an outside service and hiding the message, a clean mailbox,
// a subdomain destination, a filter destination carrying a terminal escape,
// and a suspended account that is not read.
func workspaceMailReport(t *testing.T) Input { return workspaceMailInput(t, nil) }

// workspaceMailRefusal renders the forwarding surface refused before any
// settings were read, or stopped by the breaker after one mailbox: the
// email row names why, never "no rule".
func workspaceMailRefusal(read workspace.Read, after int) func(*testing.T) Input {
	return func(t *testing.T) Input {
		return workspaceMailInput(t, func(e *workspace.Evidence) {
			e.Mail.Accounts, e.Mail.Complete = e.Mail.Accounts[:after], false
			read.Op, read.RequestID = workspace.OpMailAutoForwarding, "g000040"
			e.Mail.Accounts = append(e.Mail.Accounts, workspace.MailboxForwarding{ID: "zed", AutoRead: read})
		})
	}
}

func workspaceMailInput(t *testing.T, change func(*workspace.Evidence)) Input {
	in := workspaceInventoryReport(t)
	a := &in.Assets[0]
	a.Detail = "Workspace inventory, identity/administrator, 2-step verification and mail forwarding checks collected; notes and coverage show any unresolved evidence."
	user := func(id string, admin, suspended bool) workspace.User {
		return workspace.User{ID: id, Primary: id + "@example.com", Customer: "C123", Unit: "/", Suspended: new(suspended), Archived: new(false), IsAdmin: new(admin), Enforced: new(true), Enrolled: new(true)}
	}
	users := []workspace.User{user("admin", true, false), user("carol", false, false), user("dan", false, false), user("erin", false, false), user("eve", false, false), user("gone", false, true)}
	e := workspace.Evidence{Binding: workspace.Binding{CustomerID: "C123", Domain: "example.com", Profile: "directory_mail", Surfaces: []gate.WorkspaceSurface{gate.WorkspaceGmailForwarding}, Offers: map[gate.WorkspaceSurface]string{gate.WorkspaceOAuthGrants: "directory_oauth_mail"}},
		Users:   workspace.Population[workspace.User]{Items: users, Complete: true, Reads: []workspace.Read{{Op: workspace.OpUsers, RequestID: "g000008", Decision: "sent", Status: 200}}},
		Units:   workspace.Population[workspace.Unit]{Complete: true, Items: []workspace.Unit{{ID: "root", Path: "/"}}},
		Domains: workspace.Population[workspace.Domain]{Complete: true, Items: []workspace.Domain{{Name: "example.com", Verified: new(true)}}},
		Aliases: workspace.Population[workspace.Alias]{Complete: true, Items: []workspace.Alias{}}}
	e.Access.Roles.Complete, e.Access.Privileges.Complete = true, true
	e.Mail = workspace.MailEvidence{Selected: true, Complete: true}
	for i, u := range users {
		e.Access.Accounts = append(e.Access.Accounts, workspace.AccountAccess{ID: u.ID, Assignments: workspace.Population[workspace.Assignment]{Complete: true, Items: []workspace.Assignment{}, Reads: []workspace.Read{{Op: workspace.OpUserAssignments, RequestID: fmt.Sprintf("g%06d", 10+i), Decision: "sent", Status: 200}}}})
		if u.ID == "gone" {
			continue
		}
		m := workspace.MailboxForwarding{ID: u.ID, AutoRead: workspace.Read{Op: workspace.OpMailAutoForwarding, RequestID: fmt.Sprintf("g%06d", 20+2*i), Decision: "sent", Status: 200, ActedAs: true},
			FiltersRead: workspace.Read{Op: workspace.OpMailFilters, RequestID: fmt.Sprintf("g%06d", 21+2*i), Decision: "sent", Status: 200, ActedAs: true, Population: &gate.Population{Page: 1}},
			AutoUsable:  true, Enabled: new(false), FiltersUsable: true, FiltersComplete: true, Filters: []workspace.FilterForward{}}
		switch u.ID {
		case "admin":
			m.Enabled, m.Address, m.Disposition = new(true), "admin.home@gmail.com", "trash"
		case "carol":
			m.FiltersSeen = 3
			m.Filters = []workspace.FilterForward{{ID: "ANe1Bmj", Address: "invoices@books.example.net", Hides: true}}
		case "dan":
			m.FiltersSeen, m.Address = 2, "old.dan@gmail.com"
		case "erin":
			m.FiltersSeen, m.Filters = 1, []workspace.FilterForward{{ID: "ANe1Bmk", Address: "erin@mail.example.com"}}
		case "eve":
			m.FiltersSeen, m.Filters = 1, []workspace.FilterForward{{ID: "ANe1Bml", Address: "eve\x1b[31m@evil.example"}}
		}
		e.Mail.Accounts = append(e.Mail.Accounts, m)
	}
	if change != nil {
		change(&e)
	}
	c := workspace.Context{Zone: time.UTC, MailApproval: &workspace.MailApproval{By: "CEO, Example Ltd", Date: "2026-10-06", Expires: "2027-01-04", Current: true}}
	a.Judged = workspace.Judge(e, a.ID, c)
	a.InventoryNotes = a.InventoryNotes[:1]
	for _, n := range workspace.Readout(e, a.ID, c) {
		a.InventoryNotes = append(a.InventoryNotes, Note{Kind: n.Kind, Source: n.Source, Detail: n.Detail})
	}
	workspacePlan(a, func(w *workspace.Evidence) { w.Binding, w.Mail = e.Binding, e.Mail })
	signedIn := 0
	for _, m := range e.Mail.Accounts {
		if m.AutoRead.ActedAs || m.FiltersRead.ActedAs {
			signedIn++
		}
	}
	in.Authorization = &Authorization{Mailboxes: []MailboxReport{{
		Asset: a.ID, By: "CEO, Example Ltd", Date: "2026-10-06", Expires: "2027-01-04",
		Used: true, SignedIn: signedIn,
	}}}
	// Five mailbox sign-ins and ten settings reads left this machine.
	in.Egress.Sources = []SourceInput{{Source: "google", Operator: "Google", Host: "admin.googleapis.com", Requests: 7 + len(users), Sent: []string{a.ID}, Credentials: []string{"GOOGLE_APPLICATION_CREDENTIALS"}},
		{Source: "google", Operator: "Google", Host: "gmail.googleapis.com", Requests: 10, Sent: []string{a.ID}, Credentials: []string{"GOOGLE_APPLICATION_CREDENTIALS"}},
		{Source: "google", Operator: "Google", Host: "oauth2.googleapis.com", Requests: 6, Sent: []string{a.ID}, Credentials: []string{"GOOGLE_APPLICATION_CREDENTIALS"}}}
	return in
}

func TestMailboxHeaderNamesAnEndedApproval(t *testing.T) {
	in := workspaceInventoryReport(t)
	in.Authorization = &Authorization{Mailboxes: []MailboxReport{{
		Asset: "saas:google-workspace:example.com", By: "CEO", Date: "2020-01-01", Expires: "2020-03-01", Ended: true,
	}}}
	var b bytes.Buffer
	if err := WriteText(&b, build(in), Options{}); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, `the approval by "CEO" ended on 2020-03-01`) || strings.Contains(s, "none recorded") || !strings.Contains(s, "scheck did not verify it") {
		t.Fatal(s)
	}
	in.Authorization.Mailboxes[0] = MailboxReport{Asset: "saas:google-workspace:example.com", By: "CEO", Date: "2026-10-06", Expires: "2027-01-04", Unobserved: true}
	b.Reset()
	if err := WriteText(&b, build(in), Options{}); err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(b.String()), " ")
	if !strings.Contains(flat, "Workspace was not read, so scheck did not sign in as mailboxes") || strings.Contains(flat, `the approval by "CEO" ended on`) {
		t.Fatal(flat)
	}
}

func TestWorkspaceMailRaiseCoverageAndAcceptance(t *testing.T) {
	r := build(workspaceMailReport(t))
	sev := map[string]string{}
	var admin *Finding
	for i, f := range r.Findings {
		if f.ID == "workspace.external_forwarding" && f.Subject != nil {
			sev[f.Subject.Key] = f.Severity
			if f.Subject.Key == "admin@example.com -> admin.home@gmail.com" {
				admin = &r.Findings[i]
			}
		}
	}
	if len(sev) != 2 || sev["carol@example.com -> invoices@books.example.net"] != "medium" || admin == nil || admin.Severity != "high" ||
		len(admin.Adjustments) != 1 || admin.Adjustments[0].Rule != "attribute:admin" || admin.Subject.Kind != "mail_forward" || admin.AcceptTemplate == nil || !admin.AcceptTemplate.BySubject {
		t.Fatalf("%v %+v", sev, admin)
	}
	if len(admin.WhyHere) != 1 || !strings.HasPrefix(admin.WhyHere[0], "admin@example.com is a super administrator: mail sent to administrators") {
		t.Fatal(admin.WhyHere)
	}
	email := row(t, r, "email")
	var forwarding *SubItem
	for _, si := range email.SubItems {
		if strings.HasPrefix(si.Name, "Workspace mail forwarding") {
			forwarding = &si
		}
	}
	if forwarding == nil || forwarding.Mark != "partial" || email.Mark != "partial" || email.Population == nil || email.Population.Read != 1 ||
		!slices.ContainsFunc(forwarding.Reasons, func(d ReasonDetail) bool { return d.Reason == "unavailable:forwarding_subdomain" }) {
		t.Fatal(email, forwarding)
	}
	var b bytes.Buffer
	if err := WriteText(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatal("a destination's terminal escape reached the text report")
	}
	// An acceptance pins the destination: accepting carol's forward to her
	// accounting service accepts nothing else from her mailbox.
	in := workspaceMailReport(t)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: "workspace.external_forwarding", Asset: "Workspace", AssetID: in.Assets[0].ID, Subject: "carol@example.com -> other@books.example.net", Reason: "r", AcceptedBy: "dani", Expires: "2027-01-01"}}
	for _, f := range build(in).Findings {
		if f.Status == finding.StatusAccepted {
			t.Fatal("another destination's acceptance accepted this one", f)
		}
	}
	in.Acceptances[0].Subject = "carol@example.com -> invoices@books.example.net"
	accepted := 0
	for _, f := range build(in).Findings {
		if f.Status == finding.StatusAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("the destination's own acceptance did not apply")
	}
	// The default profile names forwarding not on plan in the email row,
	// which reads nothing for it.
	r = build(workspaceIdentityReport(t))
	email = row(t, r, "email")
	if email.Mark != "not_assessed" || email.Population == nil || email.Population.Read != 0 || len(email.Reasons) != 2 || email.Reasons[0].Reason != "not_on_plan:profile=directory" || email.Reasons[1].Reason != "not_declared" {
		t.Fatal(email)
	}
}

// A Workspace tenant whose inventory failed, in an identity row another
// collector judged, is named with its own reason in the row and its
// sub-item, never as "inventory only".
func TestAFailedWorkspaceInventoryIsNamedInAJudgedRow(t *testing.T) {
	in := githubAccessFiredReport(t)
	ws := workspaceInventoryReport(t).Assets[0]
	ws.Status, ws.Reason, ws.InventoryRead = "incomplete", "failed", false
	in.Assets = append(in.Assets, ws)
	r := build(in)
	validate(t, schema(t), r)
	got := row(t, r, "identity")
	if !slices.ContainsFunc(got.Reasons, func(rd ReasonDetail) bool { return rd.Detail == ws.Name && rd.Reason != "no_rule" }) {
		t.Errorf("the failed tenant is not named in the identity row: %+v", got.Reasons)
	}
	for _, si := range got.SubItems {
		if si.Asset == ws.ID && strings.Contains(strings.ToLower(si.Reasons[0].Detail), "inventory only") {
			t.Errorf("the unread tenant's sub-item says inventory only: %+v", si)
		}
	}
}
