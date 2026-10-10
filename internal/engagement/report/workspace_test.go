package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	_ "github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/finding"
)

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
		r := Build(in)
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
	if row(t, Build(in), "identity").Mark == "assessed" {
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
	return in
}
func TestWorkspaceIdentityCoverageAndSubjectAcceptances(t *testing.T) {
	in := workspaceIdentityReport(t)
	r := Build(in)
	if r.Exit.Code != 1 || len(r.Findings) != 3 || row(t, r, "identity").Mark != "partial" {
		t.Fatal(r.Exit, r.Findings, row(t, r, "identity"))
	}
	in.Assets[0].JudgmentEvidenceIncomplete = true
	r = Build(in)
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
