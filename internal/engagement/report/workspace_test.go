package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
