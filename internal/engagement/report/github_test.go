package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/finding"
)

func githubInventoryReport(_ *testing.T) Input {
	const asset = "saas:github:example-org"
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	ai := AssetInput{Name: "engineering", ID: asset, Kind: "saas", Root: true,
		Status: "collected", Collector: "github", InventoryRead: true,
		Detail:           "GitHub inventory only. No GitHub security control was assessed.",
		NetworkPrincipal: &Principal{Identity: "alice (user ID 41)", Scopes: []string{"read:org", "repo"}, ScopesSource: "provider"},
		InventoryNotes: []Note{
			{Kind: "github_inventory", Source: asset, Detail: "members: observed 6; owners: observed 2; outside collaborators: observed 1; pending invitations: observed 0; repositories visible to this credential: observed 4. This report contains GitHub inventory only. No GitHub security control was assessed."},
			{Kind: "github_inventory", Source: asset, Detail: "The credential may hide private repositories or concealed memberships. Completing pagination does not establish a complete organization inventory."},
		}}
	note := githubc.AssessmentCredential(githubc.PrincipalRead{Read: githubc.Read{Decision: "sent", Status: 200}, Account: &githubc.Account{ID: 41, Login: "alice", Type: "User"}, Identity: "github:user:41", Scopes: ai.NetworkPrincipal.Scopes})
	ai.InventoryNotes = append(ai.InventoryNotes, Note{Kind: "github_credential_warning", Source: asset, Detail: note.Detail})
	for i, op := range []string{"github.principal", "github.organization", "github.membership", "github.members", "github.owners", "github.outside_collaborators", "github.invitations", "github.repositories"} {
		ai.NetworkTrace = append(ai.NetworkTrace, Trace{Request: op, At: at.Add(time.Duration(i) * time.Second), Decision: "sent"})
	}
	return Input{Version: "test", Name: "GitHub inventory review", Operator: "Alex", Trigger: "routine",
		Zone: time.UTC, Path: "engagement.yaml", SHA256: strings.Repeat("a", 64), Started: at, Finished: at.Add(time.Minute),
		Directory: "/state/engagements/github-inventory/2026-10-09T12:00:00Z", Rerun: "scheck run engagement.yaml",
		LevelsUsed: []string{"observe"}, Assets: []AssetInput{ai},
		Egress: &EgressInput{Sources: []SourceInput{{Source: "github", Operator: "GitHub", Host: "api.github.com", Requests: 8,
			Sent: []string{asset}, Credentials: []string{"GITHUB_TOKEN"}}}, Tenants: []string{asset}}}
}

func githubPartialInventoryReport(t *testing.T) Input {
	in := githubInventoryReport(t)
	a := &in.Assets[0]
	a.Status, a.Reason, a.Detail = "incomplete", "limit_reached", "The run deadline ended the member inventory before the next page could be read."
	a.PopulationIncomplete = true
	a.InventoryNotes[0].Detail = "members: at least 100; owners: observed 2; outside collaborators: not read; pending invitations: observed 0; repositories visible to this credential: observed 4. This report contains GitHub inventory only. No GitHub security control was assessed."
	a.InventoryNotes = append(a.InventoryNotes,
		Note{Kind: "github_inventory", Source: a.ID, Detail: "Member list stopped before all pages were read; at least 100 members were observed."},
		Note{Kind: "github_inventory", Source: a.ID, Detail: "Outside collaborators were not read. Ask an organization owner to authorize the token with organization Members read permission, then resume the run."})
	a.NetworkTrace[5].Decision = "unavailable:permission_denied"
	a.NetworkTrace = append(a.NetworkTrace, Trace{Request: "github.members-next-page", At: in.Finished, Decision: "refused:deadline"})
	return in
}

func githubChangedPrincipalReport(t *testing.T) Input {
	in := githubInventoryReport(t)
	in.Resumed = true
	in.Finished = in.Started.Add(24 * time.Hour)
	in.Assets[0].NetworkPrincipal = &Principal{Identity: "bob (user ID 72)", ScopesSource: "unknown"}
	in.Assets[0].InventoryNotes[len(in.Assets[0].InventoryNotes)-1] = Note{Kind: "github_credential", Source: in.Assets[0].ID, Detail: githubc.AssessmentCredential(githubc.PrincipalRead{}).Detail}
	in.PrincipalChanges = []PrincipalChange{{Asset: in.Assets[0].ID, From: "alice (user ID 41)", To: "bob (user ID 72)"}}
	in.Assets[0].InventoryNotes = append(in.Assets[0].InventoryNotes, Note{Kind: "github_inventory", Source: in.Assets[0].ID,
		Detail: "Earlier authenticated GitHub successes were not reused after the principal changed; this session read the inventory again."})
	for i := range in.Assets[0].NetworkTrace {
		in.Assets[0].NetworkTrace[i].At = in.Assets[0].NetworkTrace[i].At.Add(24 * time.Hour)
	}
	in.Egress.Sources[0].Requests = 16
	return in
}

func githubAndWebInventoryReport(t *testing.T) Input {
	in := githubInventoryReport(t)
	in.Assets = append(in.Assets, AssetInput{Name: "website", ID: "url:https://example.com/", Kind: "url", Root: true, Status: "collected", Collector: "web",
		Judged: []Judgment{{ID: finding.IDWebSecretInResponse, Asset: "url:https://example.com/", Verdict: verdictDisproved,
			Subject: Subject{Kind: "secret_location", Key: "https://example.com/", Label: "https://example.com/"}, Reads: []string{"web-page"}}}})
	in.Egress.Sites = []SiteInput{{Name: "example.com", Requests: 1, FirstParty: true}}
	return in
}

func TestMixedWebAndGitHubCoverageKeepsInventoryGap(t *testing.T) {
	r := Build(githubAndWebInventoryReport(t))
	v := row(t, r, "secrets")
	if v.Mark != "partial" {
		t.Fatalf("mixed secrets coverage: %+v", v)
	}
	noRule := false
	for _, x := range v.SubItems {
		if x.Asset == "saas:github:example-org" {
			for _, reason := range x.Reasons {
				noRule = noRule || reason.Reason == "no_rule"
			}
			if x.Mark != "not_assessed" {
				t.Fatal(x)
			}
		}
	}
	if !noRule {
		t.Fatalf("GitHub inventory gap missing: %+v", v)
	}
}

func TestGitHubInventoryIsNotASecurityAssessment(t *testing.T) {
	for _, mk := range []func(*testing.T) Input{githubInventoryReport, githubPartialInventoryReport, githubChangedPrincipalReport} {
		r := Build(mk(t))
		if len(r.Findings) != 0 || len(r.Assessments) != 0 {
			t.Fatal("inventory fabricated security assessment")
		}
		for _, area := range []finding.Area{finding.AreaIdentity, finding.AreaSecrets, finding.AreaCICD} {
			v := row(t, r, string(area))
			if v.Mark != "not_assessed" {
				t.Fatalf("%s inventory assessed: %+v", area, v)
			}
			found := false
			for _, reason := range v.Reasons {
				found = found || reason.Reason == "no_rule"
			}
			if !found {
				t.Fatalf("%s missing no_rule: %+v", area, v)
			}
		}
		var b bytes.Buffer
		if err := WriteText(&b, r, Options{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(strings.Fields(b.String()), " "), "No GitHub security control was assessed") {
			t.Fatal("inventory warning not rendered")
		}
	}
	if Build(githubInventoryReport(t)).Exit.Code != 0 {
		t.Fatal("successful inventory is not execution success")
	}
	if Build(githubPartialInventoryReport(t)).Exit.Code != 2 {
		t.Fatal("partial inventory lost incomplete exit")
	}
}

func TestGitHubPrincipalChangeIsInTheHeader(t *testing.T) {
	r := Build(githubChangedPrincipalReport(t))
	if len(r.Engagement.PrincipalChanges) != 1 || r.Assets[0].Principal.Identity != "bob (user ID 72)" {
		t.Fatal("principal change lost")
	}
	var b bytes.Buffer
	if err := WriteText(&b, r, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(b.String()), " "), "alice (user ID 41)") || !strings.Contains(strings.Join(strings.Fields(b.String()), " "), "bob (user ID 72)") {
		t.Fatal("principal change absent from text")
	}
}

func TestFailedGitHubInventoryDoesNotCountAsRead(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		in := githubInventoryReport(t)
		in.Assets[0].Status, in.Assets[0].Reason = "incomplete", "failed"
		in.Assets[0].InventoryRead = false
		if mixed {
			in.Assets = append(in.Assets, withDomainRoot(t).Assets[1:]...)
		}
		r := Build(in)
		for _, area := range []string{"identity", "secrets", "cicd"} {
			v := row(t, r, area)
			want := 0
			if mixed && area == "secrets" {
				want = 1
			}
			if v.Population.Read != want {
				t.Fatalf("mixed=%v %s falsely counted inventory: %+v", mixed, area, v.Population)
			}
		}
	}
}
