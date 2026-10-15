package report

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/workspace"
	"github.com/b87/scheck/internal/finding"
)

const (
	peopleWorkspace = "saas:google-workspace:example.com"
	peopleRepo      = "repo:github:example-org/production"
)

// peopleLeftReport is a Workspace tenant and a GitHub organization with a
// production repository, and four people who left (docs/spec/report.md,
// "People who left", "A person item"):
//   - carol is still active in Workspace, an administrator there with a
//     stale account, and can still push to the production repository;
//   - dana is gone from Workspace and declares no GitHub login;
//   - erin's date had not passed at the reads;
//   - frank is an outside collaborator whose production write was not
//     established, and declares no Workspace address.
func peopleLeftReport(t *testing.T) Input {
	in := githubInventoryReport(t)
	in.Name = "Offboarding review"
	in.People = true
	in.Departed = []Departure{
		{Handle: "carol", Left: "2026-09-15", Providers: []string{"workspace", "github"}},
		{Handle: "dana", Left: "2026-08-01", Providers: []string{"workspace"}},
		{Handle: "erin", Left: "2099-01-01", Providers: []string{"workspace", "github"}},
		{Handle: "frank", Left: "2026-09-01", Providers: []string{"github"}},
	}
	org := &in.Assets[0]
	org.Detail = "GitHub identity and repository-access evidence collected."
	// F1 asked about two pairs and the cap stopped a third.
	org.PermissionAsks = &FollowUpCount{Opened: 3, Asked: 2, Capped: true}
	account := func(key, person string) finding.Subject {
		return finding.Subject{Kind: "account", Key: key, Label: key, Person: person}
	}
	leaver := func(asset string, s finding.Subject, verdict, read string) Judgment {
		return Judgment{ID: finding.IDIdentityFormerPersonHasAccess, Asset: asset, Subject: s, Verdict: verdict, Reads: []string{read},
			Sources: []string{"people." + s.Person + ".left"}, Excerpt: s.Key + "; declared leaving date passed"}
	}
	carolOrg := leaver(githubAccessOrg, account("carol-gh", "carol"), verdictFired, "members")
	carolOrg.Details = map[string]any{"membership": "member"}
	carolOrg.Attributes = []finding.Attribute{{Name: "write_held", Asset: peopleRepo}}
	frankOrg := leaver(githubAccessOrg, account("frank-gh", "frank"), verdictFired, "outside")
	frankOrg.Details = map[string]any{"membership": "outside_collaborator"}
	frankOrg.Attributes = []finding.Attribute{{Name: "write_unsettled", Asset: peopleRepo, Ref: finding.Ref{Observation: "collaborators",
		Excerpt: "frank-gh is not listed among the collaborators of example-org/production, and that list may not show everyone with access"}}}
	erinGH := leaver(githubAccessOrg, account("erin-gh", "erin"), verdictAbstained, "members")
	erinGH.Reason = "leaving_date_not_passed"
	danaGH := Judgment{ID: finding.IDIdentityFormerPersonHasAccess, Asset: githubAccessOrg, Subject: account("declared:dana", "dana"), Verdict: verdictAbstained, Reason: "no_declared_github_login"}
	org.Judged = []Judgment{carolOrg, frankOrg, erinGH, danaGH}
	carolRepo := leaver(peopleRepo, account("carol-gh", "carol"), verdictFired, "collaborators")
	carolRepo.Details = map[string]any{"membership": "collaborator"}
	carolRepo.Attributes = []finding.Attribute{{Name: "write", Ref: finding.Ref{Observation: "collaborators", Excerpt: "role_name: write; admin: false; maintain: false; push: true; pull: true"}}}
	in.Assets = append(in.Assets, AssetInput{Name: "production", ID: peopleRepo, Kind: "repo", Status: "collected", Collector: "github", InventoryRead: true,
		ReadWith: githubAccessOrg, NetworkPrincipal: org.NetworkPrincipal, Judged: []Judgment{carolRepo}})

	ws := workspaceInventoryReport(t).Assets[0]
	ws.Detail = "Workspace identity checks collected."
	carolWS := leaver(peopleWorkspace, account("carol@example.com", "carol"), verdictFired, "users")
	carolWS.Attributes = []finding.Attribute{{Name: "admin"}}
	stale := Judgment{ID: workspace.IDStaleAccount, Asset: peopleWorkspace, Subject: account("carol@example.com", "carol"), Verdict: verdictFired, Reads: []string{"users"},
		Excerpt: "Google reports no sign-in since 2026-06-01T00:00:00Z."}
	danaWS := leaver(peopleWorkspace, account("dana@example.com", "dana"), verdictDisproved, "users")
	erinWS := leaver(peopleWorkspace, account("erin@example.com", "erin"), verdictAbstained, "users")
	erinWS.Reason = "leaving_date_not_passed"
	frankWS := leaver(peopleWorkspace, account("declared:frank", "frank"), verdictAbstained, "users")
	frankWS.Reason, frankWS.NotChecked = "unavailable:workspace_evidence", []string{"Declared account identity is missing or ambiguous."}
	ws.Judged = []Judgment{carolWS, stale, danaWS, erinWS, frankWS}
	workspacePlan(&ws, nil)
	in.Assets = append(in.Assets, ws)
	in.Egress.Sources = append(in.Egress.Sources, SourceInput{Source: "google", Operator: "Google", Host: "admin.googleapis.com", Requests: 3, Sent: []string{peopleWorkspace}, Credentials: []string{"GOOGLE_APPLICATION_CREDENTIALS"}})
	in.Egress.Tenants = append(in.Egress.Tenants, peopleWorkspace)
	in.Observations = map[string]Observation{}
	for _, r := range []string{"members", "outside", "collaborators", "users"} {
		in.Observations[r] = Observation{CollectedAt: in.Started.Add(17 * time.Second)}
	}
	return graded(in, production(peopleRepo, "production"))
}

func TestPeopleWhoLeft(t *testing.T) {
	r := build(peopleLeftReport(t))
	validate(t, schema(t), r)
	lines := map[string][]string{}
	for _, p := range r.PeopleLeft {
		for _, tl := range p.Tenants {
			lines[p.Handle] = append(lines[p.Handle], tl.Line)
		}
	}
	want := map[string][]string{
		"carol": {"GitHub: carol-gh still has access as member (finding); carol-gh can still push to example-org/production, declared production (finding).",
			"Workspace: carol@example.com still active, with administrator rights (finding)."},
		"dana": {"GitHub: no login declared, not checked.", "Workspace: dana@example.com no access observed as of 2026-10-09."},
		"erin": {"GitHub: erin-gh leaving date had not passed at the read of 2026-10-09, not judged.",
			"Workspace: erin@example.com leaving date had not passed at the read of 2026-10-09, not judged."},
		"frank": {"GitHub: frank-gh still has access as outside collaborator (finding); write access to production repositories was not established.",
			"Workspace: no address declared, not checked."},
	}
	for h, w := range want {
		if !slices.Equal(lines[h], w) {
			t.Errorf("%s:\n got %q\nwant %q", h, lines[h], w)
		}
	}
	// carol's open findings span two tenants and three ids: one item, at
	// the severity R4 set, its instances out of the finding_id items.
	var person *Item
	for i, it := range r.Summary.Items {
		if it.Kind == "person" {
			if person != nil {
				t.Fatal("one person qualifies")
			}
			person = &r.Summary.Items[i]
		}
	}
	if person == nil || *person.Person != "carol" || person.Severity != "critical" ||
		person.Title != "carol, who left on 2026-09-15, still has access to GitHub, and is still active in Workspace" ||
		!slices.Contains(person.RankBasis, "person:carol") || !slices.Contains(person.RankBasis, "attribute:production_write") ||
		len(person.Keys) != 4 || person.Keys[0].Asset != peopleRepo {
		t.Fatalf("person item: %+v", person)
	}
	for _, it := range r.Summary.Items {
		if it.Kind == "finding_id" && slices.Contains(leaverIDs, it.IDs[0]) {
			if !it.OtherPeople || len(it.Keys) != 1 || it.Keys[0].Asset != githubAccessOrg {
				t.Fatalf("frank's access ranks apart: %+v", it)
			}
		}
		if it.Kind == "finding_id" && it.IDs[0] == workspace.IDStaleAccount {
			t.Fatalf("carol's stale account is in her item: %+v", it)
		}
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, r, Options{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, s := range []string{"base high, raised: can still push to example-org/production, declared production", "People who left", "  frank (left 2026-09-01)", "and other people"} {
		if !strings.Contains(out, s) {
			t.Errorf("text lacks %q", s)
		}
	}
}

// A person with one open instance stays in the finding_id item; a third
// qualifying person falls back to it; an accepted instance does not count.
func TestPersonItemThresholdsAndCap(t *testing.T) {
	in := peopleLeftReport(t)
	ws := &in.Assets[len(in.Assets)-1]
	// Without her Workspace findings carol has two GitHub ids? No: one id
	// on two assets of one tenant, so a single tenant and a single id.
	ws.Judged = slices.DeleteFunc(ws.Judged, func(j Judgment) bool { return j.Subject.Person == "carol" })
	r := build(in)
	for _, it := range r.Summary.Items {
		if it.Kind == "person" {
			t.Fatalf("one tenant, one id: %+v", it)
		}
	}

	// Three people each in two tenants: two person items at most.
	in = peopleLeftReport(t)
	ws = &in.Assets[len(in.Assets)-1]
	org := &in.Assets[0]
	for _, h := range []string{"gina", "hal"} {
		in.Departed = append(in.Departed, Departure{Handle: h, Left: "2026-09-02", Providers: []string{"workspace", "github"}})
		ws.Judged = append(ws.Judged, Judgment{ID: finding.IDIdentityFormerPersonHasAccess, Asset: peopleWorkspace, Subject: finding.Subject{Kind: "account", Key: h + "@example.com", Label: h + "@example.com", Person: h}, Verdict: verdictFired, Reads: []string{"users"}})
		org.Judged = append(org.Judged, Judgment{ID: finding.IDIdentityFormerPersonHasAccess, Asset: githubAccessOrg, Subject: finding.Subject{Kind: "account", Key: h, Label: h, Person: h}, Verdict: verdictFired, Reads: []string{"members"}, Details: map[string]any{"membership": "member"}})
	}
	in = graded(in, production(peopleRepo, "production"))
	r = build(in)
	persons := 0
	for _, it := range r.Summary.Items {
		if it.Kind == "person" {
			persons++
		}
	}
	if persons != maxPersonItems || *r.Summary.Items[0].Person != "carol" {
		t.Fatalf("cap: %+v", r.Summary.Items)
	}

	// carol's Workspace finding accepted: her item ranks on what is open.
	in = peopleLeftReport(t)
	in.Acceptances = []AcceptanceInput{{Entry: "engagement.yaml intent.accepted_risks[0]", ID: finding.IDIdentityFormerPersonHasAccess, AssetID: peopleWorkspace, Subject: "carol@example.com", AcceptedBy: "alex", Expires: "2026-12-31", Reason: "handover"}}
	r = build(in)
	for _, p := range r.PeopleLeft {
		if p.Handle == "carol" && p.Tenants[1].Line != "Workspace: carol@example.com still active (accepted until 2026-12-31)." {
			t.Fatalf("accepted line: %q", p.Tenants[1].Line)
		}
	}
	for _, it := range r.Summary.Items {
		for _, k := range it.Keys {
			if k.Asset == peopleWorkspace && k.ID == finding.IDIdentityFormerPersonHasAccess {
				t.Fatalf("an accepted instance ranks: %+v", it)
			}
		}
	}
}

// A provider the person declares with no tenant of it in scope prints
// "not in this engagement's scope"; a tenant that was not read says why.
func TestPeopleWhoLeftOutOfScopeAndUnread(t *testing.T) {
	in := peopleLeftReport(t)
	in.Assets = in.Assets[:2] // GitHub only
	in.Assets[0].Status, in.Assets[0].Reason, in.Assets[0].Judged = "failed", "failed", nil
	in.Assets[1].Judged = nil
	r := build(in)
	for _, p := range r.PeopleLeft {
		if p.Handle != "carol" {
			continue
		}
		got := []string{p.Tenants[0].Line, p.Tenants[1].Line}
		if p.Tenants[1].Asset != nil || p.Tenants[1].State != "not_in_scope" ||
			!strings.HasPrefix(got[0], "GitHub: the organization could not be read (") || got[1] != "Workspace: not in this engagement's scope, not checked." {
			t.Fatalf("%q %+v", got, p.Tenants)
		}
	}
}

// The collector's own abstentions reach the right line: an account seen
// only through an alias, an account with conflicting access evidence, a
// person with no address whose date had not passed, and an unread users
// list (internal/collector/workspace, then the report).
func TestWorkspaceLeaverAbstentionsFromTheCollector(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	user := func(id, primary string, aliases ...string) workspace.User {
		return workspace.User{ID: id, Primary: primary, Aliases: aliases, Customer: "C123", Unit: "/", Suspended: new(false), Archived: new(false), IsAdmin: new(false),
			CreationTime: new("2025-01-01T00:00:00Z"), LastLoginTime: new("2026-10-10T11:00:00Z")}
	}
	account := func(u workspace.User, conflict bool) workspace.AccountAccess {
		return workspace.AccountAccess{ID: u.ID, Conflict: conflict, Detail: &u,
			Assignments: workspace.Population[workspace.Assignment]{Complete: true, Items: []workspace.Assignment{}, Reads: []workspace.Read{{Op: workspace.OpUserAssignments, RequestID: "a" + u.ID, Decision: "sent", Status: 200, CollectedAt: now}}},
			DetailRead:  workspace.Read{Op: workspace.OpUserDetail, RequestID: "d" + u.ID, Decision: "sent", Status: 200, CollectedAt: now}}
	}
	alias, conflicted := user("1", "alice@example.com", "old@example.com"), user("2", "bob@example.com")
	e := workspace.Evidence{
		Users:  workspace.Population[workspace.User]{Complete: true, Items: []workspace.User{alias, conflicted}, Reads: []workspace.Read{{Op: workspace.OpUsers, RequestID: "users", Decision: "sent", Status: 200, CollectedAt: now}}},
		Access: workspace.AccessEvidence{Roles: workspace.Population[workspace.Role]{Complete: true, Items: []workspace.Role{}}, Privileges: workspace.Population[workspace.Privilege]{Complete: true, Items: []workspace.Privilege{}}, Accounts: []workspace.AccountAccess{account(alias, false), account(conflicted, true)}},
	}
	c := workspace.Context{Zone: time.UTC, People: []workspace.Person{
		{Handle: "olda", Kind: "employee", Left: "2026-09-01", Addresses: []string{"old@example.com"}},
		{Handle: "bob", Kind: "employee", Left: "2026-09-01", Addresses: []string{"bob@example.com"}},
		{Handle: "zed", Kind: "employee", Left: "2099-01-01"},
	}}
	in := workspaceInventoryReport(t)
	in.Departed = []Departure{{Handle: "olda", Left: "2026-09-01", Providers: []string{"workspace"}}, {Handle: "bob", Left: "2026-09-01", Providers: []string{"workspace"}}, {Handle: "zed", Left: "2099-01-01"}}
	in.Assets[0].Judged = workspace.Judge(e, peopleWorkspace, c)
	lines := func(in Input) map[string]string {
		out := map[string]string{}
		for _, p := range build(in).PeopleLeft {
			out[p.Handle] = p.Tenants[0].Line
		}
		return out
	}
	got := lines(in)
	want := map[string]string{
		"olda": "Workspace: alice@example.com account identity missing or ambiguous, not checked.",
		"bob":  "Workspace: bob@example.com account observed, but its status or access evidence was not recognized, not checked.",
		"zed":  "Workspace: no address declared, not checked.",
	}
	for h, w := range want {
		if got[h] != w {
			t.Errorf("%s: got %q, want %q", h, got[h], w)
		}
	}
	// An address missing from a partial list is not seen, never gone, and
	// no account is claimed observed.
	c.People = append(c.People, workspace.Person{Handle: "gone", Kind: "employee", Left: "2026-09-01", Addresses: []string{"gone@example.com"}})
	in.Departed = append(in.Departed, Departure{Handle: "gone", Left: "2026-09-01", Providers: []string{"workspace"}})
	e.Users.Complete = false
	in.Assets[0].Judged = workspace.Judge(e, peopleWorkspace, c)
	for _, p := range build(in).PeopleLeft {
		if p.Handle == "gone" && (p.Tenants[0].Line != "Workspace: gone@example.com not seen as of 2026-10-10; the users list was incomplete, so no access is not proven." || p.Tenants[0].State != "not_proven") {
			t.Fatalf("partial list: %+v", p.Tenants[0])
		}
	}
	// The users list refused: every leaver says so, with the asset's reason.
	e.Users = workspace.Population[workspace.User]{Reads: []workspace.Read{{Op: workspace.OpUsers, RequestID: "users", Decision: "refused", Reason: "refused"}}}
	in.Assets[0].Judged = workspace.Judge(e, peopleWorkspace, c)
	in.Assets[0].Status, in.Assets[0].Reason = "incomplete", "insufficient_permission:admin.directory.user.readonly"
	for h, l := range lines(in) {
		if h != "zed" && !strings.HasPrefix(l, "Workspace: users could not be read (the access scheck was given cannot read this; it needs admin.directory.user.readonly") {
			t.Errorf("%s unread: %q", h, l)
		}
	}
}

// GitHub's own verdicts, graded, reach the right line: a member whose
// production repository's collaborators could not be read gets R4 said and
// not taken; a login listed nowhere over a population GitHub cannot list in
// full is not proven gone.
func TestGitHubLeaverLinesFromTheCollector(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	ok := []githubc.Read{{RequestID: "r", Decision: "sent", Status: 200, ObservedAt: now}}
	pop := func(items ...githubc.Account) githubc.Population[githubc.Account] {
		return githubc.Population[githubc.Account]{Items: items, Complete: true, VisibilityComplete: true, Reads: ok}
	}
	carol := githubc.Account{ID: 7, Login: "carol-gh", Type: "User"}
	e := githubc.Evidence{OwnerAuthority: true, Members: pop(carol), Owners: pop(), OutsideCollaborators: pop(),
		Invitations: githubc.Population[githubc.Invitation]{Complete: true, VisibilityComplete: true, Reads: ok},
		RepositoriesAccess: []githubc.RepositoryAccess{{Asset: peopleRepo, Repository: &githubc.Repository{ID: 1, FullName: "example-org/production"},
			Collaborators: githubc.Population[githubc.Collaborator]{Reads: []githubc.Read{{RequestID: "collab", Decision: "sent", Status: 403, Reason: "insufficient_permission", ObservedAt: now}}}}}}
	c := githubc.Context{OrganizationAsset: githubAccessOrg, Zone: time.UTC,
		People:             []githubc.Person{{Handle: "carol", Left: "2026-09-15", GitHub: []string{"carol-gh"}}, {Handle: "dan", Left: "2026-09-15", GitHub: []string{"dan-gh"}}},
		RepositoryContexts: map[string]githubc.RepositoryContext{peopleRepo: {DeploysTo: "production"}}}
	in := githubInventoryReport(t)
	in.Departed = []Departure{{Handle: "carol", Left: "2026-09-15", Providers: []string{"github"}}, {Handle: "dan", Left: "2026-09-15", Providers: []string{"github"}}}
	in.Assets[0].Judged = githubc.JudgeAccess(e, c)
	in = graded(in, production(peopleRepo, "production"))
	got := map[string]string{}
	for _, p := range build(in).PeopleLeft {
		got[p.Handle] = p.Tenants[0].Line
	}
	want := map[string]string{
		"carol": "GitHub: carol-gh still has access as member (finding); write access to production repositories was not established.",
		"dan":   "GitHub: dan-gh not seen as of 2026-10-09; access to repositories cannot be fully listed, so no access is not proven.",
	}
	for h, w := range want {
		if got[h] != w {
			t.Errorf("%s: got %q, want %q", h, got[h], w)
		}
	}
}
