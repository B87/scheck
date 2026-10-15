package github

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

const permShop, permAPI = "repo:github:acme/shop", "repo:github:acme/api"

// permissionAnswer is a 200 permission entry for login on asset.
func permissionAnswer(asset, login, level, role string, p *Permissions) PermissionRead {
	a := &PermissionAnswer{Permission: new(level), RoleName: new(role), User: &PermissionUser{ID: 4, Login: login, Type: "User", RoleName: new(role), Permissions: p}}
	return PermissionRead{Asset: asset, Login: login, Read: Read{Op: OpCollaboratorPermission, RequestID: "perm-" + asset, Decision: "sent", Status: 200, ObservedAt: ruleRead}, Answer: a}
}

var (
	pushPerms = &Permissions{Admin: new(false), Maintain: new(false), Push: new(true), Pull: new(true), Triage: new(true)}
	readPerms = &Permissions{Admin: new(false), Maintain: new(false), Push: new(false), Pull: new(true), Triage: new(false)}
	nonePerms = &Permissions{Admin: new(false), Maintain: new(false), Push: new(false), Pull: new(false), Triage: new(false)}
)

// What one answer establishes (docs/spec/github-collector.md, "Selection
// under a budget and the permission follow-up (E9)"): the legacy level and
// the booleans must agree, a 404 is never "no access", and a login that
// names another account than the one the run saw settles nothing.
func TestInterpretPermission(t *testing.T) {
	e, _ := ruleFixture()
	e.Members.Items = append(e.Members.Items, Account{ID: 4, Login: "carol", Type: "User"})
	repo := e.RepositoriesAccess[0]
	archived := repo
	archived.Repository = &Repository{ID: 10, FullName: "acme/shop", Visibility: new("private"), Archived: new(true)}
	public := repo
	public.Repository = &Repository{ID: 10, FullName: "acme/shop", Visibility: new("public")}
	withRead := func(pr PermissionRead, r Read) PermissionRead { pr.Read, pr.Answer = r, nil; return pr }
	base := permissionAnswer(permShop, "carol", "write", "write", pushPerms)
	cases := []struct {
		name   string
		pr     PermissionRead
		repo   RepositoryAccess
		access access
		read   bool
		cause  string
	}{
		{"write", base, repo, accessWrite, false, ""},
		{"write, no user", PermissionRead{Asset: permShop, Login: "carol", Read: base.Read, Answer: &PermissionAnswer{Permission: new("write"), RoleName: new("maintain")}}, repo, accessWrite, false, ""},
		{"none", permissionAnswer(permShop, "carol", "none", "none", nonePerms), repo, accessNone, false, ""},
		{"read on private fires", permissionAnswer(permShop, "carol", "read", "read", readPerms), repo, accessNone, true, ""},
		{"read on public never fires", permissionAnswer(permShop, "carol", "read", "read", readPerms), public, accessNone, false, ""},
		{"level and booleans disagree", permissionAnswer(permShop, "carol", "read", "write", pushPerms), repo, accessUnknown, false, "the permissions returned for carol on acme/shop were missing or contradictory"},
		{"unknown level", permissionAnswer(permShop, "carol", "triage", "triage", readPerms), repo, accessUnknown, false, "the permissions returned for carol on acme/shop were missing or contradictory"},
		{"another login", func() PermissionRead {
			p := base
			p.Answer = &PermissionAnswer{Permission: new("write"), User: &PermissionUser{ID: 4, Login: "mallory", Type: "User"}}
			return p
		}(), repo, accessUnknown, false, "the permissions returned for carol on acme/shop were missing or contradictory"},
		{"redacted role", permissionAnswer(permShop, "carol", "write", "[REDACTED:x:3 bytes]", pushPerms), repo, accessUnknown, false, "the permissions returned for carol on acme/shop were missing or contradictory"},
		{"reclaimed login", func() PermissionRead {
			p := permissionAnswer(permShop, "carol", "none", "none", nonePerms)
			p.Answer.User.ID = 99
			return p
		}(), repo, accessUnknown, false, "the account now named carol is not the one this run saw in the organization"},
		{"archived write", base, archived, accessUnknown, false, "acme/shop is archived"},
		{"404", withRead(base, Read{RequestID: "p", Decision: "sent", Status: 404}), repo, accessUnknown, false, "GitHub has no account named carol now (it may have been renamed or deleted), so its access to acme/shop could not be read"},
		{"denied", withRead(base, Read{RequestID: "p", Decision: "sent", Status: 403, Reason: "insufficient_permission"}), repo, accessUnknown, false, "the credential was not allowed to read carol's permission on acme/shop"},
		{"failed", withRead(base, Read{RequestID: "p", Decision: "unavailable:server_error", Status: 502, Reason: "unavailable:server_error"}), repo, accessUnknown, false, "carol's permission on acme/shop could not be read: server error"},
		{"capped", PermissionNotAsked(PermissionTarget{Repo: RepositoryTarget{Asset: permShop}, Login: "carol"}, ReasonFollowUpCap, ""), repo, accessUnknown, false, "carol's permission on acme/shop was not asked: scheck asks GitHub about at most 20 production repositories per run"},
		{"refused before sending", withRead(base, Read{RequestID: "p", Decision: "refused:rate_limit", Reason: "limit_reached", Detail: "GitHub's rate limit for this token is used up"}), repo, accessUnknown, false, "carol's permission on acme/shop was not asked: the run stopped first (GitHub's rate limit for this token is used up)"},
		{"in flight at the deadline", withRead(base, Read{RequestID: "p", Decision: "unavailable:deadline", Reason: "limit_reached", Sent: true, Detail: "limits.timeout ended the request in flight"}), repo, accessUnknown, false, "carol's permission on acme/shop could not be read: limits.timeout ended the request in flight"},
		{"sent and limited", withRead(base, Read{RequestID: "p", Decision: "sent", Status: 403, Reason: "limit_reached", Detail: "GitHub's rate limit"}), repo, accessUnknown, false, "carol's permission on acme/shop could not be read: GitHub's rate limit"},
		{"limit", PermissionNotAsked(PermissionTarget{Repo: RepositoryTarget{Asset: permShop}, Login: "carol"}, ReasonLimitReached, "the run's timeout passed"), repo, accessUnknown, false, "carol's permission on acme/shop was not asked: the run stopped first (the run's timeout passed)"},
	}
	for _, tc := range cases {
		got := interpretPermission(tc.pr, tc.repo, e)
		if got.access != tc.access || got.read != tc.read || got.cause != tc.cause {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
}

// F1 settles R4 where the list did not, and the list wins where it does.
func TestPermissionSettlesProductionWrite(t *testing.T) {
	setup := func() (Evidence, Context) {
		e, c := ruleFixture()
		c.People = append(c.People, Person{Handle: "carol", Kind: "employee", GitHub: []string{"carol"}, Left: "2026-10-09"})
		e.Members.Items = append(e.Members.Items, Account{ID: 4, Login: "carol", Type: "User"})
		return e, c
	}
	carrier := func(out []Judgment) Judgment {
		for _, j := range out {
			if j.ID == finding.IDIdentityFormerPersonHasAccess && j.Verdict == Fired && j.Subject.Key == "carol" {
				return j
			}
		}
		t.Fatal("carol's judgment did not fire")
		return Judgment{}
	}
	e, c := setup()
	if u, ok := attr(carrier(JudgeAccess(e, c)), "write_unsettled", permShop); !ok || u.Ref.Excerpt != "carol is not listed among the collaborators of acme/shop, and that list may not show everyone with access" {
		t.Fatalf("before F1: %+v", u)
	}
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "write", "write", pushPerms)}
	h, ok := attr(carrier(JudgeAccess(e, c)), "write_held", permShop)
	if !ok || h.Ref.Observation != "perm-"+permShop || h.Ref.Excerpt != "permission: write; role_name: write; admin: false; maintain: false; push: true; pull: true" {
		t.Fatalf("held: %+v", h)
	}
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "none", "none", nonePerms)}
	if j := carrier(JudgeAccess(e, c)); j.Has("write_held") || j.Has("write_unsettled") {
		t.Fatalf("none settles false: %+v", j.Attributes)
	}
	// A listed collaborator's own entry settles it; F1's answer is not read.
	e, c = setup()
	e.RepositoriesAccess[0].Collaborators.Items = append(e.RepositoriesAccess[0].Collaborators.Items, Collaborator{ID: 4, Login: "carol", Type: "User", RoleName: new("read"), Permissions: readPerms})
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "write", "write", pushPerms)}
	for _, j := range JudgeAccess(e, c) {
		if j.Subject.Key == "carol" && (j.Has("write_held") || j.Has("write_unsettled")) {
			t.Fatalf("the list settled shop: %+v", j.Attributes)
		}
	}
}

// A login seen nowhere is access observed when GitHub reports write, or
// read on a private repository; F1 never disproves, and all-none answers
// say what was asked.
func TestPermissionFiresAnAbstainedLeaver(t *testing.T) {
	setup := func() (Evidence, Context) {
		e, c := ruleFixture()
		// No credential sees every collaborator.
		e.RepositoriesAccess[0].Collaborators.VisibilityComplete = false
		c.People = append(c.People, Person{Handle: "carol", Kind: "employee", GitHub: []string{"carol"}, Left: "2026-10-09"})
		return e, c
	}
	e, c := setup()
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "write", "write", pushPerms)}
	out := JudgeAccess(e, c)
	j, ok := fired(out, permShop)
	if !ok || j.Subject.Key != "carol" || j.Subject.ProviderID != "4" || j.Details["membership"] != "collaborator" || !j.Has("write") || !j.Has("write_held") ||
		j.Excerpt != "carol: GitHub reports write (role write) on acme/shop, through a direct, team, base or enterprise grant (GitHub does not say which); declared leaving date 2026-10-09; observed in a permission read of 2026-10-10" {
		t.Fatalf("fired: %+v", j)
	}
	if slices.ContainsFunc(out, func(j Judgment) bool { return j.Subject.Key == "carol" && j.Details["membership"] == "none" }) {
		t.Fatal("the none abstention is still emitted")
	}
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "read", "read", readPerms)}
	if j, ok := fired(JudgeAccess(e, c), permShop); !ok || j.Has("write") {
		t.Fatalf("read on private: %+v", j)
	}
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "none", "none", nonePerms)}
	for _, j := range JudgeAccess(e, c) {
		if j.ID != finding.IDIdentityFormerPersonHasAccess || j.Subject.Key != "carol" {
			continue
		}
		if j.Verdict != Abstained || !slices.Contains(j.NotChecked, "GitHub reports no access for carol to the 1 production repository asked; other repositories were not asked.") || !slices.Contains(j.Reads, "perm-"+permShop) {
			t.Fatalf("none: %+v", j)
		}
	}
	// Judged at the permission read: a leaving date after it opens nothing.
	e, c = setup()
	c.People[1].Left = "2026-10-11"
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "write", "write", pushPerms)}
	if _, ok := fired(JudgeAccess(e, c), permShop); ok {
		t.Fatal("fired before the leaving date")
	}
}

// Which pairs F1 opens (docs/spec/engagement.md, "Plan selection and
// follow-ups"): only on production repositories the engagement names,
// never twice, never for an owner or once write is held, and never where
// the collaborators read was denied.
func TestPermissionOpen(t *testing.T) {
	setup := func() (Evidence, Context) {
		e, c := ruleFixture()
		c.People = append(c.People, Person{Handle: "carol", Kind: "employee", GitHub: []string{"Carol"}, Left: "2026-10-09"})
		e.RepositoriesAccess[0].Collaborators.VisibilityComplete = false
		api := e.RepositoriesAccess[0]
		api.Asset, api.Repository = permAPI, &Repository{ID: 11, Name: "api", FullName: "acme/api", Owner: Account{ID: 2, Login: "acme", Type: "Organization"}, Visibility: new("private")}
		e.RepositoriesAccess[0].Repository.Name, e.RepositoriesAccess[0].Repository.Owner = "shop", Account{ID: 2, Login: "acme", Type: "Organization"}
		e.RepositoriesAccess = append(e.RepositoriesAccess, api)
		return e, c
	}
	open := func(e Evidence, c Context, production ...string) []PermissionLogin {
		return PermissionOpen(JudgeAccess(e, c), e, c, production)
	}
	// Abstained, seen nowhere: every production repository, in Plan's order.
	e, c := setup()
	got := open(e, c, permShop, permAPI)
	if len(got) != 1 || got[0].Fired || got[0].Login != "carol" || got[0].Trigger.Verdict != "abstained" || len(got[0].Open) != 2 ||
		got[0].Open[0].Repo.Asset != permShop || got[0].Open[0].Repo.Owner != "acme" || got[0].Open[0].Repo.Name != "shop" || got[0].Open[0].Login != "carol" {
		t.Fatalf("abstained: %+v", got)
	}
	if got := open(e, c, permShop); len(got[0].Open) != 1 {
		t.Fatalf("only production: %+v", got)
	}
	// Asked once, never again.
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "none", "none", nonePerms)}
	if got := open(e, c, permShop, permAPI); len(got) != 1 || len(got[0].Open) != 1 || got[0].Open[0].Repo.Asset != permAPI {
		t.Fatalf("reopened: %+v", got)
	}
	// A denied collaborators read: F1 needs the same permission.
	e, c = setup()
	e.RepositoriesAccess[1].Collaborators.Reads = []Read{{RequestID: "d", Decision: "sent", Status: 403, Reason: "insufficient_permission", ObservedAt: ruleRead}}
	if got := open(e, c, permShop, permAPI); len(got) != 1 || len(got[0].Open) != 1 {
		t.Fatalf("denied: %+v", got)
	}
	// Fired as a member: open until write is held on production.
	e, c = setup()
	e.Members.Items = append(e.Members.Items, Account{ID: 4, Login: "carol", Type: "User"})
	if got := open(e, c, permShop, permAPI); len(got) != 1 || !got[0].Fired || got[0].Trigger.Asset != c.OrganizationAsset || len(got[0].Open) != 2 {
		t.Fatalf("fired: %+v", got)
	}
	e.Permissions = []PermissionRead{permissionAnswer(permShop, "carol", "write", "write", pushPerms)}
	if got := open(e, c, permShop, permAPI); len(got) != 0 {
		t.Fatalf("write held, still open: %+v", got)
	}
	// An owner is admin everywhere; a leaving date not passed opens nothing.
	e, c = setup()
	e.Members.Items = append(e.Members.Items, Account{ID: 4, Login: "carol", Type: "User"})
	e.Owners.Items = append(e.Owners.Items, Account{ID: 4, Login: "carol", Type: "User"})
	if got := open(e, c, permShop); len(got) != 0 {
		t.Fatalf("owner: %+v", got)
	}
	e, c = setup()
	c.People[1].Left = "2026-10-11"
	if got := open(e, c, permShop); len(got) != 0 {
		t.Fatalf("not passed: %+v", got)
	}
	// An app's login is never asked about.
	e, c = setup()
	c.People[1].GitHub = []string{"deploy-app[bot]"}
	if got := open(e, c, permShop); len(got) != 0 {
		t.Fatalf("bot: %+v", got)
	}
}

// The read sends one compiled op with the login as its username, and a 404
// is kept as an answer (the login may name no account).
func TestCollectPermission(t *testing.T) {
	var seen gate.Request
	body, _ := json.Marshal(map[string]any{"permission": "write", "role_name": "write", "user": map[string]any{"id": 4, "login": "carol", "type": "User"}})
	g := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		seen = r
		return gate.Result{RequestID: "p1", Decision: gate.DecisionSent, Response: &gate.Response{Status: 200, Body: body}}
	})
	pr := CollectPermission(context.Background(), g, PermissionTarget{Repo: RepositoryTarget{Asset: permShop, Owner: "acme", Name: "shop"}, Login: "Carol"}, "check")
	if seen.Op != OpCollaboratorPermission || seen.Asset != permShop || seen.Stage != "check" || seen.Exists || seen.Params["username"] != "Carol" || seen.Params["owner"] != "acme" || seen.Params["repo"] != "shop" {
		t.Fatalf("request: %+v", seen)
	}
	if pr.Login != "carol" || pr.Answer == nil || *pr.Answer.Permission != "write" || pr.Read.RequestID != "p1" {
		t.Fatalf("read: %+v", pr)
	}
}

type senderFunc func(context.Context, gate.Request) gate.Result

func (f senderFunc) Send(ctx context.Context, r gate.Request) gate.Result { return f(ctx, r) }

// A read keeps whether the gate sent it: one the deadline ended in flight
// was asked, one the gate stopped before sending was not.
func TestPermissionReadKeepsSent(t *testing.T) {
	target := PermissionTarget{Repo: RepositoryTarget{Asset: permShop, Owner: "acme", Name: "shop"}, Login: "carol"}
	for _, c := range []struct {
		res     gate.Result
		notSent bool
	}{
		{gate.Result{RequestID: "g1", Decision: "unavailable:deadline", Reason: "limit_reached", Sent: true}, false},
		{gate.Result{RequestID: "g2", Decision: "refused:deadline", Reason: "limit_reached"}, true},
	} {
		pr := CollectPermission(context.Background(), senderFunc(func(context.Context, gate.Request) gate.Result { return c.res }), target, "check")
		if pr.Read.Sent != c.res.Sent || PermissionNotSent(pr.Read) != c.notSent {
			t.Fatalf("%+v: %+v", c.res, pr.Read)
		}
	}
}
