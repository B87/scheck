package github

import (
	"testing"

	"github.com/b87/scheck/internal/finding"
)

// Push access is the provider's effective permission, decided only from
// consistent fields: role_name alone never establishes it, and a read-only
// role beside a push permission is a contradiction (docs/spec/engagement.md,
// R4).
func TestEffectiveWrite(t *testing.T) {
	collab := func(role *string, admin, maintain, push, pull *bool) Collaborator {
		return Collaborator{ID: 1, Login: "alice", RoleName: role, Permissions: &Permissions{Admin: admin, Maintain: maintain, Push: push, Pull: pull}}
	}
	yes, no := new(true), new(false)
	cases := []struct {
		name         string
		c            Collaborator
		write, known bool
	}{
		{"push", collab(new("write"), no, no, yes, yes), true, true},
		{"maintain", collab(new("maintain"), no, yes, yes, yes), true, true},
		{"admin", Collaborator{RoleName: new("admin"), Permissions: &Permissions{Admin: yes}}, true, true},
		{"custom role with push", collab(new("release-manager"), no, no, yes, yes), true, true},
		{"no role name, push", collab(nil, no, no, yes, nil), true, true},
		{"read only", collab(new("read"), no, no, no, yes), false, true},
		{"read role with push", collab(new("read"), no, no, yes, yes), false, false},
		{"maintain without push", collab(new("maintain"), no, yes, no, yes), false, false},
		{"push without pull", collab(new("write"), no, no, yes, no), false, false},
		{"all null", collab(new("write"), nil, nil, nil, nil), false, false},
		{"writing role, no write", collab(new("write"), no, no, no, yes), false, false},
		{"no permissions", Collaborator{RoleName: new("write")}, false, false},
		{"redacted role", collab(new("[REDACTED:x:4 bytes]"), no, no, yes, yes), false, false},
	}
	for _, tc := range cases {
		if w, k := EffectiveWrite(tc.c); w != tc.write || k != tc.known {
			t.Errorf("%s: got (%t, %t), want (%t, %t)", tc.name, w, k, tc.write, tc.known)
		}
	}
}

func fired(out []Judgment, asset string) (Judgment, bool) {
	for _, j := range out {
		if j.ID == finding.IDIdentityFormerPersonHasAccess && j.Verdict == Fired && j.Asset == asset {
			return j, true
		}
	}
	return Judgment{}, false
}

func attr(j Judgment, name, asset string) (finding.Attribute, bool) {
	for _, a := range j.Attributes {
		if a.Name == name && a.Asset == asset {
			return a, true
		}
	}
	return finding.Attribute{}, false
}

// A left member's repository judgment carries write as a fact, never
// production; the one judgment per login that carries R4's facts is the
// organization's when it fired, and it lists each repository read where
// push is held or unsettled, with the cause.
func TestLeftPersonWriteFacts(t *testing.T) {
	const shop, api = "repo:github:acme/shop", "repo:github:acme/api"
	setup := func() (Evidence, Context) {
		e, c := ruleFixture()
		c.People[0].Left = "2026-10-09"
		e.Owners.Items = nil
		push := &Permissions{Admin: new(false), Maintain: new(false), Push: new(true), Pull: new(true), Triage: new(true)}
		e.RepositoriesAccess[0].Collaborators.Items[0].RoleName = new("write")
		e.RepositoriesAccess[0].Collaborators.Items[0].Permissions = push
		other := e.RepositoriesAccess[0]
		other.Asset, other.Repository = api, &Repository{ID: 11, FullName: "acme/api"}
		other.Collaborators = rulePop[Collaborator]()
		e.RepositoriesAccess = append(e.RepositoriesAccess, other)
		return e, c
	}
	e, c := setup()
	out := JudgeAccess(e, c)
	repo, ok := fired(out, shop)
	if !ok {
		t.Fatal("the repository judgment did not fire")
	}
	if w, ok := attr(repo, "write", ""); !ok || w.Ref.Observation != "read" || w.Ref.Excerpt != "role_name: write; admin: false; maintain: false; push: true; pull: true" {
		t.Fatalf("write fact: %+v", repo.Attributes)
	}
	if repo.Has("repository_admin") || repo.Has("admin") || repo.Has("production") {
		t.Fatalf("a push collaborator has no admin and no collector-decided production: %+v", repo.Attributes)
	}
	org, ok := fired(out, c.OrganizationAsset)
	if !ok {
		t.Fatal("the organization judgment did not fire")
	}
	if _, ok := attr(org, "write_held", shop); !ok {
		t.Fatalf("held push on shop missing: %+v", org.Attributes)
	}
	u, ok := attr(org, "write_unsettled", api)
	if !ok || u.Ref.Excerpt != "alice is not listed among the collaborators of acme/api, and that list may not show everyone with access" {
		t.Fatalf("unlisted cause: %+v", org.Attributes)
	}
	if len(repo.Attributes) != 1 {
		t.Fatalf("the facts ride on one judgment per login: %+v", repo.Attributes)
	}

	// An unread list, contradictory permissions and an archived repository
	// each leave push unsettled, with their own cause.
	e, c = setup()
	e.RepositoriesAccess[1].Collaborators.Reads = []Read{{RequestID: "denied", Decision: "sent", Status: 403, Reason: "insufficient_permission"}}
	e.RepositoriesAccess[0].Collaborators.Items[0].RoleName = new("read")
	org, _ = fired(JudgeAccess(e, c), c.OrganizationAsset)
	if u, ok := attr(org, "write_unsettled", api); !ok || u.Ref.Excerpt != "the collaborators of acme/api could not be read: the credential was not allowed to list them" || u.Ref.Observation != "denied" {
		t.Fatalf("unread cause: %+v", org.Attributes)
	}
	if u, ok := attr(org, "write_unsettled", shop); !ok || u.Ref.Excerpt != "the permissions returned for alice on acme/shop were missing or contradictory" {
		t.Fatalf("contradiction cause: %+v", org.Attributes)
	}
	e, c = setup()
	e.RepositoriesAccess[0].Repository.Archived = new(true)
	out = JudgeAccess(e, c)
	org, _ = fired(out, c.OrganizationAsset)
	repo, _ = fired(out, shop)
	if u, ok := attr(org, "write_unsettled", shop); !ok || u.Ref.Excerpt != "acme/shop is archived" || repo.Has("write") {
		t.Fatalf("archived: %+v / %+v", org.Attributes, repo.Attributes)
	}

	// Read-only on a listed repository settles it: nothing is said.
	e, c = setup()
	e.RepositoriesAccess[0].Collaborators.Items[0].RoleName = new("read")
	e.RepositoriesAccess[0].Collaborators.Items[0].Permissions = &Permissions{Admin: new(false), Maintain: new(false), Push: new(false), Pull: new(true), Triage: new(false)}
	org, _ = fired(JudgeAccess(e, c), c.OrganizationAsset)
	for _, a := range org.Attributes {
		if a.Asset == shop {
			t.Fatalf("read-only settled shop: %+v", org.Attributes)
		}
	}

	// An owner is admin everywhere: attribute:admin says it, R4 has
	// nothing to establish.
	e, c = setup()
	e.Owners.Items = e.Members.Items
	org, _ = fired(JudgeAccess(e, c), c.OrganizationAsset)
	if !org.Has("admin") || org.Has("write_unsettled") || org.Has("write_held") {
		t.Fatalf("owner: %+v", org.Attributes)
	}

	// Not a member: the lowest repository's fired judgment carries them.
	e, c = setup()
	e.Members.Items = nil
	e.RepositoriesAccess[1].Collaborators = rulePop(e.RepositoriesAccess[0].Collaborators.Items[0])
	out = JudgeAccess(e, c)
	if _, ok := fired(out, c.OrganizationAsset); ok {
		t.Fatal("not a member")
	}
	a, _ := fired(out, api)
	s, _ := fired(out, shop)
	if _, ok := attr(a, "write_held", shop); !ok || s.Has("write_held") {
		t.Fatalf("carrier: api %+v, shop %+v", a.Attributes, s.Attributes)
	}

	// Nothing fired, nothing carried.
	e, c = setup()
	c.People[0].Left = "2026-10-11"
	for _, j := range JudgeAccess(e, c) {
		if j.Has("write") || j.Has("write_held") || j.Has("write_unsettled") {
			t.Fatalf("an unfired judgment carries R4 facts: %+v", j)
		}
	}
}
