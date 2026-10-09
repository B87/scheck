package github

import (
	"slices"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func rulePop[T any](items ...T) Population[T] {
	return Population[T]{Items: items, Complete: true, VisibilityComplete: true, Reads: []Read{{RequestID: "read", Status: 200, Decision: "sent"}}}
}
func ruleFixture() (Evidence, Context) {
	a := Account{ID: 1, Login: "alice", Type: "User"}
	e := Evidence{OwnerAuthority: true, OrganizationRead: Read{Status: 200, Decision: "sent", RequestID: "org"}, Organization: &OrganizationObject{TwoFactorRequirementEnabled: new(true), DefaultRepositoryPermission: new("read")}, Members: rulePop(a), Owners: rulePop(a), OutsideCollaborators: rulePop[Account](), Invitations: rulePop[Invitation](), MembersWithoutMFA: rulePop[Account](), OwnersWithoutMFA: rulePop[Account]()}
	c := Context{OrganizationAsset: "saas:github:acme", Today: "2026-10-10", People: []Person{{Handle: "alice", Kind: "employee", GitHub: []string{"alice"}}}, OwnersDeclared: true, ExpectedOwners: []string{"alice"}, RepositoryContexts: map[string]RepositoryContext{"repo:github:acme/shop": {DeploysTo: "production", Source: "assets.repo.deploys_to"}}}
	e.RepositoriesAccess = []RepositoryAccess{{Asset: "repo:github:acme/shop", RepositoryRead: Read{Status: 200, Decision: "sent", RequestID: "repo"}, Repository: &Repository{ID: 10, FullName: "acme/shop", Visibility: new("private")}, Collaborators: rulePop(Collaborator{Account: a, RoleName: new("admin"), Permissions: &Permissions{Admin: new(true)}}), DeployKeys: rulePop(DeployKey{ID: 7, ReadOnly: new(true)})}}
	return e, c
}
func hasVerdict(out []Judgment, id, v string) bool {
	return slices.ContainsFunc(out, func(j Judgment) bool { return j.ID == id && j.Verdict == v })
}
func TestEveryGitHubRuleFiresDisprovesAndAbstains(t *testing.T) {
	type tweak func(*Evidence, *Context)
	cases := map[string]struct{ fire, negative, unknown tweak }{
		finding.IDGitHubMFANotRequired:  {func(e *Evidence, _ *Context) { e.Organization.TwoFactorRequirementEnabled = new(false) }, nil, func(e *Evidence, _ *Context) { e.OwnerAuthority = false }},
		finding.IDGitHubOwnerWithoutMFA: {func(e *Evidence, _ *Context) { e.OwnersWithoutMFA.Items = e.Owners.Items }, nil, func(e *Evidence, _ *Context) { e.OwnersWithoutMFA.Complete = false }},
		finding.IDGitHubMemberWithoutMFA: {func(e *Evidence, _ *Context) {
			a := Account{ID: 2, Login: "bob", Type: "User"}
			e.Members.Items = append(e.Members.Items, a)
			e.MembersWithoutMFA.Items = []Account{a}
		}, func(e *Evidence, _ *Context) {
			e.Members.Items = append(e.Members.Items, Account{ID: 2, Login: "bob", Type: "User"})
		}, func(e *Evidence, _ *Context) {
			e.Members.Items = append(e.Members.Items, Account{ID: 2, Login: "bob", Type: "User"})
			e.MembersWithoutMFA.Complete = false
		}},
		finding.IDIdentityUnexpectedAdmin:   {func(_ *Evidence, c *Context) { c.ExpectedOwners = nil }, nil, func(_ *Evidence, c *Context) { c.OwnersDeclared = false }},
		finding.IDIdentityUnattributedAdmin: {func(_ *Evidence, c *Context) { c.People[0].GitHub = []string{"bob"} }, nil, func(_ *Evidence, c *Context) { c.People = nil }},
		finding.IDIdentityExternalAdmin:     {func(_ *Evidence, c *Context) { c.People[0].Kind = "contractor" }, nil, func(_ *Evidence, c *Context) { c.People = nil }},
		finding.IDIdentitySharedAdmin:       {func(_ *Evidence, c *Context) { c.People[0].Kind = "shared" }, nil, func(_ *Evidence, c *Context) { c.People = nil }},
		finding.IDIdentityFormerPersonHasAccess: {func(_ *Evidence, c *Context) { c.People[0].Left = "2026-10-09" }, func(e *Evidence, c *Context) {
			c.People[0].Left = "2026-10-09"
			e.Members.Items = nil
			e.Owners.Items = nil
			e.RepositoriesAccess[0].Collaborators.Items = nil
		}, func(_ *Evidence, c *Context) { c.People[0].Left = "2026-10-10" }},
		finding.IDIdentityFormerPersonInvited: {func(e *Evidence, c *Context) {
			c.People[0].Left = "2026-10-09"
			e.Invitations.Items = []Invitation{{ID: 3, Login: new("alice")}}
		}, func(_ *Evidence, c *Context) { c.People[0].Left = "2026-10-09" }, func(_ *Evidence, c *Context) { c.People[0].Left = "2026-10-11" }},
		finding.IDGitHubTooManyOwners: {func(e *Evidence, _ *Context) {
			e.Owners.Items = append(e.Owners.Items, Account{ID: 2, Login: "bob"}, Account{ID: 3, Login: "carol"}, Account{ID: 4, Login: "dan"})
		}, nil, func(e *Evidence, _ *Context) { e.Owners.Complete = false }},
		finding.IDGitHubUndeclaredPublicRepository:   {func(e *Evidence, _ *Context) { e.RepositoriesAccess[0].Repository.Visibility = new("public") }, nil, func(e *Evidence, _ *Context) { e.RepositoriesAccess[0].Repository.Visibility = nil }},
		finding.IDGitHubBroadDefaultMemberPermission: {func(e *Evidence, _ *Context) { e.Organization.DefaultRepositoryPermission = new("write") }, nil, func(e *Evidence, _ *Context) { e.Organization.DefaultRepositoryPermission = nil }},
		finding.IDGitHubOutsideAdminOnProduction: {func(e *Evidence, _ *Context) { e.OutsideCollaborators.Items = e.Members.Items }, func(e *Evidence, c *Context) {
			e.OutsideCollaborators.Items = e.Members.Items
			c.RepositoryContexts["repo:github:acme/shop"] = RepositoryContext{DeploysTo: "staging"}
		}, func(e *Evidence, _ *Context) { e.OutsideCollaborators.Complete = false }},
		finding.IDGitHubWritableDeployKey: {func(e *Evidence, _ *Context) { e.RepositoriesAccess[0].DeployKeys.Items[0].ReadOnly = new(false) }, nil, func(e *Evidence, _ *Context) { e.RepositoriesAccess[0].DeployKeys.Complete = false }},
	}
	for _, id := range finding.GitHubIDs() {
		tc, ok := cases[id]
		if !ok {
			t.Fatalf("no fixtures for %s", id)
		}
		for _, v := range []string{Fired, Disproved, Abstained} {
			t.Run(id+"/"+v, func(t *testing.T) {
				e, c := ruleFixture()
				f := tc.fire
				if v == Disproved {
					f = tc.negative
				}
				if v == Abstained {
					f = tc.unknown
				}
				if f != nil {
					f(&e, &c)
				}
				out := Judge(e, c)
				if !hasVerdict(out, id, v) {
					t.Fatalf("missing %s %s: %+v", id, v, out)
				}
				for _, j := range out {
					if j.Verdict == Fired && finding.SubjectOf(j.ID) != "" && j.Subject == nil {
						t.Fatalf("fired without required subject: %+v", j)
					}
				}
			})
		}
	}
}

func TestGitHubPartialPopulationsNeverDisprove(t *testing.T) {
	for _, field := range []string{"owners", "members", "member_mfa", "owner_mfa", "outside", "invitations", "collaborators", "keys"} {
		t.Run(field, func(t *testing.T) {
			e, c := ruleFixture()
			c.People[0].Left = "2026-10-09"
			e.Members.Items = nil
			e.Owners.Items = nil
			e.RepositoriesAccess[0].Collaborators.Items = nil
			switch field {
			case "owners":
				e.Owners.Complete = false
			case "members":
				e.Members.Complete = false
			case "member_mfa":
				e.MembersWithoutMFA.Complete = false
			case "owner_mfa":
				e.OwnersWithoutMFA.Complete = false
			case "outside":
				e.OutsideCollaborators.Complete = false
			case "invitations":
				e.Invitations.Complete = false
			case "collaborators":
				e.RepositoriesAccess[0].Collaborators.Complete = false
			case "keys":
				e.RepositoriesAccess[0].DeployKeys.Complete = false
			}
			out := Judge(e, c)
			if field == "members" || field == "outside" || field == "invitations" || field == "collaborators" {
				if hasVerdict(out, finding.IDIdentityFormerPersonHasAccess, Disproved) {
					t.Fatal("offboarding disproved over a partial owning population")
				}
			}
			if field == "keys" && hasVerdict(out, finding.IDGitHubWritableDeployKey, Disproved) {
				t.Fatal("key risk disproved over partial keys")
			}
		})
	}
}
func TestGitHubOwnerThresholdCountsKindsAndPartialLowerBounds(t *testing.T) {
	e, c := ruleFixture()
	e.Owners.Items = []Account{{ID: 1, Login: "alice"}, {ID: 2, Login: "bob"}, {ID: 3, Login: "carol"}, {ID: 4, Login: "dan"}, {ID: 5, Login: "eve"}, {ID: 6, Login: "frank"}}
	e.Members.Items = e.Owners.Items
	c.People = append(c.People, Person{Handle: "bob", Kind: "service", GitHub: []string{"bob"}}, Person{Handle: "carol", Kind: "break_glass", GitHub: []string{"carol"}}, Person{Handle: "dan", Kind: "break_glass", GitHub: []string{"dan"}}, Person{Handle: "eve", Kind: "break_glass", GitHub: []string{"eve"}})
	if !hasVerdict(Judge(e, c), finding.IDGitHubTooManyOwners, Fired) {
		t.Fatal("third break-glass owner must count; complete ratio should fire")
	}
	e.Members.Complete = false
	if !hasVerdict(Judge(e, c), finding.IDGitHubTooManyOwners, Abstained) {
		t.Fatal("three counted owners cannot use incomplete ratio")
	}
	e.Owners.Items = append(e.Owners.Items, Account{ID: 7, Login: "grace"})
	if !hasVerdict(Judge(e, c), finding.IDGitHubTooManyOwners, Fired) {
		t.Fatal("four observed counted owners establish a lower-bound finding")
	}
}
func TestGitHubOffboardingDoesNotDuplicateUnexpectedAdmin(t *testing.T) {
	e, c := ruleFixture()
	c.People[0].Left = "2026-10-09"
	c.ExpectedOwners = nil
	out := Judge(e, c)
	if hasVerdict(out, finding.IDIdentityUnexpectedAdmin, Fired) {
		t.Fatal("unexpected owner duplicates departed owner")
	}
	if !hasVerdict(out, finding.IDIdentityFormerPersonHasAccess, Fired) {
		t.Fatal("departed owner access missing")
	}
	for _, j := range out {
		if j.ID == finding.IDIdentityFormerPersonHasAccess && j.Verdict == Fired && !slices.Contains(j.Attributes, "admin") {
			t.Fatal("departed owner administrative attribute missing")
		}
	}
}
func TestGitHubUnknownPermissionsCannotDisproveProductionAdmin(t *testing.T) {
	for _, a := range []Collaborator{
		{RoleName: new("custom"), Permissions: &Permissions{Admin: new(false)}},
		{RoleName: new("write"), Permissions: &Permissions{Admin: new(false)}},
		{RoleName: new("read"), Permissions: &Permissions{Admin: new(true)}},
	} {
		e, c := ruleFixture()
		a.Account = e.Members.Items[0]
		e.RepositoriesAccess[0].Collaborators.Items = []Collaborator{a}
		e.OutsideCollaborators.Items = e.Members.Items
		if !hasVerdict(Judge(e, c), finding.IDGitHubOutsideAdminOnProduction, Abstained) {
			t.Fatal("unknown/custom/contradictory role interpreted as no administrator")
		}
	}
}

func TestGitHubDisabledFilterPresenceSurvivesPartialMainInventory(t *testing.T) {
	e, c := ruleFixture()
	e.Owners.Items = nil
	e.Owners.Complete = false
	e.OwnersWithoutMFA.Items = []Account{{ID: 2, Login: "bob", Type: "User"}}
	if !hasVerdict(Judge(e, c), finding.IDGitHubOwnerWithoutMFA, Fired) {
		t.Fatal("affirmative owner-disabled filter account lost when main inventory partial")
	}
	e, c = ruleFixture()
	e.Members.Complete = false
	e.MembersWithoutMFA.Items = []Account{{ID: 2, Login: "bob", Type: "User"}}
	if !hasVerdict(Judge(e, c), finding.IDGitHubMemberWithoutMFA, Fired) {
		t.Fatal("affirmative non-owner disabled member lost when main inventory partial")
	}
}

func TestFormerPersonConflictingRepositoryAdminDoesNotRaiseSeverity(t *testing.T) {
	for _, v := range []Collaborator{
		{RoleName: new("read"), Permissions: &Permissions{Admin: new(true)}},
		{RoleName: new("admin"), Permissions: &Permissions{Admin: new(true), Push: new(false)}},
	} {
		e, c := ruleFixture()
		c.People[0].Left = "2026-10-09"
		e.Members.Items = nil
		e.Owners.Items = nil
		v.Account = Account{ID: 1, Login: "alice", Type: "User"}
		e.RepositoriesAccess[0].Collaborators.Items = []Collaborator{v}
		var found bool
		for _, j := range Judge(e, c) {
			if j.ID == finding.IDIdentityFormerPersonHasAccess && j.Verdict == Fired {
				found = true
				if slices.Contains(j.Attributes, "admin") {
					t.Fatalf("conflicting privilege raised former-person severity: %+v", j)
				}
			}
		}
		if !found {
			t.Fatal("observed collaborator still retains access despite unknown privilege")
		}
	}
}
func TestUnknownCollaboratorVisibilityPreventsAbsenceDisproofs(t *testing.T) {
	e, c := ruleFixture()
	c.People[0].Left = "2026-10-09"
	e.Members.Items = nil
	e.Owners.Items = nil
	e.RepositoriesAccess[0].Collaborators.Items = nil
	e.RepositoriesAccess[0].Collaborators.VisibilityComplete = false
	out := Judge(e, c)
	for _, id := range []string{finding.IDIdentityFormerPersonHasAccess, finding.IDIdentityUnattributedAdmin} {
		if hasVerdict(out, id, Disproved) {
			t.Fatalf("%s disproved with unknown collaborator visibility", id)
		}
	}
	e, c = ruleFixture()
	e.RepositoriesAccess[0].Collaborators.VisibilityComplete = false
	e.Owners.Items = nil
	e.Owners.Complete = false
	e.OutsideCollaborators.Items = e.Members.Items
	out = Judge(e, c)
	if !hasVerdict(out, finding.IDGitHubOutsideAdminOnProduction, Fired) {
		t.Fatal("unknown visibility must preserve affirmative production administrator")
	}
	if hasVerdict(out, finding.IDIdentityUnattributedAdmin, Disproved) {
		t.Fatal("attributed administrator disproof crossed unknown collaborator visibility")
	}
}

func TestPartialMFADeclarationDoesNotContradictIndividualGap(t *testing.T) {
	e, c := ruleFixture()
	c.MFA = "some"
	e.OwnersWithoutMFA.Items = e.Owners.Items
	e.Members.Items = append(e.Members.Items, Account{ID: 2, Login: "bob", Type: "User"})
	e.MembersWithoutMFA.Items = []Account{e.Members.Items[1]}
	for _, j := range Judge(e, c) {
		if (j.ID == finding.IDGitHubOwnerWithoutMFA || j.ID == finding.IDGitHubMemberWithoutMFA) && slices.Contains(j.Attributes, "contradiction") {
			t.Fatal("one disabled account does not contradict partial enforcement")
		}
	}
}
func TestNullLoginInvitationCannotDisproveFormerPersonInvite(t *testing.T) {
	e, c := ruleFixture()
	c.People[0].Left = "2026-10-09"
	e.Invitations.Items = []Invitation{{ID: 9}}
	if !hasVerdict(Judge(e, c), finding.IDIdentityFormerPersonInvited, Abstained) {
		t.Fatal("unidentified invitation cannot establish leaver absence")
	}
}
func TestFormerOwnerPresenceSurvivesUnavailableMembers(t *testing.T) {
	e, c := ruleFixture()
	c.People[0].Left = "2026-10-09"
	e.Members.Items = nil
	e.Members.Complete = false
	e.RepositoriesAccess = nil
	e.Owners.Reads = []Read{{Status: 200, Decision: "sent", RequestID: "owners-proof"}}
	var found bool
	for _, j := range Judge(e, c) {
		if j.ID == finding.IDIdentityFormerPersonHasAccess && j.Verdict == Fired {
			found = true
			if !slices.Contains(j.Attributes, "admin") || !slices.Contains(j.Reads, "owners-proof") {
				t.Fatalf("owner offboarding lost privilege or evidence: %+v", j)
			}
		}
	}
	if !found {
		t.Fatal("owner proves retained access despite absent member read")
	}
}

func TestBotMemberMFAAbstainsDespiteCompleteUserFilter(t *testing.T) {
	e, c := ruleFixture()
	e.Members.Items = append(e.Members.Items, Account{ID: 99, Login: "automation[bot]", Type: "Bot"})
	found := false
	for _, j := range Judge(e, c) {
		if j.ID == finding.IDGitHubMemberWithoutMFA && j.Subject != nil && j.Subject.Key == "automation[bot]" {
			found = true
			if j.Verdict != Abstained {
				t.Fatal("user filter settled bot MFA")
			}
		}
	}
	if !found {
		t.Fatal("bot lost from MFA coverage")
	}
}

func TestFormerAccessKeepsRepositoryPrivilegeOnItsAsset(t *testing.T) {
	e, c := ruleFixture()
	c.People[0].Left = "2026-10-09"
	e.Members.Items = nil
	e.Owners.Items = nil
	productionRepo := e.RepositoriesAccess[0]
	staging := productionRepo
	staging.Asset = "repo:github:acme/staging"
	staging.Collaborators = rulePop(Collaborator{Account: productionRepo.Collaborators.Items[0].Account, RoleName: new("read"), Permissions: &Permissions{Admin: new(false), Pull: new(true), Push: new(false), Maintain: new(false), Triage: new(false)}})
	c.RepositoryContexts[staging.Asset] = RepositoryContext{DeploysTo: "staging"}
	for _, repos := range [][]RepositoryAccess{{staging, productionRepo}, {productionRepo, staging}} {
		e.RepositoriesAccess = repos
		found := map[string]Judgment{}
		for _, j := range Judge(e, c) {
			if j.ID == finding.IDIdentityFormerPersonHasAccess && j.Verdict == Fired {
				found[j.Asset] = j
			}
		}
		if len(found) != 2 || slices.Contains(found[staging.Asset].Attributes, "admin") || !slices.Contains(found[productionRepo.Asset].Attributes, "admin") {
			t.Fatalf("misplaced privilege: %+v", found)
		}
	}
}

func TestMarkedCollaboratorRoleNeverEstablishesAdmin(t *testing.T) {
	for _, role := range []string{"[REDACTED:extra:4 bytes]", "[TRUNCATED:4 bytes]"} {
		e, c := ruleFixture()
		c.People[0].GitHub = []string{"bob"}
		e.RepositoriesAccess[0].Collaborators.Items[0].RoleName = new(role)
		for _, j := range Judge(e, c) {
			if j.Asset == e.RepositoriesAccess[0].Asset && j.ID == finding.IDIdentityUnattributedAdmin && j.Verdict == Fired {
				t.Fatalf("marked role produced admin: %+v", j)
			}
		}
		admin, known := EffectiveAdmin(e.RepositoriesAccess[0].Collaborators.Items[0])
		if admin || known {
			t.Fatalf("marked role recognized: %s", role)
		}
	}
}
