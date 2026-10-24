package engagement

import (
	"encoding/json"
	"strings"
	"testing"

	githubc "github.com/b87/scheck/internal/collector/github"
)

func TestGitHubPeopleInvitationIDIsNotAccountID(t *testing.T) {
	declared, unnamed, member := "declared", "unnamed", "member"
	r := &run{res: &Resolved{Roots: []Ref{{ID: "saas:github:acme"}}, People: map[string]Person{"employee": {Kind: "employee", GitHub: []string{declared}}}}}
	doc := &ReconDoc{Assets: []ReconAsset{{Kind: KindSaaS, Root: "saas:github:acme", GitHub: &githubc.Evidence{
		Members:     githubc.Population[githubc.Account]{Items: []githubc.Account{{ID: 123, Login: member}}},
		Invitations: githubc.Population[githubc.Invitation]{Items: []githubc.Invitation{{ID: 901, Login: &declared}, {ID: 902, Login: &unnamed}, {ID: 903, Login: &member}}},
	}}}}
	r.populateGitHubPeople(doc)
	if len(doc.Attribution) != 0 || len(doc.PeopleCandidates) != 2 {
		t.Fatalf("invitation-only declared login attributed as account: %+v", doc)
	}
	for _, c := range doc.PeopleCandidates {
		switch c.Login {
		case unnamed:
			if c.ProviderID != "" || c.InvitationID != "902" {
				t.Fatalf("invitation identity = %+v", c)
			}
			data, err := json.Marshal(c)
			if err != nil || strings.Contains(string(data), "provider_id") || !strings.Contains(string(data), `"invitation_id":"902"`) {
				t.Fatalf("invitation JSON = %s, error %v", data, err)
			}
		case member:
			if c.ProviderID != "123" || c.InvitationID != "" {
				t.Fatalf("account observation lost to invitation = %+v", c)
			}
		default:
			t.Fatalf("unexpected candidate = %+v", c)
		}
	}
}

func TestGitHubPeopleReconAttributionAndOrder(t *testing.T) {
	complete := func(items ...githubc.Account) githubc.Population[githubc.Account] {
		return githubc.Population[githubc.Account]{Items: items, Complete: true, VisibilityComplete: true}
	}
	account := func(id int64, login string) githubc.Account {
		return githubc.Account{ID: id, Login: login, Type: "User"}
	}
	admin := true
	invited := "invitee"
	r := &run{res: &Resolved{
		Source: Source{Path: "engagement.yaml"},
		Roots:  []Ref{{ID: "saas:github:z-org"}, {ID: "saas:github:a-org"}},
		People: map[string]Person{"alice": {Kind: "employee", GitHub: []string{"ALICE"}}, "owner": {Kind: "employee"}},
		Assets: []ResolvedAsset{{ID: "repo:github:z-org/prod", DeploysTo: "production"}},
	}}
	doc := &ReconDoc{Assets: []ReconAsset{
		{Kind: KindSaaS, Root: "saas:github:a-org", GitHub: &githubc.Evidence{Owners: complete(account(4, "owner")), Members: complete(), OutsideCollaborators: complete(), Invitations: githubc.Population[githubc.Invitation]{Complete: true, VisibilityComplete: true}}},
		{Kind: KindSaaS, Root: "saas:github:z-org", GitHub: &githubc.Evidence{
			Owners: complete(account(1, "Owner"), account(2, "Alice")), Members: complete(account(1, "Owner"), account(3, "member"), account(9, "app[bot]")), OutsideCollaborators: complete(account(5, "outside")),
			Invitations:        githubc.Population[githubc.Invitation]{Items: []githubc.Invitation{{ID: 6, Login: &invited, Role: "direct_member"}, {ID: 7, Role: "admin"}}, Complete: true, VisibilityComplete: true},
			RepositoriesAccess: []githubc.RepositoryAccess{{Asset: "repo:github:z-org/prod", Collaborators: githubc.Population[githubc.Collaborator]{Items: []githubc.Collaborator{{Account: account(8, "prodadmin"), Permissions: &githubc.Permissions{Admin: &admin}}}, Complete: true, VisibilityComplete: true}}},
		}},
	}}
	r.populateGitHubPeople(doc)
	if len(doc.Attribution) != 1 || doc.Attribution[0].Handle != "alice" || doc.Attribution[0].MatchedBy != "login" || doc.Attribution[0].ProviderID != "2" {
		t.Fatalf("attribution = %+v", doc.Attribution)
	}
	want := []string{"owner", "prodadmin", "app[bot]", "member", "outside", "invitee", "owner"}
	if len(doc.PeopleCandidates) != len(want) {
		t.Fatalf("candidates = %+v", doc.PeopleCandidates)
	}
	for i, candidate := range doc.PeopleCandidates {
		if candidate.Login != want[i] || candidate.Kind != "" || !nameRe.MatchString(candidate.Handle) || len(candidate.GitHub) != 1 || candidate.GitHub[0] != candidate.Login {
			t.Errorf("candidate[%d] = %+v", i, candidate)
		}
	}
	if doc.PeopleCandidates[0].Handle != "owner-2" || doc.PeopleCandidates[6].Handle != "owner-3" || doc.PeopleCandidatesPartial || len(doc.PeopleInvitationComments) != 1 {
		t.Fatalf("candidate collision/coverage/comments = %+v", doc)
	}
	// Rebuilding does not duplicate candidates, and newly attributed accounts
	// disappear rather than retaining stale suggestions.
	r.res.People["newowner"] = Person{Kind: "employee", GitHub: []string{"owner"}}
	r.populateGitHubPeople(doc)
	if len(doc.PeopleCandidates) != 5 || len(doc.Attribution) != 3 {
		t.Fatalf("rebuild = %+v", doc)
	}
}

func TestGitHubPeoplePartialPopulationAndNoEmailGuess(t *testing.T) {
	r := &run{res: &Resolved{Roots: []Ref{{ID: "saas:github:acme"}}, People: map[string]Person{"alice": {Workspace: []string{"alice@example.com"}}}}}
	doc := &ReconDoc{Assets: []ReconAsset{{Kind: KindSaaS, Root: "saas:github:acme", GitHub: &githubc.Evidence{Members: githubc.Population[githubc.Account]{Items: []githubc.Account{{ID: 1, Login: "alice"}}, Complete: true}}}}}
	r.populateGitHubPeople(doc)
	if !doc.PeopleCandidatesPartial || len(doc.Attribution) != 0 || len(doc.PeopleCandidates) != 1 || doc.PeopleCandidates[0].Handle != "alice-2" {
		t.Fatalf("partial/no guess = %+v", doc)
	}
}

func TestGitHubPeopleConflictingAdminEvidence(t *testing.T) {
	r := &run{res: &Resolved{Roots: []Ref{{ID: "saas:github:acme"}}, Assets: []ResolvedAsset{{ID: "repo:github:acme/prod", DeploysTo: "production"}}}}
	doc := &ReconDoc{Assets: []ReconAsset{{Kind: KindSaaS, Root: "saas:github:acme", GitHub: &githubc.Evidence{RepositoriesAccess: []githubc.RepositoryAccess{{Asset: "repo:github:acme/prod", Collaborators: githubc.Population[githubc.Collaborator]{Items: []githubc.Collaborator{{ID: 1, Login: "alice", Type: "User", RoleName: new("read"), Permissions: &githubc.Permissions{Admin: new(true)}}}}}}}}}}
	r.populateGitHubPeople(doc)
	if len(doc.PeopleCandidates) != 1 || doc.PeopleCandidates[0].Role != "repository collaborator" {
		t.Fatalf("contradictory administrator claim: %+v", doc.PeopleCandidates)
	}
}

func TestPeopleGitHubBotIdentifiers(t *testing.T) {
	for _, login := range []string{"release-app[bot]", "[bot]", "release-app[bot]suffix", "release_app[bot]"} {
		file := minimal + "people:\n  release:\n    kind: service\n    github: [\"" + login + "\"]\n"
		_, err := Parse("e.yaml", []byte(file), testOpts)
		if login == "release-app[bot]" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "people.release.github[0]") {
			t.Errorf("login %q error = %v", login, err)
		}
	}
}
