package github

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

// Permissions preserves every effective-permission field independently: an absent
// boolean is unknown, never false (docs/spec/github-collector.md, "Rule evidence").
type Permissions struct {
	Admin    *bool `json:"admin,omitempty"`
	Pull     *bool `json:"pull,omitempty"`
	Push     *bool `json:"push,omitempty"`
	Maintain *bool `json:"maintain,omitempty"`
	Triage   *bool `json:"triage,omitempty"`
}

type Collaborator struct {
	Account
	RoleName    *string      `json:"role_name,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"`
}

type DeployKey struct {
	ID       int64 `json:"id"`
	ReadOnly *bool `json:"read_only,omitempty"`
}

// RepositoryTarget is a scope-approved locator. No returned URL creates a target.
type RepositoryTarget struct{ Asset, Owner, Name string }
type RepositoryAccess struct {
	Asset          string                   `json:"asset"`
	RepositoryRead Read                     `json:"repository_read"`
	Repository     *Repository              `json:"repository,omitempty"`
	Collaborators  Population[Collaborator] `json:"collaborators"`
	DeployKeys     Population[DeployKey]    `json:"deploy_keys"`
}

func (a RepositoryAccess) Reads() []Read {
	out := []Read{}
	if a.RepositoryRead.Op != "" {
		out = append(out, a.RepositoryRead)
	}
	out = append(out, a.Collaborators.Reads...)
	return append(out, a.DeployKeys.Reads...)
}

// CollectAccess adds owner-only MFA lists and repository access facts. Recognized
// active owner authority is required before sending either MFA filter request.
func CollectAccess(ctx context.Context, g Sender, org Organization, e Evidence, targets []RepositoryTarget) Evidence {
	request := func(op string) gate.Request {
		return gate.Request{Op: op, Asset: org.Asset, Stage: org.Stage, Exists: true, Params: map[string]string{"org": org.Name}}
	}
	if e.OwnerAuthority {
		e.MembersWithoutMFA = population(ctx, g, request(OpMembersWithoutMFA), func(a Account) bool { return accountOK(a) && a.Type == "User" })
		e.OwnersWithoutMFA = population(ctx, g, request(OpOwnersWithoutMFA), func(a Account) bool { return accountOK(a) && a.Type == "User" })
		e.MembersWithoutMFA.VisibilityComplete, e.OwnersWithoutMFA.VisibilityComplete = true, true
	} else {
		unknown := func(op string) Population[Account] {
			return Population[Account]{Reads: []Read{{Op: op, Decision: "unavailable:owner_authority", Reason: "insufficient_permission", Gap: "owner_authority_unknown"}}, Gaps: []string{"owner_authority_unknown"}}
		}
		e.MembersWithoutMFA, e.OwnersWithoutMFA = unknown(OpMembersWithoutMFA), unknown(OpOwnersWithoutMFA)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		key := strings.ToLower(target.Owner + "/" + target.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		e.RepositoriesAccess = append(e.RepositoriesAccess, CollectRepository(ctx, g, target, org.Stage))
	}
	return e
}

// CollectRepository requires an exact locator match. A moved repository does not
// authorize reads at its new owner (docs/spec/github-collector.md, "Boundary").
func CollectRepository(ctx context.Context, g Sender, target RepositoryTarget, stage string) RepositoryAccess {
	a := RepositoryAccess{Asset: target.Asset}
	request := func(op string) gate.Request {
		return gate.Request{Op: op, Asset: target.Asset, Stage: stage, Exists: true, Params: map[string]string{"owner": target.Owner, "repo": target.Name}}
	}
	r := g.Send(ctx, request(OpRepository))
	a.RepositoryRead = readOf(OpRepository, r)
	if usable(r) {
		var repo Repository
		if json.Unmarshal(r.Response.Body, &repo) == nil && repositoryTargetOK(repo, target) {
			repo.Name, repo.FullName, repo.Owner.Login = strings.ToLower(repo.Name), strings.ToLower(repo.FullName), strings.ToLower(repo.Owner.Login)
			a.Repository = &repo
		} else {
			a.RepositoryRead.Gap = "unrecognized_repository"
		}
	}
	// Without a recognized object, do not use children to claim access to the
	// requested repository; this also avoids following transfer evidence.
	if a.Repository == nil {
		return a
	}
	a.Collaborators = population(ctx, g, request(OpCollaborators), func(c Collaborator) bool { return accountOK(c.Account) && c.Type != "Organization" })
	a.DeployKeys = population(ctx, g, request(OpDeployKeys), func(k DeployKey) bool { return k.ID > 0 })
	// Collaborator visibility is limited to the credential, even after pagination.
	// Deploy-key pagination settles the explicitly authorized key endpoint.
	a.Collaborators.VisibilityComplete = false
	a.Collaborators.Gaps = append(a.Collaborators.Gaps, "repository_collaborator_visibility_unknown")
	a.DeployKeys.VisibilityComplete = true
	return a
}

func repositoryTargetOK(r Repository, target RepositoryTarget) bool {
	return r.ID > 0 && repoRE.MatchString(r.Name) && r.Name != "." && r.Name != ".." && accountOK(r.Owner) && (r.Owner.Type == "Organization" || r.Owner.Type == "User") && strings.EqualFold(r.Owner.Login, target.Owner) && strings.EqualFold(r.Name, target.Name) && strings.EqualFold(r.FullName, target.Owner+"/"+target.Name)
}
