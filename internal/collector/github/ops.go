// Package github declares GitHub reads and preserves their recognized evidence.
// Only the scope gate sends requests (docs/spec/github-collector.md, "Boundary").
package github

import "github.com/b87/scheck/internal/engagement/gate"

const (
	OpPrincipal         = "github.principal"
	OpOrganization      = "github.organization"
	OpMembership        = "github.membership"
	OpMembers           = "github.members"
	OpOwners            = "github.owners"
	OpOutside           = "github.outside_collaborators"
	OpInvitations       = "github.invitations"
	OpRepositories      = "github.repositories"
	OpMembersWithoutMFA = "github.members_without_mfa"
	OpOwnersWithoutMFA  = "github.owners_without_mfa"
	OpRepository        = "github.repository"
	OpCollaborators     = "github.collaborators"
	OpDeployKeys        = "github.deploy_keys"
)

// Ops is the compiled, GET-only inventory surface. Pagination accepts only a
// gate-owned NextOf; role/filter values are literals, never caller parameters.
var Ops = append(append(append(inventoryOps(), ciOps()...), alertOps()...), historyOps()...)

func inventoryOps() []gate.Op {
	object := func(id, endpoint string, fields []string) gate.Op {
		return gate.Op{ID: id, Provider: "github", Method: gate.GET,
			URL: "https://api.github.com" + endpoint, Subject: "saas:github:{org}",
			Params: []gate.Param{{Name: "org", Type: gate.Login}},
			Level:  gate.Observe, Auth: gate.GitHubToken, APIVersion: "2026-03-10",
			Accept: []string{"application/json", "application/vnd.github+json"}, Keep: fields, MaxBytes: 1 << 20}
	}
	principal := object(OpPrincipal, "/user", []string{"id", "login", "type", "two_factor_authentication"})
	principal.Subject, principal.Params, principal.Class = "", nil, gate.Principal
	org := object(OpOrganization, "/orgs/{org}", []string{"id", "login", "type", "two_factor_requirement_enabled", "default_repository_permission"})
	membership := object(OpMembership, "/user/memberships/orgs/{org}", []string{"state", "role", "organization.id", "organization.login", "organization.type", "user.id", "user.login", "user.type"})
	list := func(id, endpoint, query string, fields []string, kind gate.Kind, key string) gate.Op {
		o := object(id, endpoint+"?per_page=100&page={page}"+query, fields)
		o.Params = append(o.Params, gate.Param{Name: "page", Type: gate.Count, Optional: true})
		o.List = &gate.List{Items: "$", Kind: kind, ExcludeKey: key, Next: &gate.Pages{Param: "page"}, MaxPages: 100}
		return o
	}
	accounts := []string{"id", "login", "type"}
	members := list(OpMembers, "/orgs/{org}/members", "&role=all&filter=all", accounts, gate.KindOther, "")
	owners := list(OpOwners, "/orgs/{org}/members", "&role=admin&filter=all", accounts, gate.KindOther, "")
	outside := list(OpOutside, "/orgs/{org}/outside_collaborators", "&filter=all", accounts, gate.KindOther, "")
	invitations := list(OpInvitations, "/orgs/{org}/invitations", "", []string{"id", "login", "role", "invitation_source"}, gate.KindOther, "")
	repos := list(OpRepositories, "/orgs/{org}/repos", "&type=all", []string{"id", "name", "full_name", "owner.id", "owner.login", "owner.type", "visibility", "private", "archived", "default_branch"}, gate.KindRepo, "full_name")
	repos.List.Subject = "repo:github:{key}"
	membersMFA := list(OpMembersWithoutMFA, "/orgs/{org}/members", "&role=all&filter=2fa_disabled", accounts, gate.KindOther, "")
	ownersMFA := list(OpOwnersWithoutMFA, "/orgs/{org}/members", "&role=admin&filter=2fa_disabled", accounts, gate.KindOther, "")
	repository := object(OpRepository, "/repos/{owner}/{repo}", repos.Keep)
	repository.Subject = "repo:github:{owner}/{repo}"
	repository.Params = []gate.Param{{Name: "owner", Type: gate.Login}, {Name: "repo", Type: gate.RepoName}}
	repoList := func(id, suffix string, fields []string) gate.Op {
		o := repository
		o.ID, o.URL, o.Keep = id, repository.URL+suffix+"?per_page=100&page={page}", fields
		o.Params = append([]gate.Param{}, repository.Params...)
		o.Params = append(o.Params, gate.Param{Name: "page", Type: gate.Count, Optional: true})
		o.List = &gate.List{Items: "$", Kind: gate.KindOther, Next: &gate.Pages{Param: "page"}, MaxPages: 100}
		return o
	}
	collaborators := repoList(OpCollaborators, "/collaborators", []string{"id", "login", "type", "role_name", "permissions.admin", "permissions.pull", "permissions.push", "permissions.maintain", "permissions.triage"})
	collaborators.URL += "&affiliation=all"
	keys := repoList(OpDeployKeys, "/keys", []string{"id", "read_only"})
	return []gate.Op{principal, org, membership, members, owners, outside, invitations, repos, membersMFA, ownersMFA, repository, collaborators, keys}
}
