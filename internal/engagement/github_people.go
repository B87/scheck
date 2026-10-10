package engagement

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	githubc "github.com/b87/scheck/internal/collector/github"
)

// Attribution is an explicit login match, not a guessed connection between
// accounts (docs/spec/engagement.md, "People").
type Attribution struct {
	Tenant     string `json:"tenant"`
	Key        string `json:"key"`
	ProviderID string `json:"provider_id"`
	Handle     string `json:"handle"`
	MatchedBy  string `json:"matched_by"`
}

// PeopleCandidate leaves Kind empty for the operator who knows this account.
type PeopleCandidate struct {
	Tenant       string   `json:"tenant"`
	Login        string   `json:"login"`
	GitHub       []string `json:"github"`
	Role         string   `json:"role"`
	ProviderID   string   `json:"provider_id,omitempty"`
	InvitationID string   `json:"invitation_id,omitempty"`
	Handle       string   `json:"handle"`
	Kind         string   `json:"kind"`
}

// An invitation with no login has no identifier to paste under people.
type PeopleInvitationComment struct {
	Tenant       string `json:"tenant"`
	Role         string `json:"role"`
	InvitationID string `json:"invitation_id"`
}

type githubPersonObservation struct {
	tenant, login, role string
	id                  int64
	invitationID        int64
	priority            int
}

func (r *run) populateGitHubPeople(doc *ReconDoc) {
	people := map[string]string{}
	used := map[string]bool{}
	for _, handle := range sortedKeys(r.res.People) {
		used[handle] = true
		for _, login := range r.res.People[handle].GitHub {
			people[strings.ToLower(login)] = handle
		}
	}
	doc.Attribution, doc.PeopleCandidates, doc.PeopleInvitationComments = nil, nil, nil
	doc.PeopleTenantOrder = nil
	doc.PeopleCandidatesPartial = false
	doc.PeopleSource = r.res.Source.Path
	byTenant := map[string][]githubPersonObservation{}
	observe := func(tenant string, a githubc.Account, role string, priority int) {
		if a.ID <= 0 || !isPeopleGitHubLogin(a.Login) {
			return
		}
		byTenant[tenant] = append(byTenant[tenant], githubPersonObservation{tenant: tenant, login: strings.ToLower(a.Login), role: role, id: a.ID, priority: priority})
	}
	accounts := func(tenant string, p githubc.Population[githubc.Account], role string, priority int) {
		if !p.Complete || !p.VisibilityComplete {
			doc.PeopleCandidatesPartial = true
		}
		for _, a := range p.Items {
			observe(tenant, a, role, priority)
		}
	}
	for _, a := range doc.Assets {
		if a.GitHub == nil {
			continue
		}
		tenant := strings.TrimPrefix(a.Root, "saas:")
		e := a.GitHub
		if a.Kind == KindSaaS {
			accounts(tenant, e.Owners, "owner", 0)
			accounts(tenant, e.Members, "member", 2)
			accounts(tenant, e.OutsideCollaborators, "outside collaborator", 3)
			if !e.Invitations.Complete || !e.Invitations.VisibilityComplete {
				doc.PeopleCandidatesPartial = true
			}
			for _, invitation := range e.Invitations.Items {
				if invitation.Login == nil {
					doc.PeopleInvitationComments = append(doc.PeopleInvitationComments, PeopleInvitationComment{tenant, invitation.Role, strconv.FormatInt(invitation.ID, 10)})
				} else if invitation.ID > 0 && isPeopleGitHubLogin(*invitation.Login) {
					byTenant[tenant] = append(byTenant[tenant], githubPersonObservation{tenant: tenant, login: strings.ToLower(*invitation.Login), role: "pending invitation, role " + invitation.Role, invitationID: invitation.ID, priority: 4})
				}
			}
		}
		for _, access := range e.RepositoriesAccess {
			if !access.Collaborators.Complete || !access.Collaborators.VisibilityComplete {
				doc.PeopleCandidatesPartial = true
			}
			production := false
			for _, target := range r.res.Assets {
				if target.ID == access.Asset {
					production = target.DeploysTo == "production"
					break
				}
			}
			for _, c := range access.Collaborators.Items {
				role, priority := "repository collaborator", 3
				admin, known := githubc.EffectiveAdmin(c)
				if production && known && admin {
					role, priority = "production repository admin", 1
				}
				observe(tenant, c.Account, role, priority)
			}
		}
	}
	seen := map[string]bool{}
	for _, root := range r.res.Roots {
		tenant := strings.TrimPrefix(root.ID, "saas:")
		observations := byTenant[tenant]
		tenant = githubPeopleTenant(tenant)
		if strings.HasPrefix(tenant, "github:") && !slices.Contains(doc.PeopleTenantOrder, tenant) {
			doc.PeopleTenantOrder = append(doc.PeopleTenantOrder, tenant)
		}
		slices.SortFunc(observations, func(a, b githubPersonObservation) int {
			if a.priority != b.priority {
				return a.priority - b.priority
			}
			return strings.Compare(a.login, b.login)
		})
		for _, a := range observations {
			key := tenant + "/" + a.login
			if seen[key] {
				continue
			}
			seen[key] = true
			id, invitationID := "", ""
			if a.id > 0 {
				id = strconv.FormatInt(a.id, 10)
			}
			if a.invitationID > 0 {
				invitationID = strconv.FormatInt(a.invitationID, 10)
			}
			if handle := people[a.login]; handle != "" {
				// A login on an invitation is attributable by declaration, but
				// its numeric ID identifies the invitation, not an account.
				if id != "" {
					doc.Attribution = append(doc.Attribution, Attribution{tenant, a.login, id, handle, "login"})
				}
				continue
			}
			handle := candidateHandle(a.login, used)
			doc.PeopleCandidates = append(doc.PeopleCandidates, PeopleCandidate{Tenant: tenant, Login: a.login, GitHub: []string{a.login}, Role: a.role, ProviderID: id, InvitationID: invitationID, Handle: handle})
		}
	}
}

func githubPeopleTenant(root string) string {
	if rest, ok := strings.CutPrefix(root, "repo:github:"); ok {
		owner, _, _ := strings.Cut(rest, "/")
		return "github:" + owner
	}
	return root
}

func candidateHandle(login string, used map[string]bool) string {
	base := strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || unicode.IsDigit(c) && c <= '9' || c == '-' {
			return c
		}
		return '-'
	}, strings.ToLower(login))
	base = strings.Trim(base, "-")
	if base == "" {
		base = "account"
	}
	if len(base) > 63 {
		base = base[:63]
	}
	handle := base
	for n := 2; used[handle]; n++ {
		suffix := fmt.Sprintf("-%d", n)
		prefix := base
		if len(prefix)+len(suffix) > 63 {
			prefix = prefix[:63-len(suffix)]
		}
		handle = prefix + suffix
	}
	used[handle] = true
	return handle
}
