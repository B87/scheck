package github

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
)

const (
	Fired     = "fired"
	Disproved = "disproved"
	Abstained = "abstained"
)

// Context carries explicit operator declarations; attribution never guesses from names.
// docs/spec/github-collector.md, "Context and subjects".
type Context struct {
	OrganizationAsset, Today string
	People                   []Person
	ExpectedOwners           []string
	OwnersDeclared           bool
	MFA, MFASource           string
	RepositoryContexts       map[string]RepositoryContext
}
type Person struct {
	Handle, Kind, Left string
	GitHub, UsedBy     []string
}
type RepositoryContext struct {
	Public            *bool
	DeploysTo, Source string
}

// Subject and Judgment share the collector-to-report decision contract.
type Subject = finding.Subject
type Judgment = finding.Judgment

// CoverageReason translates a collector evidence gap into report coverage.
// The original reason remains in persisted Recon evidence.
func CoverageReason(reason string) string {
	if reason == "insufficient_evidence" {
		return "unavailable:github_evidence"
	}
	return reason
}

func accountSubject(a Account, c Context) *Subject {
	s := &Subject{Kind: "account", Key: strings.ToLower(a.Login), Label: a.Login, ProviderID: strconv.FormatInt(a.ID, 10)}
	if p := personFor(a.Login, c); p != nil {
		s.Person = p.Handle
	}
	return s
}
func personFor(login string, c Context) *Person {
	for i := range c.People {
		for _, l := range c.People[i].GitHub {
			if strings.EqualFold(l, login) {
				return &c.People[i]
			}
		}
	}
	return nil
}
func hasLogin[T any](items []T, login string, get func(T) string) bool {
	return slices.ContainsFunc(items, func(a T) bool { return strings.EqualFold(get(a), login) })
}
func containsAccount(items []Account, login string) bool {
	return hasLogin(items, login, func(a Account) string { return a.Login })
}
func containsIdentity(items []Account, a Account) bool {
	return slices.ContainsFunc(items, func(b Account) bool { return b.ID == a.ID && strings.EqualFold(b.Login, a.Login) })
}
func complete[T any](p Population[T]) bool {
	if !p.Complete || !p.VisibilityComplete || len(p.Reads) == 0 {
		return false
	}
	return !slices.ContainsFunc(p.Reads, func(r Read) bool { return !usableRead(r) })
}
func readIDs(rs ...[]Read) []string {
	var ids []string
	for _, set := range rs {
		for _, r := range set {
			if r.RequestID != "" && !slices.Contains(ids, r.RequestID) {
				ids = append(ids, r.RequestID)
			}
		}
	}
	return ids
}
func usableRead(r Read) bool {
	return (r.Decision == "sent" || r.Decision == "reused") && r.Status == 200 && r.Reason == "" && r.Gap == "" && !r.Truncated && len(r.Redactions) == 0
}
func judgment(id, asset string, s *Subject, reads []string) Judgment {
	j := Judgment{ID: id, Asset: asset, Verdict: Abstained, Reason: "insufficient_evidence", Reads: reads}
	if s != nil {
		j.Subject = *s
	}
	return j
}
func settle(j *Judgment, fires bool, known bool, excerpt string) {
	j.Excerpt = excerpt
	if !known {
		return
	}
	j.Reason = ""
	j.Verdict = Disproved
	if fires {
		j.Verdict = Fired
	}
}
func passed(left, today string) bool {
	l, e := time.Parse("2006-01-02", left)
	t, f := time.Parse("2006-01-02", today)
	return e == nil && f == nil && l.Before(t)
}
func production(c Context, asset string) bool {
	return c.RepositoryContexts[asset].DeploysTo == "production"
}
func describeAccount(a Account) string { return fmt.Sprintf("%s (GitHub account %d)", a.Login, a.ID) }

// Judge reads only collected facts. Unknown and incomplete populations never
// disprove a rule (docs/spec/github-collector.md, "Boundary", "Rules: evidence outcomes").
func Judge(e Evidence, c Context) []Judgment {
	var out []Judgment
	// An owner-authorized disabled filter is affirmative membership/role evidence
	// even when the unfiltered population stopped before reaching that account.
	if e.OwnerAuthority {
		e.Owners = withDisabledAccounts(e.Owners, e.OwnersWithoutMFA)
		e.Members = withDisabledAccounts(e.Members, e.MembersWithoutMFA)
	}
	org := c.OrganizationAsset
	j := judgment(finding.IDGitHubMFANotRequired, org, nil, readIDs([]Read{e.OrganizationRead, e.MembershipRead}))
	if e.Organization != nil && e.Organization.TwoFactorRequirementEnabled != nil {
		b := *e.Organization.TwoFactorRequirementEnabled
		settle(&j, !b, e.OwnerAuthority && usableRead(e.OrganizationRead), fmt.Sprintf("two_factor_requirement_enabled: %t", b))
		if !b && (c.MFA == "everyone" || c.MFA == "some") {
			j.Attributes = []string{"contradiction"}
			j.Sources = []string{c.MFASource}
		}
	}
	out = append(out, j)
	j = judgment(finding.IDGitHubBroadDefaultMemberPermission, org, nil, readIDs([]Read{e.OrganizationRead, e.MembershipRead}))
	if e.Organization != nil && e.Organization.DefaultRepositoryPermission != nil {
		p := *e.Organization.DefaultRepositoryPermission
		settle(&j, p == "write" || p == "admin", e.OwnerAuthority && usableRead(e.OrganizationRead) && slices.Contains([]string{"none", "read", "write", "admin"}, p), "default_repository_permission: "+p)
	}
	out = append(out, j)
	for _, a := range e.Owners.Items {
		out = append(out, ownerJudgments(e, c, a)...)
	}
	for _, a := range e.Members.Items {
		if containsIdentity(e.Owners.Items, a) {
			continue
		}
		j = judgment(finding.IDGitHubMemberWithoutMFA, org, accountSubject(a, c), readIDs(e.Members.Reads, e.Owners.Reads, e.MembersWithoutMFA.Reads))
		if a.Type != "User" {
			j.Excerpt = "User MFA filters do not establish MFA enrollment for this non-user identity"
			j.NotChecked = []string{"MFA enrollment of Bot or App identities is outside the user-filter evidence domain"}
			out = append(out, j)
			continue
		}
		positive := containsIdentity(e.MembersWithoutMFA.Items, a)
		settle(&j, positive, e.OwnerAuthority && complete(e.Owners) && (positive || complete(e.Members) && complete(e.Owners) && complete(e.MembersWithoutMFA)), describeAccount(a)+" in member inventory; absence/presence in owner-authorized 2FA-disabled filter")
		if positive && c.MFA == "everyone" {
			j.Attributes = []string{"contradiction"}
			j.Sources = []string{c.MFASource}
		}
		out = append(out, j)
	}
	out = append(out, ownerCount(e, c))
	if !e.RepositoryVisibilityComplete {
		gap := judgment(finding.IDGitHubUndeclaredPublicRepository, org, nil, readIDs(e.Repositories.Reads))
		gap.Reason = "repository_visibility_unknown"
		gap.NotChecked = []string{"Repositories not visible to the assessment credential"}
		out = append(out, gap)
	}
	out = append(out, formerJudgments(e, c)...)
	for _, r := range e.RepositoriesAccess {
		out = append(out, repositoryJudgments(e, c, r)...)
	}
	// Empty or unavailable populations still contribute an explicit abstention;
	// they cannot silently disappear from coverage.
	for _, id := range finding.GitHubIDs() {
		if !slices.ContainsFunc(out, func(x Judgment) bool { return x.ID == id }) {
			gap := judgment(id, org, nil, readIDs(e.Reads()))
			switch id {
			case finding.IDGitHubOwnerWithoutMFA:
				settle(&gap, false, e.OwnerAuthority && complete(e.Owners) && complete(e.OwnersWithoutMFA), "No organization owners observed in complete trusted populations")
			case finding.IDGitHubMemberWithoutMFA:
				settle(&gap, false, e.OwnerAuthority && complete(e.Members) && complete(e.Owners) && complete(e.MembersWithoutMFA), "No non-owner members observed in complete trusted populations")
			case finding.IDIdentityUnexpectedAdmin:
				settle(&gap, false, c.OwnersDeclared && complete(e.Owners), "No organization owners observed in a complete trusted population")
			case finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin:
				settle(&gap, false, complete(e.Owners), "No organization owners observed in a complete trusted population")
			case finding.IDIdentityUnattributedAdmin:
				relevant := slices.ContainsFunc(c.People, func(p Person) bool { return len(p.GitHub) > 0 })
				all := complete(e.Owners)
				for _, r := range e.RepositoriesAccess {
					if production(c, r.Asset) {
						all = all && complete(r.Collaborators)
					}
				}
				settle(&gap, false, relevant && all, "No administrators observed in the complete assessed populations")
			}
			out = append(out, gap)
		}
	}
	return out
}
func ownerJudgments(e Evidence, c Context, a Account) []Judgment {
	p := personFor(a.Login, c)
	reads := readIDs(e.Owners.Reads)
	m := judgment(finding.IDGitHubOwnerWithoutMFA, c.OrganizationAsset, accountSubject(a, c), readIDs(e.Owners.Reads, e.OwnersWithoutMFA.Reads))
	positive := containsIdentity(e.OwnersWithoutMFA.Items, a)
	settle(&m, positive, e.OwnerAuthority && (positive || complete(e.Owners) && complete(e.OwnersWithoutMFA)), describeAccount(a)+" in owner inventory; absence/presence in owner-authorized 2FA-disabled filter")
	if positive && (c.MFA == "everyone" || c.MFA == "admins") {
		m.Attributes = []string{"contradiction"}
		m.Sources = []string{c.MFASource}
	}
	out := []Judgment{m}
	u := judgment(finding.IDIdentityUnexpectedAdmin, c.OrganizationAsset, accountSubject(a, c), reads)
	if p != nil && passed(p.Left, c.Today) {
		u.Reason = "departed_owner_reported_by_offboarding"
	} else if p != nil && c.OwnersDeclared {
		expected := slices.Contains(c.ExpectedOwners, p.Handle)
		settle(&u, !expected, !expected || complete(e.Owners), describeAccount(a)+" is an organization owner")
		u.Sources = []string{"access.admins", "people." + p.Handle}
	}
	out = append(out, u)
	out = append(out, unattributed(c, c.OrganizationAsset, a, reads, complete(e.Owners)))
	for _, kind := range []struct{ id, k string }{{finding.IDIdentityExternalAdmin, "contractor"}, {finding.IDIdentitySharedAdmin, "shared"}} {
		x := judgment(kind.id, c.OrganizationAsset, accountSubject(a, c), reads)
		if p != nil {
			fires := p.Kind == kind.k
			settle(&x, fires, fires || complete(e.Owners), describeAccount(a)+" is an owner attributed as "+p.Kind)
			x.Sources = []string{"people." + p.Handle}
		}
		out = append(out, x)
	}
	return out
}
func unattributed(c Context, asset string, a Account, reads []string, popComplete bool) Judgment {
	j := judgment(finding.IDIdentityUnattributedAdmin, asset, accountSubject(a, c), reads)
	hasPeople := slices.ContainsFunc(c.People, func(p Person) bool { return len(p.GitHub) > 0 })
	p := personFor(a.Login, c)
	settle(&j, p == nil, hasPeople && (p == nil || popComplete), describeAccount(a)+" has administrative access")
	if p != nil {
		j.Sources = []string{"people." + p.Handle}
	}
	return j
}
func ownerCount(e Evidence, c Context) Judgment {
	j := judgment(finding.IDGitHubTooManyOwners, c.OrganizationAsset, nil, readIDs(e.Owners.Reads, e.Members.Reads))
	n, bg := 0, 0
	var affected []string
	for _, a := range e.Owners.Items {
		p := personFor(a.Login, c)
		if p != nil && p.Kind == "service" {
			continue
		}
		if p != nil && p.Kind == "break_glass" && bg < 2 {
			bg++
			continue
		}
		n++
		affected = append(affected, a.Login)
	}
	humans := 0
	for _, a := range e.Members.Items {
		p := personFor(a.Login, c)
		if p == nil || p.Kind != "service" {
			humans++
		}
	}
	full := complete(e.Owners) && complete(e.Members)
	fires := n > 3 || full && n >= 3 && n*3 > humans
	settle(&j, fires, n > 3 || full, fmt.Sprintf("%d counted owners; %d observed non-service members", n, humans))
	j.Listed = affected
	j.Details = map[string]any{"owners": n, "members": humans, "complete": full}
	if !full {
		j.Context = "Counts are lower bounds. No owner-to-member ratio was evaluated."
	}
	return j
}
func formerJudgments(e Evidence, c Context) []Judgment {
	var out []Judgment
	for _, p := range c.People {
		if p.Left == "" {
			continue
		}
		if len(p.GitHub) == 0 {
			j := judgment(finding.IDIdentityFormerPersonHasAccess, c.OrganizationAsset, nil, nil)
			j.Reason = "no_declared_github_login"
			out = append(out, j)
			continue
		}
		for _, login := range p.GitHub {
			a := Account{Login: strings.ToLower(login)}
			present := false
			for _, pop := range [][]Account{e.Members.Items, e.Owners.Items, e.OutsideCollaborators.Items} {
				for _, v := range pop {
					if strings.EqualFold(v.Login, login) {
						a = v
						present = true
					}
				}
			}
			source := []string{"people." + p.Handle + ".left"}
			full := complete(e.Members) && complete(e.Owners) && complete(e.OutsideCollaborators) && complete(e.Invitations) && identifiableInvitations(e.Invitations)
			for _, repo := range e.RepositoriesAccess {
				full = full && complete(repo.Collaborators)
			}
			makeAccess := func(asset string, account Account, reads []string, present, admin bool) Judgment {
				j := judgment(finding.IDIdentityFormerPersonHasAccess, asset, accountSubject(account, c), reads)
				j.Sources = source
				j.NotChecked = []string{"Accounts renamed after declaration; undeclared logins; credential or session usability"}
				if passed(p.Left, c.Today) {
					settle(&j, present, present || full, describeAccount(account)+"; declared leaving date "+p.Left)
					if present && admin {
						j.Attributes = []string{"admin"}
					}
				} else {
					j.Reason = "leaving_date_not_passed"
				}
				return j
			}
			if present {
				out = append(out, makeAccess(c.OrganizationAsset, a, readIDs(e.Members.Reads, e.Owners.Reads, e.OutsideCollaborators.Reads), true, containsAccount(e.Owners.Items, login)))
			}
			for _, repo := range e.RepositoriesAccess {
				for _, collaborator := range repo.Collaborators.Items {
					if strings.EqualFold(collaborator.Login, login) {
						admin, known := EffectiveAdmin(collaborator)
						out = append(out, makeAccess(repo.Asset, collaborator.Account, readIDs(repo.Collaborators.Reads), true, production(c, repo.Asset) && known && admin))
						present = true
					}
				}
			}
			if !present {
				reads := readIDs(e.Members.Reads, e.Owners.Reads, e.OutsideCollaborators.Reads, e.Invitations.Reads)
				for _, repo := range e.RepositoriesAccess {
					reads = append(reads, readIDs(repo.Collaborators.Reads)...)
				}
				out = append(out, makeAccess(c.OrganizationAsset, a, reads, false, false))
			}
			invitations := []Invitation{}
			for _, i := range e.Invitations.Items {
				if i.Login != nil && strings.EqualFold(*i.Login, login) {
					invitations = append(invitations, i)
				}
			}
			if len(invitations) == 0 {
				x := judgment(finding.IDIdentityFormerPersonInvited, c.OrganizationAsset, nil, readIDs(e.Invitations.Reads))
				x.Sources = source
				if passed(p.Left, c.Today) {
					settle(&x, false, complete(e.Invitations) && identifiableInvitations(e.Invitations), "No matching pending invitation for "+login)
				} else {
					x.Reason = "leaving_date_not_passed"
				}
				out = append(out, x)
			}
			for _, i := range invitations {
				key := "invitation:" + strconv.FormatInt(i.ID, 10)
				x := judgment(finding.IDIdentityFormerPersonInvited, c.OrganizationAsset, &Subject{Kind: "invitation", Key: key, Label: login + " (" + key + ")", ProviderID: strconv.FormatInt(i.ID, 10), Person: p.Handle}, readIDs(e.Invitations.Reads))
				x.Sources = source
				if passed(p.Left, c.Today) {
					settle(&x, true, true, "Pending invitation for "+login+"; declared leaving date "+p.Left)
				} else {
					x.Reason = "leaving_date_not_passed"
				}
				out = append(out, x)
			}
		}
	}
	return out
}
func repositoryJudgments(e Evidence, c Context, r RepositoryAccess) []Judgment {
	var out []Judgment
	var sub *Subject
	if r.Repository != nil {
		sub = &Subject{Kind: "repository", Key: strings.ToLower(r.Repository.FullName), Label: r.Repository.FullName, ProviderID: strconv.FormatInt(r.Repository.ID, 10)}
	}
	j := judgment(finding.IDGitHubUndeclaredPublicRepository, r.Asset, sub, readIDs([]Read{r.RepositoryRead}))
	if r.Repository != nil && r.Repository.Visibility != nil {
		v := *r.Repository.Visibility
		declared := c.RepositoryContexts[r.Asset].Public != nil && *c.RepositoryContexts[r.Asset].Public
		known := usableRead(r.RepositoryRead) && slices.Contains([]string{"public", "private", "internal"}, v)
		settle(&j, v == "public" && !declared, known, "visibility: "+v)
		if declared {
			j.Sources = []string{c.RepositoryContexts[r.Asset].Source}
		}
	}
	out = append(out, j)
	if len(r.DeployKeys.Items) == 0 {
		x := judgment(finding.IDGitHubWritableDeployKey, r.Asset, nil, readIDs(r.DeployKeys.Reads))
		settle(&x, false, complete(r.DeployKeys), "No deploy keys in the complete returned population")
		out = append(out, x)
	}
	for _, k := range r.DeployKeys.Items {
		id := strconv.FormatInt(k.ID, 10)
		j = judgment(finding.IDGitHubWritableDeployKey, r.Asset, &Subject{Kind: "deploy_key", Key: "deploy-key:" + id, Label: "Deploy key " + id, ProviderID: id}, readIDs(r.DeployKeys.Reads))
		if k.ReadOnly != nil {
			settle(&j, !*k.ReadOnly, !*k.ReadOnly || complete(r.DeployKeys), fmt.Sprintf("read_only: %t", *k.ReadOnly))
			if !*k.ReadOnly && production(c, r.Asset) {
				j.Attributes = []string{"production"}
				j.Sources = []string{c.RepositoryContexts[r.Asset].Source}
			}
		}
		out = append(out, j)
	}
	for _, a := range r.Collaborators.Items {
		admin, known := EffectiveAdmin(a)
		if production(c, r.Asset) && admin && known {
			out = append(out, unattributed(c, r.Asset, a.Account, readIDs(r.Collaborators.Reads), complete(r.Collaborators)))
		}
		j = judgment(finding.IDGitHubOutsideAdminOnProduction, r.Asset, accountSubject(a.Account, c), readIDs(r.Collaborators.Reads, e.OutsideCollaborators.Reads))
		outside := slices.ContainsFunc(e.OutsideCollaborators.Items, func(o Account) bool { return o.ID == a.ID })
		ctx, hasContext := c.RepositoryContexts[r.Asset]
		prod := ctx.DeploysTo == "production"
		nonprod := hasContext && ctx.DeploysTo != "" && !prod
		fire := outside && known && admin && prod
		negative := outside && complete(r.Collaborators) && complete(e.OutsideCollaborators) && (nonprod || known && !admin)
		settle(&j, fire, fire || negative, describeAccount(a.Account)+"; effective repository administrator and outside membership evaluated")
		j.Sources = []string{ctx.Source}
		out = append(out, j)
	}
	return out
}

// EffectiveAdmin recognizes repository privilege from consistent provider fields.
// The second result is false when missing or contradictory evidence prevents a
// decision (docs/spec/github-collector.md, "Rule evidence").
func EffectiveAdmin(a Collaborator) (bool, bool) {
	if a.RoleName != nil && (strings.Contains(*a.RoleName, "[REDACTED:") || strings.Contains(*a.RoleName, "[TRUNCATED:")) {
		return false, false
	}
	if a.Permissions == nil || a.Permissions.Admin == nil {
		return false, false
	}
	admin := *a.Permissions.Admin
	if admin {
		for _, v := range []*bool{a.Permissions.Pull, a.Permissions.Push, a.Permissions.Maintain, a.Permissions.Triage} {
			if v != nil && !*v {
				return false, false
			}
		}
		if a.RoleName != nil && slices.Contains([]string{"read", "pull", "triage", "write", "push", "maintain"}, *a.RoleName) {
			return false, false
		}
		return true, true
	}
	if a.RoleName == nil || !slices.Contains([]string{"read", "pull", "triage", "write", "push", "maintain"}, *a.RoleName) {
		return false, false
	}
	p := a.Permissions
	if p.Pull == nil || p.Push == nil || p.Maintain == nil || p.Triage == nil {
		return false, false
	}
	if !*p.Pull {
		return false, false
	}
	switch *a.RoleName {
	case "read", "pull":
		return false, !*p.Push && !*p.Maintain && !*p.Triage
	case "triage":
		return false, *p.Triage && !*p.Push && !*p.Maintain
	case "write", "push":
		return false, *p.Push && !*p.Maintain
	case "maintain":
		return false, *p.Push && *p.Maintain
	}
	return false, false
}

func withDisabledAccounts(base, disabled Population[Account]) Population[Account] {
	base.Items = slices.Clone(base.Items)
	for _, a := range disabled.Items {
		if !slices.ContainsFunc(base.Items, func(b Account) bool { return b.ID == a.ID }) {
			base.Items = append(base.Items, a)
			base.Complete = false
			base.Reads = append(slices.Clone(base.Reads), disabled.Reads...)
		}
	}
	return base
}

func identifiableInvitations(p Population[Invitation]) bool {
	return !slices.ContainsFunc(p.Items, func(i Invitation) bool { return i.Login == nil || *i.Login == "" })
}
