package engagement

import (
	"fmt"
	"slices"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

// Readout notes consume declarations whose correctness cannot be decided by
// GitHub reads (docs/spec/engagement.md, "People", "Admins", "2-step verification").
func (r *run) githubPeopleNotes(asset string, e githubc.Evidence) []ereport.Note {
	notes := []ereport.Note{}
	add := func(kind, source, detail string) {
		notes = append(notes, ereport.Note{Kind: kind, Source: source, Detail: detail})
	}
	today := r.session.In(r.zone).Format("2006-01-02")
	passed := func(date string) bool { return date != "" && date < today }
	owner := func(login string) bool {
		return slices.ContainsFunc(e.Owners.Items, func(a githubc.Account) bool { return strings.EqualFold(a.Login, login) })
	}
	observed := func(login string) bool {
		return owner(login) || slices.ContainsFunc(e.Members.Items, func(a githubc.Account) bool { return strings.EqualFold(a.Login, login) }) || slices.ContainsFunc(e.OutsideCollaborators.Items, func(a githubc.Account) bool { return strings.EqualFold(a.Login, login) })
	}
	names := map[string]string{}
	for h, p := range r.res.People {
		for _, login := range p.GitHub {
			names[strings.ToLower(login)] = h
		}
	}
	unassigned := 0
	for _, a := range e.Members.Items {
		if names[strings.ToLower(a.Login)] == "" {
			unassigned++
		}
	}
	prefix := "observed "
	if !e.Members.Complete || !e.Members.VisibilityComplete {
		prefix = "at least "
	}
	add("unattributed_members", asset, fmt.Sprintf("%s%d members have no declared person match. GitHub does not provide sign-in history; unnamed former people and renamed old logins cannot be identified", prefix, unassigned))
	breakGlassOwners := 0
	for _, h := range sortedKeys(r.res.People) {
		p := r.res.People[h]
		seen := []string{}
		for _, login := range p.GitHub {
			if observed(login) {
				seen = append(seen, login)
			}
			if p.Kind == "break_glass" && owner(login) {
				breakGlassOwners++
			}
		}
		if len(seen) > 0 && (p.Kind == "service" || p.Kind == "break_glass") {
			kind := "service_account"
			if p.Kind == "break_glass" {
				kind = "break_glass_account"
			}
			add(kind, "people."+h, h+" is declared "+p.Kind+" and matched "+strings.Join(seen, ", "))
		}
		if p.Kind == "break_glass" && len(seen) > 0 && !slices.ContainsFunc(seen, owner) && e.Owners.Complete && e.Owners.VisibilityComplete {
			add("break_glass_account", "people."+h, "The declared break-glass account is not an observed owner; an account that cannot administer the organization cannot recover it")
		}
		if p.Kind == "shared" && len(seen) > 0 {
			for _, used := range p.UsedBy {
				if left, ok := r.res.People[used]; ok && passed(left.Left) {
					add("github_inventory", "people."+h+".used_by", "Rotate the shared account's password and second factor after "+used+" left. Rotation was not observed")
				}
			}
		}
	}
	if breakGlassOwners > 2 {
		add("break_glass_account", asset, "More than two observed break-glass owners were declared; additional break-glass accounts count toward the owner threshold")
	}
	for _, inv := range e.Invitations.Items {
		if inv.Role == "admin" {
			who := "invitation " + fmt.Sprint(inv.ID)
			if inv.Login != nil {
				who = *inv.Login
			}
			add("github_inventory", asset, "Pending owner invitation: "+who+". Invitations are future access and are not included in the owner count")
		}
	}
	for _, repo := range e.RepositoriesAccess {
		for _, j := range e.Judgments {
			if j.Asset == repo.Asset && j.ID == "identity.unattributed_admin" && j.Subject != nil {
				add("github_inventory", repo.Asset, "Observed production repository administrator: "+j.Subject.Label+". Effective privilege may be inherited; its grant source was not assessed")
			}
		}
	}
	for i, m := range r.res.Access.MFA {
		ref, ok := r.res.Lookup(m.Where)
		if !ok || ref.ID != asset {
			continue
		}
		source := fmt.Sprintf("access.mfa[%d]", i)
		if m.Enforced == "admins" {
			add("declared_not_verified", source, "GitHub cannot require MFA only for owners; owner enrollment was checked where owner-authorized evidence was available")
		}
		if e.OwnerAuthority && githubReadOK(e.OrganizationRead) && len(e.OrganizationRead.Redactions) == 0 && e.Organization != nil && e.Organization.TwoFactorRequirementEnabled != nil && *e.Organization.TwoFactorRequirementEnabled && (m.Enforced == "none" || m.Enforced == "some") {
			add("github_inventory", source, "The observed organization requires MFA for everyone, more than the declared enforcement")
		}
		if m.Enforced == "unknown" && e.OwnerAuthority && len(e.MembersWithoutMFA.Reads) > 0 {
			filter := e.MembersWithoutMFA
			read := slices.ContainsFunc(filter.Reads, func(read githubc.Read) bool { return githubReadOK(read) && len(read.Redactions) == 0 })
			if read {
				qualifier := "observed "
				if !filter.Complete || !filter.VisibilityComplete {
					qualifier = "at least "
				}
				add("github_inventory", source, fmt.Sprintf("MFA enforcement was declared unknown; %s%d accounts were returned by the owner-authorized disabled filter", qualifier, len(filter.Items)))
			} else {
				add("github_inventory", source, "MFA enforcement was declared unknown; disabled-account enrollment evidence was unavailable")
			}
		}
	}
	add("github_inventory", asset, "MFA checks do not assess factor strength, recovery, session compromise, SSH keys or tokens")
	return notes
}
