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
	OrganizationAsset string
	// Zone is engagement.timezone, in which a declared date passes at
	// 24:00; a date is judged at the collection time of the reads a rule
	// rests on, never the session's start (docs/spec/engagement.md,
	// "Severity in context").
	Zone               *time.Location
	People             []Person
	ExpectedOwners     []string
	OwnersDeclared     bool
	MFA, MFASource     string
	RepositoryContexts map[string]RepositoryContext
	// SecretStores and MattersMost are the `secrets.production` and
	// `data.matters_most` entries, by canonical asset id; only Select
	// reads them, to order repositories.
	SecretStores, MattersMost []Declared
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

// ReadTimes are the collection times of the reads that returned a
// response: a time-dependent rule is judged at them. A response with no
// recorded time is a zero, which finding.LeftAt reads as unknown.
func ReadTimes(rs ...[]Read) []time.Time {
	var out []time.Time
	for _, set := range rs {
		for _, r := range set {
			if r.Status != 0 {
				out = append(out, r.ObservedAt)
			}
		}
	}
	return out
}

// leftAt is when a declared leaving date passed relative to the reads.
func leftAt(left string, c Context, rs ...[]Read) finding.Leaving {
	return finding.LeftAt(left, c.Zone, ReadTimes(rs...))
}

// leftReason is a leaver judgment's abstention when the date had not
// passed at the earliest read it rests on; with nothing read, reason, the
// judgment's own for missing evidence, stands.
func leftReason(l finding.Leaving, reason string) string {
	switch l {
	case finding.LeftWithin:
		return finding.ReasonLeftDuringCollection
	case finding.LeftUnknown:
		return finding.ReasonNoCollectionTime
	case finding.LeftUnread:
		return reason
	}
	return "leaving_date_not_passed"
}

// leftAmbiguous says a declared leaving date neither passed nor not-passed
// at the reads: a rule that turns on it abstains rather than judge the
// account as a current person's.
func leftAmbiguous(l finding.Leaving) bool {
	return l == finding.LeftWithin || l == finding.LeftUnknown
}

// asOf names the earliest read a leaver judgment rests on, in the zone.
func asOf(c Context, rs ...[]Read) string {
	first, _, _ := finding.Span(ReadTimes(rs...))
	return finding.ReadDate(first, c.Zone)
}
func production(c Context, asset string) bool {
	return c.RepositoryContexts[asset].DeploysTo == "production"
}
func describeAccount(a Account) string { return fmt.Sprintf("%s (GitHub account %d)", a.Login, a.ID) }

// Judge is every rule family's verdicts over what was read: identity and
// repository access, CI, provider alerts and history. Analyze calls it;
// evidence carries no verdict (docs/spec/runs.md, "Verdicts are not
// evidence").
func Judge(e Evidence, c Context) []Judgment {
	return slices.Concat(JudgeAccess(e, c), JudgeCI(e, c), JudgeAlerts(e, c), JudgeHistory(e))
}

// JudgeAccess reads only collected facts. Unknown and incomplete populations never
// disprove a rule (docs/spec/github-collector.md, "Boundary", "Rules: evidence outcomes").
func JudgeAccess(e Evidence, c Context) []Judgment {
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
			j.Attributes = []finding.Attribute{{Name: "contradiction", Ref: finding.Ref{Key: c.MFASource}}}
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
			j.Attributes = []finding.Attribute{{Name: "contradiction", Ref: finding.Ref{Key: c.MFASource}}}
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
	out = append(out, inventoryPublic(e, c)...)
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
				all := complete(e.Owners) && !e.RepositoriesUnread
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
		m.Attributes = []finding.Attribute{{Name: "contradiction", Ref: finding.Ref{Key: c.MFASource}}}
		m.Sources = []string{c.MFASource}
	}
	out := []Judgment{m}
	u := judgment(finding.IDIdentityUnexpectedAdmin, c.OrganizationAsset, accountSubject(a, c), reads)
	left := finding.LeftNotPassed
	if p != nil && p.Left != "" {
		left = leftAt(p.Left, c, e.Owners.Reads)
	}
	if left == finding.LeftPassed {
		u.Reason = "departed_owner_reported_by_offboarding"
	} else if leftAmbiguous(left) {
		u.Reason = leftReason(left, u.Reason)
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
		j.Why = "Counts are lower bounds. No owner-to-member ratio was evaluated."
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
			// Attributed in every outcome, so the report's person lines
			// read it rather than the declaration (docs/spec/report.md,
			// "People who left").
			j := judgment(finding.IDIdentityFormerPersonHasAccess, c.OrganizationAsset, &Subject{Kind: "account", Key: "declared:" + p.Handle, Label: p.Handle, Person: p.Handle}, nil)
			j.Reason = "no_declared_github_login"
			out = append(out, j)
			continue
		}
		for _, login := range p.GitHub {
			a := Account{Login: strings.ToLower(login)}
			present := false
			// held are the reads of the populations that list the account.
			var held [][]Read
			for _, pop := range []Population[Account]{e.Members, e.Owners, e.OutsideCollaborators} {
				for _, v := range pop.Items {
					if strings.EqualFold(v.Login, login) {
						a = v
						present = true
						held = append(held, pop.Reads)
						break
					}
				}
			}
			source := []string{"people." + p.Handle + ".left"}
			full := complete(e.Members) && complete(e.Owners) && complete(e.OutsideCollaborators) && complete(e.Invitations) && identifiableInvitations(e.Invitations) && !e.RepositoriesUnread
			for _, repo := range e.RepositoriesAccess {
				full = full && complete(repo.Collaborators)
			}
			// A presence is judged at the reads that observed the account,
			// an absence at the earliest of the whole population's: either
			// needs the leaving date passed at the earliest of them
			// (docs/spec/engagement.md, "Severity in context").
			makeAccess := func(asset string, account Account, reads []string, present, admin bool, at ...[]Read) Judgment {
				j := judgment(finding.IDIdentityFormerPersonHasAccess, asset, accountSubject(account, c), reads)
				j.Sources = source
				j.NotChecked = []string{"Accounts renamed after declaration; undeclared logins; credential or session usability"}
				if l := leftAt(p.Left, c, at...); l == finding.LeftPassed {
					seen := "; account observed in a read of " + asOf(c, at...)
					if !present {
						seen = "; no access observed as of " + asOf(c, at...) + " (earliest of the population's reads)"
					}
					settle(&j, present, present || full, describeAccount(account)+"; declared leaving date "+p.Left+seen)
					if present && admin {
						j.Attributes = []finding.Attribute{{Name: "admin"}}
					}
				} else {
					j.Reason = leftReason(l, j.Reason)
				}
				return j
			}
			owner := containsAccount(e.Owners.Items, login)
			// carrier is the fired judgment that carries the login's R4
			// facts: the organization's, else the first repository's.
			carrier := -1
			if present {
				j := makeAccess(c.OrganizationAsset, a, readIDs(e.Members.Reads, e.Owners.Reads, e.OutsideCollaborators.Reads), true, owner, held...)
				// How the login holds access, as the report's person line
				// says it (docs/spec/report.md, "People who left").
				j.Details = map[string]any{"membership": "outside_collaborator"}
				switch {
				case owner:
					j.Details["membership"] = "owner"
				case containsAccount(e.Members.Items, login):
					j.Details["membership"] = "member"
				}
				out = append(out, j)
				if out[len(out)-1].Verdict == Fired {
					carrier = len(out) - 1
				}
			}
			for _, repo := range e.RepositoriesAccess {
				for _, collaborator := range repo.Collaborators.Items {
					if strings.EqualFold(collaborator.Login, login) {
						j := makeAccess(repo.Asset, collaborator.Account, readIDs(repo.Collaborators.Reads), true, false, repo.Collaborators.Reads)
						j.Details = map[string]any{"membership": "collaborator"}
						if j.Verdict == Fired {
							// Facts only: whether the repository deploys to
							// production is the severity table's to decide
							// (docs/spec/engagement.md, R4).
							admin, adminKnown := EffectiveAdmin(collaborator)
							if adminKnown && admin {
								j.Attributes = append(j.Attributes, finding.Attribute{Name: "repository_admin"})
							}
							if write, known := EffectiveWrite(collaborator); known && write && (!archived(repo) || adminKnown && admin) {
								j.Attributes = append(j.Attributes, finding.Attribute{Name: "write",
									Ref: finding.Ref{Observation: firstRead(readIDs(repo.Collaborators.Reads)), Excerpt: permissionExcerpt(collaborator)}})
							}
						}
						out = append(out, j)
						if j.Verdict == Fired && (carrier < 0 || out[carrier].Asset != c.OrganizationAsset && repo.Asset < out[carrier].Asset) {
							carrier = len(out) - 1
						}
						present = true
					}
				}
			}
			// An owner is admin on every repository: attribute:admin already
			// says it, and R4 has nothing to establish.
			if carrier >= 0 && !owner {
				out[carrier].Attributes = append(out[carrier].Attributes, productionWriteFacts(e, login)...)
			}
			if !present {
				population := [][]Read{e.Members.Reads, e.Owners.Reads, e.OutsideCollaborators.Reads, e.Invitations.Reads}
				for _, repo := range e.RepositoriesAccess {
					population = append(population, repo.Collaborators.Reads)
				}
				j := makeAccess(c.OrganizationAsset, a, readIDs(population...), false, false, population...)
				j.Details = map[string]any{"membership": "none"}
				out = append(out, j)
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
				if l := leftAt(p.Left, c, e.Invitations.Reads); l == finding.LeftPassed {
					settle(&x, false, complete(e.Invitations) && identifiableInvitations(e.Invitations),
						"No matching pending invitation for "+login+" as of "+asOf(c, e.Invitations.Reads)+" (earliest of the invitation reads)")
				} else {
					x.Reason = leftReason(l, x.Reason)
				}
				out = append(out, x)
			}
			for _, i := range invitations {
				key := "invitation:" + strconv.FormatInt(i.ID, 10)
				x := judgment(finding.IDIdentityFormerPersonInvited, c.OrganizationAsset, &Subject{Kind: "invitation", Key: key, Label: login + " (" + key + ")", ProviderID: strconv.FormatInt(i.ID, 10), Person: p.Handle}, readIDs(e.Invitations.Reads))
				x.Sources = source
				if l := leftAt(p.Left, c, e.Invitations.Reads); l == finding.LeftPassed {
					settle(&x, true, true, "Pending invitation for "+login+"; declared leaving date "+p.Left+"; observed in an invitation read of "+asOf(c, e.Invitations.Reads))
				} else {
					x.Reason = leftReason(l, x.Reason)
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

// EffectiveWrite recognizes push access (push, maintain or admin) from
// consistent provider fields; the booleans are GitHub's effective
// permission across direct, team and base access, so a custom role with
// push counts. The second result is false when missing or contradictory
// evidence prevents a decision; role_name alone never establishes write
// (docs/spec/github-collector.md, "Rule evidence").
func EffectiveWrite(a Collaborator) (bool, bool) {
	if a.RoleName != nil && (strings.Contains(*a.RoleName, "[REDACTED:") || strings.Contains(*a.RoleName, "[TRUNCATED:")) {
		return false, false
	}
	if admin, known := EffectiveAdmin(a); known && admin {
		return true, true
	}
	p := a.Permissions
	if p == nil {
		return false, false
	}
	isTrue := func(v *bool) bool { return v != nil && *v }
	isFalse := func(v *bool) bool { return v != nil && !*v }
	readOnly := a.RoleName != nil && slices.Contains([]string{"read", "pull", "triage"}, *a.RoleName)
	if isTrue(p.Push) || isTrue(p.Maintain) {
		if isFalse(p.Pull) || isTrue(p.Maintain) && isFalse(p.Push) || readOnly {
			return false, false
		}
		return true, true
	}
	if isFalse(p.Admin) && isFalse(p.Push) && isFalse(p.Maintain) {
		// A writing role with no write permission is a contradiction.
		if a.RoleName != nil && slices.Contains([]string{"write", "push", "maintain", "admin"}, *a.RoleName) {
			return false, false
		}
		return false, true
	}
	return false, false
}

// permissionExcerpt is a collaborator's role and permission fields as the
// write attribute cites them.
func permissionExcerpt(a Collaborator) string {
	parts := []string{}
	if a.RoleName != nil {
		parts = append(parts, "role_name: "+*a.RoleName)
	}
	if p := a.Permissions; p != nil {
		for _, f := range []struct {
			name string
			v    *bool
		}{{"admin", p.Admin}, {"maintain", p.Maintain}, {"push", p.Push}, {"pull", p.Pull}} {
			if f.v != nil {
				parts = append(parts, fmt.Sprintf("%s: %t", f.name, *f.v))
			}
		}
	}
	if len(parts) == 0 {
		return "no permission fields returned"
	}
	return strings.Join(parts, "; ")
}

// repositoryName is a repository as the report names it, owner/name.
func repositoryName(r RepositoryAccess) string {
	if r.Repository != nil && r.Repository.FullName != "" && !strings.Contains(r.Repository.FullName, "[") {
		return r.Repository.FullName
	}
	return strings.TrimPrefix(r.Asset, "repo:github:")
}

// unreadPhrase says why a population could not be read, for a cause.
func unreadPhrase[T any](p Population[T]) string {
	for _, r := range p.Reads {
		if usableRead(r) {
			continue
		}
		switch {
		case r.Reason == "insufficient_permission":
			return "the credential was not allowed to list them"
		case r.Truncated:
			return "the list was cut short"
		case len(r.Redactions) > 0:
			return "part of the list was redacted"
		case r.Reason != "":
			return strings.ReplaceAll(strings.TrimPrefix(r.Reason, "unavailable:"), "_", " ")
		case r.Gap != "":
			return InventoryGapText([]string{r.Gap})
		}
		return "the read did not succeed"
	}
	if len(p.Reads) == 0 {
		return "not read"
	}
	return InventoryGapText(p.Gaps)
}

// productionWriteFacts are what R4 reads on the judgment that carries a
// left login's "not applied" step: each repository this run read where the
// login's push access is established (write_held) or not settled
// (write_unsettled, the cause in its excerpt). The severity table keeps the
// production repositories among them (docs/spec/engagement.md, R4).
func productionWriteFacts(e Evidence, login string) []finding.Attribute {
	var out []finding.Attribute
	for _, repo := range e.RepositoriesAccess {
		name := repositoryName(repo)
		unsettled := func(cause string) {
			out = append(out, finding.Attribute{Name: "write_unsettled", Asset: repo.Asset, Ref: finding.Ref{Observation: firstRead(readIDs(repo.Collaborators.Reads)), Excerpt: cause}})
		}
		idx := slices.IndexFunc(repo.Collaborators.Items, func(c Collaborator) bool { return strings.EqualFold(c.Login, login) })
		if idx < 0 {
			if len(repo.Collaborators.Reads) == 0 || slices.ContainsFunc(repo.Collaborators.Reads, func(r Read) bool { return !usableRead(r) }) {
				unsettled("the collaborators of " + name + " could not be read: " + unreadPhrase(repo.Collaborators))
			} else {
				unsettled(login + " is not listed among the collaborators of " + name + ", and that list may not show everyone with access")
			}
			continue
		}
		c := repo.Collaborators.Items[idx]
		write, known := EffectiveWrite(c)
		admin, adminKnown := EffectiveAdmin(c)
		switch {
		case !known:
			unsettled("the permissions returned for " + login + " on " + name + " were missing or contradictory")
		case write && archived(repo) && (!adminKnown || !admin):
			unsettled(name + " is archived")
		case write:
			out = append(out, finding.Attribute{Name: "write_held", Asset: repo.Asset})
		}
	}
	return out
}

func archived(r RepositoryAccess) bool {
	return r.Repository != nil && r.Repository.Archived != nil && *r.Repository.Archived
}

func firstRead(ids []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
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

// inventoryPublic fires the undeclared-public rule from the organization's
// repository list for a public repository whose object Check did not read
// (the budget or the deadline came first, or the read failed): its
// inventory judgment stays. The list
// only fires; a repository not shown public is never disproved from it
// (docs/spec/engagement.md, "Plan selection and follow-ups").
func inventoryPublic(e Evidence, c Context) []Judgment {
	var out []Judgment
	for _, repo := range e.Repositories.Items {
		asset := "repo:github:" + strings.ToLower(repo.FullName)
		if repo.Visibility == nil || *repo.Visibility != "public" || slices.ContainsFunc(e.RepositoriesAccess, func(r RepositoryAccess) bool { return strings.EqualFold(r.Asset, asset) && r.Repository != nil }) {
			continue
		}
		if rc := c.RepositoryContexts[asset]; rc.Public != nil && *rc.Public {
			continue
		}
		j := judgment(finding.IDGitHubUndeclaredPublicRepository, asset, &Subject{Kind: "repository", Key: strings.ToLower(repo.FullName), Label: repo.FullName, ProviderID: strconv.FormatInt(repo.ID, 10)}, readIDs(e.Repositories.Reads))
		settle(&j, true, true, "visibility: public (organization repository list)")
		out = append(out, j)
	}
	return out
}
