package github

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/policy"
)

// Sender holds no credential; it is the collector's entire remote interface.
type Sender interface {
	Send(context.Context, gate.Request) gate.Result
}

// Read preserves execution and observation metadata without retaining a raw body.
type Read struct {
	Op         string           `json:"op"`
	RequestID  string           `json:"request_id"`
	Decision   string           `json:"decision"`
	Reason     string           `json:"reason,omitempty"`
	Kind       string           `json:"kind,omitempty"`
	Detail     string           `json:"detail,omitempty"`
	ObservedAt time.Time        `json:"observed_at"`
	Reused     bool             `json:"reused,omitempty"`
	Truncated  bool             `json:"truncated,omitempty"`
	Status     int              `json:"status,omitempty"`
	Population *gate.Population `json:"population,omitempty"`
	Redactions []policy.Hit     `json:"redactions,omitempty"`
	Gap        string           `json:"gap,omitempty"`
}

// Account is an explicitly identified account, never inferred from a display name.
type Account struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

// PrincipalRead identifies a PAT/App user principal. MFA null/absence remains unknown.
type PrincipalRead struct {
	Read                    Read     `json:"read"`
	Account                 *Account `json:"account,omitempty"`
	Identity                string   `json:"identity,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	TwoFactorAuthentication *bool    `json:"two_factor_authentication,omitempty"`
}

// Organization is a declared organization root, not a provider-returned URL.
type Organization struct{ Asset, Name, Stage string }

type OrganizationObject struct {
	Account
	TwoFactorRequirementEnabled *bool   `json:"two_factor_requirement_enabled,omitempty"`
	DefaultRepositoryPermission *string `json:"default_repository_permission,omitempty"`
}

type Membership struct {
	State        string  `json:"state"`
	Role         string  `json:"role"`
	Organization Account `json:"organization"`
	User         Account `json:"user"`
}

type Invitation struct {
	ID               int64   `json:"id"`
	Login            *string `json:"login,omitempty"`
	Role             string  `json:"role"`
	InvitationSource *string `json:"invitation_source,omitempty"`
}

type Repository struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	FullName      string  `json:"full_name"`
	Owner         Account `json:"owner"`
	Visibility    *string `json:"visibility,omitempty"`
	Private       *bool   `json:"private,omitempty"`
	Archived      *bool   `json:"archived,omitempty"`
	DefaultBranch *string `json:"default_branch,omitempty"`
}

// Population.Complete describes the returned visible population. Authority and
// VisibilityComplete separately control organization-wide claims; a token's
// successful list does not prove access to every private repository.
type Population[T any] struct {
	Items              []T      `json:"items,omitempty"`
	Reads              []Read   `json:"reads"`
	Complete           bool     `json:"complete"`
	VisibilityComplete bool     `json:"visibility_complete"`
	Gaps               []string `json:"gaps,omitempty"`
}

// Evidence is typed inventory only. It does not assert any security rule outcome.
type Evidence struct {
	RepositoriesHistory          []RepositoryHistory       `json:"repositories_history,omitempty"`
	OrganizationSecrets          Population[ActionsSecret] `json:"organization_secrets"`
	SelectedSecrets              []SelectedSecret          `json:"selected_secrets,omitempty"`
	RepositoriesAlerts           []RepositoryAlerts        `json:"repositories_alerts,omitempty"`
	OrganizationWorkflow         DefaultEvidence           `json:"organization_workflow"`
	RepositoriesCI               []RepositoryCI            `json:"repositories_ci,omitempty"`
	Judgments                    []Judgment                `json:"judgments,omitempty"`
	Principal                    PrincipalRead             `json:"principal"`
	OrganizationRead             Read                      `json:"organization_read"`
	Organization                 *OrganizationObject       `json:"organization,omitempty"`
	MembershipRead               Read                      `json:"membership_read"`
	Membership                   *Membership               `json:"membership,omitempty"`
	OwnerAuthority               bool                      `json:"owner_authority"`
	MemberAuthority              bool                      `json:"member_authority"`
	Members                      Population[Account]       `json:"members"`
	Owners                       Population[Account]       `json:"owners"`
	OutsideCollaborators         Population[Account]       `json:"outside_collaborators"`
	Invitations                  Population[Invitation]    `json:"invitations"`
	Repositories                 Population[Repository]    `json:"repositories"`
	MembersWithoutMFA            Population[Account]       `json:"members_without_mfa"`
	OwnersWithoutMFA             Population[Account]       `json:"owners_without_mfa"`
	RepositoriesAccess           []RepositoryAccess        `json:"repositories_access,omitempty"`
	RepositoryVisibilityComplete bool                      `json:"repository_visibility_complete"`
}

var loginRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
var repoRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
var scopeRE = regexp.MustCompile(`^[a-z_][a-z_0-9:]*(?:[a-z_0-9])?$`)

func accountOK(a Account) bool {
	loginOK := loginRE.MatchString(a.Login)
	if a.Type == "Bot" {
		loginOK = loginOK || loginRE.MatchString(strings.TrimSuffix(a.Login, "[bot]")) && strings.HasSuffix(a.Login, "[bot]")
	}
	return a.ID > 0 && loginOK && (a.Type == "User" || a.Type == "Organization" || a.Type == "Bot")
}

// ResolvePrincipal always requests the live principal before authenticated reuse.
// Installation-token handling belongs to the gate and remains unknown here.
func ResolvePrincipal(ctx context.Context, g Sender, asset, stage string) PrincipalRead {
	r := g.Send(ctx, gate.Request{Op: OpPrincipal, Asset: asset, Stage: stage})
	p := PrincipalRead{Read: readOf(OpPrincipal, r)}
	if !usable(r) || len(r.Response.Redactions) > 0 {
		p.Read.Gap = "unrecognized_principal"
		return p
	}
	var body struct {
		Account
		TwoFactorAuthentication *bool `json:"two_factor_authentication"`
	}
	if json.Unmarshal(r.Response.Body, &body) != nil || !accountOK(body.Account) || body.Type != "User" {
		p.Read.Gap = "unrecognized_principal"
		return p
	}
	body.Login = strings.ToLower(body.Login)
	for s := range strings.SplitSeq(r.Response.Header.Get("X-Oauth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			if !scopeRE.MatchString(s) {
				p.Read.Gap = "unrecognized_principal"
				return p
			}
			p.Scopes = append(p.Scopes, s)
		}
	}
	slices.Sort(p.Scopes)
	p.Scopes = slices.Compact(p.Scopes)
	p.Account, p.Identity, p.TwoFactorAuthentication = &body.Account, "github:user:"+strconv.FormatInt(body.ID, 10), body.TwoFactorAuthentication
	return p
}

func readOf(op string, r gate.Result) Read {
	v := Read{Op: op, RequestID: r.RequestID, Decision: r.Decision, Reason: r.Reason, Kind: r.Kind, Detail: r.Detail, Reused: r.Decision == gate.DecisionReused}
	if r.Response != nil {
		v.ObservedAt, v.Status, v.Population = r.Response.CollectedAt, r.Response.Status, r.Response.Population
		v.Truncated = r.Response.Truncated
		v.Redactions = slices.Clone(r.Response.Redactions)
	}
	return v
}

func usable(r gate.Result) bool {
	return r.Reason == "" && (r.Decision == gate.DecisionSent || r.Decision == gate.DecisionReused) && r.Response != nil && r.Response.Status == 200 && !r.Response.Truncated
}

// Collect reads metadata, membership, then the declared organization populations.
// Only recognized active owner membership establishes owner authority.
func Collect(ctx context.Context, g Sender, org Organization, p PrincipalRead) Evidence {
	e := Evidence{Principal: p}
	request := func(op string) gate.Request {
		return gate.Request{Op: op, Asset: org.Asset, Stage: org.Stage, Exists: true, Params: map[string]string{"org": org.Name}}
	}
	r := g.Send(ctx, request(OpOrganization))
	e.OrganizationRead = readOf(OpOrganization, r)
	if usable(r) {
		var o OrganizationObject
		if json.Unmarshal(r.Response.Body, &o) == nil && accountOK(o.Account) && o.Type == "Organization" && strings.EqualFold(o.Login, org.Name) {
			o.Login = strings.ToLower(o.Login)
			e.Organization = &o
		} else {
			e.OrganizationRead.Gap = "unrecognized_organization"
		}
	}
	r = g.Send(ctx, request(OpMembership))
	e.MembershipRead = readOf(OpMembership, r)
	if usable(r) {
		var m Membership
		if json.Unmarshal(r.Response.Body, &m) == nil && m.Organization.ID > 0 && loginRE.MatchString(m.Organization.Login) && (m.Organization.Type == "" || m.Organization.Type == "Organization") && strings.EqualFold(m.Organization.Login, org.Name) && accountOK(m.User) && m.User.Type == "User" && (m.State == "active" || m.State == "pending") && (m.Role == "admin" || m.Role == "member") {
			e.Membership = &m
			e.MemberAuthority = len(r.Response.Redactions) == 0 && p.Account != nil && p.Account.ID == m.User.ID && strings.EqualFold(p.Account.Login, m.User.Login) && e.Organization != nil && m.Organization.ID == e.Organization.ID && m.State == "active"
			e.OwnerAuthority = e.MemberAuthority && m.Role == "admin"
		} else {
			e.MembershipRead.Gap = "unrecognized_membership"
		}
	}
	e.Members = population(ctx, g, request(OpMembers), func(a Account) bool { return accountOK(a) && a.Type != "Organization" })
	e.Owners = population(ctx, g, request(OpOwners), func(a Account) bool { return accountOK(a) && a.Type == "User" })
	e.OutsideCollaborators = population(ctx, g, request(OpOutside), func(a Account) bool { return accountOK(a) && a.Type != "Organization" })
	e.Invitations = population(ctx, g, request(OpInvitations), invitationOK)
	e.Repositories = population(ctx, g, request(OpRepositories), func(r Repository) bool { return repositoryOK(r, org.Name) })
	e.Members.VisibilityComplete = e.MemberAuthority
	e.Owners.VisibilityComplete = e.MemberAuthority
	e.OutsideCollaborators.VisibilityComplete = e.OwnerAuthority
	e.Invitations.VisibilityComplete = e.OwnerAuthority
	if !e.MemberAuthority {
		e.Members.Gaps = append(e.Members.Gaps, "member_visibility_unknown")
		e.Owners.Gaps = append(e.Owners.Gaps, "member_visibility_unknown")
	}
	// Complete pagination is independent of the authority needed for full visibility.
	if !e.OwnerAuthority {
		e.OutsideCollaborators.Gaps = append(e.OutsideCollaborators.Gaps, "owner_visibility_unknown")
		e.Invitations.Gaps = append(e.Invitations.Gaps, "owner_visibility_unknown")
	}
	// Repository selection grants are not observable from these endpoints.
	e.Repositories.Gaps = append(e.Repositories.Gaps, "repository_visibility_unknown")
	return e
}

func invitationOK(i Invitation) bool {
	return i.ID > 0 && (i.Login == nil || loginRE.MatchString(*i.Login)) && (i.Role == "direct_member" || i.Role == "admin" || i.Role == "billing_manager" || i.Role == "hiring_manager" || i.Role == "reinstate")
}

func repositoryOK(r Repository, org string) bool {
	return r.ID > 0 && repoRE.MatchString(r.Name) && r.Name != "." && r.Name != ".." && accountOK(r.Owner) && r.Owner.Type == "Organization" && strings.EqualFold(r.Owner.Login, org) && strings.EqualFold(r.FullName, org+"/"+r.Name)
}

func uncertain[T any](p *Population[T], gap string) { p.Complete = false; p.Gaps = append(p.Gaps, gap) }

func population[T any](ctx context.Context, g Sender, req gate.Request, valid func(T) bool) Population[T] {
	p := Population[T]{Complete: true}
	seen := map[string]bool{}
	ids := map[int64]bool{}
	for range 100 {
		r := g.Send(ctx, req)
		read := readOf(req.Op, r)
		p.Reads = append(p.Reads, read)
		if !usable(r) {
			uncertain(&p, "read_unavailable")
			return p
		}
		var items []T
		if len(r.Response.Body) == 0 || string(r.Response.Body) == "null" || json.Unmarshal(r.Response.Body, &items) != nil {
			uncertain(&p, "unrecognized_population")
			p.Reads[len(p.Reads)-1].Gap = "unrecognized_population"
			return p
		}
		for _, item := range items {
			if valid(item) {
				id := itemID(item)
				if ids[id] {
					uncertain(&p, "duplicate_item")
					continue
				}
				ids[id] = true
				p.Items = append(p.Items, item)
			} else {
				uncertain(&p, "unrecognized_item")
			}
		}
		pop := r.Response.Population
		if pop == nil {
			uncertain(&p, "population_unknown")
			return p
		}
		for _, gap := range pop.Incomplete {
			uncertain(&p, gap)
		}
		if !pop.More {
			p.Gaps = slices.Compact(p.Gaps)
			return p
		}
		if r.RequestID == "" || seen[r.RequestID] {
			uncertain(&p, "pagination_unrecognized")
			return p
		}
		seen[r.RequestID] = true
		req.NextOf = r.RequestID
	}
	uncertain(&p, "page_limit")
	return p
}

func itemID[T any](item T) int64 {
	switch v := any(item).(type) {
	case Account:
		return v.ID
	case Invitation:
		return v.ID
	case Repository:
		return v.ID
	case Collaborator:
		return v.ID
	case DeployKey:
		return v.ID
	}
	return 0
}

// Reads returns execution metadata for every request, in collection order.
func (e Evidence) Reads() []Read {
	out := []Read{}
	for _, h := range e.RepositoriesHistory {
		if h.Read.Op != "" {
			out = append(out, h.Read)
		}
		out = append(out, h.References...)
	}
	for _, read := range []Read{e.Principal.Read, e.OrganizationRead, e.MembershipRead} {
		if read.Op != "" {
			out = append(out, read)
		}
	}
	out = append(out, e.Members.Reads...)
	out = append(out, e.Owners.Reads...)
	out = append(out, e.OutsideCollaborators.Reads...)
	out = append(out, e.Invitations.Reads...)
	out = append(out, e.Repositories.Reads...)
	out = append(out, e.MembersWithoutMFA.Reads...)
	out = append(out, e.OwnersWithoutMFA.Reads...)
	for _, access := range e.RepositoriesAccess {
		out = append(out, access.Reads()...)
	}
	if e.OrganizationWorkflow.Read.Op != "" {
		out = append(out, e.OrganizationWorkflow.Read)
	}
	for _, ci := range e.RepositoriesCI {
		out = append(out, ci.Reads()...)
	}
	out = append(out, e.OrganizationSecrets.Reads...)
	for _, selected := range e.SelectedSecrets {
		out = append(out, selected.Repositories.Reads...)
	}
	for _, alerts := range e.RepositoriesAlerts {
		out = append(out, alerts.Reads()...)
	}
	return out
}
