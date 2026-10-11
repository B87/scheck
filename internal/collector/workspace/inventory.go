package workspace

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// Target is a declared tenant, never a provider-returned selector.
type Target struct{ Asset, Stage string }
type Person struct {
	Handle     string
	Kind, Left string
	UsedBy     []string
	Addresses  []string
}
type Context struct {
	People         []Person
	ExpectedAdmins []string
	AdminsDeclared bool
	AssessedAt     time.Time
	Zone           *time.Location
	// MFA is the tenant's access.mfa[i].enforced and MFASource its key;
	// both are empty when the operator declared nothing for this tenant.
	MFA, MFASource string
}
type Attribution struct {
	Tenant     string `json:"tenant"`
	Key        string `json:"key"`
	ProviderID string `json:"provider_id"`
	Handle     string `json:"handle"`
	MatchedBy  string `json:"matched_by"`
}
type Note struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Detail string `json:"detail"`
}
type Domain struct {
	Name     string `json:"domainName"`
	Verified *bool  `json:"verified"`
}
type Alias struct {
	Name     string `json:"domainAliasName"`
	Parent   string `json:"parentDomainName"`
	Verified *bool  `json:"verified"`
}
type Unit struct {
	ID         string `json:"orgUnitId"`
	Path       string `json:"orgUnitPath"`
	ParentID   string `json:"parentOrgUnitId,omitempty"`
	ParentPath string `json:"parentOrgUnitPath,omitempty"`
	Name       string `json:"name,omitempty"`
}
type User struct {
	ID                 string   `json:"id"`
	Primary            string   `json:"primaryEmail"`
	Customer           string   `json:"customerId"`
	Unit               string   `json:"orgUnitPath"`
	Aliases            []string `json:"aliases,omitempty"`
	NonEditableAliases []string `json:"nonEditableAliases,omitempty"`
	Name               struct {
		FullName string `json:"fullName,omitempty"`
	} `json:"name"`
	Suspended        *bool   `json:"suspended,omitempty"`
	Archived         *bool   `json:"archived,omitempty"`
	IsAdmin          *bool   `json:"isAdmin,omitempty"`
	IsDelegatedAdmin *bool   `json:"isDelegatedAdmin,omitempty"`
	CreationTime     *string `json:"creationTime,omitempty"`
	LastLoginTime    *string `json:"lastLoginTime,omitempty"`
	Enrolled         *bool   `json:"isEnrolledIn2Sv,omitempty"`
	Enforced         *bool   `json:"isEnforcedIn2Sv,omitempty"`
	Mailbox          *bool   `json:"isMailboxSetup,omitempty"`
}
type Population[T any] struct {
	Items    []T      `json:"items"`
	Reads    []Read   `json:"reads"`
	Complete bool     `json:"complete"`
	Gaps     []string `json:"gaps,omitempty"`
}
type Evidence struct {
	Access            AccessEvidence     `json:"access"`
	OAuth             OAuthEvidence      `json:"oauth"`
	InventoryComplete bool               `json:"inventory_complete"`
	Binding           Binding            `json:"binding"`
	Domains           Population[Domain] `json:"domains"`
	Aliases           Population[Alias]  `json:"aliases"`
	Units             Population[Unit]   `json:"units"`
	Users             Population[User]   `json:"users"`
	PrincipalRead     Read               `json:"principal_read"`
	DelegatedUser     *User              `json:"delegated_user,omitempty"`
	Attribution       []Attribution      `json:"attribution,omitempty"`
	Notes             []Note             `json:"notes"`
	Judgments         []finding.Judgment `json:"judgments,omitempty"`
}

func usable(r gate.Result) bool {
	return r.OK() && r.Response != nil && r.Response.Status == 200 && !r.Response.Truncated
}
func readOf(op string, r gate.Result) Read {
	out := Read{Op: op, RequestID: r.RequestID, Decision: r.Decision, Reason: r.Reason, Detail: r.Detail}
	if r.Response != nil {
		out.Status = r.Response.Status
		out.Population = r.Response.Population
		out.Truncated = r.Response.Truncated
		out.Redactions = r.Response.Redactions
	}
	return out
}

// Collect hides binding order, population reads, recognition, attribution and
// diagnostic wording (docs/spec/workspace-collector.md, "Reads and projections").
func Collect(ctx context.Context, sender Sender, target Target, view Context) Evidence {
	e := Evidence{Binding: Bind(ctx, sender, target.Asset)}
	if e.Binding.CustomerID == "" {
		e.finish(target.Asset, view)
		e.Judgments = Judge(e, target.Asset, view)
		return e
	}
	domain := e.Binding.Domain
	req := func(op string) gate.Request {
		return gate.Request{Op: op, Asset: target.Asset, Stage: target.Stage, Exists: true, Params: map[string]string{"domain": domain}}
	}
	e.Domains = population(ctx, sender, req(OpDomains), func(v Domain) string { return v.Name }, func(v Domain) bool { return v.Name != "" && v.Verified != nil })
	e.Aliases = population(ctx, sender, req(OpAliases), func(v Alias) string { return v.Name }, func(v Alias) bool { return v.Name != "" && v.Parent != "" && v.Verified != nil })
	e.Units = population(ctx, sender, req(OpUnits), func(v Unit) string { return v.ID }, func(v Unit) bool { return v.ID != "" && v.Path != "" })
	// Explicit exclusions make the retained population incomplete but the gate
	// still has the privately recognized tree needed to admit the users list.
	unitUsable := len(e.Units.Reads) > 0 && e.Units.Reads[0].Reason == "" && e.Units.Reads[0].Status == 200 && !slices.Contains(e.Units.Gaps, "unrecognized_population") && !slices.Contains(e.Units.Gaps, "unrecognized_item") && !slices.Contains(e.Units.Gaps, "population_unknown")
	if unitUsable {
		e.Users = population(ctx, sender, req(OpUsers), func(v User) string { return v.ID }, func(v User) bool {
			return v.ID != "" && v.Primary != "" && v.Customer == e.Binding.CustomerID && v.Unit != ""
		})
		r := sender.Send(ctx, req(opDelegatedUser))
		e.PrincipalRead = readOf(opDelegatedUser, r)
		if usable(r) && len(r.Response.Redactions) == 0 {
			var user User
			if json.Unmarshal(r.Response.Body, &user) == nil && user.ID != "" && user.Customer == e.Binding.CustomerID {
				e.DelegatedUser = &user
			} else {
				e.PrincipalRead.Reason = "insufficient_evidence"
			}
		}
	}
	e.collectAccess(ctx, sender, target, view)
	e.collectGrants(ctx, sender, target, view)
	e.finish(target.Asset, view)
	e.Judgments = Judge(e, target.Asset, view)
	return e
}

func population[T any](ctx context.Context, sender Sender, request gate.Request, key func(T) string, valid func(T) bool) Population[T] {
	const pages, cap = 10, 1000
	p := Population[T]{Complete: true, Items: []T{}}
	seen := map[string]string{}
	cursors := map[string]bool{}
	conflicts := map[string]bool{}
	for range pages {
		r := sender.Send(ctx, request)
		p.Reads = append(p.Reads, readOf(request.Op, r))
		if !usable(r) {
			p.Complete = false
			p.Gaps = append(p.Gaps, "read_unavailable")
			return p
		}
		if len(r.Response.Redactions) > 0 {
			p.Complete = false
			p.Gaps = append(p.Gaps, "redacted_population")
		}
		var items []T
		if json.Unmarshal(r.Response.Body, &items) != nil || items == nil {
			p.Complete = false
			p.Gaps = append(p.Gaps, "unrecognized_population")
			return p
		}
		for _, item := range items {
			if !valid(item) {
				p.Complete = false
				p.Gaps = append(p.Gaps, "unrecognized_item")
				continue
			}
			if conflicts[key(item)] {
				continue
			}
			raw, _ := json.Marshal(item)
			if old, exists := seen[key(item)]; exists {
				if old != string(raw) {
					p.Complete = false
					p.Gaps = append(p.Gaps, "conflicting_duplicate")
					conflicts[key(item)] = true
					p.Items = slices.DeleteFunc(p.Items, func(v T) bool { return key(v) == key(item) })
				}
				continue
			}
			if len(p.Items) >= cap {
				p.Complete = false
				p.Gaps = append(p.Gaps, "item_limit")
				continue
			}
			seen[key(item)] = string(raw)
			p.Items = append(p.Items, item)
		}
		pop := r.Response.Population
		if pop == nil {
			p.Complete = false
			p.Gaps = append(p.Gaps, "population_unknown")
			return p
		}
		for _, gap := range pop.Incomplete {
			p.Complete = false
			p.Gaps = append(p.Gaps, gap)
		}
		if !pop.More {
			p.Gaps = slices.Compact(p.Gaps)
			return p
		}
		if r.RequestID == "" || cursors[r.RequestID] {
			p.Complete = false
			p.Gaps = append(p.Gaps, "cursor_loop")
			return p
		}
		cursors[r.RequestID] = true
		request.NextOf = r.RequestID
	}
	p.Complete = false
	p.Gaps = append(p.Gaps, "page_limit")
	return p
}

func (e Evidence) Reads() []Read {
	out := slices.Clone(e.Binding.Reads)
	out = append(out, e.Domains.Reads...)
	out = append(out, e.Aliases.Reads...)
	out = append(out, e.Units.Reads...)
	out = append(out, e.Users.Reads...)
	if e.PrincipalRead.Op != "" {
		out = append(out, e.PrincipalRead)
	}
	out = append(out, e.Access.Roles.Reads...)
	out = append(out, e.Access.Privileges.Reads...)
	for _, account := range e.Access.Accounts {
		out = append(out, account.Assignments.Reads...)
		if account.DetailRead.Op != "" {
			out = append(out, account.DetailRead)
		}
	}
	for _, account := range e.OAuth.Accounts {
		out = append(out, account.Read)
	}
	return out
}

func (e *Evidence) finish(asset string, view Context) {
	e.InventoryComplete = e.Binding.CustomerID != "" && len(e.Users.Reads) > 0 && e.Domains.Complete && e.Aliases.Complete && e.Units.Complete && e.Users.Complete
	credential := CredentialNote(e.Binding)
	credential.Source = asset
	e.Notes = append(e.Notes, credential)
	counts := func(label string, n int, complete bool) string {
		qualifier := "observed"
		if !complete {
			qualifier = "at least"
		}
		return fmt.Sprintf("%s: %s %d", label, qualifier, n)
	}
	e.Notes = append(e.Notes, Note{Kind: "workspace_inventory", Source: asset, Detail: strings.Join([]string{counts("domains", len(e.Domains.Items), e.Domains.Complete), counts("organizational units", len(e.Units.Items), e.Units.Complete), counts("accounts", len(e.Users.Items), e.Users.Complete)}, "; ") + ". Account security conclusions appear separately; inventory alone proves no security control."})
	if e.DelegatedUser == nil {
		e.Notes = append(e.Notes, Note{Kind: "workspace_inventory", Source: asset, Detail: "scheck could not identify the Google account used for this run. Information from earlier Workspace reads was not used in this report."})
	} else {
		e.Notes = append(e.Notes, Note{Kind: "workspace_inventory", Source: asset, Detail: "The delegated account " + e.DelegatedUser.Primary + " (account id " + e.DelegatedUser.ID + ") was freshly verified. Authenticated Workspace evidence was not reused."})
	}
	for _, read := range e.Reads() {
		e.Notes = append(e.Notes, ReadNotes(read, asset)...)
	}
	e.Attribution = attribute(asset, e.Users.Items, view.People, e.Users.Complete)
	e.Notes = append(e.Notes, Readout(*e, asset, view)...)
	for _, a := range e.Attribution {
		if a.MatchedBy == "alias" {
			e.Notes = append(e.Notes, Note{Kind: "workspace_people", Source: asset, Detail: a.Handle + " → " + a.Key + ", by alias. Record the current primary address in people."})
		}
	}
}

func attribute(asset string, users []User, people []Person, complete bool) []Attribution {
	out := []Attribution{}
	for _, person := range people {
		matched := map[string]int{}
		for _, address := range person.Addresses {
			primary, aliases := map[string]User{}, map[string]User{}
			for _, user := range users {
				if strings.EqualFold(address, user.Primary) {
					primary[user.ID] = user
				}
				for _, alias := range append(slices.Clone(user.Aliases), user.NonEditableAliases...) {
					if strings.EqualFold(address, alias) {
						aliases[user.ID] = user
					}
				}
			}
			matches, method := primary, "primary"
			if len(matches) == 0 {
				if !complete {
					continue
				}
				matches, method = aliases, "alias"
			}
			if len(matches) != 1 {
				continue
			}
			for _, user := range matches {
				if index, exists := matched[user.ID]; exists {
					if method == "primary" {
						out[index].MatchedBy = method
					}
					continue
				}
				matched[user.ID] = len(out)
				out = append(out, Attribution{Tenant: asset, Key: strings.ToLower(user.Primary), ProviderID: user.ID, Handle: person.Handle, MatchedBy: method})
			}
		}
	}
	// Two people claiming the same current account is unknown attribution.
	counts := map[string]int{}
	for _, a := range out {
		counts[a.ProviderID]++
	}
	return slices.DeleteFunc(out, func(a Attribution) bool { return counts[a.ProviderID] != 1 })
}
