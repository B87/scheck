package workspace

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
)

// The per-user read order: Plan orders a tenant's accounts by the tier
// table below, Recon reads each account's assignments and detail in it,
// and Check reads OAuth grants in it (docs/spec/engagement.md, "Plan
// selection and follow-ups"; docs/spec/workspace-collector.md, "Per-user
// read order under caps"). There is no request budget: the order decides
// what a cap, the deadline or a rate limit leaves unread.

// UserTiersVersion versions the tier table and the within-tier order.
const UserTiersVersion = "workspace-user-tiers:2026-10-15"

type userTier struct{ basis, source string }

// userTiers is the table, 1 to 6; the lowest tier wins.
var userTiers = []userTier{
	{},
	{"left and still active", "people.*.left"},
	{"admin holders no one named", "observed"},
	{"admins a handle names", "people"},
	{"contractor and shared accounts", "people.*.kind"},
	{"break-glass and service accounts", "people.*.kind"},
	{"the rest, active and most recently signed in first", ""},
}

// mailTiers is Gmail forwarding's own order, 1 to 3.
var mailTiers = []userTier{
	{},
	{"left and still active", "people.*.left"},
	{"admin holders", "observed"},
	{"the rest, active first", ""},
}

// SelectedUser is one account in Plan's order.
type SelectedUser struct {
	ID      string `json:"id"`
	Primary string `json:"primary_email"`
	Tier    int    `json:"tier"`
	Basis   string `json:"basis"`
	Handle  string `json:"handle,omitempty"`
	Active  bool   `json:"active"`
}

// UserSelection is Plan's order of one tenant's accounts.
type UserSelection struct {
	Asset   string `json:"asset"`
	Version string `json:"tiers_version"`
	InScope int    `json:"in_scope"`
	// InScopeAtLeast is true when the users list was not complete.
	InScopeAtLeast bool `json:"in_scope_at_least,omitempty"`
	// Grants says the profile reads OAuth grants, which Check reads in
	// this order.
	Grants bool           `json:"grants"`
	Order  []SelectedUser `json:"order"`
}

// Counts are the selection's tiers with how many accounts each holds, in
// tier order, for Plan's text.
func (s UserSelection) Counts() []finding.SelectionTier {
	return tierCounts(userTiers, s.Order, nil)
}

func tierCounts(table []userTier, order []SelectedUser, keep func(SelectedUser) bool) []finding.SelectionTier {
	counts := map[int]int{}
	for _, u := range order {
		if keep == nil || keep(u) {
			counts[u.Tier]++
		}
	}
	out := []finding.SelectionTier{}
	for t := 1; t < len(table); t++ {
		if counts[t] > 0 {
			out = append(out, finding.SelectionTier{Basis: table[t].basis, Source: table[t].source, Count: counts[t]})
		}
	}
	return out
}

// Select orders the tenant's accounts by the tier table, from what Recon
// read and the people the engagement declares. It sends nothing.
func Select(e Evidence, asset string, view Context) UserSelection {
	return UserSelection{Asset: asset, Version: UserTiersVersion, InScope: len(e.Users.Items), InScopeAtLeast: !e.Users.Complete, Grants: e.OAuth.Selected,
		Order: orderUsers(e.Users.Items, e.Access.Accounts, attribute(asset, e.Users.Items, view.People, e.Users.Complete), view)}
}

// orderUsers is the one per-user order. An admin holder, for ordering, is
// an account Google flags admin or delegated admin, or one holding an
// observed role assignment: wider than any finding's rule, since ordering
// is no verdict (docs/spec/engagement.md, "Plan selection and follow-ups").
func orderUsers(users []User, access []AccountAccess, attributions []Attribution, view Context) []SelectedUser {
	out := make([]SelectedUser, 0, len(users))
	login := map[string]time.Time{}
	for _, u := range users {
		p := personForUser(u, attributions, view)
		assigned := slices.ContainsFunc(access, func(a AccountAccess) bool { return a.ID == u.ID && len(a.Assignments.Items) > 0 })
		admin := yes(u.IsAdmin) || yes(u.IsDelegatedAdmin) || assigned
		tier := 6
		switch {
		case p != nil && p.Left != "" && active(u):
			tier = 1
		case admin && p == nil:
			tier = 2
		case admin:
			tier = 3
		case p != nil && (p.Kind == "contractor" || p.Kind == "shared"):
			tier = 4
		case p != nil && (p.Kind == "break_glass" || p.Kind == "service"):
			tier = 5
		}
		s := SelectedUser{ID: u.ID, Primary: u.Primary, Tier: tier, Basis: userTiers[tier].basis, Active: active(u)}
		if p != nil {
			s.Handle = p.Handle
		}
		if u.LastLoginTime != nil {
			if t, err := time.Parse(time.RFC3339, *u.LastLoginTime); err == nil {
				login[u.ID] = t
			}
		}
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b SelectedUser) int {
		if a.Tier != b.Tier {
			return a.Tier - b.Tier
		}
		if a.Active != b.Active {
			if a.Active {
				return -1
			}
			return 1
		}
		if c := login[b.ID].Compare(login[a.ID]); c != 0 {
			return c
		}
		return cmp.Or(strings.Compare(strings.ToLower(a.Primary), strings.ToLower(b.Primary)), strings.Compare(a.ID, b.ID))
	})
	return out
}

// inOrder is views ordered as order lists them; an account order does not
// name keeps its place after them.
func inOrder(views []accountView, order []SelectedUser) []accountView {
	rank := map[string]int{}
	for i, u := range order {
		rank[u.ID] = i
	}
	out := slices.Clone(views)
	slices.SortStableFunc(out, func(a, b accountView) int {
		ra, oka := rank[a.user.ID]
		rb, okb := rank[b.user.ID]
		switch {
		case oka && okb:
			return ra - rb
		case oka:
			return -1
		case okb:
			return 1
		}
		return 0
	})
	return out
}

// mailOrder is Gmail forwarding's own order: a person who left and is
// still active first, then admin holders, then the rest; active first,
// then primaryEmail. It returns the views and the order with its tiers.
func mailOrder(views []accountView) ([]accountView, []SelectedUser) {
	tier := func(v accountView) int {
		admin := yes(v.user.IsAdmin) || yes(v.user.IsDelegatedAdmin) || len(v.access.Assignments.Items) > 0
		switch {
		case v.person != nil && v.person.Left != "" && active(v.user):
			return 1
		case admin:
			return 2
		}
		return 3
	}
	out := slices.Clone(views)
	slices.SortStableFunc(out, func(a, b accountView) int {
		if x := tier(a) - tier(b); x != 0 {
			return x
		}
		if active(a.user) != active(b.user) {
			if active(a.user) {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.user.Primary), strings.ToLower(b.user.Primary))
	})
	order := make([]SelectedUser, len(out))
	for i, v := range out {
		t := tier(v)
		order[i] = SelectedUser{ID: v.user.ID, Primary: v.user.Primary, Tier: t, Basis: mailTiers[t].basis, Active: active(v.user)}
	}
	return out, order
}

// readAccounts calls read for each account in the order given. It stops
// after the first account whose result the gate says every later one would
// repeat (read returns true), and reports whether it reached the end.
func readAccounts(views []accountView, read func(accountView) (repeats bool)) bool {
	return !slices.ContainsFunc(views, read)
}

// CollectUsers is what Check reads of a tenant: each account's OAuth
// grants in Plan's order, then each readable mailbox's forwarding in its
// own order, through the gate. The evidence's notes are written again over
// everything read.
func CollectUsers(ctx context.Context, sender Sender, target Target, e Evidence, view Context, sel UserSelection) Evidence {
	e.usersPending = false
	if e.Binding.CustomerID == "" {
		e.finish(target.Asset, view)
		return e
	}
	views := accountViews(e, view, attribute(target.Asset, e.Users.Items, view.People, e.Users.Complete))
	e.collectGrants(ctx, sender, target, inOrder(views, sel.Order))
	if e.OAuth.Selected {
		var read []string
		var reads []Read
		for _, a := range e.OAuth.Accounts {
			reads = append(reads, a.Read)
			if a.Usable {
				read = append(read, a.ID)
			}
		}
		e.OAuth.Selection = userSelection("oauth_grants", userTiers, sel.Order, read, reads, sel.InScopeAtLeast)
	}
	e.collectMail(ctx, sender, target, views)
	if e.Mail.Selected {
		var read []string
		var reads []Read
		for _, m := range e.Mail.Accounts {
			reads = append(reads, m.AutoRead, m.FiltersRead)
			if m.AutoUsable {
				read = append(read, m.ID)
			}
		}
		e.Mail.Selection = userSelection("mail_forwarding", mailTiers, e.Mail.order, read, reads, sel.InScopeAtLeast)
	}
	e.finish(target.Asset, view)
	return e
}

// userSelection is the selection of a per-user population a cap, the
// deadline or a rate limit cut: nil when nothing cut it, or when the cut was
// a failure every later account would repeat that is not a limit
// (docs/spec/report.md, "Coverage").
func userSelection(kind string, table []userTier, order []SelectedUser, read []string, reads []Read, inScopeAtLeast bool) *finding.Selection {
	limited := slices.ContainsFunc(reads, limitedRead)
	if !limited || len(read) >= len(order) {
		return nil
	}
	fallback := "active, last sign-in desc, primaryEmail"
	if kind == "mail_forwarding" {
		fallback = "active, primaryEmail"
	}
	return &finding.Selection{Kind: kind, Unit: "users", Fallback: fallback,
		Tiers: tierCounts(table, order, func(u SelectedUser) bool { return slices.Contains(read, u.ID) }),
		Read:  len(read), InScope: len(order), InScopeAtLeast: inScopeAtLeast}
}

// limitedRead says a read was stopped by a limit: the deadline, a rate
// limit, or the Workspace session's token expiring before it was sent.
// The token lives about an hour and expiry never keeps an authorization,
// so a read it stops is unread for time, as a deadline's is.
func limitedRead(r Read) bool {
	return r.Reason == "limit_reached" || r.Decision == "unavailable:bootstrap_required"
}
