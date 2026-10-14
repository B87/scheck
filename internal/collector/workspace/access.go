package workspace

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
)

type Privilege struct {
	Service  string      `json:"serviceId"`
	Name     string      `json:"privilegeName"`
	OU       *bool       `json:"isOuScopable,omitempty"`
	Children []Privilege `json:"childPrivileges,omitempty"`
}
type Role struct {
	ID         string      `json:"roleId"`
	Name       string      `json:"roleName"`
	Privileges []Privilege `json:"rolePrivileges"`
	Super      *bool       `json:"isSuperAdminRole,omitempty"`
}
type Assignment struct {
	ID         string          `json:"roleAssignmentId"`
	Role       string          `json:"roleId"`
	Assignee   string          `json:"assignedTo"`
	Type       string          `json:"assigneeType"`
	Scope      string          `json:"scopeType"`
	Unit       string          `json:"orgUnitId,omitempty"`
	Condition  json.RawMessage `json:"condition,omitempty"`
	Expiration json.RawMessage `json:"expirationDetails,omitempty"`
}
type AccountAccess struct {
	ID          string                 `json:"id"`
	Assignments Population[Assignment] `json:"assignments"`
	Detail      *User                  `json:"detail,omitempty"`
	DetailRead  Read                   `json:"detail_read"`
	Conflict    bool                   `json:"conflict,omitempty"`
	// TwoStepUnknown marks fresh detail that disagreed on, or could not be
	// read for, the 2-step flags; only the 2-step rules abstain on it.
	TwoStepUnknown bool `json:"two_step_unknown,omitempty"`
}
type AccessEvidence struct {
	InterpretationGaps     []string              `json:"interpretation_gaps,omitempty"`
	AdministrationComplete bool                  `json:"administration_complete"`
	Roles                  Population[Role]      `json:"roles"`
	Privileges             Population[Privilege] `json:"privileges"`
	Accounts               []AccountAccess       `json:"accounts"`
	Complete               bool                  `json:"complete"`
}

// collectAccess keeps the request sequence and budget ordering inside Collect.
// docs/spec/workspace-collector.md, "Reads and projections", "Dates and fresh evidence".
func (e *Evidence) collectAccess(ctx context.Context, sender Sender, target Target, view Context) {
	req := func(op string) gate.Request {
		return gate.Request{Op: op, Asset: target.Asset, Stage: target.Stage, Exists: true, Params: map[string]string{"domain": e.Binding.Domain}}
	}
	e.Access.Roles = population(ctx, sender, req(OpRoles), func(v Role) string { return v.ID }, func(v Role) bool { return v.ID != "" })
	e.Access.Privileges = population(ctx, sender, req(OpPrivileges), func(v Privilege) string { return v.Service + ":" + v.Name }, func(v Privilege) bool { return v.Service != "" && v.Name != "" })
	valid := func(v Assignment) bool {
		// Directory returns user and group; a missing type never becomes USER.
		typ := strings.ToUpper(v.Type)
		return v.ID != "" && v.Role != "" && v.Assignee != "" && (typ == "USER" || typ == "GROUP") && (v.Scope == "CUSTOMER" || v.Scope == "ORG_UNIT" && v.Unit != "")
	}

	users := slices.Clone(e.Users.Items)
	attributions := attribute(target.Asset, e.Users.Items, view.People, e.Users.Complete)
	slices.SortFunc(users, func(a, b User) int {
		if x := readPriority(a, attributions, view) - readPriority(b, attributions, view); x != 0 {
			return x
		}
		return strings.Compare(a.ID, b.ID)
	})
	observations := 0
	for _, u := range users {
		account := AccountAccess{ID: u.ID}
		request := req(OpUserAssignments)
		request.Params["user"] = u.ID
		if observations < 10000 {
			account.Assignments = population(ctx, sender, request, func(v Assignment) string { return v.ID }, valid)
			for i := range account.Assignments.Items {
				account.Assignments.Items[i].Type = strings.ToUpper(account.Assignments.Items[i].Type)
			}
			observations += len(account.Assignments.Items)
		} else {
			account.Assignments.Gaps = []string{"assignment_limit"}
		}
		p := personForUser(u, attributions, view)
		if !inactive(u) && (p == nil || p.Kind != "service" && p.Kind != "break_glass") {
			request = req(OpUserDetail)
			request.Params["user"] = u.ID
			result := sender.Send(ctx, request)
			account.DetailRead = readOf(OpUserDetail, result)
			if usable(result) && len(result.Response.Redactions) == 0 {
				var detail User
				if json.Unmarshal(result.Response.Body, &detail) == nil && detail.ID == u.ID && strings.EqualFold(detail.Primary, u.Primary) && detail.Customer == u.Customer && strings.EqualFold(detail.Unit, u.Unit) {
					account.Detail = &detail
					account.Conflict = securityConflict(u, detail)
					account.TwoStepUnknown = twoStepFlagsUnreadable(result.Response.Body) || twoStepConflict(u, detail)
				} else {
					account.DetailRead.Reason = "insufficient_evidence"
				}
			}
			// A fresh answer that was refused or rejected must not fall back
			// to the list's 2-step flags; a failed read still may.
			if account.Detail == nil && result.Response != nil && result.Response.Status == 200 {
				account.TwoStepUnknown = true
			}
		}
		e.Access.Accounts = append(e.Access.Accounts, account)
	}
	e.Access.AdministrationComplete = e.Access.Roles.Complete && e.Access.Privileges.Complete && e.Users.Complete
	e.Access.Complete = e.Access.AdministrationComplete
	for _, a := range e.Access.Accounts {
		e.Access.AdministrationComplete = e.Access.AdministrationComplete && a.Assignments.Complete && !a.Conflict
		e.Access.Complete = e.Access.Complete && a.Assignments.Complete && !a.Conflict && (a.DetailRead.Op == "" || readUsable(a.DetailRead))
	}
	for _, u := range e.Users.Items {
		for _, a := range e.Access.Accounts {
			if a.ID == u.ID {
				_, known, _ := administrative(u, a, *e)
				if !known {
					e.Access.AdministrationComplete = false
					e.Access.InterpretationGaps = append(e.Access.InterpretationGaps, "Administrative privilege interpretation remains unknown for "+u.Primary+"; roles, privileges, conditions or expiry were not fully interpretable.")
				}
			}
		}
	}
}

// readAccounts calls read for each account in optional-surface read order:
// passed leavers, super administrators, contractors, then the rest, active
// before inactive within each, then by id. It stops after the first account
// whose result the gate says every later one would repeat (read returns
// true), and reports whether it reached the end.
func readAccounts(views []accountView, read func(accountView) (repeats bool)) bool {
	ordered := slices.Clone(views)
	rank := func(v accountView) int {
		r := personPriority(v.user, v.person) * 2
		if !active(v.user) {
			r++
		}
		return r
	}
	slices.SortFunc(ordered, func(a, b accountView) int {
		if x := rank(a) - rank(b); x != 0 {
			return x
		}
		return strings.Compare(a.user.ID, b.user.ID)
	})
	return !slices.ContainsFunc(ordered, read)
}

// personPriority is readPriority for an account whose person is known.
func personPriority(u User, p *Person) int {
	switch {
	case p != nil && p.Left != "":
		// Read selection, before any read time is known: a declared
		// leaver's account is read first whether or not the date has
		// passed; Judge decides that at the read's time.
		return 0
	case yes(u.IsAdmin):
		return 1
	case p != nil && p.Kind == "contractor":
		return 2
	}
	return 3
}

// readPriority orders per-account reads so a budget cut loses the least:
// declared leavers, super administrators, contractors, then everyone else.
func readPriority(u User, attributions []Attribution, view Context) int {
	for _, a := range attributions {
		if a.ProviderID == u.ID {
			if p := person(view, a.Handle); p != nil && p.Left != "" {
				return 0
			}
		}
	}
	if yes(u.IsAdmin) {
		return 1
	}
	for _, a := range attributions {
		if a.ProviderID == u.ID {
			if p := person(view, a.Handle); p != nil && p.Kind == "contractor" {
				return 2
			}
		}
	}
	return 3
}

func securityConflict(a, b User) bool {
	for _, pair := range [][2]*bool{{a.Suspended, b.Suspended}, {a.Archived, b.Archived}, {a.IsAdmin, b.IsAdmin}, {a.IsDelegatedAdmin, b.IsDelegatedAdmin}} {
		if pair[0] != nil && pair[1] != nil && *pair[0] != *pair[1] {
			return true
		}
	}
	if a.CreationTime != nil && b.CreationTime != nil {
		x, ex := time.Parse(time.RFC3339Nano, *a.CreationTime)
		y, ey := time.Parse(time.RFC3339Nano, *b.CreationTime)
		if ex == nil && ey == nil && !x.Equal(y) {
			return true
		}
	}
	if a.LastLoginTime != nil && b.LastLoginTime != nil && *a.LastLoginTime != neverLogin {
		x, ex := time.Parse(time.RFC3339Nano, *a.LastLoginTime)
		y, ey := time.Parse(time.RFC3339Nano, *b.LastLoginTime)
		if ex == nil && ey == nil && y.Before(x) {
			return true
		}
	}
	return false
}
