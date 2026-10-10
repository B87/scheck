package workspace

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
)

const (
	IDTooManySuperAdmins       = "workspace.too_many_super_admins"
	IDStaleAccount             = "workspace.stale_account"
	IDNeverSignedIn            = "workspace.never_signed_in"
	IDSuspendedAdminAssignment = "workspace.suspended_admin_assignment"
	Fired                      = "fired"
	Disproved                  = "disproved"
	Abstained                  = "abstained"
	neverLogin                 = "1970-01-01T00:00:00.000Z"
)

func init() {
	for _, d := range []finding.Def{
		workspaceDef(IDTooManySuperAdmins, "Workspace has more super administrators than its size needs", finding.SevMedium, "", "More accounts retain full administrative control.", "Reduce super-administrator rights to the people who need them, retaining dedicated recovery accounts."),
		workspaceDef(IDStaleAccount, "Google reports no account sign-in for more than 90 days", finding.SevMedium, "account", "An active account remains available despite no recent reported sign-in; sessions and application activity were not reviewed.", "Confirm whether this account is needed before suspending it; review its sessions and application grants."),
		workspaceDef(IDNeverSignedIn, "An active Workspace account has never signed in", finding.SevLow, "account", "Google reports no sign-in for an account created more than 30 days ago; this does not prove it is unused.", "Confirm whether the account is needed before suspending it."),
		workspaceDef(IDSuspendedAdminAssignment, "A suspended account retains an administrative assignment", finding.SevMedium, "account", "Suspension prevents ordinary sign-in. The retained assignment is cleanup risk, not proven usable access.", "Ask your administrator whether this assignment is still needed, and remove it if not."),
	} {
		finding.Register(d)
	}
}
func workspaceDef(id, title string, severity finding.Severity, subject finding.SubjectKind, impact, fix string) finding.Def {
	return finding.Def{ID: id, Title: title, Category: "accounts", Area: finding.AreaIdentity, Exposure: finding.NotExposure, Subject: subject, Judges: title, BaseSeverity: severity, Impact: impact, Remediation: finding.Remediation{Summary: fix}}
}
func RuleIDs() []string {
	return []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin, finding.IDIdentityFormerPersonHasAccess, IDTooManySuperAdmins, IDStaleAccount, IDNeverSignedIn, IDSuspendedAdminAssignment, IDTwoStepNotEnforced, IDAdminWithoutTwoStep}
}
func yes(v *bool) bool     { return v != nil && *v }
func no(v *bool) bool      { return v != nil && !*v }
func inactive(u User) bool { return yes(u.Suspended) || yes(u.Archived) }
func active(u User) bool   { return no(u.Suspended) && no(u.Archived) }
func person(c Context, handle string) *Person {
	for i := range c.People {
		if c.People[i].Handle == handle {
			return &c.People[i]
		}
	}
	return nil
}
func personForUser(u User, attrs []Attribution, c Context) *Person {
	for _, a := range attrs {
		if a.ProviderID == u.ID {
			return person(c, a.Handle)
		}
	}
	return nil
}
func zone(c Context) *time.Location {
	if c.Zone != nil {
		return c.Zone
	}
	return time.UTC
}
func leftPassed(left string, c Context) bool {
	t, err := time.Parse("2006-01-02", left)
	return err == nil && !c.AssessedAt.IsZero() && t.Format("2006-01-02") < c.AssessedAt.In(zone(c)).Format("2006-01-02")
}
func readUsable(r Read) bool {
	return (r.Decision == "sent" || r.Decision == "reused") && r.Status == 200 && r.Reason == "" && !r.Truncated && len(r.Redactions) == 0
}
func reads(sets ...[]Read) []string {
	out := []string{}
	for _, set := range sets {
		for _, r := range set {
			if r.RequestID != "" && !slices.Contains(out, r.RequestID) {
				out = append(out, r.RequestID)
			}
		}
	}
	return out
}
func subject(u User, p *Person) finding.Subject {
	s := finding.Subject{Kind: "account", Key: strings.ToLower(u.Primary), Label: u.Primary, ProviderID: u.ID}
	if p != nil {
		s.Person = p.Handle
	}
	return s
}
func newJudgment(id, asset string, s finding.Subject, rs []string) finding.Judgment {
	return finding.Judgment{ID: id, Asset: asset, Subject: s, Verdict: Abstained, Reason: "unavailable:workspace_evidence", Reads: rs}
}
func decide(j *finding.Judgment, known, fire bool, text string) {
	j.Excerpt = text
	if known {
		j.Verdict = Disproved
		j.Reason = ""
		if fire {
			j.Verdict = Fired
		}
	}
}

// Judge evaluates redacted current evidence and explicit operator declarations.
// docs/spec/workspace-collector.md, "Rules", "Administrative privilege interpretation".
func Judge(e Evidence, asset string, c Context) []finding.Judgment {
	attrs := attribute(asset, e.Users.Items, c.People, e.Users.Complete)
	out := []finding.Judgment{}
	for _, view := range accountViews(e, c, attrs) {
		u, p, a, rs := view.user, view.person, view.access, view.reads
		admin, adminKnown, adminText, adminReads := view.admin, view.adminKnown, view.adminText, view.adminReads
		superKnown := u.IsAdmin != nil && !a.Conflict
		passed := p != nil && leftPassed(p.Left, c)
		j := newJudgment(finding.IDIdentityUnexpectedAdmin, asset, subject(u, p), rs)
		j.Sources = []string{"access.admins"}
		if p != nil {
			j.Sources = append(j.Sources, "people."+p.Handle+".workspace")
		}
		known := superKnown && (!yes(u.IsAdmin) || c.AdminsDeclared && p != nil && !passed)
		decide(&j, known, yes(u.IsAdmin) && p != nil && !slices.Contains(c.ExpectedAdmins, p.Handle), fmt.Sprintf("%s; isAdmin: %v; attributed declared person: %s; expected administrator declaration: %t", u.Primary, boolValue(u.IsAdmin), handleOf(p), c.AdminsDeclared))
		out = append(out, j)
		tenantPeople := slices.ContainsFunc(c.People, func(p Person) bool { return len(p.Addresses) > 0 })
		ambiguous := false
		if p == nil {
			for _, v := range c.People {
				for _, address := range v.Addresses {
					if userHasAddress(u, address) {
						ambiguous = true
					}
				}
			}
		}
		j = newJudgment(finding.IDIdentityUnattributedAdmin, asset, subject(u, p), adminReads)
		j.Sources = []string{"people"}
		decide(&j, p != nil || adminKnown && !admin || adminKnown && admin && tenantPeople && e.Users.Complete && !ambiguous, admin && p == nil, adminText)
		out = append(out, j)
		for _, rule := range []struct{ id, kind string }{{finding.IDIdentityExternalAdmin, "contractor"}, {finding.IDIdentitySharedAdmin, "shared"}} {
			j = newJudgment(rule.id, asset, subject(u, p), rs)
			j.Sources = []string{"people"}
			decide(&j, superKnown && (!yes(u.IsAdmin) || p != nil && p.Kind != ""), yes(u.IsAdmin) && p != nil && p.Kind == rule.kind, fmt.Sprintf("isAdmin: %v; declared account kind: %s", boolValue(u.IsAdmin), kindOf(p)))
			out = append(out, j)
		}
		if p != nil && p.Left != "" {
			j = newJudgment(finding.IDIdentityFormerPersonHasAccess, asset, subject(u, p), rs)
			j.Sources = []string{"people." + p.Handle + ".left", "people." + p.Handle + ".workspace"}
			primary := slices.ContainsFunc(p.Addresses, func(s string) bool { return strings.EqualFold(s, u.Primary) })
			decide(&j, passed && !a.Conflict && (inactive(u) || primary && active(u)), passed && primary && active(u), fmt.Sprintf("declared left: %s; suspended: %v; archived: %v; primary match: %t", p.Left, boolValue(u.Suspended), boolValue(u.Archived), primary))
			if j.Verdict == Fired && admin {
				j.Attributes = []string{"admin"}
				j.Reads = adminReads
			}
			out = append(out, j)
		}
		j = newJudgment(IDSuspendedAdminAssignment, asset, subject(u, p), adminReads)
		decide(&j, !a.Conflict && (no(u.Suspended) || yes(u.Suspended) && adminKnown), yes(u.Suspended) && admin, "suspended: "+fmt.Sprint(boolValue(u.Suspended))+"; "+adminText+". The account is suspended, so this assignment does not establish usable access. Review whether the retained assignment is still needed.")
		out = append(out, j)
		out = append(out, inactivity(u, a, p, asset, c, rs)...)
	}
	// Departed declarations still need an explicit unknown outcome when identity
	// is missing or ambiguous; absence is decided only over a complete population.
	for _, p := range c.People {
		if !leftPassed(p.Left, c) {
			continue
		}
		addresses := p.Addresses
		if len(addresses) == 0 {
			addresses = []string{"declared:" + p.Handle}
		}
		for _, address := range addresses {
			matched := false
			attributed := false
			for _, u := range e.Users.Items {
				if userHasAddress(u, address) {
					matched = true
					if owner := personForUser(u, attrs, c); owner != nil && owner.Handle == p.Handle {
						attributed = true
					}
				}
			}
			if attributed {
				continue
			}
			j := newJudgment(finding.IDIdentityFormerPersonHasAccess, asset, finding.Subject{Kind: "account", Key: strings.ToLower(address), Label: address, Person: p.Handle}, reads(e.Users.Reads))
			j.Sources = []string{"people." + p.Handle + ".left", "people." + p.Handle + ".workspace"}
			decide(&j, len(p.Addresses) > 0 && !matched && e.Users.Complete, false, "Declared current address was not found. Renamed accounts whose old address was removed cannot be identified by this comparison.")
			if matched || len(p.Addresses) == 0 {
				j.NotChecked = []string{"Declared account identity is missing or ambiguous."}
			}
			out = append(out, j)
		}
	}
	out = append(out, adminCount(e, asset, c, attrs))
	out = append(out, twoStepJudgments(e, asset, c)...)
	if len(e.Users.Items) == 0 {
		for _, id := range RuleIDs() {
			if id == IDTooManySuperAdmins {
				continue
			}
			j := newJudgment(id, asset, finding.Subject{}, reads(e.Users.Reads))
			j.NotChecked = []string{"No current account evidence was available for this rule."}
			out = append(out, j)
		}
	}
	return out
}

// accountView is one current account with what every rule reads about it,
// so administrative interpretation is decided once per account.
type accountView struct {
	user              User
	access            AccountAccess
	person            *Person
	admin, adminKnown bool
	adminText         string
	reads, adminReads []string
}

func accountViews(e Evidence, c Context, attrs []Attribution) []accountView {
	out := []accountView{}
	for _, u := range e.Users.Items {
		a := AccountAccess{ID: u.ID}
		for _, v := range e.Access.Accounts {
			if v.ID == u.ID {
				a = v
				break
			}
		}
		v := accountView{user: u, access: a, person: personForUser(u, attrs, c), reads: reads(e.Users.Reads)}
		v.admin, v.adminKnown, v.adminText = administrative(u, a, e, c)
		v.adminReads = reads(e.Users.Reads, e.Access.Roles.Reads, e.Access.Privileges.Reads, a.Assignments.Reads)
		out = append(out, v)
	}
	return out
}

func boolValue(v *bool) any {
	if v == nil {
		return "unknown"
	}
	return *v
}
func handleOf(p *Person) string {
	if p == nil {
		return "unknown"
	}
	return p.Handle
}
func kindOf(p *Person) string {
	if p == nil {
		return "unknown"
	}
	return p.Kind
}
func userHasAddress(u User, s string) bool {
	return strings.EqualFold(u.Primary, s) || slices.ContainsFunc(append(slices.Clone(u.Aliases), u.NonEditableAliases...), func(a string) bool { return strings.EqualFold(a, s) })
}

func inactivity(u User, a AccountAccess, p *Person, asset string, c Context, rs []string) []finding.Judgment {
	out := []finding.Judgment{}
	exempt := p != nil && (p.Kind == "service" || p.Kind == "break_glass")
	for _, id := range []string{IDStaleAccount, IDNeverSignedIn} {
		j := newJudgment(id, asset, subject(u, p), reads([]Read{a.DetailRead}))
		j.Reads = append(j.Reads, rs...)
		if p != nil {
			j.Sources = []string{"people." + p.Handle + ".kind"}
		}
		if !a.Conflict && (inactive(u) || exempt) {
			decide(&j, true, false, "Account is inactive or explicitly exempt.")
			out = append(out, j)
			continue
		}
		if p == nil && possibleExemption(u, c) {
			out = append(out, j)
			continue
		}
		if !active(u) || a.Conflict || a.Detail == nil || !readUsable(a.DetailRead) || !active(*a.Detail) || c.AssessedAt.IsZero() {
			out = append(out, j)
			continue
		}
		d := a.Detail
		created, creationOK := timestamp(d.CreationTime, c.AssessedAt)
		if d.LastLoginTime == nil {
			out = append(out, j)
			continue
		}
		if *d.LastLoginTime == neverLogin {
			if creationOK {
				decide(&j, id == IDNeverSignedIn, id == IDNeverSignedIn && created.Before(c.AssessedAt.In(zone(c)).AddDate(0, 0, -30)), "Google reports the exact never-sign-in marker; creation: "+created.Format(time.RFC3339))
			}
		} else {
			login, ok := timestamp(d.LastLoginTime, c.AssessedAt)
			if ok && creationOK && !login.Before(created) {
				decide(&j, true, id == IDStaleAccount && login.Before(c.AssessedAt.In(zone(c)).AddDate(0, 0, -90)), "Google reports no sign-in since "+login.Format(time.RFC3339)+". Sessions and application activity were not reviewed.")
			}
		}
		out = append(out, j)
	}
	return out
}
func timestamp(s *string, now time.Time) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	return t, err == nil && !t.After(now)
}

func possibleExemption(u User, c Context) bool {
	for _, p := range c.People {
		if p.Kind == "service" || p.Kind == "break_glass" {
			for _, address := range p.Addresses {
				if userHasAddress(u, address) {
					return true
				}
			}
		}
	}
	return false
}

func adminCount(e Evidence, asset string, c Context, attrs []Attribution) finding.Judgment {
	j := newJudgment(IDTooManySuperAdmins, asset, finding.Subject{}, reads(e.Users.Reads))
	j.Sources = []string{"people"}
	count, humans, breaks := 0, 0, 0
	known := e.Users.Complete
	users := slices.Clone(e.Users.Items)
	slices.SortFunc(users, func(a, b User) int { return strings.Compare(a.ID, b.ID) })
	for _, u := range users {
		p := personForUser(u, attrs, c)
		conflict := slices.ContainsFunc(e.Access.Accounts, func(a AccountAccess) bool { return a.ID == u.ID && a.Conflict })
		if conflict {
			known = false
			continue
		}
		possibleExempt := p == nil && possibleExemption(u, c)
		if possibleExempt {
			known = false
			continue
		}
		excluded := p != nil && p.Kind == "service"
		if p != nil && p.Kind == "break_glass" {
			breaks++
			if breaks <= 2 {
				excluded = true
			}
		}
		if u.IsAdmin == nil {
			known = false
		}
		if yes(u.IsAdmin) && !excluded {
			count++
		}
		if !inactive(u) && !active(u) {
			known = false
		}
		if active(u) && (p == nil || p.Kind != "service" && p.Kind != "break_glass") {
			humans++
		}
	}
	fire := count > 3 || known && humans > 0 && count >= 3 && count*3 > humans
	decide(&j, known && (count < 3 || humans > 0) || count > 3, fire, fmt.Sprintf("Observed %d retained super-administrator flags after exemptions; active-human denominator %d. Suspended accounts cannot ordinarily sign in.", count, humans))
	j.Details = map[string]any{"super_admins": count, "active_humans": humans, "population_complete": e.Users.Complete}
	if !known {
		j.Excerpt = "At least " + j.Excerpt
	}
	return j
}

var privilegedNames = map[string][]string{
	"00haapch16h1ysv": {"ROOT_APP_ADMIN", "ADMIN_APIS_ALL", "USERS_ALL", "USERS_CREATE", "USERS_UPDATE", "USERS_MOVE", "USERS_ALIAS", "USERS_RESET_PASSWORD", "USERS_FORCE_PASSWORD_CHANGE", "USERS_ADD_NICKNAME", "USERS_SUSPEND", "USER_SECURITY_ALL", "ORGANIZATION_UNITS_ALL", "ORGANIZATION_UNITS_CREATE", "ORGANIZATION_UNITS_UPDATE", "ORGANIZATION_UNITS_DELETE", "GROUPS_ALL"},
	"01ci93xb3tmzyin": {"SUPER_ADMIN", "CHANGE_USER_GROUP_MEMBERSHIP"},
}

var narrowNames = map[string][]string{"00haapch16h1ysv": {"USERS_RETRIEVE", "ORGANIZATION_UNITS_RETRIEVE"}, "01ci93xb3tmzyin": {"ADMIN_DASHBOARD"}}

func narrow(p Privilege) bool    { return slices.Contains(narrowNames[p.Service], p.Name) }
func supported(p Privilege) bool { return slices.Contains(privilegedNames[p.Service], p.Name) }
func privilege(p Privilege, tree []Privilege) (bool, bool) {
	if supported(p) {
		return true, true
	}
	if narrow(p) {
		return false, true
	}
	if _, ok := privilegedNames[p.Service]; !ok {
		return false, false
	}
	for _, node := range tree {
		if node.Service == p.Service && node.Name == p.Name {
			found := false
			known := narrow(node)
			var walk func(Privilege)
			walk = func(v Privilege) {
				if !supported(v) && !narrow(v) {
					known = false
				}
				found = found || supported(v)
				for _, child := range v.Children {
					walk(child)
				}
			}
			walk(node)
			return found, known
		}
		if found, known := privilegeInChildren(p, node.Children); found || known {
			return found, known
		}
	}
	return false, false
}
func privilegeInChildren(p Privilege, tree []Privilege) (bool, bool) {
	if len(tree) == 0 {
		return false, false
	}
	return privilege(p, tree)
}
func administrative(u User, a AccountAccess, e Evidence, c Context) (bool, bool, string) {
	if a.Conflict {
		return false, false, "Current account metadata conflicted."
	}
	if yes(u.IsAdmin) {
		return true, true, "isAdmin: true"
	}
	known := no(u.IsAdmin) && a.Assignments.Complete && e.Access.Roles.Complete && e.Access.Privileges.Complete
	texts := []string{}
	for _, assignment := range a.Assignments.Items {
		current, ok := currentAssignment(assignment, c.AssessedAt)
		if !ok {
			known = false
			continue
		}
		if !current {
			continue
		}
		if assignment.Type == "USER" && assignment.Assignee != u.ID || assignment.Type != "USER" && assignment.Type != "GROUP" {
			known = false
			continue
		}
		roleKnown := false
		for _, role := range e.Access.Roles.Items {
			if role.ID != assignment.Role {
				continue
			}
			roleKnown = true
			if role.Privileges == nil || yes(role.Super) {
				known = false
			}
			for _, p := range role.Privileges {
				positive, recognized := privilege(p, e.Access.Privileges.Items)
				if !recognized {
					known = false
				}
				if positive {
					texts = append(texts, p.Service+"/"+p.Name+privilegeLabel(p)+"; "+assignment.Scope+" "+assignment.Unit+"; "+assignment.Type+" assignee "+assignment.Assignee)
				}
			}
		}
		if !roleKnown {
			known = false
		}
	}
	if len(texts) > 0 {
		return true, true, strings.Join(texts, "; ")
	}
	return false, known, "No supported administrative assignment was recognized; unsupported or missing evidence remains unknown."
}
func currentAssignment(a Assignment, now time.Time) (bool, bool) {
	if len(a.Condition) > 0 {
		var condition string
		if json.Unmarshal(a.Condition, &condition) != nil || string(a.Condition) == "null" || condition != "" {
			return false, false
		}
	}
	if len(a.Expiration) == 0 {
		return true, true
	}
	var expiry struct {
		At string `json:"expireTime"`
	}
	if string(a.Expiration) == "null" || json.Unmarshal(a.Expiration, &expiry) != nil || expiry.At == "" || now.IsZero() {
		return false, false
	}
	t, err := time.Parse(time.RFC3339Nano, expiry.At)
	if err != nil {
		return false, false
	}
	return t.After(now), true
}

func privilegeLabel(p Privilege) string {
	if p.Service == "00haapch16h1ysv" && p.Name == "USERS_RESET_PASSWORD" {
		return " (reset account passwords)"
	}
	return ""
}
