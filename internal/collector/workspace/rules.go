package workspace

import (
	"cmp"
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

// baselineRuleIDs are the rules every profile judges; each optional
// surface's rule speaks for itself, and only when selected.
func baselineRuleIDs() []string {
	return []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin, finding.IDIdentityFormerPersonHasAccess, IDTooManySuperAdmins, IDStaleAccount, IDNeverSignedIn, IDSuspendedAdminAssignment, IDTwoStepNotEnforced, IDAdminWithoutTwoStep}
}

// RuleIDs are every rule the collector judges.
func RuleIDs() []string    { return append(baselineRuleIDs(), IDOAuthBroadScope, IDExternalForwarding) }
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

// readTimes are the collection times of the reads that returned a
// response; one with no recorded time is a zero, which no time-dependent
// rule judges at another clock.
func readTimes(rs []Read) []time.Time {
	var out []time.Time
	for _, r := range rs {
		if r.Status != 0 {
			out = append(out, r.CollectedAt)
		}
	}
	return out
}

// leftAt is when a declared leaving date passed relative to the users
// reads, which a leaver judgment rests on whether it found the account or
// not.
func leftAt(left string, c Context, users []Read) finding.Leaving {
	return finding.LeftAt(left, zone(c), readTimes(users))
}

// leftReason is a leaver judgment's abstention when the date had not
// passed at the earliest read; with nothing read, reason, the judgment's
// own for missing evidence, stands.
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

// usersAsOf names the earliest users read, in the zone.
func usersAsOf(c Context, users []Read) string {
	first, _, ok := finding.Span(readTimes(users))
	if !ok {
		return "an unrecorded time"
	}
	return finding.ReadDate(first, zone(c))
}

// assignmentsAt is when an account's role assignments were read: the
// earliest of their reads, zero when one carries no time, which leaves an
// expiring assignment's currency unknown.
func assignmentsAt(a AccountAccess) time.Time {
	first, _, ok := finding.Span(readTimes(a.Assignments.Reads))
	if !ok {
		return time.Time{}
	}
	return first
}
func readUsable(r Read) bool {
	// The filters read's HTTP 204 with no body is an empty list. The status
	// stays 204 (docs/spec/workspace-collector.md, "Reads and projections").
	statusOK := r.Status == 200 || (r.Op == OpMailFilters && r.Status == 204)
	return (r.Decision == "sent" || r.Decision == "reused") && statusOK && r.Reason == "" && !r.Truncated && len(r.Redactions) == 0
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
	views := accountViews(e, c, attrs)
	for _, view := range views {
		u, p, a, rs := view.user, view.person, view.access, view.reads
		admin, adminKnown, adminText, adminReads := view.admin, view.adminKnown, view.adminText, view.adminReads
		superKnown := u.IsAdmin != nil && !a.Conflict
		left := finding.LeftNotPassed
		if p != nil && p.Left != "" {
			left = leftAt(p.Left, c, e.Users.Reads)
		}
		passed := left == finding.LeftPassed
		j := newJudgment(finding.IDIdentityUnexpectedAdmin, asset, subject(u, p), rs)
		j.Sources = []string{"access.admins"}
		if p != nil {
			j.Sources = append(j.Sources, "people."+p.Handle+".workspace")
		}
		// An administrator whose leaving date is ambiguous at the reads is
		// neither a current person nor offboarding's: it abstains.
		known := superKnown && (!yes(u.IsAdmin) || c.AdminsDeclared && p != nil && !passed && !leftAmbiguous(left))
		decide(&j, known, yes(u.IsAdmin) && p != nil && !slices.Contains(c.ExpectedAdmins, p.Handle), fmt.Sprintf("%s; isAdmin: %v; attributed declared person: %s; expected administrator declaration: %t", u.Primary, boolValue(u.IsAdmin), handleOf(p), c.AdminsDeclared))
		if !known && yes(u.IsAdmin) && leftAmbiguous(left) {
			j.Reason = leftReason(left, j.Reason)
		}
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
			decide(&j, passed && !a.Conflict && (inactive(u) || primary && active(u)), passed && primary && active(u), fmt.Sprintf("declared left: %s; suspended: %v; archived: %v; primary match: %t; account observed in the users read of %s", p.Left, boolValue(u.Suspended), boolValue(u.Archived), primary, usersAsOf(c, e.Users.Reads)))
			if !passed {
				j.Reason = leftReason(left, j.Reason)
			}
			// An account that was read but not decided says why, so the
			// person line never reads it as an unread users list
			// (docs/spec/report.md, "People who left").
			if j.Verdict == Abstained && passed {
				switch {
				case a.Conflict:
					j.NotChecked = []string{finding.NotCheckedLeaverUnrecognized}
				case !primary && active(u):
					j.NotChecked = []string{finding.NotCheckedLeaverIdentity}
				default:
					j.NotChecked = []string{finding.NotCheckedLeaverUnrecognized}
				}
			}
			if j.Verdict == Fired && admin {
				j.Reads = adminReads
				j.Attributes = []finding.Attribute{{Name: "admin"}}
			}
			if j.Verdict == Fired {
				j.NotChecked = append(j.NotChecked, e.leaverUnread(u, c)...)
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
		if p.Left == "" {
			continue
		}
		left := leftAt(p.Left, c, e.Users.Reads)
		// Not passed, or nothing read: no absence to judge, but the person
		// still gets an attributed abstention, so every left person's
		// Workspace line reads a judgment (docs/spec/report.md, "People
		// who left").
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
			// An absence is as current as the earliest users read: one read
			// before the date passed says nothing about offboarding.
			text := "Declared current address was not found as of " + usersAsOf(c, e.Users.Reads) + " (earliest of the users reads). Renamed accounts whose old address was removed cannot be identified by this comparison."
			switch left {
			case finding.LeftUnread:
				text = "The users were not read."
				j.NotChecked = []string{finding.NotCheckedUsersUnread}
			case finding.LeftNotPassed:
				text = "The declared leaving date " + p.Left + " had not passed at the users read of " + usersAsOf(c, e.Users.Reads) + "."
			}
			decide(&j, left == finding.LeftPassed && len(p.Addresses) > 0 && !matched && e.Users.Complete, false, text)
			if left != finding.LeftPassed {
				j.Reason = leftReason(left, j.Reason)
			}
			if left != finding.LeftUnread && (matched || len(p.Addresses) == 0) {
				j.NotChecked = []string{finding.NotCheckedLeaverIdentity}
			}
			// Absent from a list known to be partial: not seen, never gone.
			if left == finding.LeftPassed && len(p.Addresses) > 0 && !matched && !e.Users.Complete {
				j.NotChecked = []string{finding.NotCheckedUsersIncomplete}
			}
			out = append(out, j)
		}
	}
	out = append(out, adminCount(e, asset, c, attrs))
	out = append(out, twoStepJudgments(e, asset, c)...)
	out = append(out, oauthJudgments(e, asset, views)...)
	out = append(out, mailJudgments(e, asset, views, c)...)
	if len(e.Users.Items) == 0 {
		for _, id := range baselineRuleIDs() {
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
		v.admin, v.adminKnown, v.adminText = administrative(u, a, e)
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
		if !active(u) || a.Conflict || a.Detail == nil || !readUsable(a.DetailRead) || !active(*a.Detail) {
			out = append(out, j)
			continue
		}
		// Judged at the detail read that returned the sign-in and creation
		// times, never the session's start (docs/spec/engagement.md,
		// "Severity in context").
		at := a.DetailRead.CollectedAt
		if at.IsZero() {
			j.Reason = finding.ReasonNoCollectionTime
			out = append(out, j)
			continue
		}
		read := finding.ReadDate(at, zone(c))
		d := a.Detail
		created, creationOK := timestamp(d.CreationTime, at)
		if d.LastLoginTime == nil {
			out = append(out, j)
			continue
		}
		if *d.LastLoginTime == neverLogin {
			if creationOK {
				decide(&j, id == IDNeverSignedIn, id == IDNeverSignedIn && created.Before(at.In(zone(c)).AddDate(0, 0, -30)),
					fmt.Sprintf("Google reports the exact never-sign-in marker: created %s, no sign-in as of the account read of %s (%d days)", created.Format(time.RFC3339), read, days(created, at)))
			}
		} else {
			login, ok := timestamp(d.LastLoginTime, at)
			if ok && creationOK && !login.Before(created) {
				decide(&j, true, id == IDStaleAccount && login.Before(at.In(zone(c)).AddDate(0, 0, -90)),
					fmt.Sprintf("Google reports last sign-in %s, %d days before the account read of %s. Sessions and application activity were not reviewed.", login.Format(time.RFC3339), days(login, at), read))
			}
		}
		out = append(out, j)
	}
	return out
}

// clockSkew is how far a provider timestamp may run past the read that
// returned it before it is malformed.
const clockSkew = 5 * time.Minute

// timestamp parses a provider time; one later than the read that returned
// it, beyond clockSkew, is malformed.
func timestamp(s *string, read time.Time) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	return t, err == nil && !t.After(read.Add(clockSkew))
}

// days is the whole days from t to at.
func days(t, at time.Time) int { return int(at.Sub(t).Hours() / 24) }

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
func administrative(u User, a AccountAccess, e Evidence) (bool, bool, string) {
	if a.Conflict {
		return false, false, "Current account metadata conflicted."
	}
	if yes(u.IsAdmin) {
		return true, true, "isAdmin: true"
	}
	known := no(u.IsAdmin) && a.Assignments.Complete && e.Access.Roles.Complete && e.Access.Privileges.Complete
	texts := []string{}
	for _, assignment := range a.Assignments.Items {
		current, ok := currentAssignment(assignment, assignmentsAt(a))
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

// leaverUnread names, for a fired leaver, the account's OAuth grants and
// mail forwarding that were not read: tier 1 reads them first, so F2 is
// no follow-up row, and the finding says what that order did not reach
// (docs/spec/workspace-collector.md, "Rules").
func (e Evidence) leaverUnread(u User, c Context) []string {
	var out []string
	address := u.Primary
	stopped := func(reads []Read) string {
		for _, r := range reads {
			if limitedRead(r) {
				return "the run stopped first (" + cmp.Or(r.Detail, "a limit was reached") + ")"
			}
		}
		return "the run stopped first (a limit was reached)"
	}
	failed := func(r Read) string {
		return "the read failed: " + cmp.Or(r.Detail, strings.ReplaceAll(strings.TrimPrefix(cmp.Or(r.Reason, r.Decision), "unavailable:"), "_", " "))
	}
	switch i := slices.IndexFunc(e.OAuth.Accounts, func(a AccountGrants) bool { return a.ID == u.ID }); {
	case !e.OAuth.Selected:
		out = append(out, "Third-party app grants of "+address+" were not read: the optional OAuth grants profile is not selected (`directory_oauth`)")
	case i < 0:
		var reads []Read
		for _, a := range e.OAuth.Accounts {
			reads = append(reads, a.Read)
		}
		out = append(out, "Third-party app grants of "+address+" were not read: "+stopped(reads))
	case !e.OAuth.Accounts[i].Usable:
		out = append(out, "Third-party app grants of "+address+" were not read: "+failed(e.OAuth.Accounts[i].Read))
	}
	mail := "Mail forwarding from " + address + " was not read: "
	switch i := slices.IndexFunc(e.Mail.Accounts, func(a MailboxForwarding) bool { return a.ID == u.ID }); {
	case i >= 0 && e.Mail.Accounts[i].AutoUsable && e.Mail.Accounts[i].FiltersUsable:
	case c.MailApproval == nil:
		out = append(out, mail+"`authorization.mailboxes` does not name this mailbox")
	case !c.MailApproval.Current:
		out = append(out, mail+"`authorization.mailboxes` is not current")
	case !e.Mail.Selected:
		// The profile's own coverage line says forwarding was not read.
	case i < 0:
		var reads []Read
		for _, a := range e.Mail.Accounts {
			reads = append(reads, a.AutoRead, a.FiltersRead)
		}
		out = append(out, mail+stopped(reads))
	default:
		r := e.Mail.Accounts[i].AutoRead
		if e.Mail.Accounts[i].AutoUsable {
			r = e.Mail.Accounts[i].FiltersRead
		}
		out = append(out, mail+failed(r))
	}
	return out
}
