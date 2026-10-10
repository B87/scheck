package workspace

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

const (
	IDTwoStepNotEnforced  = "workspace.two_step_not_enforced"
	IDAdminWithoutTwoStep = "workspace.admin_without_two_step"
)

// twoStepParagraph is the fixed client wording for an enforcement finding
// (docs/spec/workspace-collector.md, "Client-facing wording").
const twoStepParagraph = "For these accounts, Google reports that 2-step verification is not currently enforced. Enrollment, counted above, is a separate flag: a user who enrolled can still turn it off while Google does not require it. scheck did not assess organizational-unit policy, grace periods or protection provided by another sign-in service. Review these accounts and the current Admin console settings yourself, or with whoever administers your Workspace."

// federationCaveat goes with every raised instance: a truthful declaration
// can be met by another identity provider that scheck does not read.
const federationCaveat = "Whether these people sign in to Google through another identity provider, for example Okta or Microsoft Entra, that requires a second factor; if so, Google not requiring its own 2-step verification may be expected for them, and the raise above may not apply. scheck did not read that service or Google's single sign-on settings. Super administrators normally sign in to Google directly and need Google's 2-step verification regardless."

func init() {
	finding.Register(workspaceDef(IDTwoStepNotEnforced, "Google does not currently require 2-step verification for these accounts", finding.SevHigh, "org_unit",
		"For these accounts, a stolen, reused or guessed password may be enough to sign in unless the user has turned on 2-step verification themselves. That gives access to their mail and files and to password resets for other services. While Google does not require it, users can turn it off again, and new accounts in the same place may start without it.",
		"In the Admin console, open Security → Authentication → 2-step verification. Check which setting applies to these accounts' organizational unit or groups, and turn on enforcement with a short new-user enrollment period. Tell users before the enforcement date so nobody is locked out. Prefer security keys or passkeys for administrators and for people with access to production or customer data. If people sign in to Google through another identity provider, confirm it requires a second factor for these accounts. Run scheck again to confirm that Google reports them as required."))
	finding.Register(workspaceDef(IDAdminWithoutTwoStep, "An administrator has not enrolled in 2-step verification", finding.SevHigh, "account",
		"Anyone who gets this administrator's password, through phishing, reuse from another site's breach or malware on a laptop, can sign in and use its administrative privileges. Depending on the role, that means resetting other users' passwords and taking over their accounts or, for a super administrator, control of the whole organization, including locking you out of it.",
		"Have this administrator enroll in 2-step verification now, preferably with a security key or passkey. For a break-glass account, register two hardware keys and store them apart. If the role is not needed, remove it or suspend the account until it is enrolled. Then require 2-step verification for administrators in the Admin console (Security → Authentication → 2-step verification) so it cannot be turned off."))
}

// stepAccount is one account's observed 2-step state. Flags are Google's
// current per-account values; nothing here describes unit policy or grace.
type stepAccount struct {
	accountView
	securityConflict    bool // step-3 list/detail conflict on suspension, archive or admin status
	flagConflict        bool // fresh detail disagreed on, or could not be read for, the 2-step flags
	activeKnown, active bool
	enforced, enrolled  *bool
	superUser           bool
}

func (a stepAccount) known() bool     { return !a.securityConflict && !a.flagConflict }
func (a stepAccount) affected() bool  { return a.known() && a.active && no(a.enforced) }
func (a stepAccount) protected() bool { return a.known() && a.active && yes(a.enforced) }
func (a stepAccount) inactive() bool  { return a.activeKnown && !a.active }

type stepUnit struct {
	key, label        string
	inTree, ambiguous bool
	accounts          []stepAccount
	// raised is the declaration comparison for this unit, decided in twoStepView.
	raised bool
}

// stepTally counts the tenant once for the declaration comparison and the
// readout. unknown includes accounts whose activity is unknown.
type stepTally struct {
	active, off, on, unknown int
	superActive, superOn     int
	// superUnknown counts super administrators of unknown activity or flags,
	// and accounts whose super-administrator flag is itself unknown.
	superUnknown int
}

// stepState is the one view both rules and readout notes read, so the
// declaration comparison is decided in one place.
type stepState struct {
	accounts []stepAccount
	units    []stepUnit
	tally    stepTally
	complete bool
	read     bool
	// allOff is a complete active population with every flag known false.
	allOff bool
}

func twoStepFlagsUnreadable(body []byte) bool {
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return true
	}
	for _, key := range []string{"isEnforcedIn2Sv", "isEnrolledIn2Sv"} {
		if v, ok := doc[key]; ok && string(v) != "true" && string(v) != "false" {
			return true
		}
	}
	return false
}

func twoStepConflict(list, detail User) bool {
	for _, pair := range [][2]*bool{{list.Enforced, detail.Enforced}, {list.Enrolled, detail.Enrolled}} {
		if pair[0] != nil && pair[1] != nil && *pair[0] != *pair[1] {
			return true
		}
	}
	return false
}

func twoStepView(e Evidence, asset string, c Context) stepState {
	attrs := attribute(asset, e.Users.Items, c.People, e.Users.Complete)
	s := stepState{complete: e.Users.Complete, read: len(e.Users.Reads) > 0 && readUsable(e.Users.Reads[0])}
	tree := map[string][]string{}
	for _, unit := range e.Units.Items {
		key := strings.ToLower(unit.Path)
		if !slices.Contains(tree[key], unit.Path) {
			tree[key] = append(tree[key], unit.Path)
		}
	}
	index := map[string]int{}
	for _, view := range accountViews(e, c, attrs) {
		u, a := view.user, view.access
		v := stepAccount{accountView: view, securityConflict: a.Conflict, flagConflict: a.TwoStepUnknown}
		v.enforced, v.enrolled = u.Enforced, u.Enrolled
		if a.Detail != nil {
			if v.enforced == nil {
				v.enforced = a.Detail.Enforced
			}
			if v.enrolled == nil {
				v.enrolled = a.Detail.Enrolled
			}
			v.reads = append(v.reads, reads([]Read{a.DetailRead})...)
		} else if a.TwoStepUnknown {
			// Cite the refused fresh detail that made the flags unknown.
			v.reads = append(v.reads, reads([]Read{a.DetailRead})...)
		}
		if !v.known() {
			v.enforced, v.enrolled = nil, nil
		}
		v.activeKnown = !a.Conflict && (active(u) || inactive(u))
		v.active = v.activeKnown && active(u)
		v.superUser = yes(u.IsAdmin) && !a.Conflict
		s.accounts = append(s.accounts, v)
		key := strings.ToLower(u.Unit)
		i, ok := index[key]
		if !ok {
			label := u.Unit
			if paths := tree[key]; len(paths) == 1 {
				label = paths[0]
			}
			i = len(s.units)
			index[key] = i
			s.units = append(s.units, stepUnit{key: key, label: label, inTree: len(tree[key]) > 0, ambiguous: len(tree[key]) > 1})
		}
		s.units[i].accounts = append(s.units[i].accounts, v)
	}
	slices.SortFunc(s.units, func(a, b stepUnit) int { return strings.Compare(a.key, b.key) })
	t := &s.tally
	s.allOff = s.complete
	for _, v := range s.accounts {
		if !v.activeKnown {
			s.allOff = false
			t.unknown++
		}
		if v.user.IsAdmin == nil || v.securityConflict || yes(v.user.IsAdmin) && !v.activeKnown {
			t.superUnknown++
		}
		if !v.active {
			continue
		}
		t.active++
		s.allOff = s.allOff && v.affected()
		switch {
		case v.affected():
			t.off++
		case v.protected():
			t.on++
		default:
			t.unknown++
		}
		if v.superUser {
			t.superActive++
			switch {
			case v.protected():
				t.superOn++
			case !v.affected():
				t.superUnknown++
			}
		}
	}
	s.allOff = s.allOff && t.active > 0
	for i := range s.units {
		u := &s.units[i]
		super := slices.ContainsFunc(u.accounts, func(v stepAccount) bool { return v.affected() && v.superUser })
		off := slices.ContainsFunc(u.accounts, stepAccount.affected)
		u.raised = off && c.MFASource != "" && (c.MFA == "everyone" || c.MFA == "admins" && super || c.MFA == "some" && s.allOff)
	}
	return s
}

// twoStepJudgments reads Google's current per-account flags only
// (docs/spec/workspace-collector.md, "Observed 2-step verification").
func twoStepJudgments(e Evidence, asset string, c Context) []finding.Judgment {
	s := twoStepView(e, asset, c)
	out := []finding.Judgment{}
	if len(e.Users.Items) == 0 {
		return out
	}
	units := 0
	for _, unit := range s.units {
		if !judgedUnit(unit) {
			continue
		}
		units++
		out = append(out, unitJudgment(unit, s, asset, c))
	}
	if units == 0 {
		j := newJudgment(IDTwoStepNotEnforced, asset, finding.Subject{}, reads(e.Users.Reads))
		j.NotChecked = []string{"No active account was observed, so no account's 2-step verification requirement could be judged."}
		if !s.complete {
			j.NotChecked = append(j.NotChecked, "The account list was incomplete.")
		}
		out = append(out, j)
	}
	for _, v := range s.accounts {
		out = append(out, adminTwoStep(v, asset))
	}
	return out
}

// judgedUnit is a unit with at least one account that is or may be active.
func judgedUnit(u stepUnit) bool {
	return slices.ContainsFunc(u.accounts, func(v stepAccount) bool { return !v.inactive() })
}

type unitCounts struct {
	notEnrolled, enrolled, enrollmentUnknown []string
	active, unknown, superOff                int
}

func countUnit(unit stepUnit) unitCounts {
	var n unitCounts
	for _, v := range unit.accounts {
		if v.active {
			n.active++
		}
		switch {
		case v.affected():
			if v.superUser {
				n.superOff++
			}
			switch {
			case no(v.enrolled):
				n.notEnrolled = append(n.notEnrolled, v.user.Primary)
			case yes(v.enrolled):
				n.enrolled = append(n.enrolled, v.user.Primary)
			default:
				n.enrollmentUnknown = append(n.enrollmentUnknown, v.user.Primary)
			}
		case v.protected(), v.inactive():
		default:
			n.unknown++
		}
	}
	for _, list := range [][]string{n.notEnrolled, n.enrolled, n.enrollmentUnknown} {
		slices.SortFunc(list, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	}
	return n
}

// unitVerdict is the one place a unit's outcome is decided: any affected
// account fires; only a complete, unambiguous, fully known unit disproves.
func unitVerdict(unit stepUnit, s stepState) (unitCounts, string) {
	n := countUnit(unit)
	switch {
	case len(n.notEnrolled)+len(n.enrolled)+len(n.enrollmentUnknown) > 0:
		return n, Fired
	case s.complete && unit.inTree && !unit.ambiguous && n.unknown == 0 && n.active > 0:
		return n, Disproved
	}
	return n, Abstained
}

func (u stepUnit) where() string {
	where := "unit " + u.label
	if !u.inTree {
		where += " (unit not found in the unit list)"
	}
	if u.ambiguous {
		where += " (more than one unit has this path when case is ignored)"
	}
	return where
}

func unitJudgment(unit stepUnit, s stepState, asset string, c Context) finding.Judgment {
	j := newJudgment(IDTwoStepNotEnforced, asset, finding.Subject{Kind: "org_unit", Key: unit.key, Label: unit.label}, nil)
	for _, v := range unit.accounts {
		j.Reads = append(j.Reads, v.reads...)
	}
	j.Reads = sortedUnique(j.Reads)
	n, verdict := unitVerdict(unit, s)
	j.Listed = slices.Concat(n.notEnrolled, n.enrolled, n.enrollmentUnknown)
	affected := len(j.Listed)
	j.Details = map[string]any{"affected": affected, "not_enrolled": len(n.notEnrolled), "enrolled": len(n.enrolled), "enrollment_unknown": len(n.enrollmentUnknown), "active_observed": n.active, "state_unknown": n.unknown, "population_complete": s.complete}
	where := unit.where()
	switch verdict {
	case Fired:
		qualifier, why := "", ""
		if n.unknown > 0 {
			qualifier = "at least "
			why += " The activity or 2-step flag of " + plural(n.unknown, "more account") + " in this unit was unknown."
		}
		if !s.complete {
			qualifier = "at least "
			why += " The list of users was incomplete."
		}
		decide(&j, true, true, fmt.Sprintf("Google reports that 2-step verification is not currently required for %s%s in %s (isEnforcedIn2Sv: false).%s Enrollment, as Google reports it: %d not enrolled, %d enrolled, %d unknown. %s %s", qualifier, plural(affected, "active account"), where, why, len(n.notEnrolled), len(n.enrolled), len(n.enrollmentUnknown), listAccounts(n.notEnrolled, n.enrolled, n.enrollmentUnknown), twoStepParagraph))
		if unit.raised {
			j.Attributes = []string{"contradiction"}
			j.Sources = []string{c.MFASource}
			j.Context = raisedWhy(c, n.superOff)
			j.NotChecked = []string{federationCaveat}
		}
	case Disproved:
		decide(&j, true, false, fmt.Sprintf("Google reports every active account observed in %s as currently required to use 2-step verification (%s).", where, plural(n.active, "active account")))
	default:
		j.Excerpt = fmt.Sprintf("%s observed in %s; no account was reported without the requirement.", plural(n.active, "active account"), where)
		if n.unknown > 0 {
			j.NotChecked = append(j.NotChecked, plural(n.unknown, "account")+" in this unit had an unknown, missing or conflicting activity or 2-step verification flag.")
		}
		if !s.complete {
			j.NotChecked = append(j.NotChecked, "The account list was incomplete, so an account without the requirement may not have been read.")
		}
		if !unit.inTree || unit.ambiguous {
			j.NotChecked = append(j.NotChecked, "This unit could not be matched to exactly one unit in the unit list.")
		}
	}
	return j
}

// raisedWhy is one sentence, so "Fix these first" can quote it whole.
func raisedWhy(c Context, superOff int) string {
	switch c.MFA {
	case "admins":
		return "You declared that every super administrator must use 2-step verification in this tenant, and Google does not require it for " + plural(superOff, "super administrator") + " in this unit, so this ranks one step higher."
	case "some":
		return "You declared that some accounts must use 2-step verification in this tenant, but Google requires it for no active account in the tenant, so this ranks one step higher."
	}
	return "You declared that every account must use 2-step verification in this tenant, so this ranks one step higher."
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// listAccounts names affected accounts in the text, capped; the finding's
// affected list carries every one.
func listAccounts(groups ...[]string) string {
	const shown = 20
	parts, n, total := []string{}, 0, 0
	for i, group := range groups {
		total += len(group)
		take := min(len(group), max(shown-n, 0))
		if take > 0 {
			parts = append(parts, []string{"Not enrolled: ", "Enrolled: ", "Enrollment unknown: "}[i]+strings.Join(group[:take], ", ")+".")
			n += take
		}
	}
	if total > n {
		parts = append(parts, fmt.Sprintf("And %d more, listed in the JSON report (--format json).", total-n))
	}
	return strings.Join(parts, " ")
}

func adminTwoStep(v stepAccount, asset string) finding.Judgment {
	j := newJudgment(IDAdminWithoutTwoStep, asset, subject(v.user, v.person), v.reads)
	if v.admin {
		j.Reads = sortedUnique(append(j.Reads, v.adminReads...))
	}
	role := "administrator status: unknown"
	if v.superUser {
		role = "super administrator (isAdmin: true)"
	} else if v.admin {
		role = "holds a supported administrative privilege: " + v.adminText
	} else if v.adminKnown {
		role = "no administrative privilege recognized"
	}
	switch {
	case v.securityConflict:
		j.Excerpt = v.user.Primary + ": current list and fresh detail disagreed on suspension, archive or administrator status; 2-step verification was not judged."
		j.NotChecked = []string{"The account's current status is unknown."}
	case v.flagConflict:
		j.Excerpt = v.user.Primary + ": 2-step verification flags conflicted or were unreadable in fresh account detail."
		j.NotChecked = []string{"Current list and detail values disagreed or the detail could not be read; enrollment remains unknown."}
	case yes(v.enrolled):
		decide(&j, true, false, v.user.Primary+": isEnrolledIn2Sv: true. This does not establish the verification method or phishing resistance.")
	case v.inactive():
		decide(&j, true, false, v.user.Primary+": suspended or archived; "+role+".")
	case v.adminKnown && !v.admin:
		decide(&j, true, false, v.user.Primary+": "+role+".")
	case v.active && v.admin && no(v.enrolled):
		text := v.user.Primary + ": " + role + "; isEnrolledIn2Sv: false."
		if yes(v.enforced) {
			text += " Google requires 2-step verification for this account but reports it not yet enrolled; until it enrolls, a password alone may sign it in."
		}
		decide(&j, true, true, text)
	default:
		j.Excerpt = fmt.Sprintf("%s: %s; isEnrolledIn2Sv: %v; suspended: %v; archived: %v.", v.user.Primary, role, boolValue(v.enrolled), boolValue(v.user.Suspended), boolValue(v.user.Archived))
	}
	return j
}

// twoStepNotes owns the readout wording: limits, possible grace, what was
// not judged, and the comparison with the declaration
// (docs/spec/engagement.md, "2-step verification").
func twoStepNotes(e Evidence, asset string, c Context) []Note {
	s := twoStepView(e, asset, c)
	if !s.read {
		return nil
	}
	out := []Note{}
	note := func(text string) { out = append(out, Note{Kind: "workspace_inventory", Source: asset, Detail: text}) }
	note("2-step verification checks read Google's current per-account enforcement and enrollment flags. Organizational-unit policy, grace periods, configuration groups, sign-in through another identity provider, verification methods, backup codes and phishing resistance were not assessed.")
	atLeast := func(n int, noun string) string {
		if !s.complete {
			return "at least " + plural(n, noun)
		}
		return plural(n, noun)
	}
	var grace, unknownAdmin []string
	for _, v := range s.accounts {
		if v.flagConflict {
			note("2-step verification flags for " + v.user.Primary + " (account id " + v.user.ID + ") conflicted or were unreadable in Google's fresh account detail; its 2-step verification state remains unknown.")
		}
		if !v.active || !v.known() || !no(v.enrolled) || v.admin {
			continue
		}
		if yes(v.enforced) {
			grace = append(grace, v.user.Primary)
		} else if !v.adminKnown {
			unknownAdmin = append(unknownAdmin, v.user.Primary)
		}
	}
	unjudged := []string{}
	for _, unit := range s.units {
		if unit.ambiguous {
			note("Two units are both called " + unit.label + ", written with different capitals. scheck could not tell which accounts belong to which, so it did not decide 2-step verification for " + unit.label + ". Rename one in the Admin console and run again.")
		}
		if !judgedUnit(unit) {
			continue
		}
		if n, verdict := unitVerdict(unit, s); verdict == Abstained {
			label := unit.label
			if n.unknown > 0 {
				label += " (" + plural(n.unknown, "account") + " with a missing, unreadable or conflicting flag or activity status)"
			}
			unjudged = append(unjudged, label)
		}
	}
	if len(unjudged) > 0 {
		note("scheck could not tell whether Google requires 2-step verification for every active account in " + plural(len(unjudged), "organizational unit") + ": " + strings.Join(unjudged, ", ") + ". Treat these units as not checked, not as fine.")
	}
	if !s.complete {
		note("The list of users was incomplete, so no organizational unit could be shown to require 2-step verification for every account.")
	}
	if len(grace) > 0 {
		slices.Sort(grace)
		note(fmt.Sprintf("Google requires 2-step verification for %s that it reports as not yet enrolled: %s. Either they are still within an enrollment period, when a password alone signs them in, or the period has ended and Google will not let them sign in until they enroll. scheck cannot read which. Check these accounts in the Admin console.", atLeast(len(grace), "account"), strings.Join(grace, ", ")))
	}
	if len(unknownAdmin) > 0 {
		slices.Sort(unknownAdmin)
		note(fmt.Sprintf("Google reports %s not enrolled in 2-step verification whose administrative status scheck could not establish: %s. If any of them is an administrator, it is an administrator without 2-step verification.", atLeast(len(unknownAdmin), "account"), strings.Join(unknownAdmin, ", ")))
	}
	t := s.tally
	required := " Required is not the same as enrolled: an account can be required and still sign in with a password alone during its enrollment period."
	switch c.MFA {
	case "", "unknown":
		text := ""
		switch {
		case !s.complete && t.off == 0:
			text = "No observed active account in this Workspace was reported without the 2-step verification requirement, but the list of users was incomplete (see the inventory notes for why)."
		case !s.complete:
			verb := " were"
			if t.active == 1 {
				verb = " was"
			}
			text = fmt.Sprintf("Google reports at least %s in this Workspace not currently required to use 2-step verification; %s%s observed and the list of users was incomplete (see the inventory notes for why).", plural(t.off, "active account"), plural(t.active, "active account"), verb)
		case t.active == 0:
		case t.off == 0 && t.unknown == 0:
			text = fmt.Sprintf("Google reports that every active account in this Workspace (%s) is currently required to use 2-step verification.", plural(t.active, "active account"))
		default:
			text = fmt.Sprintf("Google reports %d of %s in this Workspace not currently required to use 2-step verification.", t.off, plural(t.active, "active account"))
			if t.unknown > 0 {
				text += " Activity or the requirement was unknown for " + plural(t.unknown, "account") + "."
			}
		}
		if text != "" {
			if t.off > 0 {
				text += " They are listed in the 2-step verification findings."
			}
			if c.MFA == "unknown" {
				text += " You answered that you do not know who must use it."
			} else {
				text += " You did not say who must use it; declare it under access.mfa in the engagement file."
			}
			note(text)
		}
	case "none":
		if t.on > 0 {
			note("Google reports " + atLeast(t.on, "active account") + " currently required to use 2-step verification, more than you declared.")
		}
	case "everyone", "some":
		if s.complete && t.unknown == 0 && t.active > 0 && t.on == t.active {
			than := "as you declared"
			if c.MFA == "some" {
				than = "more than you declared"
			}
			note("Google reports every active account currently required to use 2-step verification, " + than + "." + required)
		}
	case "admins":
		if s.complete && t.superUnknown == 0 && t.superActive > 0 && t.superOn == t.superActive {
			note("Google reports every super administrator observed currently required to use 2-step verification, as you declared." + required)
		}
	}
	return out
}
