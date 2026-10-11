package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// workspaceGroups are the coverage sub-items over Workspace rule ids; every
// id the collector judges belongs to exactly one (workspace_test.go).
var workspaceGroups = []struct {
	name, limit string
	// empty is the detail of an always group with no outcome.
	empty string
	ids   []string
	// assignments marks the group whose absence verdicts need role and
	// assignment interpretation.
	assignments bool
	// always marks a group the collector judges for every read account, so
	// no judgment means not assessed, never not applicable.
	always bool
	// unassessed names the group in the row's reason when nothing in it
	// was decided.
	unassessed string
}{
	{name: "Workspace administrator identity", ids: []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin}},
	{name: "Workspace offboarding", ids: []string{finding.IDIdentityFormerPersonHasAccess}},
	{name: "Workspace administrator assignments and counts", ids: []string{"workspace.too_many_super_admins", "workspace.suspended_admin_assignment"}, assignments: true},
	{name: "Workspace account sign-in", ids: []string{"workspace.stale_account", "workspace.never_signed_in"}},
	{name: "Workspace 2-step verification (Google's enforcement and enrollment flags)", ids: []string{"workspace.two_step_not_enforced", "workspace.admin_without_two_step"}, always: true,
		empty: "No 2-step verification outcome was recorded for this tenant",
		limit: "Checked: each account's 2-step verification enforcement and enrollment as Google reports it. Not checked: organizational-unit policy, grace periods, sign-in through another identity provider, verification methods and phishing resistance"},
	{name: "Workspace OAuth grants (third-party app access)", ids: []string{"workspace.oauth_broad_scope"}, always: true, unassessed: "OAuth grants",
		empty: "No OAuth grant outcome was recorded for this tenant",
		limit: "Checked: the apps each account authorized with its Google account and the access Google reports they hold. Not checked: domain-wide delegation, service-account keys, apps an administrator installed for everyone from Marketplace, app passwords, when each app was authorized or last used, and what any app did with its access"},
}

const workspaceDelegation = "Workspace domain-wide delegation"

func (b *builder) workspaceCoverage(row *Row, a AssetInput) bool {
	groups := workspaceGroups
	some := false
	unassessed := []string{}
	for _, group := range groups {
		si := SubItem{Name: group.name, Asset: a.ID, Rules: group.ids, Mark: "not_assessed", Reasons: []ReasonDetail{}}
		if i := slices.IndexFunc(a.NotOnPlan, func(n NotOnPlan) bool {
			return slices.ContainsFunc(n.Rules, func(id string) bool { return slices.Contains(group.ids, id) })
		}); i >= 0 {
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: a.NotOnPlan[i].Reason, Detail: a.NotOnPlan[i].Detail})
			row.SubItems = append(row.SubItems, si)
			continue
		}
		decided, unknown, unclassified := 0, 0, 0
		for _, j := range a.Judged {
			if !slices.Contains(group.ids, j.ID) {
				continue
			}
			if j.Verdict == verdictAbstained {
				unknown++
				if j.Reason == "unavailable:oauth_unclassified" {
					unclassified++
					continue
				}
				detail := j.Subject.Label
				if len(j.NotChecked) > 0 {
					detail = strings.TrimSpace(detail + ": " + j.NotChecked[0])
					detail = strings.TrimPrefix(detail, ": ")
				}
				si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: j.Reason, Detail: detail})
			} else {
				decided++
			}
		}
		if unclassified > 0 {
			// Most tenants hold many such apps; one line, the JSON lists each.
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "unavailable:oauth_unclassified", Detail: fmt.Sprintf("%d %s scopes scheck does not classify and none it classifies as broad; listed in the JSON report and the readout", unclassified, map[bool]string{true: "app holds", false: "apps hold"}[unclassified == 1])})
		}
		switch {
		case decided > 0 && unknown == 0 && !a.PopulationIncomplete:
			si.Mark = "assessed"
		case decided > 0:
			si.Mark = "partial"
		case unknown == 0 && !a.PopulationIncomplete && !group.always:
			si.Mark = "not_applicable"
		}
		if decided == 0 && unknown == 0 && group.always {
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "unavailable:workspace_evidence", Detail: group.empty})
		}
		if a.JudgmentEvidenceIncomplete && group.assignments {
			if decided > 0 {
				si.Mark = "partial"
			} else {
				si.Mark = "not_assessed"
			}
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "unavailable:workspace_evidence", Detail: "Required role or assignment evidence was incomplete; observed account flags do not establish absence of delegated privilege"})
		}
		if group.limit != "" {
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "no_rule", Detail: group.limit})
		}
		if a.PopulationIncomplete {
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "unavailable:workspace_inventory", Detail: "Current population is incomplete"})
		}
		if decided > 0 {
			si.Judged = []string{group.name}
			some = true
		} else if group.unassessed != "" {
			unassessed = append(unassessed, group.unassessed)
		}
		row.SubItems = append(row.SubItems, si)
	}
	row.SubItems = append(row.SubItems, SubItem{Name: workspaceDelegation, Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{{Reason: "no_rule", Detail: "Nothing was read: Google offers no Directory read for it. Review it in the Admin console at Security → Access and data control → API controls → Manage Domain Wide Delegation. With a service-account credential, scheck's own delegation is listed there"}}})
	verb := " remains unassessed"
	if len(unassessed) > 0 {
		verb = " remain unassessed"
	}
	row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: "Workspace " + strings.Join(append(unassessed, "domain-wide delegation"), " and ") + verb + "; 2-step verification policy, grace periods and other sign-in services were not assessed"})
	return some
}
