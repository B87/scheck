package report

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// workspaceGroups are the coverage sub-items over Workspace rule ids; every
// id the collector judges belongs to exactly one (workspace_test.go).
var workspaceGroups = []struct {
	name, limit string
	ids         []string
	// assignments marks the group whose absence verdicts need role and
	// assignment interpretation.
	assignments bool
	// always marks a group the collector judges for every read account, so
	// no judgment means not assessed, never not applicable.
	always bool
}{
	{name: "Workspace administrator identity", ids: []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin}},
	{name: "Workspace offboarding", ids: []string{finding.IDIdentityFormerPersonHasAccess}},
	{name: "Workspace administrator assignments and counts", ids: []string{"workspace.too_many_super_admins", "workspace.suspended_admin_assignment"}, assignments: true},
	{name: "Workspace account sign-in", ids: []string{"workspace.stale_account", "workspace.never_signed_in"}},
	{name: "Workspace 2-step verification (Google's enforcement and enrollment flags)", ids: []string{"workspace.two_step_not_enforced", "workspace.admin_without_two_step"}, always: true,
		limit: "Checked: each account's 2-step verification enforcement and enrollment as Google reports it. Not checked: organizational-unit policy, grace periods, sign-in through another identity provider, verification methods and phishing resistance"},
}

func (b *builder) workspaceCoverage(row *Row, a AssetInput) bool {
	groups := workspaceGroups
	some := false
	for _, group := range groups {
		si := SubItem{Name: group.name, Asset: a.ID, Rules: group.ids, Mark: "not_assessed", Reasons: []ReasonDetail{}}
		decided, unknown := 0, 0
		for _, j := range a.Judged {
			if !slices.Contains(group.ids, j.ID) {
				continue
			}
			if j.Verdict == verdictAbstained {
				unknown++
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
		switch {
		case decided > 0 && unknown == 0 && !a.PopulationIncomplete:
			si.Mark = "assessed"
		case decided > 0:
			si.Mark = "partial"
		case unknown == 0 && !a.PopulationIncomplete && !group.always:
			si.Mark = "not_applicable"
		}
		if decided == 0 && unknown == 0 && group.always {
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "unavailable:workspace_evidence", Detail: "No 2-step verification outcome was recorded for this tenant"})
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
		}
		row.SubItems = append(row.SubItems, si)
	}
	row.SubItems = append(row.SubItems, SubItem{Name: "Workspace OAuth grants and domain-wide delegation", Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{{Reason: "no_rule", Detail: "Not assessed in this build; effective permissions and group membership paths were not tested"}}})
	row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: "Workspace OAuth grants and domain-wide delegation remain unassessed; 2-step verification policy, grace periods and other sign-in services were not assessed"})
	return some
}
