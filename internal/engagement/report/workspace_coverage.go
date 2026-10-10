package report

import (
	"slices"

	"github.com/b87/scheck/internal/finding"
)

func (b *builder) workspaceCoverage(row *Row, a AssetInput) bool {
	groups := []struct {
		name string
		ids  []string
	}{
		{"Workspace administrator identity", []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin}},
		{"Workspace offboarding", []string{finding.IDIdentityFormerPersonHasAccess}},
		{"Workspace administrator assignments and counts", []string{"workspace.too_many_super_admins", "workspace.suspended_admin_assignment"}},
		{"Workspace account sign-in", []string{"workspace.stale_account", "workspace.never_signed_in"}},
	}
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
				si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: j.Reason, Detail: j.Subject.Label})
			} else {
				decided++
			}
		}
		switch {
		case decided > 0 && unknown == 0 && !a.PopulationIncomplete:
			si.Mark = "assessed"
		case decided > 0:
			si.Mark = "partial"
		case unknown == 0 && !a.PopulationIncomplete:
			si.Mark = "not_applicable"
		}
		if a.JudgmentEvidenceIncomplete && group.name == "Workspace administrator assignments and counts" {
			if decided > 0 {
				si.Mark = "partial"
			} else {
				si.Mark = "not_assessed"
			}
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "unavailable:workspace_evidence", Detail: "Required role or assignment evidence was incomplete; observed account flags do not establish absence of delegated privilege"})
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
	row.SubItems = append(row.SubItems, SubItem{Name: "Workspace 2-step verification, OAuth grants and domain-wide delegation", Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{{Reason: "no_rule", Detail: "Not assessed in this build; effective permissions and group membership paths were not tested"}}})
	row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: "Workspace second-factor and application/delegation controls remain unassessed"})
	return some
}
