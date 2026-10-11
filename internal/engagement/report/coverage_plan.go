package report

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

// CoveragePlan is a network collector's coverage for one asset in one area.
type CoveragePlan = finding.CoveragePlan

// planOf is the asset's plan for area, nil when its collector gave none.
func planOf(a AssetInput, area finding.Area) *CoveragePlan {
	for i := range a.Coverage {
		if a.Coverage[i].Area == area {
			return &a.Coverage[i]
		}
	}
	return nil
}

// planCoverage marks a collector's plan from the asset's judgments
// (docs/spec/report.md, "Coverage"): the marking rules live here, every
// word of the sub-items in the collector. It reports whether any group was
// decided.
func (b *builder) planCoverage(row *Row, a AssetInput, plan CoveragePlan) bool {
	some := false
	unassessed := []string{}
	for _, group := range plan.Groups {
		si := SubItem{Name: group.Name, Asset: a.ID, Rules: group.Rules, Mark: "not_assessed", Reasons: []ReasonDetail{}}
		if group.NotOnPlan != nil {
			si.Reasons = appendReason(si.Reasons, ReasonDetail(*group.NotOnPlan))
			row.SubItems = append(row.SubItems, si)
			continue
		}
		decided, unknown, collapsed := 0, 0, 0
		for _, j := range a.Judged {
			if !slices.Contains(group.Rules, j.ID) {
				continue
			}
			if j.Decided() {
				decided++
				continue
			}
			unknown++
			if group.Collapse != nil && j.Reason == group.Collapse.Reason {
				collapsed++
				continue
			}
			detail := j.Subject.Label
			if len(j.NotChecked) > 0 {
				detail = strings.TrimPrefix(strings.TrimSpace(detail+": "+j.NotChecked[0]), ": ")
			}
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: j.Reason, Detail: detail})
		}
		if collapsed > 0 {
			si.Reasons = appendReason(si.Reasons, ReasonDetail(*group.Collapse))
		}
		switch {
		case decided > 0 && unknown == 0 && !a.PopulationIncomplete:
			si.Mark = "assessed"
		case decided > 0:
			si.Mark = "partial"
		case unknown == 0 && !a.PopulationIncomplete && !group.Always:
			si.Mark = "not_applicable"
		}
		if decided == 0 && unknown == 0 && group.Always {
			si.Reasons = appendReason(si.Reasons, ReasonDetail(group.Empty))
		}
		if group.Gap != nil {
			if decided > 0 {
				si.Mark = "partial"
			} else {
				si.Mark = "not_assessed"
			}
			si.Reasons = appendReason(si.Reasons, ReasonDetail(*group.Gap))
		}
		if group.Limit != "" {
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "no_rule", Detail: group.Limit})
		}
		if a.PopulationIncomplete {
			si.Reasons = appendReason(si.Reasons, ReasonDetail(plan.Incomplete))
		}
		if decided > 0 {
			si.Judged = []string{group.Name}
			some = true
		} else if group.Unassessed != "" {
			unassessed = append(unassessed, group.Unassessed)
		}
		row.SubItems = append(row.SubItems, si)
	}
	for _, u := range plan.Unread {
		row.SubItems = append(row.SubItems, SubItem{Name: u.Name, Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{{Reason: "no_rule", Detail: u.Detail}}})
		if u.Unassessed != "" {
			unassessed = append(unassessed, u.Unassessed)
		}
	}
	var parts []string
	if len(unassessed) > 0 {
		verb := " remains unassessed"
		if len(unassessed) > 1 {
			verb = " remain unassessed"
		}
		parts = append(parts, plan.Label+" "+strings.Join(unassessed, " and ")+verb)
	}
	if plan.RowAlso != "" {
		parts = append(parts, plan.RowAlso)
	}
	if len(parts) > 0 {
		row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: strings.Join(parts, "; ")})
	}
	return some
}
