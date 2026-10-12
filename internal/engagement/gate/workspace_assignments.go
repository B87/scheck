package gate

import "strings"

// Assignment admission recognizes references before persistence, never whether
// a role is privileged (docs/spec/workspace-collector.md, "Administrative privilege interpretation").
func (g *Gate) workspaceAssignment(r Request, a admitted, item any, excluded []OrgUnit) string {
	s := g.workspace[r.Asset]
	f := a.b.op.List.Assignment
	if !s.usersComplete || s.unitIDs == nil {
		return "unattributable"
	}
	// Drop names are fixed tokens. They never include the field value.
	switch scalarAt(item, f.Scope) {
	case "CUSTOMER":
		if v, present := fieldAt(item, f.Unit); present && v != "" {
			return "scope_customer_has_unit"
		}
	case "ORG_UNIT":
		unit := s.unitIDs[scalarAt(item, f.Unit)]
		if unit == "" {
			return "scope_unit_unknown"
		}
		for _, ou := range excluded {
			if orgUnitUnder(unit, strings.ToLower(ou.Path)) {
				return ou.ExcludedBy
			}
		}
	default:
		return "scope_unrecognized"
	}
	assignee := scalarAt(item, f.Assignee)
	_, typePresent := fieldAt(item, f.Type)
	switch strings.ToUpper(scalarAt(item, f.Type)) {
	case "USER":
		user, ok := s.inventory[assignee]
		if !ok || user.id != assignee || a.b.params["user"] != "" && a.b.params["user"] != assignee {
			return "assignee_mismatch"
		}
	case "GROUP":
		// Only the specific admitted-user query establishes group-derived association.
		if a.b.params["user"] == "" || !customerIDRE.MatchString(assignee) {
			return "assignee_mismatch"
		}
	default:
		if !typePresent {
			return "assignee_type_missing"
		}
		return "assignee_type_unrecognized"
	}
	return ""
}
