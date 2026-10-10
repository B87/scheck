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
	scope := scalarAt(item, f.Scope)
	switch scope {
	case "CUSTOMER":
		if v, present := fieldAt(item, f.Unit); present && v != "" {
			return "unattributable"
		}
	case "ORG_UNIT":
		unit := s.unitIDs[scalarAt(item, f.Unit)]
		if unit == "" {
			return "unattributable"
		}
		for _, ou := range excluded {
			if orgUnitUnder(unit, strings.ToLower(ou.Path)) {
				return ou.ExcludedBy
			}
		}
	default:
		return "unattributable"
	}
	assignee := scalarAt(item, f.Assignee)
	switch scalarAt(item, f.Type) {
	case "USER":
		user, ok := s.inventory[assignee]
		if !ok || user.id != assignee || a.b.params["user"] != "" && a.b.params["user"] != assignee {
			return "unattributable"
		}
	case "GROUP":
		// Only the specific admitted-user query establishes group-derived association.
		if a.b.params["user"] == "" || !customerIDRE.MatchString(assignee) {
			return "unattributable"
		}
	default:
		return "unattributable"
	}
	return ""
}
