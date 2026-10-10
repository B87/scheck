package gate

import (
	"path"
	"strings"
	"unicode"
)

// Unit admission uses declared fields on redacted inventory, not Directory
// posture parsing (docs/spec/workspace-collector.md, "Tenant binding and scope").
func opaqueUnitID(id string) bool {
	return id != "" && len(id) <= 256 && !strings.ContainsFunc(id, unicode.IsControl) && !strings.Contains(id, "[REDACTED:")
}
func optionalString(doc any, field string) bool {
	v, present := fieldAt(doc, field)
	if !present {
		return true
	}
	_, ok := v.(string)
	return ok
}

func canonicalUnit(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\\%") && !strings.ContainsFunc(p, unicode.IsControl) && strings.Count(p, "/") <= 35
}

func (g *Gate) workspaceUnits(asset string, l *List, items []any) bool {
	s := g.workspace[asset]
	s.units = nil
	if len(items) == 0 || len(items) > l.MaxItems {
		return false
	}
	type unit struct{ id, parentID, parentPath string }
	units, ids := map[string]unit{}, map[string]string{}
	f := l.Tree
	for _, item := range items {
		p, id := strings.ToLower(scalarAt(item, l.ExcludeKey)), scalarAt(item, f.ID)
		if !canonicalUnit(p) || !opaqueUnitID(id) || ids[id] != "" {
			return false
		}
		if _, exists := units[p]; exists {
			return false
		}
		if !optionalString(item, f.Name) || !optionalString(item, f.ParentID) || !optionalString(item, f.ParentPath) {
			return false
		}
		name := scalarAt(item, f.Name)
		if p != "/" && name != "" && !strings.EqualFold(name, path.Base(p)) {
			return false
		}
		units[p] = unit{id, scalarAt(item, f.ParentID), strings.ToLower(scalarAt(item, f.ParentPath))}
		ids[id] = p
	}
	if _, ok := units["/"]; !ok {
		return false
	}
	for p, u := range units {
		if p == "/" {
			if u.parentID != "" || u.parentPath != "" {
				return false
			}
			continue
		}
		parent := path.Dir(p)
		expected, exists := units[parent]
		if !exists || u.parentID == "" && u.parentPath == "" || u.parentID != "" && u.parentID != expected.id || u.parentPath != "" && u.parentPath != parent {
			return false
		}
	}
	s.units = map[string]bool{}
	for p := range units {
		s.units[p] = true
	}
	return true
}
