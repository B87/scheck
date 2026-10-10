package gate

import (
	"slices"
	"strings"
)

type workspaceUser struct {
	id, primary, customer, unit string
	aliases                     []string
}

// Identity recognition protects admission; posture fields are parsed only by
// the collector (docs/spec/workspace-collector.md, "Tenant binding and scope").
func structuralUser(doc any, f *UserIdentity) (workspaceUser, bool) {
	u := workspaceUser{id: scalarAt(doc, f.ID), primary: scalarAt(doc, f.Primary), customer: scalarAt(doc, f.Customer), unit: scalarAt(doc, f.Unit)}
	primary, err := userKey(u.primary)
	if err != nil || !strings.Contains(primary, "@") || !customerIDRE.MatchString(u.id) || u.id == "my_customer" || !customerIDRE.MatchString(u.customer) || !canonicalUnit(u.unit) {
		return workspaceUser{}, false
	}
	u.primary = primary
	for _, field := range f.Aliases {
		raw, present := fieldAt(doc, field)
		if !present {
			continue
		}
		entries, ok := raw.([]any)
		if !ok {
			return workspaceUser{}, false
		}
		for _, entry := range entries {
			address, ok := entry.(string)
			if !ok {
				return workspaceUser{}, false
			}
			key, err := userKey(address)
			if err != nil || !strings.Contains(key, "@") {
				return workspaceUser{}, false
			}
			u.aliases = append(u.aliases, key)
		}
	}
	slices.Sort(u.aliases)
	u.aliases = slices.Compact(u.aliases)
	return u, true
}

func (g *Gate) workspaceUsersStart(asset string) {
	s := g.workspace[asset]
	s.inventory, s.fingerprints, s.owners = map[string]workspaceUser{}, map[string]string{}, map[string]string{}
	s.usersComplete, s.inventoryBad, s.principal = false, false, ""
	s.cursors = map[string]bool{}
}

func (g *Gate) workspaceUserItem(asset string, op *compiled, item any, rule string) string {
	s := g.workspace[asset]
	u, ok := structuralUser(item, op.UserIdentity)
	if !ok || u.customer != s.customer || !s.units[strings.ToLower(u.unit)] {
		s.inventoryBad = true
		return "unattributable"
	}
	fingerprint := string(marshal(project(item, op.keep)))
	if prior, exists := s.fingerprints[u.id]; exists {
		if prior != fingerprint {
			s.inventoryBad = true
			s.inventory = map[string]workspaceUser{}
			return "conflicting_duplicate"
		}
		return "duplicate"
	}
	if len(s.fingerprints) >= op.List.MaxItems {
		s.inventoryBad = true
		return "item_limit"
	}
	s.fingerprints[u.id] = fingerprint
	// Include excluded identities in collision checks without exposing them.
	for _, key := range append([]string{u.id, u.primary}, u.aliases...) {
		if old, exists := s.owners[key]; exists && old != u.id {
			s.inventoryBad = true
			s.inventory = map[string]workspaceUser{}
			return "conflicting_identity"
		}
		s.owners[key] = u.id
	}
	if rule != "" {
		return rule
	}
	if !s.inventoryBad {
		for _, key := range append([]string{u.id, u.primary}, u.aliases...) {
			s.inventory[key] = u
		}
	}
	return ""
}

func (g *Gate) workspaceUsersDone(asset string, out *shaped) {
	s := g.workspace[asset]
	if s.inventoryBad {
		out.pop.Incomplete = append(out.pop.Incomplete, "unrecognized_inventory")
	}
	bad := s.inventoryBad
	if out.next != nil {
		if s.cursors[out.next.cursor] {
			out.next = nil
			out.pop.More = false
			out.pop.Incomplete = append(out.pop.Incomplete, "cursor_loop")
			bad = true
		} else {
			s.cursors[out.next.cursor] = true
		}
	}
	for _, gap := range out.pop.Incomplete {
		if gap != "dropped" {
			bad = true
		}
	}
	s.usersComplete = !out.pop.More && !bad
	if !s.usersComplete {
		s.principal = ""
	}
}

func (g *Gate) workspaceDetail(r Request, a admitted, doc any) bool {
	s := g.workspace[r.Asset]
	u, ok := structuralUser(doc, a.b.op.UserIdentity)
	before, admitted := s.inventory[a.b.params["user"]]
	if !ok || !admitted || !s.usersComplete || u.id != before.id || u.primary != before.primary || u.customer != s.customer || !strings.EqualFold(u.unit, before.unit) || !s.units[strings.ToLower(u.unit)] {
		s.principal = ""
		return false
	}
	for _, excluded := range g.scope.OrgUnits(r.Asset) {
		if orgUnitUnder(strings.ToLower(u.unit), strings.ToLower(excluded.Path)) {
			s.principal = ""
			return false
		}
	}
	if a.b.op.ID == "workspace.delegated_user" {
		s.principal = u.id
	}
	return true
}
