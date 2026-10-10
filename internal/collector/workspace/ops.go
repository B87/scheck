// Package workspace declares the Workspace read surface. Only the gate holds
// credentials or sends requests (docs/spec/workspace-collector.md, "Boundary").
package workspace

import "github.com/b87/scheck/internal/engagement/gate"

const (
	opBootstrapCustomer = "workspace.bootstrap_customer"
	opBootstrapDomains  = "workspace.bootstrap_domains"
	opBootstrapAliases  = "workspace.bootstrap_aliases"
	OpCustomer          = "workspace.customer"
)

// Ops declares binding and tenant inventory; posture and optional mailbox reads
// land in later E6 steps.
var Ops = []gate.Op{
	foundationOp(opBootstrapCustomer, "/customers/my_customer", []string{"id"}, false),
	foundationOp(opBootstrapDomains, "/customer/{customer}/domains", []string{"domains.domainName", "domains.verified"}, true),
	foundationOp(opBootstrapAliases, "/customer/{customer}/domainaliases", []string{"domainAliases.domainAliasName", "domainAliases.parentDomainName", "domainAliases.verified"}, true),
	foundationOp(OpCustomer, "/customers/{customer}", []string{"id"}, true),
}

func foundationOp(id, path string, keep []string, customer bool) gate.Op {
	params := []gate.Param{{Name: "domain", Type: gate.DNSName}}
	if customer {
		params = append(params, gate.Param{Name: "customer", Type: gate.CustomerID})
	}
	return gate.Op{ID: id, Provider: "google", Method: gate.GET, URL: "https://admin.googleapis.com/admin/directory/v1" + path,
		Subject: "saas:google-workspace:{domain}", Params: params, Level: gate.Observe, Auth: gate.WorkspaceADC, Accept: []string{"application/json"}, Keep: keep, MaxBytes: 1 << 20}
}

const (
	OpDomains       = "workspace.domains"
	OpAliases       = "workspace.aliases"
	OpUnits         = "workspace.units"
	OpUsers         = "workspace.users"
	opDelegatedUser = "workspace.delegated_user"
)

var userKeep = []string{"id", "primaryEmail", "customerId", "orgUnitPath", "aliases", "nonEditableAliases", "name.fullName", "suspended", "archived", "isAdmin", "isDelegatedAdmin", "creationTime", "lastLoginTime", "isEnrolledIn2Sv", "isEnforcedIn2Sv", "isMailboxSetup"}

func userIdentity() *gate.UserIdentity {
	return &gate.UserIdentity{ID: "id", Primary: "primaryEmail", Customer: "customerId", Unit: "orgUnitPath", Aliases: []string{"aliases", "nonEditableAliases"}}
}

func init() {
	domains := foundationOp(OpDomains, "/customer/{customer}/domains", []string{"domainName", "verified"}, true)
	domains.List = &gate.List{Items: "domains", Kind: gate.KindOther, Envelope: "admin#directory#domains", MaxItems: 1000}
	aliases := foundationOp(OpAliases, "/customer/{customer}/domainaliases", []string{"domainAliasName", "parentDomainName", "verified"}, true)
	aliases.List = &gate.List{Items: "domainAliases", Kind: gate.KindOther, Envelope: "admin#directory#domainAliases", MaxItems: 1000}
	units := foundationOp(OpUnits, "/customer/{customer}/orgunits?orgUnitPath=/&type=all_including_parent", []string{"orgUnitId", "orgUnitPath", "parentOrgUnitId", "parentOrgUnitPath", "name"}, true)
	units.List = &gate.List{Items: "organizationUnits", Kind: gate.KindOrgUnit, ExcludeKey: "orgUnitPath", Envelope: "admin#directory#orgUnits", MaxItems: 1000, Tree: &gate.UnitTree{ID: "orgUnitId", ParentID: "parentOrgUnitId", ParentPath: "parentOrgUnitPath", Name: "name"}}
	users := foundationOp(OpUsers, "/users?customer={customer}&projection=full&viewType=admin_view&maxResults=100&pageToken={page_token}", userKeep, true)
	users.Params = append(users.Params, gate.Param{Name: "page_token", Type: gate.Cursor, Optional: true})
	users.UserIdentity = userIdentity()
	users.List = &gate.List{Items: "users", Kind: gate.KindUser, ExcludeKey: "orgUnitPath", UserIDs: []string{"id", "primaryEmail", "aliases", "nonEditableAliases"}, UserKeys: []string{"id", "primaryEmail", "aliases", "nonEditableAliases"}, Next: &gate.Pages{Param: "page_token", Field: "nextPageToken"}, MaxPages: 10, MaxItems: 1000, Envelope: "admin#directory#users"}
	detail := foundationOp(opDelegatedUser, "/users/{user}?projection=full&viewType=admin_view", userKeep, false)
	detail.Subject += "/users/{user}"
	detail.Params = append(detail.Params, gate.Param{Name: "user", Type: gate.UserKey})
	detail.UserIdentity = userIdentity()
	Ops = append(Ops, domains, aliases, units, users, detail)
}

const (
	OpRoles           = "workspace.roles"
	OpPrivileges      = "workspace.privileges"
	OpUserAssignments = "workspace.user_assignments"
	OpUserDetail      = "workspace.user_detail"
)

func init() {
	roles := foundationOp(OpRoles, "/customer/{customer}/roles?maxResults=100&pageToken={page_token}", []string{"kind", "roleId", "roleName", "rolePrivileges.serviceId", "rolePrivileges.privilegeName", "isSuperAdminRole"}, true)
	roles.PreserveMalformed = true
	roles.Params = append(roles.Params, gate.Param{Name: "page_token", Type: gate.Cursor, Optional: true})
	roles.List = &gate.List{Items: "items", Kind: gate.KindOther, Envelope: "admin#directory#roles", MaxItems: 1000, MaxPages: 10, Next: &gate.Pages{Param: "page_token", Field: "nextPageToken"}}
	privileges := foundationOp(OpPrivileges, "/customer/{customer}/roles/ALL/privileges", []string{"kind", "serviceId", "privilegeName", "isOuScopable"}, true)
	privileges.PreserveMalformed = true
	privileges.List = &gate.List{Items: "items", Kind: gate.KindOther, Envelope: "admin#directory#privileges", MaxItems: 1000, Children: "childPrivileges", MaxDepth: 32}
	indirect := foundationOp(OpUserAssignments, "/customer/{customer}/roleassignments?maxResults=100&pageToken={page_token}&userKey={user}&includeIndirectRoleAssignments=true", []string{"kind", "roleAssignmentId", "roleId", "assignedTo", "assigneeType", "scopeType", "orgUnitId", "condition", "expirationDetails.expireTime"}, true)
	indirect.PreserveMalformed = true
	indirect.Subject += "/users/{user}"
	indirect.Params = append(indirect.Params, gate.Param{Name: "page_token", Type: gate.Cursor, Optional: true}, gate.Param{Name: "user", Type: gate.UserKey})
	indirect.List = &gate.List{Items: "items", Kind: gate.KindOther, Envelope: "admin#directory#roleAssignments", MaxItems: 1000, MaxPages: 10, Next: &gate.Pages{Param: "page_token", Field: "nextPageToken"}, Assignment: &gate.AssignmentRefs{Assignee: "assignedTo", Type: "assigneeType", Scope: "scopeType", Unit: "orgUnitId"}}
	detail := foundationOp(OpUserDetail, "/users/{user}?projection=full&viewType=admin_view", userKeep, false)
	detail.Subject += "/users/{user}"
	detail.Params = append(detail.Params, gate.Param{Name: "user", Type: gate.UserKey})
	detail.UserIdentity = userIdentity()
	Ops = append(Ops, roles, privileges, indirect, detail)
}
