// Package workspace declares the Workspace read surface. Only the gate holds
// credentials or sends requests (docs/spec/workspace-collector.md, "Boundary").
package workspace

import "github.com/b87/scheck/internal/engagement/gate"

const (
	OpBootstrapCustomer = "workspace.bootstrap_customer"
	OpBootstrapDomains  = "workspace.bootstrap_domains"
	OpBootstrapAliases  = "workspace.bootstrap_aliases"
	OpCustomer          = "workspace.customer"
)

// Ops is step 1's binding surface; no user or mailbox reads are implemented yet.
var Ops = []gate.Op{
	foundationOp(OpBootstrapCustomer, "/customers/my_customer", []string{"id"}, false),
	foundationOp(OpBootstrapDomains, "/customer/{customer}/domains", []string{"domains.domainName", "domains.verified"}, true),
	foundationOp(OpBootstrapAliases, "/customer/{customer}/domainaliases", []string{"domainAliases.domainAliasName", "domainAliases.parentDomainName", "domainAliases.verified"}, true),
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
