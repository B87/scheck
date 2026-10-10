package workspace

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

// Binding is only the declared root's verified tenant. No foreign bootstrap
// inventory, credential, or caller identity reaches the collector.
type Binding struct {
	CustomerID  string   `json:"customer_id,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Profile     string   `json:"profile,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	ScopesKnown bool     `json:"scopes_known"`
	Reads       []Read   `json:"reads"`
}

type Read struct {
	Op        string `json:"op"`
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Bind asks the gate to run its ordered private bootstrap. The gate, not this
// caller, selects the returned customer on later reads.
func Bind(ctx context.Context, g *gate.Gate, asset string) Binding {
	var out Binding
	domain, valid := strings.CutPrefix(asset, "saas:google-workspace:")
	if !valid {
		return out
	}
	for _, op := range []string{OpBootstrapCustomer, OpBootstrapDomains, OpBootstrapAliases} {
		params := map[string]string{"domain": domain}
		result := g.Send(ctx, gate.Request{Op: op, Asset: asset, Params: params, Stage: "recon"})
		out.Reads = append(out.Reads, Read{Op: op, RequestID: result.RequestID, Decision: result.Decision, Reason: result.Reason, Detail: result.Detail})
		if !result.OK() {
			return out
		}
		if op == OpBootstrapAliases && result.Response != nil {
			var body struct {
				ID          string   `json:"id"`
				Domain      string   `json:"domain"`
				Profile     string   `json:"profile"`
				Scopes      []string `json:"scopes"`
				ScopesKnown bool     `json:"scopes_known"`
			}
			if json.Unmarshal(result.Response.Body, &body) == nil {
				out.CustomerID, out.Domain = body.ID, body.Domain
				out.Profile, out.Scopes, out.ScopesKnown = body.Profile, body.Scopes, body.ScopesKnown && len(result.Response.Redactions) == 0
			}
		}
	}
	return out
}
