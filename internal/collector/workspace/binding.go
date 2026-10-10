package workspace

import (
	"context"
	"encoding/json"
	"regexp"
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

// Sender is the collector's only access to the gate.
type Sender interface {
	Send(context.Context, gate.Request) gate.Result
}

// Bind runs the ordered private bootstrap. The gate selects the customer on
// later reads (docs/spec/workspace-collector.md, "Tenant binding and scope").
func Bind(ctx context.Context, g Sender, asset string) Binding {
	var out Binding
	domain, valid := strings.CutPrefix(asset, "saas:google-workspace:")
	if !valid {
		return out
	}
	for _, op := range []string{opBootstrapCustomer, opBootstrapDomains, opBootstrapAliases} {
		params := map[string]string{"domain": domain}
		result := g.Send(ctx, gate.Request{Op: op, Asset: asset, Params: params, Stage: "recon"})
		out.Reads = append(out.Reads, Read{Op: op, RequestID: result.RequestID, Decision: result.Decision, Reason: result.Reason, Detail: result.Detail})
		if !result.OK() {
			return out
		}
		if op == opBootstrapAliases {
			if !out.summary(result, domain) {
				last := &out.Reads[len(out.Reads)-1]
				last.Decision, last.Reason, last.Detail = "unavailable:binding_summary", "insufficient_evidence", "The gate did not return a recognized Workspace binding summary"
			}
		}
	}
	return out
}

var bindingCustomerID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (b *Binding) summary(result gate.Result, domain string) bool {
	if result.Response == nil || result.Response.Status != 200 || result.Response.Truncated {
		return false
	}
	var body struct {
		ID          string   `json:"id"`
		Domain      string   `json:"domain"`
		Profile     string   `json:"profile"`
		Scopes      []string `json:"scopes"`
		ScopesKnown *bool    `json:"scopes_known"`
	}
	if json.Unmarshal(result.Response.Body, &body) != nil || !bindingCustomerID.MatchString(body.ID) || body.ID == "my_customer" || body.Domain != domain || body.ScopesKnown == nil {
		return false
	}
	switch body.Profile {
	case "directory", "directory_oauth", "directory_mail", "directory_oauth_mail":
	default:
		return false
	}
	if *body.ScopesKnown && len(body.Scopes) == 0 {
		return false
	}
	b.CustomerID, b.Domain, b.Profile, b.Scopes = body.ID, body.Domain, body.Profile, body.Scopes
	b.ScopesKnown = *body.ScopesKnown && len(result.Response.Redactions) == 0
	return true
}
