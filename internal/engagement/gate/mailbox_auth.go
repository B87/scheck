package gate

import "time"

// MailboxApproval is one authorization.mailboxes entry the engagement has
// already resolved: a canonical Workspace asset, and the instants from the
// start of date through 24:00 on expires in the engagement's zone.
// Current is [From, Until). The gate admits a mailbox sign-in only when the
// profile selects the surface and one of these is current for the asset
// (docs/spec/workspace-collector.md, "Mailbox authorization").
type MailboxApproval struct {
	Asset, By, Date, Expires string
	From, Until              time.Time
}

// MailboxAuth is the approval an audit line records. State is set on a
// refusal: missing, expired, not_yet_current or other_asset. A send line
// leaves State empty. By is redacted with every other free-text field; the
// line never carries a staff address.
type MailboxAuth struct {
	Asset   string `json:"asset"`
	By      string `json:"by,omitempty"`
	Date    string `json:"date,omitempty"`
	Expires string `json:"expires,omitempty"`
	State   string `json:"state,omitempty"`
}

// MailboxRefusal is what a collector sees when a mailbox read was refused
// for the approval: the code word and the entry's own fields, never a
// staff address. The collector words it; it does not decide admission.
type MailboxRefusal struct {
	State, Asset, By, Date, Expires string
}

// mailboxDecision is the approval for asset at the gate's clock. A current
// entry is returned with a nil halt. Anything else is a remembered refusal
// for the surface, and that surface's cached mailbox tokens are dropped so
// a token minted while the approval was current is not used after it ends
// (docs/spec/workspace-collector.md, "Mailbox authorization").
func (g *Gate) mailboxDecision(asset string) (*MailboxApproval, *halt) {
	now := g.now()
	var match *MailboxApproval
	other := false
	for i := range g.mailboxApprovals {
		a := &g.mailboxApprovals[i]
		if a.Asset != asset {
			other = true
			continue
		}
		match = a
		break
	}
	if match != nil && !now.Before(match.From) && now.Before(match.Until) {
		return match, nil
	}
	state := "missing"
	switch {
	case match != nil && now.Before(match.From):
		state = "not_yet_current"
	case match != nil:
		state = "expired"
	case other:
		state = "other_asset"
	}
	g.dropMailboxTokens(asset)
	reason := "unavailable:mailbox_authorization_missing"
	if state == "expired" || state == "not_yet_current" {
		reason = "unavailable:mailbox_authorization_expired"
	}
	stamp := &MailboxAuth{Asset: asset, State: state}
	if match != nil {
		stamp.By, stamp.Date, stamp.Expires = match.By, match.Date, match.Expires
	}
	return nil, &halt{
		decision: "refused:mailbox_authorization",
		detail:   state,
		reason:   reason,
		sticky:   true,
		mailbox:  stamp,
	}
}

// dropMailboxTokens forgets every cached mailbox token for the asset. A
// read already holding a credential finishes; the next one does not reuse it.
func (g *Gate) dropMailboxTokens(asset string) {
	s := g.workspace[asset]
	if s == nil || s.optional == nil {
		return
	}
	if opt := s.optional[WorkspaceGmailForwarding]; opt != nil {
		opt.tokens = map[string]*workspaceToken{}
	}
}

// MailboxApprovalsUsed is the approval each Workspace asset's mailbox
// sign-in was sent under in this session, taken from the send lines, or
// none when no mailbox was signed in as.
func (g *Gate) MailboxApprovalsUsed() []MailboxAuth {
	var out []MailboxAuth
	seen := map[string]bool{}
	for _, e := range g.Entries() {
		if e.Event != "send" || e.MailboxAuthorization == nil || e.MailboxAuthorization.State != "" || seen[e.MailboxAuthorization.Asset] {
			continue
		}
		seen[e.MailboxAuthorization.Asset] = true
		a := *e.MailboxAuthorization
		out = append(out, a)
	}
	return out
}
