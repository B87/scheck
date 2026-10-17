package workspace

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
)

// The tier table, lowest wins; within a tier active first, then the most
// recent sign-in, then primaryEmail.
func TestOrderUsersByTier(t *testing.T) {
	user := func(id string) User { return stepUser(id, "/Sales", new(true), new(true)) }
	leaver, gone, unnamed, named, contractor, service := user("leaver"), user("gone"), user("unnamed"), user("named"), user("contractor"), user("service")
	gone.Suspended = new(true)
	unnamed.IsDelegatedAdmin = new(true)
	named.IsAdmin = new(true)
	recent, older, idle := user("recent"), user("older"), user("idle")
	recent.LastLoginTime, older.LastLoginTime = new("2026-10-10T00:00:00Z"), new("2026-09-01T00:00:00Z")
	idle.Archived = new(true)
	users := []User{idle, older, recent, service, contractor, named, unnamed, gone, leaver}
	c := Context{People: []Person{
		{Handle: "l", Addresses: []string{"leaver@example.com"}, Left: "2026-01-01"},
		{Handle: "g", Addresses: []string{"gone@example.com"}, Left: "2026-01-01"},
		{Handle: "n", Addresses: []string{"named@example.com"}, Kind: "employee"},
		{Handle: "k", Addresses: []string{"contractor@example.com"}, Kind: "contractor"},
		{Handle: "s", Addresses: []string{"service@example.com"}, Kind: "service"},
	}}
	order := orderUsers(users, nil, attribute("asset", users, c.People, true), c)
	var got []string
	for _, u := range order {
		got = append(got, u.ID)
	}
	// gone left but is suspended: not tier 1; it falls to the rest, after
	// the active accounts.
	want := []string{"leaver", "unnamed", "named", "contractor", "service", "recent", "older", "gone", "idle"}
	if !slices.Equal(got, want) {
		t.Fatalf("\n got %v\nwant %v", got, want)
	}
	if order[1].Tier != 2 || order[2].Tier != 3 || order[2].Handle != "n" {
		t.Fatalf("%+v", order[:3])
	}
}

// An observed role assignment makes an admin holder for ordering, even
// without Google's admin flags.
func TestAnAssignmentMakesAnAdminHolderForOrdering(t *testing.T) {
	a, b := oauthUser("aaa"), oauthUser("bbb")
	access := []AccountAccess{{ID: "bbb", Assignments: Population[Assignment]{Items: []Assignment{{ID: "x", Role: "r", Assignee: "bbb", Type: "USER", Scope: "CUSTOMER"}}}}}
	order := orderUsers([]User{a, b}, access, nil, Context{})
	if order[0].ID != "bbb" || order[0].Tier != 2 {
		t.Fatalf("%+v", order)
	}
}

// A limit that cuts the grant sequence gains the selection; a failure that
// every later account would repeat, and is no limit, does not.
func TestGrantsCutByALimitCarryTheSelection(t *testing.T) {
	e, c := oauthFixture(oauthUser("amy"), oauthUser("bob"), oauthUser("cat"))
	e.OAuth = OAuthEvidence{}
	sel := Select(e, "asset", c)
	full := &gate.Population{}
	n := 0
	limited := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		if r.Op != OpUserTokens {
			return gate.Result{RequestID: "x", Decision: "refused:not_selected", Reason: "not_on_plan"}
		}
		if n++; n > 1 {
			return gate.Result{RequestID: "x", Decision: "refused:deadline", Reason: "limit_reached", Repeats: true}
		}
		return gate.Result{RequestID: "t", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`[]`), Population: full}}
	})
	got := CollectUsers(context.Background(), limited, Target{Asset: "asset", Stage: "check"}, e, c, sel)
	s := got.OAuth.Selection
	if s == nil || s.Read != 1 || s.InScope != 3 || s.Unit != "users" || s.Kind != "oauth_grants" || len(s.Tiers) != 1 || s.Tiers[0].Count != 1 {
		t.Fatalf("%+v", s)
	}
	refused := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		return gate.Result{RequestID: "x", Decision: "unavailable:credential_exchange", Reason: "insufficient_permission:admin.directory.user.security", Repeats: true}
	})
	if got := CollectUsers(context.Background(), refused, Target{Asset: "asset", Stage: "check"}, e, c, sel); got.OAuth.Selection != nil {
		t.Fatalf("a refusal is no limit: %+v", got.OAuth.Selection)
	}
}

// Forwarding keeps its own order: a person who left and is still active,
// then admin holders, then the rest, active first; and it is read in Check.
func TestForwardingReadsInItsOwnOrderInCheck(t *testing.T) {
	admin, rest, leaver := mailUser("zadmin"), mailUser("arest"), mailUser("mleaver")
	admin.IsAdmin = new(true)
	e, c := mailFixture(rest, admin, leaver)
	c.People = []Person{{Handle: "m", Addresses: []string{"mleaver@example.com"}, Left: "2026-01-01"}}
	e.Mail = MailEvidence{}
	var asked []string
	full := &gate.Population{}
	send := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		if r.Stage != "check" {
			t.Fatalf("%s read in stage %q", r.Op, r.Stage)
		}
		if r.Op == OpMailAutoForwarding {
			asked = append(asked, r.Params["user"])
		}
		return gate.Result{RequestID: "m", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`{}`), Population: full}}
	})
	got := CollectUsers(context.Background(), send, Target{Asset: "asset", Stage: "check"}, e, c, Select(e, "asset", c))
	if !slices.Equal(asked, []string{"mleaver", "zadmin", "arest"}) || got.Mail.Selection != nil {
		t.Fatalf("asked %v selection %+v", asked, got.Mail.Selection)
	}
}

// A deadline that cuts forwarding gains its selection; an expired session
// token is a limit too, and the tenant's outcome says limit_reached.
func TestForwardingCutByALimitAndAnExpiredToken(t *testing.T) {
	e, c := mailFixture(mailUser("amy"), mailUser("bob"))
	e.Mail = MailEvidence{}
	n := 0
	send := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		if n++; n > 2 {
			return gate.Result{RequestID: "x", Decision: "unavailable:bootstrap_required", Reason: "unavailable:bootstrap_required", Repeats: true}
		}
		return gate.Result{RequestID: "m", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`{}`), Population: &gate.Population{}}}
	})
	got := CollectUsers(context.Background(), send, Target{Asset: "asset", Stage: "check"}, e, c, Select(e, "asset", c))
	if s := got.Mail.Selection; s == nil || s.Read != 1 || s.InScope != 2 || s.Kind != "mail_forwarding" {
		t.Fatalf("%+v", s)
	}
	if o := got.Outcome(); o.Reason != "limit_reached" {
		t.Fatalf("%+v", o)
	}
}

// Recon writes no grant or forwarding readout: they are Check's to read.
func TestReconLeavesGrantsAndForwardingToCheck(t *testing.T) {
	e, c := mailFixture(mailUser("amy"))
	e.Mail, e.usersPending = MailEvidence{Selected: true}, true
	e.finish("asset", c)
	for _, n := range e.Notes {
		if strings.Contains(n.Detail, "Mail forwarding was not checked") || strings.Contains(n.Detail, "Third-party app access was not checked") || strings.Contains(n.Detail, "read whole for") {
			t.Fatalf("Recon wrote %q", n.Detail)
		}
	}
	if !slices.ContainsFunc(e.Notes, func(n Note) bool {
		return n.Detail == "This profile reads mail forwarding; Check reads them after Plan orders the accounts."
	}) {
		t.Fatalf("no note that Check reads forwarding: %v", e.Notes)
	}
	if strings.Contains(e.Outcome().Detail, "mail forwarding") {
		t.Fatalf("Recon claims forwarding collected: %s", e.Outcome().Detail)
	}
}

// The session's token expires during the grant reads: the gate answers
// every later read with the expiry, so grants and forwarding both gain
// their selection and the tenant's outcome is limit_reached.
func TestAnExpiryDuringGrantsCutsForwardingToo(t *testing.T) {
	e, c := mailFixture(mailUser("amy"), mailUser("bob"))
	e.Binding.Surfaces = append(e.Binding.Surfaces, gate.WorkspaceOAuthGrants)
	e.OAuth, e.Mail = OAuthEvidence{}, MailEvidence{}
	n := 0
	send := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		if n++; n > 1 {
			return gate.Result{RequestID: "x", Decision: "unavailable:bootstrap_required", Reason: "unavailable:bootstrap_required", Repeats: true}
		}
		return gate.Result{RequestID: "t", Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(`[]`), Population: &gate.Population{}}}
	})
	got := CollectUsers(context.Background(), send, Target{Asset: "asset", Stage: "check"}, e, c, Select(e, "asset", c))
	if s := got.OAuth.Selection; s == nil || s.Read != 1 {
		t.Fatalf("grants %+v", s)
	}
	if s := got.Mail.Selection; s == nil || s.Read != 0 || s.InScope != 2 {
		t.Fatalf("forwarding %+v", s)
	}
	if o := got.Outcome(); o.Reason != "limit_reached" {
		t.Fatalf("%+v", o)
	}
}
