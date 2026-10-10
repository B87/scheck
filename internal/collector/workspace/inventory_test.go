package workspace

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement/gate"
)

func inventoryResult(op, body string) gate.Result {
	return gate.Result{RequestID: op, Decision: "sent", Response: &gate.Response{Status: 200, Body: []byte(body), Population: &gate.Population{}}}
}
func inventoryFixture(op string) gate.Result {
	switch op {
	case opBootstrapCustomer, opBootstrapDomains:
		return gate.Result{RequestID: op, Decision: "sent", Response: &gate.Response{Status: 200}}
	case opBootstrapAliases:
		return inventoryResult(op, `{"id":"C123","domain":"example.com","profile":"directory","scopes_known":false}`)
	case OpDomains:
		return inventoryResult(op, `[{"domainName":"example.com","verified":true}]`)
	case OpAliases:
		return inventoryResult(op, `[]`)
	case OpUnits:
		return inventoryResult(op, `[{"orgUnitId":"id:root","orgUnitPath":"/"}]`)
	case OpUsers:
		return inventoryResult(op, `[{"id":"123","primaryEmail":"alice@secondary.example","customerId":"C123","orgUnitPath":"/","aliases":["old@example.com"],"isAdmin":false,"isEnrolledIn2Sv":false}]`)
	default:
		return gate.Result{RequestID: op, Decision: "unavailable:principal_unknown", Reason: "insufficient_evidence"}
	}
}

func TestCollectOwnsSequenceAndPreservesUnknownFlags(t *testing.T) {
	calls := []string{}
	sender := senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		if len(r.Params) != 1 || r.Params["domain"] != "example.com" || r.Asset != "saas:google-workspace:example.com" {
			t.Fatal(r)
		}
		calls = append(calls, r.Op)
		return inventoryFixture(r.Op)
	})
	e := Collect(context.Background(), sender, Target{Asset: "saas:google-workspace:example.com", Stage: "recon"}, Context{People: []Person{{Handle: "alice", Addresses: []string{"old@example.com"}}}})
	want := []string{opBootstrapCustomer, opBootstrapDomains, opBootstrapAliases, OpDomains, OpAliases, OpUnits, OpUsers, opDelegatedUser}
	a, _ := json.Marshal(calls)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatal(calls)
	}
	if !e.Users.Complete || len(e.Users.Items) != 1 || len(e.Judgments) != 0 || len(e.Attribution) != 1 || e.Attribution[0].MatchedBy != "alias" || e.Attribution[0].ProviderID != "123" {
		t.Fatal(e)
	}
	u := e.Users.Items[0]
	if u.IsAdmin == nil || *u.IsAdmin || u.Enrolled == nil || *u.Enrolled || u.Enforced != nil || u.Suspended != nil {
		t.Fatal("false/missing evidence conflated", u)
	}
	if len(e.Reads()) != 8 || !strings.Contains(e.Notes[1].Detail, "Inventory alone does not assess") {
		t.Fatal(e.Notes)
	}
}

func TestCollectInventoryUnavailableAndUnrecognized(t *testing.T) {
	for _, op := range []string{opBootstrapDomains, OpUnits, OpUsers} {
		for _, malformed := range []bool{false, true} {
			calls := []string{}
			e := Collect(context.Background(), senderFunc(func(_ context.Context, r gate.Request) gate.Result {
				calls = append(calls, r.Op)
				if r.Op == op {
					if malformed {
						return inventoryResult(op, `"unknown"`)
					}
					return gate.Result{RequestID: op, Decision: "unavailable:permission", Reason: "insufficient_permission", Response: &gate.Response{Status: 403}}
				}
				return inventoryFixture(r.Op)
			}), Target{Asset: "saas:google-workspace:example.com", Stage: "recon"}, Context{})
			if op == opBootstrapDomains && !malformed && len(calls) != 2 {
				t.Fatal(calls)
			}
			if op == OpUnits && strings.Contains(strings.Join(calls, ","), OpUsers) {
				t.Fatal("users read without unit recognition", calls)
			}
			if op == OpUsers && e.Users.Complete {
				t.Fatal(e.Users)
			}
			if len(e.Judgments) != 0 {
				t.Fatal("inventory created verdicts")
			}
		}
	}
}

func TestCollectContinuesEmptyPagesAndNotesPartialInventory(t *testing.T) {
	count := 0
	e := Collect(context.Background(), senderFunc(func(_ context.Context, r gate.Request) gate.Result {
		if r.Op != OpUsers {
			return inventoryFixture(r.Op)
		}
		count++
		if count == 1 {
			v := inventoryResult("page1", `[]`)
			v.Response.Population.More = true
			return v
		}
		if r.NextOf != "page1" || r.Params["page_token"] != "" {
			t.Fatal(r)
		}
		v := inventoryFixture(OpUsers)
		v.Response.Population.Incomplete = []string{"dropped"}
		return v
	}), Target{Asset: "saas:google-workspace:example.com", Stage: "recon"}, Context{})
	if count != 2 || e.Users.Complete || len(e.Users.Items) != 1 {
		t.Fatal(e.Users)
	}
	found := false
	for _, n := range e.Notes {
		found = found || strings.Contains(n.Detail, "accounts: at least 1")
	}
	if !found {
		t.Fatal(e.Notes)
	}
}

func TestPeopleAttributionRequiresUnambiguousPrimaryOrAlias(t *testing.T) {
	users := []User{{ID: "1", Primary: "one@example.com", Aliases: []string{"old@example.com"}}, {ID: "2", Primary: "two@example.com", Aliases: []string{"shared@example.com", "old@example.com"}}}
	people := []Person{{Handle: "one", Addresses: []string{"one@example.com", "old@example.com"}}, {Handle: "ambiguous", Addresses: []string{"old@example.com"}}, {Handle: "two", Addresses: []string{"shared@example.com"}}, {Handle: "display", Addresses: []string{"One Person"}}}
	out := attribute("saas:google-workspace:example.com", users, people, true)
	if len(out) != 2 || out[0].ProviderID != "1" || out[0].MatchedBy != "primary" || out[1].ProviderID != "2" || out[1].MatchedBy != "alias" {
		t.Fatal(out)
	}
	if out := attribute("tenant", users, []Person{{Handle: "a", Addresses: []string{"one@example.com"}}, {Handle: "b", Addresses: []string{"one@example.com"}}}, true); len(out) != 0 {
		t.Fatal(out)
	}
}

func TestCredentialNotesUseOnlyExactRecognizedReturnedScopes(t *testing.T) {
	for _, tc := range []struct {
		scopes         []string
		known          bool
		kind, contains string
	}{
		{nil, false, "workspace_credential", "unknown"},
		{[]string{"https://www.googleapis.com/auth/admin.directory.user.readonly"}, true, "workspace_credential", "No recognized beyond-read"},
		{[]string{"made-up.readonly"}, true, "workspace_credential", "unknown"},
		{[]string{"https://www.googleapis.com/auth/admin.directory.user.security", "unknown"}, true, "workspace_credential_warning", "beyond"},
	} {
		note := CredentialNote(Binding{Scopes: tc.scopes, ScopesKnown: tc.known})
		if note.Kind != tc.kind || !strings.Contains(note.Detail, tc.contains) {
			t.Fatal(note)
		}
	}
}

func TestPeopleAttributionPreservesMultipleAccountsAndDeduplicatesAliases(t *testing.T) {
	users := []User{{ID: "1", Primary: "one@example.com", Aliases: []string{"old@example.com"}}, {ID: "2", Primary: "two@example.com"}}
	out := attribute("tenant", users, []Person{{Handle: "person", Addresses: []string{"old@example.com", "one@example.com", "two@example.com"}}}, true)
	if len(out) != 2 || out[0].ProviderID != "1" || out[0].MatchedBy != "primary" || out[1].ProviderID != "2" {
		t.Fatal(out)
	}
}
