package github

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/policy"
)

type fakeSender struct {
	requests []gate.Request
	results  map[string][]gate.Result
}

func (f *fakeSender) Send(_ context.Context, r gate.Request) gate.Result {
	f.requests = append(f.requests, r)
	x := f.results[r.Op]
	if len(x) == 0 {
		return gate.Result{RequestID: "missing", Decision: "unavailable:missing", Reason: "missing_permission"}
	}
	f.results[r.Op] = x[1:]
	return x[0]
}

func result(id, body string, list bool) gate.Result {
	r := gate.Result{RequestID: id, Decision: gate.DecisionSent, Response: &gate.Response{Status: 200, Body: []byte(body), CollectedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}}
	if list {
		r.Response.Population = &gate.Population{Page: 1}
	}
	return r
}

func inventoryFake() *fakeSender {
	return &fakeSender{results: map[string][]gate.Result{
		OpPrincipal:    {result("p", `{"id":1,"login":"Alice","type":"User","two_factor_authentication":false}`, false)},
		OpOrganization: {result("o", `{"id":2,"login":"Acme","type":"Organization","two_factor_requirement_enabled":false}`, false)},
		OpMembership:   {result("m", `{"state":"active","role":"admin","organization":{"id":2,"login":"acme","type":"Organization"},"user":{"id":1,"login":"alice","type":"User"}}`, false)},
		OpMembers:      {result("all", `[{"id":1,"login":"alice","type":"User"}]`, true)},
		OpOwners:       {result("owners", `[{"id":1,"login":"alice","type":"User"}]`, true)},
		OpOutside:      {result("outside", `[]`, true)},
		OpInvitations:  {result("invitations", `[{"id":3,"login":null,"role":"direct_member"}]`, true)},
		OpRepositories: {result("repos", `[{"id":4,"name":"Example","full_name":"Acme/Example","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"private","private":true,"archived":false,"default_branch":"main"}]`, true)},
	}}
}

func collectFake(f *fakeSender) Evidence {
	p := ResolvePrincipal(context.Background(), f, "github:acme", "recon")
	return Collect(context.Background(), f, Organization{Asset: "github:acme", Name: "acme", Stage: "recon"}, p)
}

func TestInventoryPreservesAuthorityUnknownsAndRequestMetadata(t *testing.T) {
	f := inventoryFake()
	f.results[OpPrincipal][0].Response.Header = http.Header{"X-Oauth-Scopes": []string{"repo, read:org, repo"}}
	e := collectFake(f)
	if !e.OwnerAuthority || e.Principal.Identity != "github:user:1" || e.Principal.Account.Login != "alice" || len(e.Principal.Scopes) != 2 {
		t.Fatalf("authority/principal: %+v", e)
	}
	if e.Organization.TwoFactorRequirementEnabled == nil || *e.Organization.TwoFactorRequirementEnabled {
		t.Fatal("explicit false lost")
	}
	if e.Organization.DefaultRepositoryPermission != nil {
		t.Fatal("absent field is known")
	}
	if !e.Members.Complete || !e.Invitations.Complete || len(e.Invitations.Items) != 1 || e.Invitations.Items[0].Login != nil {
		t.Fatal("complete population/null invitation lost")
	}
	if !e.Repositories.Complete || e.RepositoryVisibilityComplete || len(e.Repositories.Gaps) == 0 {
		t.Fatal("limited-token visibility overstated")
	}
	if len(e.Reads()) != 8 || len(f.requests) != 8 {
		t.Fatalf("missing requests: %v", e.Reads())
	}
	for _, r := range f.requests {
		if r.Stage != "recon" || r.Asset != "github:acme" {
			t.Fatal("request attribution lost")
		}
	}
	for _, r := range e.Reads() {
		if r.ObservedAt.IsZero() || r.Status != 200 {
			t.Fatal("observation lost")
		}
	}
}

func TestNullSettingsAndUnsupportedPrincipalStayUnknown(t *testing.T) {
	f := inventoryFake()
	f.results[OpPrincipal][0] = gate.Result{RequestID: "p", Decision: "unavailable:unsupported_principal", Reason: "missing_permission"}
	f.results[OpOrganization][0].Response.Body = []byte(`{"id":2,"login":"acme","type":"Organization","two_factor_requirement_enabled":null}`)
	e := collectFake(f)
	if e.Principal.Account != nil || e.Principal.Identity != "" || e.OwnerAuthority || e.Members.VisibilityComplete || e.Owners.VisibilityComplete {
		t.Fatal("unknown principal claims authority")
	}
	if e.Organization == nil || e.Organization.TwoFactorRequirementEnabled != nil {
		t.Fatal("null setting treated as false")
	}
}

func TestMembershipRequiresPrincipalAndOrganizationIdentityMatch(t *testing.T) {
	for _, replace := range []struct{ from, to string }{{`"id":1`, `"id":9`}, {`"id":2`, `"id":9`}, {`"active"`, `"pending"`}, {`"admin"`, `"member"`}, {`"alice"`, `"mallory"`}} {
		f := inventoryFake()
		r := &f.results[OpMembership][0]
		r.Response.Body = []byte(strings.ReplaceAll(string(r.Response.Body), replace.from, replace.to))
		if collectFake(f).OwnerAuthority {
			t.Fatalf("authority trusted mismatch %v", replace)
		}
	}
}

func TestPaginationUsesNextOfAndPreservesPartialEvidence(t *testing.T) {
	f := inventoryFake()
	f.results[OpMembers][0].Response.Population.More = true
	r := result("all2", `[{"id":5,"login":"bob","type":"User"}]`, true)
	r.Response.Population.Page = 2
	r.Decision = gate.DecisionReused
	f.results[OpMembers] = append(f.results[OpMembers], r)
	e := collectFake(f)
	if len(e.Members.Items) != 2 || !e.Members.Complete || !e.Members.Reads[1].Reused {
		t.Fatal("pagination metadata lost")
	}
	var next gate.Request
	for _, r := range f.requests {
		if r.NextOf != "" {
			next = r
		}
	}
	if next.NextOf != "all" || len(next.Params) != 1 || next.Params["org"] != "acme" {
		t.Fatalf("collector passed cursor: %+v", next)
	}
	f = inventoryFake()
	f.results[OpMembers][0].Response.Population.More = true
	e = collectFake(f)
	if e.Members.Complete || len(e.Members.Items) != 1 || len(e.Members.Reads) != 2 {
		t.Fatal("failed next page loses presence or proves absence")
	}
}

func TestMalformedAndDroppedPopulationsNeverProveAbsence(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `[{"id":0,"login":"alice","type":"User"}]`, `[{"id":1,"login":"bad/login","type":"User"}]`, `[{"id":1,"login":"alice","type":"unknown"}]`} {
		f := inventoryFake()
		f.results[OpMembers][0].Response.Body = []byte(body)
		if collectFake(f).Members.Complete {
			t.Fatalf("malformed list is complete: %s", body)
		}
	}
	f := inventoryFake()
	f.results[OpMembers][0].Response.Population.Incomplete = []string{"dropped"}
	if collectFake(f).Members.Complete {
		t.Fatal("dropped list complete")
	}
	f = inventoryFake()
	f.results[OpMembers][0].Response.Truncated = true
	e := collectFake(f)
	if !e.Members.Reads[0].Truncated {
		t.Fatal("truncation metadata lost")
	}
	if e.Members.Complete {
		t.Fatal("truncated list complete")
	}
}

func TestMalformedRepositoryAndUnknownSettingsRemainUnknown(t *testing.T) {
	f := inventoryFake()
	f.results[OpRepositories][0].Response.Body = []byte(`[{"id":4,"name":"x","full_name":"other/x","owner":{"id":2,"login":"other","type":"Organization"}}]`)
	e := collectFake(f)
	if e.Repositories.Complete || len(e.Repositories.Items) != 0 {
		t.Fatal("foreign repository accepted")
	}
	f = inventoryFake()
	f.results[OpOrganization][0].Response.Body = []byte(`{"id":2,"login":"acme","type":"Organization","two_factor_requirement_enabled":"false"}`)
	if collectFake(f).Organization != nil {
		t.Fatal("unrecognized bool accepted")
	}
}

func TestTypedEvidenceDoesNotRetainUnconsumedMetadata(t *testing.T) {
	f := inventoryFake()
	f.results[OpPrincipal][0].Response.Body = []byte(`{"id":1,"login":"alice","type":"User","email":"private@example.com","bio":"secret-value"}`)
	b, err := json.Marshal(collectFake(f))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "private@example.com") || strings.Contains(string(b), "secret-value") {
		t.Fatal("unconsumed provider metadata retained")
	}
}

func TestInventoryOpsAreValidatedAndReadOnly(t *testing.T) {
	if _, err := gate.NewRegistry(Ops...); err != nil {
		t.Fatal(err)
	}
	for _, o := range Ops {
		if o.Method != gate.GET || o.APIVersion != "2026-03-10" || o.Auth != gate.GitHubToken {
			t.Fatalf("unfrozen op %+v", o)
		}
		for _, p := range o.Params {
			if p.Name == "role" || p.Name == "filter" {
				t.Fatal("caller controls semantic filter")
			}
		}
	}
}

func TestMemberVisibilityDoesNotRequireOwnerRole(t *testing.T) {
	f := inventoryFake()
	f.results[OpMembership][0].Response.Body = []byte(strings.ReplaceAll(string(f.results[OpMembership][0].Response.Body), `"admin"`, `"member"`))
	e := collectFake(f)
	if e.OwnerAuthority || !e.MemberAuthority || !e.Members.VisibilityComplete || !e.Owners.VisibilityComplete || e.Invitations.VisibilityComplete || e.OutsideCollaborators.VisibilityComplete {
		t.Fatalf("visibility authority wrong: %+v", e)
	}
	if !e.Invitations.Complete || !e.OutsideCollaborators.Complete {
		t.Fatal("visibility uncertainty corrupted pagination completeness")
	}
}

func TestDuplicateIDsAndBots(t *testing.T) {
	f := inventoryFake()
	f.results[OpMembers][0].Response.Body = []byte(`[{"id":1,"login":"alice","type":"User"},{"id":1,"login":"alice","type":"User"},{"id":8,"login":"dependabot[bot]","type":"Bot"}]`)
	e := collectFake(f)
	if e.Members.Complete || len(e.Members.Items) != 2 {
		t.Fatalf("duplicate inflated count or bot missing: %+v", e.Members)
	}
}

func TestMarkedPrincipalAndScopesCannotEstablishAuthority(t *testing.T) {
	f := inventoryFake()
	f.results[OpPrincipal][0].Response.Redactions = []policy.Hit{{}}
	if collectFake(f).MemberAuthority {
		t.Fatal("marked principal grants authority")
	}
	for _, scope := range []string{"[REDACTED:token:20 bytes]", "REPO", "foo.bar"} {
		f = inventoryFake()
		f.results[OpPrincipal][0].Response.Header = http.Header{"X-Oauth-Scopes": []string{scope}}
		e := collectFake(f)
		if e.Principal.Identity != "" || e.MemberAuthority {
			t.Fatalf("unrecognized scope grants authority: %s", scope)
		}
	}
	f = inventoryFake()
	f.results[OpMembership][0].Response.Redactions = []policy.Hit{{}}
	if collectFake(f).MemberAuthority {
		t.Fatal("marked membership grants authority")
	}
}

func TestMembershipOrganizationSimpleShape(t *testing.T) {
	f := inventoryFake()
	// GitHub's nested organization-simple has id/login, but no type field.
	f.results[OpMembership][0].Response.Body = []byte(`{"state":"active","role":"admin","organization":{"id":2,"login":"acme"},"user":{"id":1,"login":"alice","type":"User"}}`)
	e := collectFake(f)
	if !e.OwnerAuthority || !e.MemberAuthority || e.Membership.Organization.Type != "" {
		t.Fatal("organization-simple rejected or fabricated type")
	}
}
