package gate_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
)

// engagementFile is the scope these tests read, through the engagement's
// own validation and Scope: the gate's answers come from the file.
const engagementFile = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - domain: example.com
  - url: https://app.example.net/portal/
  - network: 10.20.0.0/16
  - network: 169.254.0.0/16
  - saas: github:example-org
  - saas: google-workspace:example.com
exclude:
  - network: 203.0.113.0/28
  - repo: github:example-org/client-nda
  - {saas: google-workspace:example.com, org_unit: /Board}
  - url: https://legacy.example.com/
  - network: "64:ff9b::c633:64c0/124"
`

const testToken = "test-token-0123456789abcdef"

func harness(t *testing.T) (*gate.Harness, *gate.Gate) {
	t.Helper()
	res, err := engagement.Parse("e.yaml", []byte(engagementFile), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	h := gate.NewHarness(t, res.GateScope(time.Now()))
	h.Setenv("GITHUB_TOKEN", testToken)
	return h, h.Gate()
}

func web(scheme, host, path string) gate.Request {
	return gate.Request{Op: "web.get", Asset: "domain:example.com", Params: map[string]string{"scheme": scheme, "host": host, "path": path}}
}

// E4 test 2, and an exclude under an organization root, with the
// engagement's Scope.
func TestEngagementScopeRepositories(t *testing.T) {
	h, g := harness(t)
	hits := h.GitHub(`{"name":"x"}`)
	repo := func(owner, name string) gate.Result {
		return g.Send(context.Background(), gate.Request{Op: "github.repo", Asset: "saas:github:example-org",
			Params: map[string]string{"owner": owner, "repo": name}})
	}
	if res := repo("other-org", "x"); res.Decision != "refused:out_of_scope" || res.Reason != "unavailable:refused_by_gate" {
		t.Errorf("another organization: %+v", res)
	}
	if res := repo("Example-Org", "Client-NDA"); res.Decision != "refused:excluded" || res.Detail != "exclude[1]" {
		t.Errorf("an excluded repository, case-folded: %+v", res)
	}
	if hits() != 0 || h.Dials() != 0 {
		t.Fatalf("the server saw %d requests", hits())
	}
	other := gate.Request{Op: "github.repo", Asset: "saas:github:Example-Org", Params: map[string]string{"owner": "example-org", "repo": "shop"}}
	if res := g.Send(context.Background(), other); res.Decision != "refused:out_of_scope" {
		t.Errorf("an asset not written canonically: %+v", res)
	}
	if res := repo("example-org", "shop"); !res.OK() {
		t.Errorf("an in-scope repository: %+v", res)
	}
}

// E4 test 3 with the engagement's Scope: a per-user op on a user in /Board
// or /Board/Sub is refused, and /Boardroom is sent.
func TestEngagementScopeOrgUnits(t *testing.T) {
	h, g := harness(t)
	seen := h.Workspace()
	ctx := context.Background()
	ws := func(op string, params map[string]string) gate.Request {
		return gate.Request{Op: op, Asset: "saas:google-workspace:example.com", Params: params}
	}
	first := g.Send(ctx, ws("ws.users", nil))
	next := ws("ws.users", nil)
	next.NextOf = first.RequestID
	if second := g.Send(ctx, next); !first.OK() || !second.OK() {
		t.Fatalf("users: %+v %+v", first, second)
	}
	for user, want := range map[string]string{"101": "refused:excluded", "102": "refused:excluded", "103": "sent"} {
		if res := g.Send(ctx, ws("ws.user_tokens", map[string]string{"user": user})); res.Decision != want {
			t.Errorf("tokens of %s: %+v", user, res)
		}
	}
	if got := seen(); slices.Contains(got, "/admin/directory/v1/users/101/tokens") || slices.Contains(got, "/admin/directory/v1/users/102/tokens") {
		t.Errorf("an excluded user's tokens were read: %v", got)
	}
}

// E4 tests 6 and 7 with the engagement's Scope: every address in the
// answer is checked against the file's excludes and network roots, and
// metadata and loopback are never admitted, even under a network root.
func TestEngagementScopeAddresses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		want    string
	}{
		{"re-pointed into an excluded range", []string{"203.0.113.9"}, "refused:address_excluded"},
		{"one public, one excluded", []string{"198.51.100.20", "203.0.113.9"}, "refused:address_excluded"},
		{"an IPv4 address a NAT64 exclude carries", []string{"198.51.100.200"}, "refused:address_excluded"},
		{"cloud metadata under a network root", []string{"169.254.169.254"}, "refused:address_not_public"},
		{"IPv4-mapped loopback", []string{"::ffff:127.0.0.1"}, "refused:address_not_public"},
		{"private, outside every network root", []string{"192.168.1.10"}, "refused:address_not_public"},
		{"private, inside a network root", []string{"10.20.0.5"}, "sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, g := harness(t)
			for _, a := range tc.answers[1:] {
				h.Answer("www.example.com", a)
			}
			seen := h.Site("www.example.com", tc.answers[0])
			if res := g.Send(context.Background(), web("https", "www.example.com", "/")); res.Decision != tc.want {
				t.Fatalf("%+v", res)
			}
			if tc.want != "sent" && (h.Dials() != 0 || len(seen()) != 0) {
				t.Error("a refused name was dialled")
			}
		})
	}
}

// E4 tests 9 and 10 with the engagement's Scope: a discovered name without
// first-party evidence is read at / over https and http and nowhere else; a
// url root reads its entry points, robots.txt and security.txt.
func TestEngagementScopeEntryPoints(t *testing.T) {
	h, g := harness(t)
	ctx := context.Background()
	shop := h.Site("shop.example.com", "198.51.100.30")
	for _, scheme := range []string{"https", "http"} {
		if res := g.Send(ctx, web(scheme, "shop.example.com", "/")); !res.OK() {
			t.Errorf("%s front page: %+v", scheme, res)
		}
	}
	// The file has network roots, so robots.txt and security.txt wait on
	// one holding every address; the name's address is outside them.
	for p, want := range map[string]string{"/robots.txt": "refused:address_moved", "/.well-known/security.txt": "refused:address_moved",
		"/admin": "refused:entry_point"} {
		if res := g.Send(ctx, web("https", "shop.example.com", p)); res.Decision != want {
			t.Errorf("%s: %+v", p, res)
		}
	}
	if res := g.Send(ctx, gate.Request{Op: "web.cert", Asset: "domain:example.com", Params: map[string]string{"host": "shop.example.com"}}); !res.OK() {
		t.Errorf("certificate: %+v", res)
	}
	got := shop()
	slices.Sort(got)
	if !slices.Equal(got, []string{"http GET /", "https GET /"}) {
		t.Errorf("the discovered name's servers saw %v", got)
	}

	app := h.Site("app.example.net", "198.51.100.40")
	asset := "url:https://app.example.net/portal/"
	for p, want := range map[string]string{
		"/portal/": "sent", "/robots.txt": "sent", "/.well-known/security.txt": "sent",
		"/": "refused:out_of_scope", "/portal/admin": "refused:entry_point", "/admin": "refused:out_of_scope",
	} {
		r := web("https", "app.example.net", p)
		r.Asset = asset
		if res := g.Send(ctx, r); res.Decision != want {
			t.Errorf("url root %s: %+v", p, res)
		}
	}
	got = app()
	slices.Sort(got)
	if !slices.Equal(got, []string{"https GET /.well-known/security.txt", "https GET /portal/", "https GET /robots.txt"}) {
		t.Errorf("the url root's server saw %v", got)
	}
}

// A url exclude written with https stops the http read of the same name,
// which every discovered name otherwise gets.
func TestEngagementScopeURLExcludeCoversBothSchemes(t *testing.T) {
	h, g := harness(t)
	seen := h.Site("legacy.example.com", "198.51.100.50")
	for _, scheme := range []string{"https", "http"} {
		if res := g.Send(context.Background(), web(scheme, "legacy.example.com", "/")); res.Decision != "refused:excluded" || res.Detail != "exclude[3]" {
			t.Errorf("%s: %+v", scheme, res)
		}
	}
	if got := seen(); len(got) != 0 || h.Dials() != 0 {
		t.Errorf("an excluded site was contacted: %v", got)
	}
}
