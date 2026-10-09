package engagement

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/engagement/gate"
)

const scopeFile = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - domain: example.com
  - url: https://app.example.net/portal/
  - network: 198.51.100.0/24
  - host: deploy@203.0.113.5
  - saas: github:example-org
  - saas: google-workspace:example.com
  - cloud: gcp:organizations/123456789012
exclude:
  - domain: legacy.example.com
  - network: 198.51.100.128/25
  - host: 203.0.113.9
  - url: https://shop.example.com/checkout/
  - repo: github:example-org/client-nda
  - {saas: google-workspace:example.com, org_unit: /Board}
  - cloud: gcp:example-sandbox
defaults:
  throttle: {rate: 120/m, concurrency: 3}
people:
  alice: {kind: employee, workspace: [alice@example.com]}
assets:
  blog:
    domain: blog.example.com
    first_party: {confirmed_by: alice, date: 2026-10-07, target: blog.example-hosting.net}
  slow-org:
    saas: github:example-org
    throttle: {rate: 2/s, concurrency: 1}
  slow-tenant:
    saas: google-workspace:example.com
    throttle: {concurrency: 1}
  www:
    domain: www.example.com
    throttle: {rate: 1/s}
  edge:
    host: 198.51.100.9
intent:
  exposed_on_purpose:
    - {url: "https://app.example.net/portal/status", audience: internet}
    - {url: "https://www.example.com/api/", audience: internet}
`

// runStart is the run every scope test reads the file at, inside the
// year of the confirmations its files carry.
var runStart = time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)

func scopeOf(t *testing.T, file string) gate.Scope {
	t.Helper()
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	return res.GateScope(runStart)
}

// Subjects are placed by the file's own locators, compared case-folded,
// and the first exclude covering one names it (E4 tests 2 and 3).
func TestScopeSubject(t *testing.T) {
	s := scopeOf(t, scopeFile)
	for _, tc := range []struct {
		asset, id string
		want      gate.Standing
	}{
		{"saas:github:example-org", "saas:github:example-org", gate.Standing{UnderAsset: true, Root: "saas:github:example-org"}},
		{"saas:github:example-org", "repo:github:Example-Org/Shop", gate.Standing{UnderAsset: true, Root: "saas:github:example-org"}},
		{"saas:github:example-org", "repo:github:other-org/x", gate.Standing{}},
		{"saas:github:other-org", "repo:github:other-org/x", gate.Standing{UnderAsset: true}},
		{"saas:github:example-org", "repo:github:example-org/Client-NDA", gate.Standing{UnderAsset: true, Root: "saas:github:example-org", ExcludedBy: "exclude[4]"}},
		{"domain:example.com", "url:https://www.example.com/", gate.Standing{UnderAsset: true, Root: "domain:example.com"}},
		{"domain:example.com", "url:https://xexample.com/", gate.Standing{}},
		{"domain:example.com", "url:https://a.legacy.example.com/", gate.Standing{UnderAsset: true, Root: "domain:example.com", ExcludedBy: "exclude[0]"}},
		{"domain:example.com", "url:https://shop.example.com/check%6Fut/x", gate.Standing{UnderAsset: true, Root: "domain:example.com", ExcludedBy: "exclude[3]"}},
		{"domain:example.com", "url:https://shop.example.com/checkoutx", gate.Standing{UnderAsset: true, Root: "domain:example.com"}},
		// By whole segments, with or without the exclude's slash.
		{"domain:example.com", "url:https://shop.example.com/checkout", gate.Standing{UnderAsset: true, Root: "domain:example.com", ExcludedBy: "exclude[3]"}},
		// A url exclude written with https stops http too.
		{"domain:example.com", "url:http://shop.example.com/checkout/", gate.Standing{UnderAsset: true, Root: "domain:example.com", ExcludedBy: "exclude[3]"}},
		{"domain:example.com", "url:http://shop.example.com/", gate.Standing{UnderAsset: true, Root: "domain:example.com"}},
		{"domain:example.com", "url:https://shop.example.com:8443/checkout/", gate.Standing{UnderAsset: true, Root: "domain:example.com"}},
		// The same port written out under the other scheme is the same port.
		{"domain:example.com", "url:http://shop.example.com:443/checkout/", gate.Standing{UnderAsset: true, Root: "domain:example.com", ExcludedBy: "exclude[3]"}},
		// A url root reads robots.txt and security.txt at its origin's root,
		// outside its own path; nothing else there.
		{"url:https://app.example.net/portal/", "url:https://app.example.net/robots.txt", gate.Standing{UnderAsset: true, Root: "url:https://app.example.net/portal/"}},
		{"url:https://app.example.net/portal/", "url:https://app.example.net/.well-known/security.txt", gate.Standing{UnderAsset: true, Root: "url:https://app.example.net/portal/"}},
		{"url:https://app.example.net/portal/", "url:https://app.example.net/admin", gate.Standing{}},
		{"url:https://app.example.net/portal/", "url:http://app.example.net/robots.txt", gate.Standing{}},
		{"network:198.51.100.0/24", "url:https://198.51.100.7/", gate.Standing{UnderAsset: true, Root: "network:198.51.100.0/24"}},
		{"network:198.51.100.0/24", "url:https://198.51.100.200/", gate.Standing{UnderAsset: true, Root: "network:198.51.100.0/24", ExcludedBy: "exclude[1]"}},
		{"host:203.0.113.5:22", "url:https://203.0.113.5/", gate.Standing{UnderAsset: true, Root: "host:203.0.113.5:22"}},
		// A name read for its records may hold underscore labels; it is
		// placed by its labels, its excludes included.
		{"domain:example.com", "domain:_dmarc.example.com", gate.Standing{UnderAsset: true, Root: "domain:example.com"}},
		{"domain:example.com", "domain:s1._domainkey.example.com", gate.Standing{UnderAsset: true, Root: "domain:example.com"}},
		{"domain:example.com", "domain:_dmarc.a.legacy.example.com", gate.Standing{UnderAsset: true, Root: "domain:example.com", ExcludedBy: "exclude[0]"}},
		{"domain:example.com", "domain:_dmarc.example.org", gate.Standing{}},
		{"domain:example.com", "domain:_dmarc.example.123", gate.Standing{}},
		// A Workspace per-user subject is its tenant's; an organizational
		// unit exclude never covers the tenant itself.
		{"saas:google-workspace:example.com", "saas:google-workspace:example.com/users/12345", gate.Standing{UnderAsset: true, Root: "saas:google-workspace:example.com"}},
		{"saas:google-workspace:example.com", "saas:google-workspace:example.com/users/", gate.Standing{}},
		{"saas:google-workspace:example.com", "saas:google-workspace:example.com/users/a/tokens", gate.Standing{}},
		{"saas:google-workspace:example.com", "saas:google-workspace:example.com/groups/x", gate.Standing{}},
		{"saas:github:example-org", "saas:github:example-org/users/x", gate.Standing{}},
		{"cloud:gcp:organizations/123456789012", "cloud:gcp:example-prod", gate.Standing{UnderAsset: true, Root: "cloud:gcp:organizations/123456789012"}},
		{"cloud:gcp:organizations/123456789012", "cloud:gcp:example-sandbox", gate.Standing{UnderAsset: true, Root: "cloud:gcp:organizations/123456789012", ExcludedBy: "exclude[6]"}},
		{"domain:example.com", "not an id", gate.Standing{}},
		// The asset is read strictly: another spelling of an in-scope one
		// is outside every root, so it never gets a throttle of its own.
		{"saas:github:Example-Org", "repo:github:example-org/shop", gate.Standing{}},
		{"domain:Example.com", "url:https://www.example.com/", gate.Standing{}},
		{"bogus", "url:https://www.example.com/", gate.Standing{}},
	} {
		if got := s.Subject(tc.asset, tc.id); got != tc.want {
			t.Errorf("Subject(%s, %s) = %+v, want %+v", tc.asset, tc.id, got, tc.want)
		}
	}
}

// Every address is placed against the excluded networks, the hosts
// excluded by address and the network roots (E4 tests 6 and 7).
// An exclude written in a translated form holds the IPv4 addresses it
// carries; an IPv4-mapped one is refused, so it has one spelling.
func TestScopeAddressTranslatedExcludes(t *testing.T) {
	s := scopeOf(t, minimal+`exclude:
  - network: "64:ff9b::c633:6400/120"
  - network: "2002:c633:6500::/40"
  - host: "[64:ff9b::c000:201]"
`)
	for addr, want := range map[string]string{
		"198.51.100.30":          "exclude[0]",
		"64:ff9b::c633:641e":     "exclude[0]",
		"::ffff:198.51.100.30":   "exclude[0]",
		"64:ff9b::c633:641e%en0": "exclude[0]",
		"fe80::1%en0":            "",
		"::ffff:192.0.2.1":       "exclude[2]",
		"198.51.101.1":           "exclude[1]",
		"203.0.113.77":           "",
		"198.51.102.1":           "",
		"192.0.2.1":              "exclude[2]",
		"192.0.2.2":              "",
		"2001:db8::1":            "",
	} {
		if got, _ := s.Address(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Address(%s) = %q, want %q", addr, got, want)
		}
	}
	for _, line := range []string{"  - host: \"[::ffff:198.51.100.30]\"\n", "  - network: \"::ffff:198.51.100.0/120\"\n"} {
		if _, err := Parse("e.yaml", []byte(minimal+"exclude:\n"+line), testOpts); err == nil || !strings.Contains(err.Error(), "IPv4") {
			t.Errorf("%q: %v", line, err)
		}
	}
}

func TestScopeAddress(t *testing.T) {
	s := scopeOf(t, scopeFile)
	for _, tc := range []struct {
		addr     string
		excluded string
		inRoot   bool
	}{
		{"198.51.100.7", "", true},
		{"::ffff:198.51.100.7", "", true},
		{"198.51.100.200", "exclude[1]", true},
		{"::ffff:203.0.113.9", "exclude[2]", false},
		{"203.0.113.9", "exclude[2]", false},
		{"203.0.113.5", "", false},
		{"192.0.2.1", "", false},
	} {
		x, in := s.Address(netip.MustParseAddr(tc.addr))
		if x != tc.excluded || in != tc.inRoot {
			t.Errorf("Address(%s) = %q, %v; want %q, %v", tc.addr, x, in, tc.excluded, tc.inRoot)
		}
	}
}

// A discovered name has its front page; robots.txt and security.txt need
// first-party evidence: a root's, a network root holding every address, or
// the operator's confirmation with its target; a url root reads its entry
// points (E4 tests 9 and 10).
func TestScopeSite(t *testing.T) {
	s := scopeOf(t, scopeFile)
	well := []string{"/.well-known/security.txt", "/robots.txt"}
	for _, tc := range []struct {
		origin string
		want   siteList
	}{
		// Discovered, no evidence: the front page, over https and http.
		{"https://shop.example.com", siteList{Paths: []string{"/"}, Network: well}},
		{"http://shop.example.com", siteList{Paths: []string{"/"}, Network: well}},
		// No other port, and nothing outside every root.
		{"https://shop.example.com:8443", siteList{}},
		{"https://example.org", siteList{}},
		// Confirmed by the operator: while it points at its target, or
		// through a network root.
		{"https://blog.example.com", siteList{Paths: []string{"/"}, Network: well, Confirmed: well, Target: "blog.example-hosting.net"}},
		// The intent URL on a discovered name is an entry point only with
		// first-party evidence.
		{"https://www.example.com", siteList{Paths: []string{"/"}, Network: []string{"/.well-known/security.txt", "/api/", "/robots.txt"}}},
		// A url root: its own path, the intent URL on it, the two files;
		// not its front page.
		{"https://app.example.net", siteList{Paths: []string{"/.well-known/security.txt", "/portal/", "/portal/status", "/robots.txt"}}},
		{"http://app.example.net", siteList{}},
		// A host root and an address in a network root are first-party.
		{"https://203.0.113.5", siteList{Paths: []string{"/", "/.well-known/security.txt", "/robots.txt"}}},
		{"https://198.51.100.7", siteList{Paths: []string{"/", "/.well-known/security.txt", "/robots.txt"}}},
		// An origin not written canonically lists nothing.
		{"https://Shop.example.com", siteList{}},
		{"https://shop.example.com:443", siteList{}},
		{"https://shop.example.com/x", siteList{}},
	} {
		if got := siteOf(s, tc.origin); !sameSite(got, tc.want) {
			t.Errorf("Site(%s) = %+v; want %+v", tc.origin, got, tc.want)
		}
	}
}

// siteList is site's lists as these tests write them, with the
// confirmation's target the confirmed paths wait on.
type siteList struct {
	Paths, Network, Confirmed []string
	Target                    string
}

func siteOf(s gate.Scope, origin string) siteList {
	sp := s.(*scope).site(origin)
	out := siteList{Paths: sp.paths, Network: sp.network, Confirmed: sp.confirmed}
	if sp.ev != nil {
		out.Target = sp.ev.Target
	}
	return out
}

func sameSite(a, b siteList) bool {
	return slices.Equal(a.Paths, b.Paths) && slices.Equal(a.Network, b.Network) && slices.Equal(a.Confirmed, b.Confirmed) && a.Target == b.Target
}

// With no network root, nothing beyond a discovered name's front page
// waits on one.
func TestScopeSiteWithoutNetworkRoots(t *testing.T) {
	if got := siteOf(scopeOf(t, minimal), "https://www.example.com"); !sameSite(got, siteList{Paths: []string{"/"}}) {
		t.Errorf("Site = %+v", got)
	}
}

// A confirmation names its target canonically and holds for a year, through
// its last day in engagement.timezone.
func TestConfirmationYear(t *testing.T) {
	file := strings.Replace(minimal, "  - saas: github:example-org\n", "  - saas: github:example-org\npeople:\n  alice: {kind: employee, workspace: [alice@example.com]}\nassets:\n"+
		"  www:\n    domain: www.example.com\n    first_party: {confirmed_by: alice, date: 2026-10-07, target: \"198.51.100.9, 198.51.100.8\"}\n", 1)
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	madrid, _ := time.LoadLocation("Europe/Madrid")
	for at, want := range map[time.Time]string{
		time.Date(2027, 10, 7, 23, 59, 0, 0, madrid): "198.51.100.8,198.51.100.9",
		time.Date(2027, 10, 8, 0, 0, 0, 0, madrid):   "",
	} {
		if got := siteOf(res.GateScope(at), "https://www.example.com"); got.Target != want {
			t.Errorf("at %s: %+v", at, got)
		}
	}
	if ev := res.firstParty(res.Assets[len(res.Assets)-1], time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)); ev.String() != "none: the confirmation of 2026-10-07 expired" {
		t.Errorf("expired: %s", ev)
	}
	// Dated after the run, a typo for a year to come: not evidence.
	future := strings.Replace(file, "date: 2026-10-07", "date: 2062-10-07", 1)
	if res, err := Parse("e.yaml", []byte(future), testOpts); err != nil {
		t.Fatal(err)
	} else if got := siteOf(res.GateScope(runStart), "https://www.example.com"); got.Target != "" || len(got.Confirmed) != 0 {
		t.Errorf("a future confirmation: %+v", got)
	} else if ev := res.firstParty(res.Assets[len(res.Assets)-1], runStart); ev.String() != "none: the confirmation is dated 2062-10-07, after this run" {
		t.Errorf("future: %s", ev)
	}
	for _, bad := range []string{"", "not a target!", "198.51.100.7,x"} {
		f := strings.Replace(file, `"198.51.100.9, 198.51.100.8"`, `"`+bad+`"`, 1)
		if _, err := Parse("e.yaml", []byte(f), testOpts); err == nil || !strings.Contains(err.Error(), "first_party.target") {
			t.Errorf("target %q: %v", bad, err)
		}
	}
}

// A web asset takes its entry's throttle or the defaults; a SaaS asset only
// what its own entry sets.
func TestScopeThrottle(t *testing.T) {
	s := scopeOf(t, scopeFile)
	for _, tc := range []struct {
		asset string
		rate  float64
		conc  int
	}{
		{"domain:www.example.com", 1, 3},
		{"domain:shop.example.com", 2, 3}, // discovered: the defaults, 120/m
		{"domain:example.com", 2, 3},
		{"saas:github:example-org", 2, 1},
		{"saas:google-workspace:example.com", 0, 1}, // its own concurrency, never the defaults' rate
		{"repo:github:example-org/shop", 0, 0},
	} {
		if rate, conc := s.Throttle(tc.asset); rate != tc.rate || conc != tc.conc {
			t.Errorf("Throttle(%s) = %v, %d; want %v, %d", tc.asset, rate, conc, tc.rate, tc.conc)
		}
	}
}

func TestScopeOrgUnits(t *testing.T) {
	s := scopeOf(t, scopeFile)
	want := []gate.OrgUnit{{Path: "/Board", ExcludedBy: "exclude[5]"}}
	if got := s.OrgUnits("saas:google-workspace:example.com"); !slices.Equal(got, want) {
		t.Errorf("OrgUnits = %+v", got)
	}
	if got := s.OrgUnits("saas:github:example-org"); got != nil {
		t.Errorf("a GitHub organization has organizational units: %+v", got)
	}
}

// scope.json names each web asset's first-party evidence.
func TestFirstPartyEvidence(t *testing.T) {
	res, err := Parse("e.yaml", []byte(scopeFile), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range res.Assets {
		got[a.ID] = res.firstParty(a, runStart).String()
	}
	for id, want := range map[string]string{
		"domain:example.com":                  "none",
		"url:https://app.example.net/portal/": "url root",
		"host:203.0.113.5:22":                 "host root",
		"host:198.51.100.9:22":                "inside network:198.51.100.0/24",
		"domain:blog.example.com":             "operator confirmed (alice, 2026-10-07)",
		"domain:www.example.com":              "none",
		"saas:github:example-org":             "none",
	} {
		if got[id] != want {
			t.Errorf("%s: %q, want %q", id, got[id], want)
		}
	}
}

// scope.json's evidence and the gate agree in both directions: every web
// asset's origin with evidence reads robots.txt, and one without reads it
// only through a network root (networkPaths), never as an entry point.
func TestEvidenceMatchesTheGate(t *testing.T) {
	const small = `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
  - domain: example.com
  - url: https://app.example.net/
  - url: http://app.example.org:8080/x/
  - host: deploy@web.example.com
people:
  alice: {kind: employee, workspace: [alice@example.com]}
assets:
  sub:
    url: https://app.example.net/sub/
  web:
    domain: web.example.com
  plain:
    domain: plain.example.com
  port:
    url: http://app.example.org:8080/x/y/
  confirmed:
    url: https://shop.example.com/
    first_party: {confirmed_by: alice, date: 2026-10-07, target: blog.example-hosting.net}
`
	for name, file := range map[string]string{"scopeFile": scopeFile, "small": small} {
		res, err := Parse("e.yaml", []byte(file), testOpts)
		if err != nil {
			t.Fatal(err)
		}
		s := res.GateScope(runStart)
		networkRoot := slices.ContainsFunc(res.Roots, func(r Ref) bool { return r.Kind == KindNetwork })
		for _, a := range res.Assets {
			var origins []Ref
			switch {
			case a.Kind == KindURL:
				origins = []Ref{a.Ref}
			case (a.Kind == KindDomain || a.Kind == KindHost) && !a.Local():
				for _, scheme := range []string{"https", "http"} {
					origins = append(origins, Ref{Kind: KindURL, scheme: scheme, name: a.name, addr: a.addr})
				}
			default:
				continue
			}
			for _, o := range origins {
				ev, _ := res.evidence(o, runStart)
				host := o.Address()
				if o.addr.Is6() {
					host = "[" + host + "]"
				}
				if o.Port != 0 {
					host += ":" + strconv.Itoa(o.Port)
				}
				site := siteOf(s, o.scheme+"://"+host)
				paths, netPaths := slices.Concat(site.Paths, site.Confirmed), site.Network
				if reads := slices.Contains(paths, "/robots.txt"); reads != (ev != nil) {
					t.Errorf("%s %s at %s://%s: evidence %v, the gate reads %v", name, a.Name, o.scheme, host, ev, paths)
				}
				wantNet := (ev == nil || ev.Kind == "operator") && slices.Contains(site.Paths, "/") && networkRoot
				if got := slices.Contains(netPaths, "/robots.txt"); got != wantNet {
					t.Errorf("%s %s at %s://%s: robots.txt through a network root %v, want %v", name, a.Name, o.scheme, host, got, wantNet)
				}
			}
		}
	}
}

// The SSH transport's check reads an address in every form the resolver
// or the socket may give it, IPv4-mapped included.
func TestAllowAddressForms(t *testing.T) {
	res, err := Parse("e.yaml", []byte(scopeFile), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	for addr, refused := range map[string]bool{
		"203.0.113.9": true, "::ffff:203.0.113.9": true, "64:ff9b::cb00:7109": true, "2002:cb00:7109::1": true,
		"198.51.100.130": true, "::ffff:198.51.100.130": true, "203.0.113.5": false, "::ffff:203.0.113.5": false,
		"64:ff9b::cb00:7109%en0": true, "::ffff:203.0.113.9%lo0": true,
	} {
		if err := res.allowAddress(netip.MustParseAddr(addr)); (err != nil) != refused {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

// A DNS name is excluded by a domain exclude over it, a host exclude
// written as it, or a url exclude at its site's root on the default port;
// not by a url exclude below the root or on another port.
func TestScopeName(t *testing.T) {
	s := scopeOf(t, minimal+`exclude:
  - domain: legacy.example.com
  - host: billing.example.com
  - url: https://store.example.com/
  - url: https://docs.example.com/private/
  - url: https://admin.example.com:8443/
  - host: 203.0.113.9
`)
	for name, want := range map[string]string{
		"legacy.example.com":    "exclude[0]",
		"a.legacy.example.com":  "exclude[0]",
		"billing.example.com":   "exclude[1]",
		"a.billing.example.com": "",
		"store.example.com":     "exclude[2]",
		"docs.example.com":      "",
		"admin.example.com":     "",
		"www.example.com":       "",
	} {
		if got := s.Name(name); got != want {
			t.Errorf("Name(%s) = %q, want %q", name, got, want)
		}
	}
}

// What left this machine for SSH is what the transport recorded: the
// names this machine resolved, a host's own or a jump host's, and those a
// jump host resolved; a host the transport never got to adds none.
func TestEgressSSHNames(t *testing.T) {
	res, err := Parse("e.yaml", []byte(minimal), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := &run{res: res, o: RunOptions{Version: "test"}, recon: &ReconDoc{Assets: []ReconAsset{
		{Name: "direct", ResolvedHere: []string{"direct.example.com"}, Contact: ContactConnected},
		{Name: "inner", ResolvedHere: []string{"bastion.example.com"}, ResolvedByJump: "inner.example.com", Contact: ContactConnected},
		{Name: "again", ResolvedHere: []string{"bastion.example.com"}, Contact: ContactUnreached},
		{Name: "refused-early"},
	}}}
	e := r.egress()
	if !slices.Equal(e.SSHResolved, []string{"bastion.example.com", "direct.example.com"}) ||
		!slices.Equal(e.SSHResolvedByJump, []string{"inner.example.com"}) || e.UserAgent != "scheck/test (security self-assessment)" {
		t.Errorf("%+v", e)
	}
}

// A network root written inside NAT64 holds the addresses written in it,
// as one written in IPv4 holds their translated forms.
func TestScopeAddressTranslatedRoot(t *testing.T) {
	s := scopeOf(t, strings.Replace(minimal, "roots:\n", "roots:\n  - network: \"64:ff9b::c633:6400/120\"\n  - network: 203.0.114.0/24\n", 1))
	for addr, want := range map[string]bool{
		"64:ff9b::c633:6402": true, "64:ff9b::c633:6402%en0": true, "64:ff9b::cb00:7201": true,
		"::ffff:203.0.114.1": true, "64:ff9b::c633:6502": false, "198.51.101.2": false,
	} {
		if _, in := s.Address(netip.MustParseAddr(addr)); in != want {
			t.Errorf("Address(%s) in a root = %v, want %v", addr, in, want)
		}
	}
}

// A mail domain is read under the most specific domain root that holds it,
// once: nested roots do not read it twice or give it two SPF budgets.
func TestWebDomainNestedRoots(t *testing.T) {
	file := strings.Replace(minimal, "  - domain: example.com\n", "  - domain: example.com\n  - domain: sub.example.com\n", 1) +
		"mail:\n  senders:\n    - {domain: sub.example.com, service: sendgrid, dkim_selectors: [S1]}\n    - {domain: example.com, service: google-workspace}\n  no_mail: [old.example.com]\n"
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := &run{res: res}
	mail := map[string][]string{}
	for _, a := range res.Assets {
		if a.Kind == KindDomain && a.Root == a.ID {
			for _, m := range r.webDomain(a).Mail {
				mail[a.ID] = append(mail[a.ID], m.Name+fmt.Sprint(m.Selectors))
			}
		}
	}
	if !slices.Equal(mail["domain:example.com"], []string{"example.com[]", "old.example.com[]"}) ||
		!slices.Equal(mail["domain:sub.example.com"], []string{"sub.example.com[s1]"}) {
		t.Errorf("%v", mail)
	}
}

// The web collector reads Scope's name statuses as scope.json writes them.
func TestWebCollectorReadsScopeStatuses(t *testing.T) {
	for theirs, ours := range map[string]string{
		web.StatusResolves: NameResolves, web.StatusDangling: NameDangling, web.StatusGone: NameGone,
		web.StatusNoAddress: NameNoAddress, web.StatusInsufficient: NameInsufficient, web.StatusWildcard: NameMatchesWildcard,
		web.StatusExcluded: NameExcluded, web.StatusNotChecked: NameNotChecked,
	} {
		if theirs != ours {
			t.Errorf("%q != %q", theirs, ours)
		}
	}
}

// Each name is judged under the most specific domain root that holds it,
// and a resolver whose control lookup said nothing is not trusted.
func TestWebInputNestedRootsAndResolver(t *testing.T) {
	file := strings.Replace(minimal, "  - domain: example.com\n", "  - domain: example.com\n  - domain: sub.example.com\n", 1)
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	var root ResolvedAsset
	for _, a := range res.Assets {
		if a.ID == "domain:example.com" {
			root = a
		}
	}
	names := []ScopeName{{Name: "www.example.com", Status: NameResolves}, {Name: "sub.example.com", Status: NameResolves},
		{Name: "x.sub.example.com", Status: NameResolves}}
	for control, doubt := range map[string]string{"nxdomain": "", "nodata": "", "timeout": "unavailable:resolver_unchecked",
		"unavailable:no_resolver": "unavailable:resolver_unchecked"} {
		r := &run{res: res, scoped: &ScopeDoc{Resolver: &Resolver{Control: control},
			Domains: []ScopeDomain{{Root: "domain:example.com", CT: "ok", Names: names}}},
			reconResolver: &Resolver{Control: "nxdomain"}}
		in := r.webInput(root, web.Evidence{})
		var got []string
		for _, n := range in.Names {
			got = append(got, n.Name)
		}
		if !slices.Equal(got, []string{"www.example.com"}) || in.Doubt != doubt {
			t.Errorf("control %s: names %v, doubt %q", control, got, in.Doubt)
		}
	}
	// A resumed session reads through its own resolver, which may rewrite
	// where Scope's did not.
	r := &run{res: res, scoped: &ScopeDoc{Resolver: &Resolver{Control: "nxdomain"}}, reconResolver: &Resolver{Rewrites: true, Control: "addresses"}}
	if in := r.webInput(root, web.Evidence{}); in.Doubt != "unavailable:resolver_rewrites" {
		t.Errorf("this session's resolver rewrites: doubt %q", in.Doubt)
	}
}

// A matched provider fingerprint invalidates only the operator confirmation;
// subsequent admission still requires independent root evidence or the front
// page allowance (docs/spec/web-collector.md, "Never claim a name").
func TestFingerprintSuspendsConfirmation(t *testing.T) {
	s := scopeOf(t, scopeFile).(*scope)
	l := gate.Lookup{Outcome: gate.OutcomeAddresses, Chain: []string{"blog.example-hosting.net"}, Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.70")}}
	if a := s.Admits("https://blog.example.com", "/robots.txt", nil); a.Refused != "" || !a.Resolve || !slices.Contains(s.site("https://blog.example.com").confirmed, "/robots.txt") {
		t.Fatal(a)
	}
	fp := &Evidence{Kind: "operator", Target: "blog.example-hosting.net"}
	r := run{webScope: s, scoped: &ScopeDoc{Assets: []ScopeAsset{{ID: "domain:blog.example.com", FirstParty: fp}}, Domains: []ScopeDomain{{Root: "domain:example.com", Names: []ScopeName{{Name: "blog.example.com", FirstParty: &Evidence{Kind: "operator"}}}}}}}
	r.suspendConfirmations([]web.Judgment{{ID: "dns.takeover_candidate", Verdict: web.Fired, Subject: web.Subject{Key: "*.example.com"}, Members: []string{"blog.example.com"}}})
	if a := s.Admits("https://blog.example.com", "/robots.txt", &l); a.Refused != "address_moved" {
		t.Fatal(a)
	}
	if a := s.Admits("https://blog.example.com", "/", &l); a.Refused != "" || a.FirstParty {
		t.Fatal(a)
	}
	if s.confirmationSuspended("other.example.com") {
		t.Fatal("unobserved sibling confirmation suspended")
	}
	if fp.Kind != "suspended" || fp.counts() || r.scoped.Domains[0].Names[0].FirstParty.Kind != "suspended" {
		t.Fatal(r.scoped)
	}
	if a := s.Admits("https://app.example.net", "/portal/", &l); a.Refused != "" || !a.FirstParty {
		t.Fatal(a)
	}
}

func TestWildcardNeedsRecognizedEqualChains(t *testing.T) {
	l := gate.Lookup{Outcome: gate.OutcomeAddresses, Chain: []string{"[REDACTED:extra:0:12 bytes]"}, Addrs: []netip.Addr{netip.MustParseAddr("198.51.100.77")}}
	c := &ScopeName{Status: NameResolves, Outcome: "addresses", Chain: l.Chain, Addresses: []string{"198.51.100.77"}}
	if matchesWildcard(l, c) {
		t.Fatal("equal redaction markers treated as equal DNS targets")
	}
	l.Chain = []string{"one.provider.example"}
	c.Chain = []string{"two.provider.example"}
	if matchesWildcard(l, c) {
		t.Fatal("equal addresses treated as equal CNAME chains")
	}
	c.Chain = l.Chain
	if !matchesWildcard(l, c) {
		t.Fatal("recognized equal answer rejected")
	}
}

func TestDeclaredURLEntriesInheritContainingURLRoot(t *testing.T) {
	s := scopeOf(t, `schema: 1
engagement: {name: entries, timezone: Europe/Madrid, trigger: routine}
roots:
 - {domain: example.com}
 - {url: 'https://admin.example.com/app/'}
assets:
 login: {url: 'https://admin.example.com/app/login'}
 sibling: {url: 'https://admin.example.com/login'}
 other-host: {url: 'https://other.example.com/login'}
 other-scheme: {url: 'http://admin.example.com/app/login'}
 other-port: {url: 'https://admin.example.com:8443/app/login'}
`)
	for _, tc := range []struct {
		origin, path string
		allowed      bool
	}{
		{"https://admin.example.com", "/app/login", true},
		{"https://admin.example.com", "/app/login/extra", false},
		{"https://admin.example.com", "/login", false},
		{"https://other.example.com", "/login", false},
		{"http://admin.example.com", "/app/login", false},
		{"https://admin.example.com:8443", "/app/login", false},
	} {
		got := s.Admits(tc.origin, tc.path, nil)
		if tc.allowed {
			if got.Refused != "" || !got.FirstParty || got.Resolve {
				t.Fatal(tc, got)
			}
		} else if got.Refused != "entry_point" {
			t.Fatal(tc, got)
		}
	}
}
