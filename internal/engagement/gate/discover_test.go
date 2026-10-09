package gate_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	webc "github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/gate"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

const discoveryFile = `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
  - domain: example.com
exclude:
  - domain: legacy.example.com
assets:
  www:
    domain: www.example.com
`

// What crt.sh answers for %.example.com: an S/MIME certificate's email
// identity, an excluded name, a wildcard, a name seen only in an expired
// certificate.
const crtBody = `[
 {"issuer_name":"C=US, O=Let's Encrypt","common_name":"www.example.com","name_value":"www.example.com\nexample.com","not_after":"2027-01-01T00:00:00"},
 {"issuer_name":"x","name_value":"shop.example.com","not_after":"2027-02-01T00:00:00"},
 {"issuer_name":"x","name_value":"a.legacy.example.com\nalice.private@example.com","not_after":"2027-02-01T00:00:00"},
 {"issuer_name":"x","name_value":"*.example.com","not_after":"2027-03-01T00:00:00"},
 {"issuer_name":"x","name_value":"old.example.com","not_after":"2020-01-01T00:00:00"},
 {"issuer_name":"x","name_value":"mail.example.com","not_after":"2027-01-01T00:00:00"},
 {"issuer_name":"x","name_value":"flaky.example.com","not_after":"2027-01-01T00:00:00"},
 {"issuer_name":"x","name_value":"cdn.example.com","not_after":"2027-01-01T00:00:00"},
 {"issuer_name":"x","name_value":"A.Legacy.example.com.\na.legacy.example.com","not_after":"2026-02-01T00:00:00"}
]`

var discoveryStart = time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)

// discover runs an engagement through Scope against the harness and
// returns its scope document and run directory.
func discover(t *testing.T, h *gate.Harness, file string) (*engagement.ScopeDoc, string) {
	t.Helper()
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := engagement.CreateRunDir(t.TempDir(), "acme", discoveryStart)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, StopAfter: "scope",
		Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	return out.Document.(*engagement.ScopeDoc), dir.Path
}

// runDir is a run directory the test removes: a run that sends through the
// gate keeps its audit log.
func runDir(t *testing.T) *engagement.RunDir {
	t.Helper()
	dir, err := engagement.CreateRunDir(t.TempDir(), "acme", discoveryStart)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	return dir
}

func byName(doc *engagement.ScopeDoc) map[string]engagement.ScopeName {
	out := map[string]engagement.ScopeName{}
	for _, d := range doc.Domains {
		for _, n := range d.Names {
			out[n.Name] = n
		}
	}
	return out
}

// Discovery from certificate transparency and DNS (E4 tests 8 and 23): a
// dangling record from DNS alone with nothing dialled, an excluded name
// never queried, an email identity never stored, services outside every
// root listed and never resolved on their own.
func TestDiscovery(t *testing.T) {
	h := gate.NewHarness(t, nil)
	crt := h.CrtSh(crtBody)
	h.DNS(map[string]string{
		"example.com":              "addrs:198.51.100.1",
		"www.example.com":          "addrs:198.51.100.2",
		"shop.example.com":         "cname:gone.shops.example-provider.net",
		"old.example.com":          "cname:old-lb.example.com",
		"mail.example.com":         "nodata",
		"flaky.example.com":        "servfail",
		"cdn.example.com":          "cname:edge.cdnprovider.example",
		"edge.cdnprovider.example": "addrs:198.51.100.9",
	})
	doc, dir := discover(t, h, discoveryFile)

	if q := crt(); len(q) != 1 || q[0] != "deduplicate=Y&output=json&q=%25.example.com" {
		t.Errorf("crt.sh was asked %q", q)
	}
	if h.Dials() != 1 {
		t.Errorf("%d connections; discovery opens one, to crt.sh", h.Dials())
	}
	names := byName(doc)
	for name, want := range map[string]string{
		"example.com":       engagement.NameResolves,
		"www.example.com":   engagement.NameResolves,
		"cdn.example.com":   engagement.NameResolves,
		"shop.example.com":  engagement.NameDangling,
		"old.example.com":   engagement.NameDangling,
		"mail.example.com":  engagement.NameNoAddress,
		"flaky.example.com": engagement.NameInsufficient,
	} {
		if names[name].Status != want {
			t.Errorf("%s: %+v, want %s", name, names[name], want)
		}
	}
	if d := names["shop.example.com"].Detail; !strings.Contains(d, "takeover candidate") {
		t.Errorf("shop: %s", d)
	}
	if d := names["old.example.com"].Detail; !strings.Contains(d, "stale record") || !names["old.example.com"].ExpiredOnly {
		t.Errorf("old: %+v", names["old.example.com"])
	}
	if !names["cdn.example.com"].Read || !names["www.example.com"].Read || names["shop.example.com"].Read {
		t.Errorf("read marks: cdn %v, www %v, shop %v", names["cdn.example.com"].Read, names["www.example.com"].Read, names["shop.example.com"].Read)
	}
	if names["cdn.example.com"].Target != "edge.cdnprovider.example" {
		t.Errorf("cdn target %q", names["cdn.example.com"].Target)
	}
	if _, ok := names["a.legacy.example.com"]; ok {
		t.Error("an excluded name from certificate transparency was kept")
	}
	d := doc.Domains[0]
	if !slices.Equal(d.WildcardCerts, []string{"example.com"}) || d.CT != "ok" {
		t.Errorf("domain %+v", d)
	}
	drops := map[string]int{}
	for _, dr := range d.Dropped {
		drops[dr.Rule] = dr.Count
	}
	if drops["exclude[0]"] != 1 || drops["not_a_name"] != 1 {
		t.Errorf("dropped %+v", d.Dropped)
	}
	pointsAt := map[string][]string{}
	for _, p := range doc.PointsAt {
		pointsAt[p.Target] = p.Names
	}
	if !slices.Equal(pointsAt["edge.cdnprovider.example"], []string{"cdn.example.com"}) || !slices.Equal(pointsAt["gone.shops.example-provider.net"], []string{"shop.example.com"}) {
		t.Errorf("points at %+v", doc.PointsAt)
	}
	if doc.Resolver == nil || doc.Resolver.Address != "192.0.2.53" || doc.Resolver.Rewrites || doc.Resolver.Controls != 2 || !doc.Resolver.Invalid {
		t.Errorf("resolver %+v", doc.Resolver)
	}
	// A chain the resolver answered whole is not asked again, except a
	// dangling chain's end, once, for the CNAME a DNS host may hide.
	ends := 0
	for _, q := range h.Queries() {
		if q == "gone.shops.example-provider.net." {
			ends++
			continue
		}
		if strings.Contains(q, "legacy") || strings.Contains(q, "alice") || q == "edge.cdnprovider.example." ||
			!strings.HasSuffix(q, ".example.com.") && q != "example.com." && !strings.HasSuffix(q, ".invalid.") && q != "crt.sh." {
			t.Errorf("queried %q", q)
		}
	}
	if ends != 1 {
		t.Errorf("a dangling chain's end was asked %d times", ends)
	}
	// The email identity reached no file in the run directory.
	err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if strings.Contains(string(raw), "alice.private") {
			t.Errorf("%s holds the email identity", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A resolver that answers names that do not exist, and a root with
// wildcard DNS, are caught by the control queries: nothing is read on
// their strength, and a declared name still is.
func TestDiscoveryControls(t *testing.T) {
	t.Run("a rewriting resolver", func(t *testing.T) {
		h := gate.NewHarness(t, nil)
		h.CrtSh(crtBody)
		h.DNS(map[string]string{"*.invalid": "addrs:198.51.100.250", "*.example.com": "addrs:198.51.100.250", "example.com": "addrs:198.51.100.1"})
		doc, _ := discover(t, h, discoveryFile)
		if !doc.Resolver.Rewrites {
			t.Fatal("the rewriting resolver went unnoticed")
		}
		names := byName(doc)
		if names["cdn.example.com"].Read || !names["www.example.com"].Read {
			t.Errorf("cdn %+v, www %+v", names["cdn.example.com"], names["www.example.com"])
		}
	})
	t.Run("a wildcard root", func(t *testing.T) {
		h := gate.NewHarness(t, nil)
		h.CrtSh(crtBody)
		h.DNS(map[string]string{"*.example.com": "addrs:198.51.100.77", "example.com": "addrs:198.51.100.1"})
		doc, _ := discover(t, h, discoveryFile)
		names := byName(doc)
		if names["cdn.example.com"].Status != engagement.NameMatchesWildcard || names["cdn.example.com"].Read ||
			names["www.example.com"].Status != engagement.NameResolves || !names["www.example.com"].Read {
			t.Errorf("cdn %+v, www %+v", names["cdn.example.com"], names["www.example.com"])
		}
		if !slices.Equal(doc.Domains[0].Wildcard, []string{"198.51.100.77"}) {
			t.Errorf("wildcard %v", doc.Domains[0].Wildcard)
		}
	})
	t.Run("crt.sh down", func(t *testing.T) {
		h := gate.NewHarness(t, nil)
		h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2"})
		doc, _ := discover(t, h, discoveryFile)
		if doc.Domains[0].CT != "unavailable:ct_source" || len(doc.Domains[0].Names) != 2 {
			t.Errorf("%+v", doc.Domains[0])
		}
	})
}

// The report's "What left this machine" names crt.sh with the root asked
// about, the resolver with its query count, and the model line; an exclude
// that dropped a discovered name says so (E4 test 23).
func TestDiscoveryEgress(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(crtBody)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2"})
	res, err := engagement.Parse("e.yaml", []byte(discoveryFile), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(discoveryFile),
		Dir: runDir(t), Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	rep := out.Document.(*ereport.Report)
	var text strings.Builder
	if err := ereport.WriteText(&text, rep, ereport.Options{Width: 200}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"crt.sh, a public certificate log run by Sectigo: asked which certificates exist for example.com; 1 request.",
		"Your DNS resolver at 192.0.2.53, and whatever it forwards to",
		"including 1 random test name under your domains and one under invalid.",
		"Nothing was sent to an AI model provider.",
		"domain:legacy.example.com: dropped 1 discovered name",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	srcs := map[string]ereport.EgressSource{}
	for _, s := range rep.Egress.Sources {
		srcs[s.Source] = s
	}
	if c := srcs["crt.sh"]; c.Requests != 1 || !slices.Equal(c.Sent, []string{"example.com"}) || c.Operator != "Sectigo" {
		t.Errorf("crt.sh %+v", c)
	}
	if d := srcs["dns"]; d.Host != "192.0.2.53" || d.Requests != len(h.Queries()) || d.ControlLookups != 1 || !d.ControlInvalid ||
		d.ScopedResolversIgnored {
		t.Errorf("dns %+v, %d queries", d, len(h.Queries()))
	}
}

// A confirmation whose name no longer points at its target is shown as
// moved, which is not evidence: what Scope lists is what the gate admits.
func TestDiscoveryMovedConfirmation(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(crtBody)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2",
		"cdn.example.com": "cname:edge.cdnprovider.example", "edge.cdnprovider.example": "addrs:198.51.100.9"})
	file := discoveryFile + `  cdn:
    domain: cdn.example.com
    first_party: {confirmed_by: alice, date: 2026-10-01, target: old-edge.cdnprovider.example}
people:
  alice: {kind: employee, workspace: alice@example.com}
`
	doc, _ := discover(t, h, file)
	cdn := byName(doc)["cdn.example.com"]
	if ev := cdn.FirstParty; ev == nil || ev.Kind != "moved" || ev.String() != "none: confirmed for old-edge.cdnprovider.example, which the name no longer points at" {
		t.Errorf("cdn %+v", cdn)
	}
}

// An exclude written as a host or a url, not a domain, still covers its
// name: certificate transparency drops it, discovery never queries it, and
// a chain that enters it ends there, in discovery and when a request is
// sent through it (docs/spec/scope.md, "Discovery").
func TestDiscoveryHostAndURLExcludes(t *testing.T) {
	file := `schema: 1
engagement: {name: acme, timezone: Europe/Madrid, trigger: routine}
roots:
  - domain: example.com
exclude:
  - host: billing.example.com
  - url: https://store.example.com/
  - url: https://docs.example.com/private/
`
	crt := `[{"issuer_name":"x","name_value":"billing.example.com\nstore.example.com\nshop.example.com\nblog.example.com\ndocs.example.com",` +
		`"not_after":"2027-01-01T00:00:00"}]`
	zone := map[string]string{"example.com": "addrs:198.51.100.1", "shop.example.com": "cname:billing.example.com",
		"blog.example.com": "cname:store.example.com", "billing.example.com": "addrs:198.51.100.40",
		"store.example.com": "addrs:198.51.100.41", "docs.example.com": "addrs:198.51.100.42"}
	h := gate.NewHarness(t, nil)
	h.CrtSh(crt)
	h.DNS(zone)
	doc, _ := discover(t, h, file)
	names := byName(doc)
	for name, x := range map[string]string{"shop.example.com": "exclude[0]", "blog.example.com": "exclude[1]"} {
		if n := names[name]; n.Status != engagement.NameExcluded || n.ExcludedBy != x || n.Read || len(n.Addresses) != 0 {
			t.Errorf("%s: %+v", name, n)
		}
	}
	// A url exclude below the site's root leaves the name.
	if n := names["docs.example.com"]; n.Status != engagement.NameResolves {
		t.Errorf("docs: %+v", n)
	}
	for _, n := range []string{"billing.example.com", "store.example.com"} {
		if _, ok := names[n]; ok {
			t.Errorf("%s was kept from certificate transparency", n)
		}
	}
	drops := map[string]int{}
	for _, dr := range doc.Domains[0].Dropped {
		drops[dr.Rule] = dr.Count
	}
	if drops["exclude[0]"] != 1 || drops["exclude[1]"] != 1 {
		t.Errorf("dropped %+v", doc.Domains[0].Dropped)
	}
	for _, q := range h.Queries() {
		if strings.HasPrefix(q, "billing.") || strings.HasPrefix(q, "store.") {
			t.Errorf("queried the excluded name %s", q)
		}
	}

	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	h = gate.NewHarness(t, res.GateScope(time.Now()))
	h.DNS(zone)
	g := h.Gate()
	for host, x := range map[string]string{"shop.example.com": "exclude[0]", "blog.example.com": "exclude[1]"} {
		if r := g.Send(context.Background(), web("https", host, "/")); r.Decision != "refused:excluded" || !strings.HasSuffix(r.Detail, x) {
			t.Errorf("%s: %+v", host, r)
		}
	}
	if h.Dials() != 0 {
		t.Errorf("%d connections through an excluded name", h.Dials())
	}
}

// A CNAME target redact_extra matches never reaches scope.json, the report
// or any file of the run as written; its marker does (AGENTS.md rule 5).
// The gate still reads the name as answered, to follow the chain.
func TestDiscoveryRedactsAnswerNames(t *testing.T) {
	word := "tange" + "rine" // built at run time, so no fixture holds it
	file := discoveryFile + "redact_extra: [" + word + "]\n"
	zone := map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2",
		"cdn.example.com": "cname:" + word + "-edge.example.net", word + "-edge.example.net": "addrs:198.51.100.9",
		"shop.example.com": "cname:" + word + "-gone.example.org"}
	h := gate.NewHarness(t, nil)
	h.CrtSh(crtBody)
	h.DNS(zone)
	doc, dir := discover(t, h, file)
	cdn := byName(doc)["cdn.example.com"]
	if cdn.Status != engagement.NameResolves || !strings.HasPrefix(cdn.Target, "[REDACTED:extra:0:") ||
		len(cdn.Chain) != 1 || cdn.Chain[0] != cdn.Target {
		t.Errorf("cdn %+v", cdn)
	}
	if shop := byName(doc)["shop.example.com"]; shop.Status != engagement.NameDangling {
		t.Errorf("shop %+v", shop)
	}
	marked := false
	err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if strings.Contains(string(raw), word) {
			t.Errorf("%s holds the redacted value", path)
		}
		marked = marked || strings.Contains(string(raw), "[REDACTED:extra:0:")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Error("no file of the run holds the marker")
	}

	h = gate.NewHarness(t, nil)
	h.CrtSh(crtBody)
	h.DNS(zone)
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file),
		Dir: runDir(t), Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if err := ereport.WriteText(&text, out.Document.(*ereport.Report), ereport.Options{Width: 200}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), word) {
		t.Error("the report holds the redacted value")
	}
}

// A discovered name every address of which a network root holds has that
// root as its evidence, as the gate weighs it at send time.
func TestDiscoveryNetworkRootEvidence(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(crtBody)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2",
		"cdn.example.com": "cname:edge.cdnprovider.example", "edge.cdnprovider.example": "addrs:198.51.100.9,203.0.113.9"})
	file := strings.Replace(discoveryFile, "  - domain: example.com\n", "  - domain: example.com\n  - network: 198.51.100.0/24\n", 1)
	doc, _ := discover(t, h, file)
	names := byName(doc)
	if ev := names["www.example.com"].FirstParty; ev == nil || ev.Kind != "network_root" || ev.Root != "network:198.51.100.0/24" {
		t.Errorf("www %+v", names["www.example.com"])
	}
	if ev := names["cdn.example.com"].FirstParty; ev != nil {
		t.Errorf("cdn, one address outside the root: %+v", ev)
	}
}

// A CNAME that an address query does not show, whose target does not
// exist, is found by the CNAME query and listed as dangling, with and
// without compact denial of existence, as the lab's DNS host answers it
// (docs/eval/lab-0.0.2-domain.md).
func TestDiscoveryFindsAHiddenDanglingCNAME(t *testing.T) {
	for _, compact := range []bool{false, true} {
		h := gate.NewHarness(t, nil)
		h.CrtSh(`[{"name_value":"old.example.com","not_after":"2027-01-01T00:00:00"}]`)
		h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "old.example.com": "hidden:gone.example.net"})
		if compact {
			h.CompactDenial()
		}
		doc, _ := discover(t, h, discoveryFile)
		if old := byName(doc)["old.example.com"]; old.Status != engagement.NameDangling || !slices.Equal(old.Chain, []string{"gone.example.net"}) {
			t.Errorf("compact %v: %+v", compact, old)
		}
	}
}

// What discovery says of a name whose chain redact_extra names is the
// gate's verdict on the names as answered: a confirmation still holds, a
// stale record under a root is still stale.
func TestDiscoveryVerdictsOnRedactedNames(t *testing.T) {
	word := "tange" + "rine"
	h := gate.NewHarness(t, nil)
	h.CrtSh(crtBody)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2",
		"cdn.example.com": "cname:" + word + "-edge.cdnprovider.example", word + "-edge.cdnprovider.example": "addrs:198.51.100.9",
		"old.example.com": "cname:" + word + "-lb.example.com"})
	file := discoveryFile + `  cdn:
    domain: cdn.example.com
    first_party: {confirmed_by: alice, date: 2026-10-01, target: ` + word + `-edge.cdnprovider.example}
people:
  alice: {kind: employee, workspace: alice@example.com}
redact_extra: [` + word + `]
`
	doc, dir := discover(t, h, file)
	names := byName(doc)
	if ev := names["cdn.example.com"].FirstParty; ev == nil || ev.Kind != "operator" {
		t.Errorf("cdn %+v", names["cdn.example.com"])
	}
	if old := names["old.example.com"]; old.Status != engagement.NameDangling || !strings.Contains(old.Detail, "stale record") {
		t.Errorf("old %+v", old)
	}
	// The confirmation's target, written in the file, is redacted in every
	// file of the run like the chain it is compared with.
	marked := false
	err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if strings.Contains(string(raw), word) {
			t.Errorf("%s holds the redacted value", path)
		}
		marked = marked || strings.Contains(string(raw), "[REDACTED:extra:0:")
		return err
	})
	if err != nil || !marked {
		t.Errorf("walk %v, marker present %v", err, marked)
	}
	if ev := names["cdn.example.com"].FirstParty; ev == nil || !strings.HasPrefix(ev.Target, "[REDACTED:extra:0:") {
		t.Errorf("cdn evidence %+v", ev)
	}
}

// A certificate-transparency name redact_extra matches on its own, as
// written or once lowercased, is dropped and counted: never stored, never queried,
// never a name Recon reads (AGENTS.md rule 5).
func TestDiscoveryDropsRedactedCTNames(t *testing.T) {
	hidden, cased, plain := "sec"+"ret.example.com", "Zebra"+"Fish.example.com", "pro"+"jx-db.example.com"
	written := "Anch" + "ored.example.com" // matched only as written: the pattern is cased and anchored
	body := `[{"issuer_name":"x","name_value":"www.example.com\n` + hidden + `\n` + cased + `\n` + plain + `\n` + written + `","not_after":"2027-01-01T00:00:00"},` +
		`{"issuer_name":"x","name_value":["shop.example.com"],"not_after":"2027-01-01T00:00:00"}]`
	file := discoveryFile + "redact_extra: ['^sec" + "ret\\.example\\.com$', 'zebra" + "fish', 'pro" + "jx', '^Anch" + "ored\\.example\\.com$']\n"
	h := gate.NewHarness(t, nil)
	h.CrtSh(body)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.1", "www.example.com": "addrs:198.51.100.2"})
	doc, dir := discover(t, h, file)
	drops := map[string]int{}
	for _, dr := range doc.Domains[0].Dropped {
		drops[dr.Rule] = dr.Count
	}
	// Each pattern as the body's own redaction meets it or misses it, and a
	// record whose names are not the declared string: all counted.
	if drops["redacted"] != 4 || drops["unattributable"] != 1 || drops["not_a_name"] != 0 {
		t.Errorf("dropped %+v", doc.Domains[0].Dropped)
	}
	for _, q := range h.Queries() {
		if strings.Contains(q, "ret.example") || strings.Contains(strings.ToLower(q), "zebra") || strings.Contains(strings.ToLower(q), "anch") {
			t.Errorf("queried %s", q)
		}
	}
	err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if s := strings.ToLower(string(raw)); strings.Contains(s, hidden) || strings.Contains(s, "zebra"+"fish.") ||
			strings.Contains(s, plain) || strings.Contains(s, strings.ToLower(written)) {
			t.Errorf("%s holds a redacted name", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The engagement's authorization windows reach the gate, every one of
// them, at the instants the file names.
func TestRunPassesWindows(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.10"})
	h.CrtSh(`[]`)
	file := discoveryFile + `authorization:
  by: CTO
  date: 2026-10-06
  windows:
    - {from: 2026-10-07T09:00:00+02:00, to: 2026-10-07T18:00:00+02:00}
    - {from: 2026-10-08T09:00:00Z, to: 2026-10-08T10:00:00Z}
`
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	var got []gate.Window
	newGate := func(cfg gate.Config) (*gate.Gate, error) {
		got = cfg.Windows
		return h.NewGate(cfg)
	}
	if _, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: runDir(t), StopAfter: "scope",
		Started: discoveryStart, Version: "test", NewGate: newGate}); err != nil {
		t.Fatal(err)
	}
	want := []gate.Window{
		{From: time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)},
		{From: time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)},
	}
	if len(got) != len(want) {
		t.Fatalf("windows %v", got)
	}
	for i := range want {
		if !got[i].From.Equal(want[i].From) || !got[i].To.Equal(want[i].To) {
			t.Errorf("window %d: %v, want %v", i, got[i], want[i])
		}
	}
}

// scopeRun runs file, written at path, through Scope in dir, resuming it
// when dir already holds the run.
func scopeRun(t *testing.T, h *gate.Harness, path, dir string) *engagement.ScopeDoc {
	t.Helper()
	return scopeRunAt(t, h, path, dir, discoveryStart.Add(time.Hour))
}

// scopeRunAt is scopeRun with a resumed session starting at session.
func scopeRunAt(t *testing.T, h *gate.Harness, path, dir string, session time.Time) *engagement.ScopeDoc {
	t.Helper()
	opts := engagement.Options{KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }}
	ro := engagement.RunOptions{StopAfter: "scope", Started: discoveryStart, Version: "v0.0.2", NewGate: h.NewGate}
	var res *engagement.Resolved
	if _, err := os.Stat(filepath.Join(dir, "run.json")); err == nil {
		d, err := engagement.OpenRun(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		p, err := engagement.LoadPrior(d)
		if err != nil {
			t.Fatal(err)
		}
		if res, ro.Raw, err = p.LoadEngagement(opts); err != nil {
			t.Fatal(err)
		}
		ro.Dir, ro.Resume, ro.Started, ro.Session = d, p, p.Manifest.Started, session
	} else {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if res, err = engagement.Parse(path, raw, opts); err != nil {
			t.Fatal(err)
		}
		d, err := engagement.CreateRunDir(filepath.Dir(filepath.Dir(filepath.Dir(dir))), "acme", discoveryStart)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		ro.Raw, ro.Dir = raw, d
	}
	out, err := engagement.Run(context.Background(), res, ro)
	if err != nil {
		t.Fatal(err)
	}
	return out.Document.(*engagement.ScopeDoc)
}

// A resume keeps Scope's document while what Scope read is unchanged and it
// found no gap, sending nothing; a gap, or a changed file, runs Scope again.
func TestResumeKeepsACompleteScope(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.10", "www.example.com": "addrs:198.51.100.11"})
	path := filepath.Join(t.TempDir(), "e.yaml")
	if err := os.WriteFile(path, []byte(discoveryFile), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "engagements", "acme", discoveryStart.UTC().Format(time.RFC3339))

	// crt.sh is not reachable: certificate transparency is a gap.
	first := scopeRun(t, h, path, dir)
	if first.Domains[0].CT == "ok" {
		t.Fatalf("crt.sh answered: %+v", first.Domains[0])
	}
	crt := h.CrtSh(`[]`)
	asked := len(h.Queries())
	again := scopeRun(t, h, path, dir)
	if again.Domains[0].CT != "ok" || len(crt()) != 1 || len(h.Queries()) == asked {
		t.Fatalf("a gap is closed on resume: %+v, crt.sh %v", again.Domains[0], crt())
	}

	asked = len(h.Queries())
	kept := scopeRun(t, h, path, dir)
	if len(crt()) != 1 || len(h.Queries()) != asked || kept.Domains[0].CT != "ok" {
		t.Errorf("a complete Scope is kept: crt.sh %v, %d lookups", crt(), len(h.Queries())-asked)
	}

	// An exclude added since runs Scope again.
	if err := os.WriteFile(path, []byte(strings.Replace(discoveryFile, "exclude:\n", "exclude:\n  - domain: old.example.com\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	scopeRun(t, h, path, dir)
	if len(crt()) != 2 {
		t.Errorf("a changed exclude: crt.sh %v", crt())
	}
}

// A confirmation that expired since the Scope on record runs Scope again,
// though the file did not change.
func TestResumeRunsScopeAgainWhenAConfirmationExpired(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.10", "blog.example.com": "cname:blog.example-hosting.net",
		"blog.example-hosting.net": "addrs:203.0.113.40"})
	crt := h.CrtSh(`[]`)
	file := discoveryFile + "  blog:\n    domain: blog.example.com\n" +
		"    first_party: {confirmed_by: alice, date: 2026-10-07, target: blog.example-hosting.net}\npeople:\n  alice: {kind: employee}\n"
	path := filepath.Join(t.TempDir(), "e.yaml")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "engagements", "acme", discoveryStart.UTC().Format(time.RFC3339))
	scopeRun(t, h, path, dir)
	scopeRun(t, h, path, dir)
	if len(crt()) != 1 {
		t.Fatalf("an unchanged Scope was run again: crt.sh %v", crt())
	}
	scopeRunAt(t, h, path, dir, discoveryStart.AddDate(1, 0, 2))
	if len(crt()) != 2 {
		t.Errorf("a confirmation that expired since: crt.sh %v", crt())
	}
}

// Recon reads a domain root with the web collector through the gate: its
// mail records, the names they point at (an excluded one refused unasked),
// and each name Scope chose to read; nothing else is queried or contacted.
func TestReconReadsADomainRoot(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[]`)
	root := h.Site("example.com", "198.51.100.10")
	www := h.Site("www.example.com", "198.51.100.11")
	h.DNS(map[string]string{"example.com": "addrs:198.51.100.10", "www.example.com": "addrs:198.51.100.11",
		"mx.mailhost.example": "addrs:198.51.100.25"})
	word := "zebra" + "fish"
	h.TXT("example.com", "v=spf1 include:_spf.esp.example ~all", "site-verification="+word+"-abc123")
	h.TXT("_spf.esp.example", "v=spf1 -all")
	h.TXT("_dmarc.example.com", "v=DMARC1; p=none")
	h.MX("example.com", 10, "mx.mailhost.example")
	h.NS("example.com", "ns1.dns-host.example", "ns.legacy.example.com")
	file := discoveryFile + "mail:\n  senders:\n    - {domain: example.com, service: google-workspace, dkim_selectors: [Google]}\n" +
		"redact_extra: [" + word + "]\n"
	res, err := engagement.Parse("e.yaml", []byte(file), engagement.Options{
		KnownCheck: func(string) bool { return false }, KnownFinding: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := engagement.CreateRunDir(t.TempDir(), "acme", discoveryStart)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	out, err := engagement.Run(context.Background(), res, engagement.RunOptions{Raw: []byte(file), Dir: dir, StopAfter: "recon",
		Started: discoveryStart, Version: "test", NewGate: h.NewGate})
	if err != nil {
		t.Fatal(err)
	}
	var ev *webc.Evidence
	judged := map[string]string{}
	for _, a := range out.Document.(*engagement.ReconDoc).Assets {
		if a.ID == "domain:example.com" {
			ev = a.Web
			for _, j := range a.Judged {
				judged[j.ID+" "+j.Subject.Key] = j.Verdict
			}
		}
	}
	// The run's own rules judged what it read: the NS target that does not
	// exist fires, the MX target that resolves disproves.
	// Scope's names reach the rules too: the root and www resolve to
	// public addresses.
	for key, want := range map[string]string{
		"dns.dangling_external example.com/NS/ns1.dns-host.example": webc.Fired,
		"dns.dangling_external example.com/MX/mx.mailhost.example":  webc.Disproved,
		"dns.dangling_external example.com/TXT/_spf.esp.example":    webc.Disproved,
		"dns.private_address example.com":                           webc.Disproved,
		"dns.private_address www.example.com":                       webc.Disproved,
	} {
		if judged[key] != want {
			t.Errorf("%s: %q, want %q (all: %v)", key, judged[key], want, judged)
		}
	}
	if ev == nil || len(ev.Mail) != 1 {
		t.Fatalf("evidence %+v", ev)
	}
	m := ev.Mail[0]
	if len(m.TXT.TXT) != 1 || len(m.SPF) != 1 || !m.SPFComplete || len(m.DMARCRecords) != 1 || m.DMARCRecords[0].Tags["p"] != "none" ||
		len(m.MXTargets) != 1 || m.MXTargets[0].Outcome != "addresses" || len(m.DKIM) != 1 || m.DKIM[0].Selector != "google" ||
		m.DKIM[0].Read.Outcome != "nxdomain" {
		t.Errorf("mail %+v", m)
	}
	if len(ev.NSTargets) != 2 || ev.NSTargets[0].Outcome != "nxdomain" || ev.NSTargets[1].Decision != "refused:excluded" {
		t.Errorf("NS targets %+v", ev.NSTargets)
	}
	sites := map[string]webc.Site{}
	for _, s := range ev.Sites {
		sites[s.Name] = s
	}
	if len(sites) != 2 || sites["example.com"].HTTPS.Status != 200 || sites["www.example.com"].HTTP.Status != 200 || !sites["www.example.com"].HTTPS.TLS.Verified {
		t.Errorf("sites %+v", ev.Sites)
	}
	for _, seen := range [][]string{root(), www()} {
		slices.Sort(seen)
		if !slices.Equal(seen, []string{"http GET /", "https GET /"}) {
			t.Errorf("a server saw %v", seen)
		}
	}
	for _, q := range h.Queries() {
		if strings.Contains(q, "legacy") {
			t.Errorf("queried %s", q)
		}
	}
	// The seeded value reaches no file of the run, its marker does.
	marked := false
	err = filepath.WalkDir(dir.Path, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if strings.Contains(string(raw), word) {
			t.Errorf("%s holds the redacted value", path)
		}
		marked = marked || strings.Contains(string(raw), "[REDACTED:extra:")
		return err
	})
	if err != nil || !marked {
		t.Errorf("walk %v, marker %v", err, marked)
	}
}

// When the control lookup under invalid. says nothing, whether the resolver
// invents answers is unknown: a discovered name without first-party
// evidence is not read on its answer.
func TestDiscoveryReadsNothingOnAnUnknownResolver(t *testing.T) {
	h := gate.NewHarness(t, nil)
	h.CrtSh(`[{"name_value":"shop.example.com","not_after":"2027-01-01T00:00:00"}]`)
	h.DNS(map[string]string{"*.invalid": "servfail", "example.com": "addrs:198.51.100.1", "shop.example.com": "addrs:198.51.100.2",
		"www.example.com": "addrs:198.51.100.3"})
	doc, _ := discover(t, h, discoveryFile)
	shop := byName(doc)["shop.example.com"]
	if shop.Read || !strings.Contains(shop.Detail, "unknown") || doc.Resolver.Known() {
		t.Errorf("shop %+v, resolver %+v", shop, doc.Resolver)
	}
	if www := byName(doc)["www.example.com"]; !www.Read {
		t.Errorf("a declared name is still read: %+v", www)
	}
}
