package engagement

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/finding"
)

var testOpts = Options{
	KnownCheck: func(id string) bool {
		for _, c := range check.All() {
			if c.ID == id {
				return true
			}
		}
		return false
	},
	KnownFinding:   func(id string) bool { _, ok := finding.Lookup(id); return ok },
	FindingSubject: func(id string) string { return string(finding.SubjectOf(id)) },
	HostFinding:    func(id string) bool { d, ok := finding.Lookup(id); return ok && d.Area == finding.AreaHosts },
}

// specExample is the complete file docs/spec/engagement.md shows under
// "The file". It must validate as written, so the spec and the code cannot
// drift apart silently.
func specExample(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../docs/spec/engagement.md")
	if err != nil {
		t.Fatal(err)
	}
	const open = "```yaml\n# engagement.yaml"
	_, rest, ok := strings.Cut(string(raw), open)
	if !ok {
		t.Fatal("docs/spec/engagement.md has no engagement.yaml example")
	}
	body, _, ok := strings.Cut(rest, "\n```")
	if !ok {
		t.Fatal("unterminated example")
	}
	return []byte("# engagement.yaml" + body + "\n")
}

func TestSpecExampleValidates(t *testing.T) {
	res, err := Parse("engagement.yaml", specExample(t), testOpts)
	if err != nil {
		t.Fatalf("the spec's example does not validate:\n%v", err)
	}
	if res.Engagement.Name != "example-ltd-2026-q4" || len(res.Roots) != 6 || len(res.Exclude) != 3 {
		t.Fatalf("unexpected resolution: %+v", res)
	}
	byName := map[string]ResolvedAsset{}
	for _, a := range res.Assets {
		byName[a.Name] = a
	}
	deploy := byName["deploy"]
	if deploy.ID != "host:203.0.113.5:22" || deploy.User != "deploy" || deploy.Root != "host:203.0.113.5:22" {
		t.Errorf("deploy = %+v", deploy)
	}
	if deploy.Profile != "hardened" || deploy.Elevate != "sudo" || deploy.Jump != "ops@198.51.100.7" ||
		len(deploy.DisableChecks) != 1 || len(deploy.DenyPaths) != 1 || deploy.Context == nil {
		t.Errorf("deploy settings = %+v", deploy)
	}
	if shop := byName["shop"]; shop.ID != "url:https://shop.example.com/" || shop.Root != "domain:example.com" || shop.Probe != "off" {
		t.Errorf("shop = %+v", shop)
	}
	if repo := byName["shop-repo"]; repo.ID != "repo:github:example-org/shop" || repo.Root != "saas:github:example-org" {
		t.Errorf("shop-repo = %+v", repo)
	}
	if d := byName["domain:example.com"]; d.Throttle.Rate != "5/s" || d.Throttle.Concurrency != 2 || d.Profile != "" {
		t.Errorf("an undeclared root takes the defaults and no host settings: %+v", d)
	}
	if res.Limits.Timeout != "1h0m0s" || res.Timeout().Hours() != 1 {
		t.Errorf("limits = %+v", res.Limits)
	}
	if res.RedactPatterns != 1 || res.RedactExtra()[0] != "project-tangerine" {
		t.Errorf("redact_extra = %d %v", res.RedactPatterns, res.RedactExtra())
	}
	if r, ok := res.Lookup("github:example-org"); !ok || r.ID != "saas:github:example-org" {
		t.Errorf("Lookup(root as written) = %+v %v", r, ok)
	}
	if r, ok := res.Lookup("deploy"); !ok || r.ID != "host:203.0.113.5:22" {
		t.Errorf("Lookup(asset name) = %+v %v", r, ok)
	}
	if len(res.Source.SHA256) != 64 {
		t.Errorf("source = %+v", res.Source)
	}
}

// minimal is the smallest valid file; cases append to it or replace it.
const minimal = `schema: 1
engagement:
  name: acme
  timezone: Europe/Madrid
  trigger: routine
roots:
  - domain: example.com
  - host: deploy@203.0.113.5
  - saas: github:example-org
`

// A url exclude narrows a url root over the other scheme too, so it is
// accepted, and it covers the root's path there.
// So does one written on the root's port under the other scheme
// (http://x:443/ is read where https://x/ is).
func TestURLExcludeUnderAURLRootOverHTTP(t *testing.T) {
	for _, x := range []string{"http://app.example.net/admin/", "http://app.example.net:443/admin/"} {
		res, err := Parse("e.yaml", []byte(minimal+"  - url: https://app.example.net/\nexclude:\n  - url: "+x+"\n"), testOpts)
		if err != nil {
			t.Fatalf("%s: %v", x, err)
		}
		if st := res.GateScope(time.Now()).Subject("url:https://app.example.net/", "url:https://app.example.net/admin/x"); st.ExcludedBy != "exclude[0]" {
			t.Errorf("%s: %+v", x, st)
		}
	}
}

func TestMinimalFile(t *testing.T) {
	res, err := Parse("e.yaml", []byte(minimal), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Assets) != 3 || res.Assets[1].Profile != "baseline" || res.Assets[1].Elevate != "none" || res.Assets[1].User != "deploy" {
		t.Fatalf("assets = %+v", res.Assets)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		file string
		line int
		key  string
		msg  string
		// notAvailable marks "not available in this build".
		notAvailable bool
	}{
		{"unknown top-level key", minimal + "colour: blue\n", 10, "colour", "unknown key", false},
		{"unknown nested key", minimal + "defaults:\n  probes: off\n", 11, "defaults.probes", "unknown key", false},
		{"wrong shape", minimal + "redact_extra: tangerine\n", 10, "redact_extra", "must be a list", false},
		{"schema", strings.Replace(minimal, "schema: 1", "schema: 2", 1), 1, "schema", "must be 1", false},
		{"name", strings.Replace(minimal, "name: acme", "name: Acme_Co", 1), 3, "engagement.name", "must match", false},
		{"timezone", strings.Replace(minimal, "Europe/Madrid", "CEST", 1), 4, "engagement.timezone", "IANA", false},
		{"missing trigger", strings.Replace(minimal, "  trigger: routine\n", "", 1), 2, "engagement.trigger", "is required", false},
		{"no roots", strings.SplitAfter(minimal, "routine\n")[0], 1, "roots", "at least one root", false},
		{"root with two kinds", minimal + "  - {domain: example.net, host: local}\n", 10, "roots[3]", "more than one", false},
		{"malformed domain", minimal + "  - domain: https://example.net\n", 10, "roots[3].domain", "not a domain name", false},
		{"wildcard domain", minimal + "  - domain: \"*.example.net\"\n", 10, "roots[3].domain", "wildcard", false},
		{"network with host bits", minimal + "  - network: 203.0.113.5/28\n", 10, "roots[3].network", "203.0.113.0/28", false},
		{"bare ipv6 host", minimal + "  - host: 2001:db8::1\n", 10, "roots[3].host", "brackets", false},
		{"bad port", minimal + "  - host: web:99999\n", 10, "roots[3].host", "1-65535", false},
		{"url with credentials", minimal + "  - url: https://bob@shop.example.org/\n", 10, "roots[3].url", "never carries a user", false},
		{"url with query", minimal + "  - url: https://shop.example.org/?a=1\n", 10, "roots[3].url", "no query", false},
		{"unknown saas", minimal + "  - saas: gitlab:acme\n", 10, "roots[3].saas", "known: github", false},
		{"duplicate root", minimal + "  - host: ops@203.0.113.5:22\n", 10, "roots[3]", "again", false},
		{"local repo", minimal + "  - repo: ./\n", 10, "roots[3].repo", "not a repository locator", false},
		{"exclude under no root", minimal + "exclude:\n  - domain: example.org\n", 11, "exclude[0]", "falls under no root", false},
		{"url exclude under no root", minimal + "exclude:\n  - url: https://shop.example.org/x/\n", 11, "exclude[0]", "falls under no root", false},
		{"cloud exclude without org", minimal + "exclude:\n  - cloud: gcp:example-sandbox\n", 11, "exclude[0]", "organization root", false},
		{"org unit on github", minimal + "exclude:\n  - {saas: github:example-org, org_unit: /Board}\n", 11, "exclude[0].org_unit", "only a google-workspace", false},
		{"asset outside every root", minimal + "assets:\n  shop:\n    url: https://shop.example.org/\n", 12, "assets.shop.url", "never adds scope", false},
		{"two entries for one asset", minimal + "assets:\n  a:\n    host: 203.0.113.5\n  b:\n    host: ops@203.0.113.5\n", 13, "assets.b", "one entry per asset", false},
		{"host setting on a url", minimal + "assets:\n  shop:\n    url: https://shop.example.com/\n    elevate: sudo\n", 13, "assets.shop.elevate", "only to a host asset", false},
		{"unknown check id", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    disable_checks: [fs.suidd]\n", 13, "assets.deploy.disable_checks[0]", "not a check in the catalog", false},
		{"relative deny path", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    deny_paths: [srv/backups]\n", 13, "assets.deploy.deny_paths[0]", "not an absolute path", false},
		{"root deny path", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    deny_paths: [\"/\"]\n", 13, "assets.deploy.deny_paths[0]", "every path", false},
		{"context field outside the four", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    context:\n      owner: ops\n", 14, "assets.deploy.context.owner", "unknown key", false},
		{"free-text audience", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    context:\n      expected_services:\n        - {port: 5432, proto: tcp, audience: vpc-only}\n", 15, "assets.deploy.context.expected_services[0].audience", "not one of", false},
		{"bad jump", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    jump: ops@2001:db8::1\n", 13, "assets.deploy.jump", "brackets", false},
		{"invalid redact_extra", minimal + "redact_extra:\n  - \"tangerine[\"\n", 11, "redact_extra[0]", "not a valid RE2 pattern (missing closing ])", false},
		{"probe mode", minimal + "defaults:\n  probe: confirm\n", 11, "defaults.probe", "not available in this build", true},
		{"scan mode on an asset", minimal + "assets:\n  shop:\n    url: https://shop.example.com/\n    scan: all\n", 13, "assets.shop.scan", "not available in this build", true},
		{"unknown mode", minimal + "defaults:\n  scan: sometimes\n", 11, "defaults.scan", "not one of", false},
		{"full scope", minimal + "scope: full\n", 10, "scope", "not available in this build", true},
		{"max_cost", minimal + "limits:\n  max_cost: 2.00\n", 11, "limits.max_cost", "not available in this build", true},
		{"zero timeout", minimal + "limits:\n  timeout: 0\n", 11, "limits.timeout", "write none", false},
		{"timeout without unit", minimal + "limits:\n  timeout: 3600\n", 11, "limits.timeout", "not a duration", false},
		{"zero concurrency", minimal + "defaults:\n  throttle: {rate: 5/s, concurrency: 0}\n", 11, "defaults.throttle.concurrency", "1 or more", false},
		{"rate", minimal + "defaults:\n  throttle: {rate: fast}\n", 11, "defaults.throttle.rate", "not a rate", false},
		{"timestamp without seconds", minimal + "authorization:\n  by: CTO\n  date: 2026-10-06\n  windows:\n    - {from: 2026-10-07T09:00+02:00, to: 2026-10-07T18:00:00+02:00}\n", 14, "authorization.windows[0].from", "RFC 3339", false},
		{"timestamp without offset", minimal + "authorization:\n  by: CTO\n  date: 2026-10-06\n  windows:\n    - {from: 2026-10-07T09:00:00, to: 2026-10-07T18:00:00+02:00}\n", 14, "authorization.windows[0].from", "RFC 3339", false},
		{"window backwards", minimal + "authorization:\n  by: CTO\n  date: 2026-10-06\n  windows:\n    - {from: 2026-10-07T18:00:00+02:00, to: 2026-10-07T09:00:00+02:00}\n", 14, "authorization.windows[0].to", "after from", false},
		{"bad date", minimal + "people:\n  carol: {kind: employee, left: 15/09/2026}\n", 11, "people.carol.left", "YYYY-MM-DD", false},
		{"unknown handle", minimal + "access:\n  admins:\n    github:example-org: [alice]\n", 12, "access.admins.github:example-org[0]", "not a handle", false},
		{"admins of a non-tenant", minimal + "people:\n  alice: {kind: employee}\naccess:\n  admins:\n    example.com: [alice]\n", 14, "access.admins.example.com", "not a SaaS tenant", false},
		{"dangling reference", minimal + "secrets:\n  production:\n    - {store: env-file, asset: web}\n", 12, "secrets.production[0].asset", "neither an assets name nor a root", false},
		{"unknown accepted risk", minimal + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n    - {id: sshd.nope, asset: deploy@203.0.113.5, reason: r, accepted_by: alice}\n", 14, "intent.accepted_risks[0].id", "neither a catalog finding", false},
		{"accepted risk on an id outside scope", minimal + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n    - {id: sshd.password_auth_enabled, asset: \"host:198.51.100.7:22\", reason: r, accepted_by: alice}\n", 14, "intent.accepted_risks[0].asset", "canonical id of an asset under a root", false},
		{"accepted risk on an excluded id", minimal + "exclude:\n  - repo: github:example-org/old\npeople:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n    - {id: sshd.password_auth_enabled, asset: \"repo:github:example-org/old\", reason: r, accepted_by: alice}\n", 16, "intent.accepted_risks[0].asset", "is excluded by repo:github:example-org/old", false},
		{"intent url outside scope", minimal + "intent:\n  not_exposed:\n    - {url: https://admin.example.org/, audience: vpn}\n", 12, "intent.not_exposed[0].url", "falls under no root", false},
		{"mail domain outside scope", minimal + "mail:\n  no_mail: [example.org]\n", 11, "mail.no_mail[0]", "no domain root", false},
		{"sending and no_mail", minimal + "mail:\n  senders:\n    - {domain: example.com, service: sendgrid}\n  no_mail: [example.com]\n", 13, "mail.no_mail[0]", "also has a sender", false},
		{"dkim selector with an underscore", minimal + "mail:\n  senders:\n    - {domain: example.com, service: sendgrid, dkim_selectors: [s_1]}\n", 12, "mail.senders[0].dkim_selectors[0]", "not a DKIM selector", false},
		{"dkim selector label too long", minimal + "mail:\n  senders:\n    - {domain: example.com, service: sendgrid, dkim_selectors: [" + strings.Repeat("s", 64) + "]}\n", 12, "mail.senders[0].dkim_selectors[0]", "not a DKIM selector", false},
		{"not_used area", minimal + "not_used: [servers]\n", 10, "not_used[0]", "not one of", false},
		{"ci not declared", minimal + "assets:\n  shop-repo:\n    repo: github:example-org/shop\n    ci: circleci\n", 13, "assets.shop-repo.ci", "not a tool declared", false},
		{"empty kind, as the recon stanza writes it", minimal + "people:\n  dave: {kind: \"\", workspace: [dave@example.com]}\n", 11, "people.dave.kind", "find out: an admin nobody can name", false},
		{"admin is not a kind", minimal + "people:\n  dave: {kind: admin}\n", 11, "people.dave.kind", "admins are listed under access.admins", false},
		{"agency is gone", minimal + "people:\n  acme: {kind: agency}\n", 11, "people.acme.kind", "\"agency\" is not a kind", false},
		{"a scalar where a list belongs", minimal + "people:\n  alice: {kind: employee, github: alice-ex}\n", 11, "people.alice.github", "put the value in brackets", false},
		{"an empty list", minimal + "people:\n  carol: {kind: employee, github: []}\n", 11, "people.carol.github", "an empty list says nothing", false},
		{"a display name for an address", minimal + "people:\n  alice: {kind: employee, workspace: [\"Alice <alice@example.com>\"]}\n", 11, "people.alice.workspace[0]", "is not an address", false},
		{"a marker for an address", minimal + "people:\n  dave: {kind: employee, workspace: [\"[REDACTED:custom:9 bytes]\"]}\n", 11, "people.dave.workspace[0]", "a marker scheck printed", false},
		{"the same login twice under one handle", minimal + "people:\n  carol: {kind: employee, github: [carol-codes, Carol-Codes]}\n", 11, "people.carol.github[1]", "listed twice", false},
		{"org on an employee", minimal + "people:\n  alice: {kind: employee, org: Acme}\n", 11, "people.alice.org", "alice is an employee", false},
		{"used_by on a person", minimal + "people:\n  alice: {kind: employee}\n  bob: {kind: employee, used_by: [alice]}\n", 12, "people.bob.used_by", "only a shared account has used_by", false},
		{"shared without used_by", minimal + "people:\n  ops: {kind: shared, workspace: [ops@example.com]}\n", 11, "people.ops.used_by", "whose departure means rotating it", false},
		{"shared used by a service", minimal + "people:\n  bot: {kind: service}\n  ops: {kind: shared, used_by: [bot]}\n", 12, "people.ops.used_by[0]", "not a person who signs in", false},
		{"shared used by itself", minimal + "people:\n  ops: {kind: shared, used_by: [ops]}\n", 11, "people.ops.used_by[0]", "names the account itself", false},
		{"an admin with no identifier there", minimal + "people:\n  carol: {kind: employee, workspace: [carol@example.com]}\naccess:\n  admins:\n    github:example-org: [carol]\n", 14, "access.admins.github:example-org[0]", "people.carol has no GitHub login", false},
		{"mfa as a boolean", minimal + "access:\n  mfa:\n    - {where: github:example-org, enforced: true}\n", 12, "access.mfa[0].enforced", "true is ambiguous", false},
		{"mfa unknown value", minimal + "access:\n  mfa:\n    - {where: github:example-org, enforced: mostly}\n", 12, "access.mfa[0].enforced", "mostly", false},
		{"mfa twice for one tenant", minimal + "access:\n  mfa:\n    - {where: github:example-org, enforced: everyone}\n    - {where: github:example-org, enforced: admins}\n", 13, "access.mfa[1].where", "already declared at access.mfa[0]", false},
		{"mfa enforcement missing", minimal + "access:\n  mfa:\n    - {where: github:example-org}\n", 12, "access.mfa[0].enforced", "is required: everyone, admins, some, none, or unknown", false},
		{"mfa twice through an asset name", minimal + "assets:\n  gh: {saas: github:example-org}\naccess:\n  mfa:\n    - {where: gh, enforced: everyone}\n    - {where: github:example-org, enforced: none}\n", 15, "access.mfa[1].where", "already declared at access.mfa[0]", false},
		{"admins twice through an asset name", minimal + "assets:\n  gh: {saas: github:example-org}\npeople:\n  alice: {kind: employee, github: [alice-ex]}\naccess:\n  admins:\n    gh: [alice]\n    github:example-org: [alice]\n", 17, "access.admins.github:example-org", "names the same tenant as access.admins.gh", false},
		{"an admin through an asset name with no identifier", minimal + "assets:\n  gh: {saas: github:example-org}\npeople:\n  carol: {kind: employee, workspace: [carol@example.com]}\naccess:\n  admins:\n    gh: [carol]\n", 16, "access.admins.gh[0]", "people.carol has no GitHub login", false},
		{"used_by names nobody", minimal + "people:\n  ops: {kind: shared, used_by: [zed]}\n", 11, "people.ops.used_by[0]", "\"zed\" is not a handle under people", false},
		{"used_by twice", minimal + "people:\n  a: {kind: employee}\n  ops: {kind: shared, used_by: [a, a]}\n", 12, "people.ops.used_by[1]", "a is listed twice", false},
		{"an empty used_by on a person", minimal + "people:\n  a: {kind: employee, used_by: []}\n", 11, "people.a.used_by", "only a shared account has used_by", false},
		{"a malformed login", minimal + "people:\n  bob: {kind: contractor, github: [\"bob acme\"]}\n", 11, "people.bob.github[0]", "is not a GitHub login (letters, digits and single hyphens, up to 39)", false},
		{"a marker for an org", minimal + "people:\n  bob: {kind: contractor, org: \"[REDACTED:custom:9 bytes]\"}\n", 11, "people.bob.org", "a marker scheck printed", false},
		{"same login twice", minimal + "people:\n  a: {kind: employee, github: [Alice]}\n  b: {kind: contractor, github: [alice]}\n", 12, "people.b.github[0]", "is also people.a.github[0]", false},
		{"alias", minimal + "defaults: &d\n  probe: off\n", 10, "defaults", "anchors and aliases", false},
		{"not yaml", "schema: 1\nroots: [\n", 2, "(file)", "not valid YAML", false},
		{"organization under an organization", minimal + "  - cloud: gcp:organizations/123\nassets:\n  other:\n    cloud: gcp:organizations/999\n", 13, "assets.other.cloud", "never adds scope", false},
		{"second document", minimal + "---\nexclude:\n  - domain: legacy.example.com\n", 10, "(file)", "a second YAML document", false},
		{"broken second document", minimal + "---\nfoo: [unclosed\n", 10, "(file)", "not valid YAML", false},
		{"duplicate key", minimal + "people:\n  a: {kind: employee}\n  a: {kind: agency}\n", 12, "people.a", "appears twice in this mapping (first on line 11)", false},
		{"duplicate top-level key", minimal + "schema: 1\n", 10, "schema", "appears twice", false},
		{"int overflow", minimal + "defaults:\n  throttle: {concurrency: 9223372036854775808}\n", 11, "defaults.throttle.concurrency", "whole number", false},
		{"key anchor", minimal + "  - &a domain: example.net\n", 10, "roots[3].domain", "anchors and aliases", false},
		{"explicit tag", strings.Replace(minimal, "name: acme", "name: !!str acme", 1), 3, "engagement.name", "explicit tags", false},
		{"binary tag", minimal + "tools:\n  - {category: ci, name: !!binary Z2l0aHVi}\n", 11, "tools[0].name", "explicit tags", false},
		{"merge key", minimal + "defaults:\n  <<: {probe: off}\n", 11, "defaults.<<", "merge keys", false},
		{"roots written alike", minimal + "  - domain: example.net\n  - host: example.net\n", 11, "roots[4]", "could not tell them apart", false},
		{"settings for an excluded asset", minimal + "exclude:\n  - domain: legacy.example.com\nassets:\n  old:\n    url: https://legacy.example.com/\n", 14, "assets.old.url", "is excluded by domain:legacy.example.com", false},
		{"settings under a url exclude, without its slash, over http", minimal + "exclude:\n  - url: https://shop.example.com/checkout/\nassets:\n  co:\n    url: http://shop.example.com/checkout\n    first_party: {confirmed_by: alice, date: 2026-10-07, target: shops.myshopify.com}\n", 14, "assets.co.url", "is excluded by url:https://shop.example.com/checkout/", false},
		{"a root under a network exclude", minimal + "exclude:\n  - network: 203.0.113.0/24\n", 8, "roots[1]", "is excluded by network:203.0.113.0/24", false},
		{"a root an exclude names", minimal + "exclude:\n  - host: 203.0.113.5\n", 8, "roots[1]", "exclude always wins", false},
		{"a root an exclude holds in NAT64 form", minimal + "exclude:\n  - network: \"64:ff9b::cb00:7100/120\"\n", 8, "roots[1]", "exclude always wins", false},
		{"a root an exclude names in 6to4 form", minimal + "exclude:\n  - host: \"[2002:cb00:7105::1]\"\n", 8, "roots[1]", "exclude always wins", false},
		{"a NAT64 root under an IPv4 exclude", strings.Replace(minimal, "deploy@203.0.113.5", "deploy@[64:ff9b::cb00:7105]", 1) + "exclude:\n  - network: 203.0.113.0/24\n", 8, "roots[1]", "exclude always wins", false},
		{"a 6to4 root under an IPv4 host exclude", strings.Replace(minimal, "deploy@203.0.113.5", "deploy@[2002:cb00:7105::1]", 1) + "exclude:\n  - host: 203.0.113.5\n", 8, "roots[1]", "exclude always wins", false},
		{"a host exclude on another port", minimal + "exclude:\n  - host: 203.0.113.5:2222\n", 8, "roots[1]", "exclude always wins", false},
		{"a host exclude by name on another port", minimal + "  - host: deploy@bastion.example.net:2222\nexclude:\n  - host: bastion.example.net\n", 10, "roots[3]", "exclude always wins", false},
		{"a jump excluded by name on another port", minimal + "exclude:\n  - host: bastion.example.com\nassets:\n  deploy:\n    host: 203.0.113.5\n    jump: ops@bastion.example.com:2222\n", 15, "assets.deploy.jump", "a jump host is contacted", false},
		{"a root in the local-use NAT64 prefix", strings.Replace(minimal, "deploy@203.0.113.5", "deploy@[64:ff9b:1::cb00:7105]", 1), 8, "roots[1].host", "never contacts", false},
		{"a wide exclude holding all of NAT64", minimal + "exclude:\n  - network: \"64:ff9b::/64\"\n", 8, "roots[1]", "exclude always wins", false},
		{"a network root an address exclude empties", minimal + "  - network: 198.51.100.7/32\nexclude:\n  - host: 198.51.100.7\n", 10, "roots[3]", "exclude always wins", false},
		{"a host by name behind a jump host with an address exclude", minimal + "  - host: deploy@db.internal.example.com\nexclude:\n  - network: 192.0.2.0/24\nassets:\n  db:\n    host: db.internal.example.com\n    jump: ops@198.51.100.7\n",
			16, "assets.db.jump", "write this host as its address", false},
		{"an excluded jump host", minimal + "exclude:\n  - network: 198.51.100.0/24\nassets:\n  deploy:\n    host: 203.0.113.5\n    jump: ops@198.51.100.7\n", 15, "assets.deploy.jump", "a jump host is contacted", false},
		{"a url root under its own path without the slash", minimal + "  - url: https://app.example.net/portal/\nexclude:\n  - url: https://app.example.net/portal\n", 10, "roots[3]", "is excluded by url:https://app.example.net/portal", false},
		{"an excluded intent URL", minimal + "exclude:\n  - url: https://shop.example.com/checkout/\nintent:\n  exposed_on_purpose:\n    - {url: \"https://shop.example.com/checkout\", audience: internet}\n", 14, "intent.exposed_on_purpose[0].url", "never read", false},
		{"local jump", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    jump: local\n", 13, "assets.deploy.jump", "local is the machine running scheck", false},
		{"numeric last label", minimal + "  - host: 203.0.113.05\n", 10, "roots[3].host", "looks like an address", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("e.yaml", []byte(tc.file), testOpts)
			var errs Errors
			if !errors.As(err, &errs) {
				t.Fatalf("want Errors, got %v", err)
			}
			for _, e := range errs {
				if e.Key == tc.key && e.Line == tc.line && strings.Contains(e.Msg, tc.msg) {
					if e.NotAvailable != tc.notAvailable {
						t.Errorf("NotAvailable = %v", e.NotAvailable)
					}
					if !strings.HasPrefix(e.Error(), "e.yaml:") {
						t.Errorf("error does not name the file: %s", e)
					}
					return
				}
			}
			t.Fatalf("want e.yaml:%d:%s: ...%s...; got\n%v", tc.line, tc.key, tc.msg, err)
		})
	}
}

// A credential anywhere in the file, comments included, is a usage error
// that names the key and the detector and never prints the value.
func TestCredentialIsRefusedWithoutPrintingIt(t *testing.T) {
	const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	cases := []struct{ name, file, key string }{
		{"value", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    identity: " + token + "\n", "assets.deploy.identity"},
		{"comment", minimal + "# token: " + token + "\n", "roots[2].saas"},
		{"redact pattern", minimal + "redact_extra:\n  - " + token + "\n", "redact_extra[0]"},
		{"escaped value", minimal + "tools:\n  - {category: ci, name: \"\\x67hp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\"}\n", "tools[0].name"},
		{"private key", minimal + "assets:\n  deploy:\n    host: 203.0.113.5\n    identity: |\n      -----BEGIN OPENSSH PRIVATE KEY-----\n      b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9u\n", "assets.deploy.identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("e.yaml", []byte(tc.file), testOpts)
			if err == nil {
				t.Fatal("a credential validated")
			}
			msg := err.Error()
			if strings.Contains(msg, "ABCDEFGHIJ") || strings.Contains(msg, "b3BlbnNzaC1") {
				t.Fatalf("the error printed the value: %s", msg)
			}
			if !strings.Contains(msg, ":"+tc.key+": ") || !strings.Contains(msg, "detector ") {
				t.Fatalf("want key %s and the detector, got %s", tc.key, msg)
			}
		})
	}
}

func TestLocatorIDs(t *testing.T) {
	cases := []struct {
		kind Kind
		in   string
		id   string
	}{
		{KindDomain, "Example.COM.", "domain:example.com"},
		{KindURL, "HTTPS://Shop.Example.com:443", "url:https://shop.example.com/"},
		{KindURL, "http://shop.example.com:8080/a/b", "url:http://shop.example.com:8080/a/b"},
		{KindURL, "https://shop.example.com/a/../%63heckout/", "url:https://shop.example.com/checkout/"},
		{KindURL, "https://shop.example.com/a%20b", "url:https://shop.example.com/a%20b"},
		{KindHost, "deploy@203.0.113.5", "host:203.0.113.5:22"},
		{KindHost, "203.0.113.5:2222", "host:203.0.113.5:2222"},
		{KindHost, "ops@[2001:db8::1]:2222", "host:[2001:db8::1]:2222"},
		{KindHost, "Web1", "host:web1:22"},
		{KindHost, "local", "host:local"},
		{KindNetwork, "203.0.113.0/28", "network:203.0.113.0/28"},
		{KindSaaS, "github:Example-Org", "saas:github:example-org"},
		{KindSaaS, "google-workspace:Example.com", "saas:google-workspace:example.com"},
		{KindRepo, "github:example-org/Shop", "repo:github:example-org/shop"},
		{KindCloud, "gcp:example-prod", "cloud:gcp:example-prod"},
		{KindCloud, "gcp:organizations/123456789012", "cloud:gcp:organizations/123456789012"},
	}
	for _, tc := range cases {
		r, err := parseLocator(tc.kind, tc.in)
		if err != nil || r.ID != tc.id {
			t.Errorf("%s %q = %q, %v; want %q", tc.kind, tc.in, r.ID, err, tc.id)
		}
	}
}

func TestUnder(t *testing.T) {
	ref := func(k Kind, s string) Ref {
		r, err := parseLocator(k, s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := []struct {
		c, root Ref
		want    bool
	}{
		{ref(KindDomain, "a.example.com"), ref(KindDomain, "example.com"), true},
		{ref(KindDomain, "badexample.com"), ref(KindDomain, "example.com"), false},
		{ref(KindURL, "https://shop.example.com/x"), ref(KindDomain, "example.com"), true},
		{ref(KindHost, "web.example.com"), ref(KindDomain, "example.com"), true},
		{ref(KindHost, "203.0.113.9"), ref(KindNetwork, "203.0.113.0/28"), true},
		{ref(KindHost, "203.0.113.99"), ref(KindNetwork, "203.0.113.0/28"), false},
		{ref(KindNetwork, "203.0.113.8/29"), ref(KindNetwork, "203.0.113.0/28"), true},
		{ref(KindNetwork, "203.0.112.0/23"), ref(KindNetwork, "203.0.113.0/28"), false},
		{ref(KindURL, "https://shop.example.com/admin/x"), ref(KindURL, "https://shop.example.com/admin"), true},
		{ref(KindURL, "https://shop.example.com/administrator"), ref(KindURL, "https://shop.example.com/admin"), false},
		{ref(KindURL, "http://shop.example.com/admin"), ref(KindURL, "https://shop.example.com/"), false},
		{ref(KindURL, "https://203.0.113.5/"), ref(KindHost, "deploy@203.0.113.5"), true},
		{ref(KindRepo, "github:example-org/shop"), ref(KindSaaS, "github:example-org"), true},
		{ref(KindRepo, "github:other/shop"), ref(KindSaaS, "github:example-org"), false},
		{ref(KindCloud, "gcp:example-prod"), ref(KindCloud, "gcp:organizations/1"), true},
		{ref(KindCloud, "gcp:example-prod"), ref(KindCloud, "gcp:example-other"), false},
		{ref(KindCloud, "gcp:organizations/999"), ref(KindCloud, "gcp:organizations/1"), false},
	}
	for _, tc := range cases {
		if got := Under(tc.c, tc.root); got != tc.want {
			t.Errorf("Under(%s, %s) = %v", tc.c.ID, tc.root.ID, got)
		}
	}
}

// A password the detector has no shape for (user:password before @ without
// a scheme, or a URL that does not parse) is refused without being quoted.
func TestPasswordInALocatorIsNeverQuoted(t *testing.T) {
	for _, line := range []string{
		"  - host: admin:hunter2@203.0.113.5\n",
		"  - url: \"https://admin:hunter2/x@shop.example.com/\"\n",
		"  - url: \"ftp://admin:hunter2@shop.example.com/\"\n",
		"  - url: \"https:admin:hunter2@shop.example.com/\"\n",
	} {
		_, err := Parse("e.yaml", []byte(minimal+line), testOpts)
		if err == nil {
			t.Fatalf("%q validated", line)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%q: the password was printed: %v", line, err)
		}
	}
	_, err := Parse("e.yaml", []byte(minimal+"assets:\n  deploy:\n    host: 203.0.113.5\n    jump: ops:hunter2@198.51.100.7\n"), testOpts)
	if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "never carries a password") {
		t.Errorf("jump: %v", err)
	}
}

func TestNotAvailableIsSaidOnce(t *testing.T) {
	_, err := Parse("e.yaml", []byte(minimal+"limits:\n  max_cost: 5usd\n"), testOpts)
	if err == nil || strings.Count(err.Error(), "not available in this build") != 1 || !strings.Contains(err.Error(), "0.0.4") {
		t.Fatalf("got %v", err)
	}
}

// A local checkout is not a locator; the message says where it goes.
func TestLocalCheckoutIsNotALocator(t *testing.T) {
	_, err := Parse("e.yaml", []byte(minimal+"  - repo: ./\n"), testOpts)
	if err == nil || strings.Contains(err.Error(), "not available") || !strings.Contains(err.Error(), "checkout setting") {
		t.Fatalf("got %v", err)
	}
}

func TestCredentialInACommentIsReportedOnce(t *testing.T) {
	_, err := Parse("e.yaml", []byte(minimal+"# AKIAIOSFODNN7EXAMPLE\nredact_extra: [tangerine]\n"), testOpts)
	errs, ok := errors.AsType[Errors](err)
	if !ok || len(errs) != 1 || errs[0].Line != 10 {
		t.Fatalf("want one error on line 10, got %v", err)
	}
}

// A report names an asset found under a root by its canonical id, and the
// paste it prints must validate: an accepted risk may name one
// (docs/spec/engagement.md, "Identity, references and validation").
func TestAcceptedRiskByCanonicalID(t *testing.T) {
	file := minimal + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n" +
		"    - {id: sshd.password_auth_enabled, asset: \"repo:github:example-org/shop\", reason: r, accepted_by: alice}\n" +
		"    - {id: sshd.password_auth_enabled, asset: deploy@203.0.113.5, reason: r, accepted_by: alice}\n"
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := res.AssetID("repo:github:example-org/shop"); !ok || id != "repo:github:example-org/shop" {
		t.Errorf("canonical id: %q %v", id, ok)
	}
	if id, ok := res.AssetID("deploy@203.0.113.5"); !ok || id != "host:203.0.113.5:22" {
		t.Errorf("root as written: %q %v", id, ok)
	}
	if _, ok := res.AssetID("host:198.51.100.7:22"); ok {
		t.Error("an id under no root resolved")
	}
}

// A name or locator that matches a redact_extra pattern is written into the
// stage documents as declared, so validation warns, naming neither the
// pattern nor the value (docs/spec/engagement.md, "Narrowing travels with
// the engagement").
func TestRedactExtraMatchingANameWarns(t *testing.T) {
	file := minimal + "redact_extra: [\"tanger[i]ne\"]\nassets:\n  tangerine-db:\n    host: 203.0.113.5\n"
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "1 assets entry match redact_extra[0]") {
		t.Fatalf("warnings %q", res.Warnings)
	}
	if strings.Contains(res.Warnings[0], "tangerine") || strings.Contains(res.Warnings[0], "tanger[i]ne") {
		t.Errorf("the warning quotes what it should hide: %q", res.Warnings[0])
	}
	if res, _ := Parse("e.yaml", []byte(minimal+"redact_extra: [\"tanger[i]ne\"]\n"), testOpts); len(res.Warnings) != 0 {
		t.Errorf("a pattern that matches no name warns: %q", res.Warnings)
	}
}

// An acceptance must name its subject when the finding id is reported per
// instance: without one it would also accept every instance found later
// (docs/spec/engagement.md, "Accepted risks"). No 0.0.2 catalog id has a
// subject kind yet, so the catalog is stubbed with the E6 OAuth finding.
func TestAcceptedRiskNeedsSubjectWhenTheFindingHasOne(t *testing.T) {
	opts := testOpts
	opts.KnownFinding = func(id string) bool { return id == "workspace.oauth_broad_scope" || testOpts.KnownFinding(id) }
	opts.FindingSubject = func(id string) string {
		if id == "workspace.oauth_broad_scope" {
			return "oauth_app"
		}
		return ""
	}
	file := func(subject string) []byte {
		return []byte(minimal + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n" +
			"    - {id: workspace.oauth_broad_scope, asset: deploy@203.0.113.5" + subject + ", reason: r, accepted_by: alice, expires: 2026-12-31}\n" +
			"    - {id: sshd.password_auth_enabled, asset: deploy@203.0.113.5, reason: r, accepted_by: alice, expires: 2026-12-31}\n")
	}
	_, err := Parse("e.yaml", file(""), opts)
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("want validation errors, got %v", err)
	}
	if len(errs) != 1 || errs[0].Key != "intent.accepted_risks[0].subject" ||
		!strings.Contains(errs[0].Msg, "reported per OAuth app") || !strings.Contains(errs[0].Msg, "each new one found later") {
		t.Fatalf("want one subject error on the OAuth entry, the whole-id host entry accepted; got %v", errs)
	}
	if _, err := Parse("e.yaml", file(", subject: \"1234.apps.googleusercontent.com\""), opts); err != nil {
		t.Fatalf("an acceptance naming its subject must validate: %v", err)
	}
}

func TestOptionsNeedFindingSubject(t *testing.T) {
	for _, field := range []string{"FindingSubject", "HostFinding"} {
		opts := testOpts
		if field == "FindingSubject" {
			opts.FindingSubject = nil
		} else {
			opts.HostFinding = nil
		}
		if _, err := Parse("e.yaml", []byte(minimal), opts); err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("want Options.%s required, got %v", field, err)
		}
	}
}

// A subject on an id about the whole asset could never match: refused for a
// network collector's id, listed as not applied for a host's.
func TestSubjectOnAWholeAssetFinding(t *testing.T) {
	opts := testOpts
	opts.KnownFinding = func(id string) bool { return id == "github.too_many_owners" || testOpts.KnownFinding(id) }
	file := minimal + "people:\n  alice: {kind: employee}\nintent:\n  accepted_risks:\n" +
		"    - {id: github.too_many_owners, asset: github:example-org, subject: alice-ex, reason: r, accepted_by: alice, expires: 2026-12-31}\n" +
		"    - {id: sshd.password_auth_enabled, asset: deploy@203.0.113.5, subject: \"22/tcp\", reason: r, accepted_by: alice, expires: 2026-12-31}\n"
	_, err := Parse("e.yaml", []byte(file), opts)
	var errs Errors
	if !errors.As(err, &errs) || len(errs) != 1 || errs[0].Key != "intent.accepted_risks[0].subject" ||
		!strings.Contains(errs[0].Msg, "about the asset as a whole") {
		t.Fatalf("want one error on the organization-wide acceptance, the host one left to Recon; got %v", err)
	}
}

func TestIntentURLCannotBeBothPublicAndRestricted(t *testing.T) {
	file := `schema: 1
engagement: {name: contradictory, timezone: UTC, trigger: routine}
roots: [{url: 'https://example.com/'}]
intent:
 exposed_on_purpose: [{url: 'https://EXAMPLE.com:443/admin', audience: internet}]
 not_exposed: [{url: 'https://example.com/admin', audience: vpn}]
`
	_, err := Parse("e.yaml", []byte(file), testOpts)
	if err == nil || !strings.Contains(err.Error(), "same URL is also declared exposed_on_purpose") {
		t.Fatal(err)
	}
}
