package engagement

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

// Kind is an asset kind (docs/spec/engagement.md, "Identity, references and
// validation").
type Kind string

// The seven kinds, in the order of the id table.
const (
	KindDomain  Kind = "domain"
	KindURL     Kind = "url"
	KindHost    Kind = "host"
	KindNetwork Kind = "network"
	KindSaaS    Kind = "saas"
	KindRepo    Kind = "repo"
	KindCloud   Kind = "cloud"
)

// Providers per kind. A provider not listed has no locator syntax yet.
const (
	ProviderGitHub          = "github"
	ProviderGoogleWorkspace = "google-workspace"
	ProviderGCP             = "gcp"
)

// LocalHost is the host locator for the machine running scheck.
const LocalHost = "local"

// Ref is a parsed locator: its kind, its canonical id and the parts the
// "falls under" relation and later stages read. Nothing here is resolved
// over the network; a name stays a name.
type Ref struct {
	Kind    Kind   `json:"kind" yaml:"kind"`
	ID      string `json:"id" yaml:"id"`
	Written string `json:"written" yaml:"written"`
	OrgUnit string `json:"org_unit,omitempty" yaml:"org_unit,omitempty"`

	// User is a host's SSH user: a connection setting, not part of the id.
	User string `json:"user,omitempty" yaml:"user,omitempty"`
	// Port is a host's SSH port or a URL's explicit port.
	Port int `json:"port,omitempty" yaml:"port,omitempty"`

	name     string       // domain; url, host or workspace host name, lowercase
	addr     netip.Addr   // host or url address literal
	prefix   netip.Prefix // network
	scheme   string       // url
	path     string       // url path, never empty
	provider string       // saas, repo, cloud
	tenant   string       // github org, workspace domain, gcp project or organizations/N
	repo     string       // repository name, lowercase
}

// Local reports whether the ref is `host: local`.
func (r Ref) Local() bool { return r.Kind == KindHost && r.name == LocalHost }

// Address is a host's address as SSH dials it: an IP literal or a name.
func (r Ref) Address() string {
	if r.addr.IsValid() {
		return r.addr.String()
	}
	return r.name
}

var (
	dnsLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	sshUser    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)
	githubName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$`)
	repoName   = regexp.MustCompile(`^[a-z0-9._-]{1,100}$`)
	gcpProject = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpOrg     = regexp.MustCompile(`^organizations/[0-9]{1,20}$`)
)

// kindOf returns the one kind key a locator sets.
func kindOf(l Locator) (Kind, string, error) {
	var kind Kind
	var value string
	n := 0
	for _, kv := range []struct {
		k Kind
		v string
	}{
		{KindDomain, l.Domain}, {KindURL, l.URL}, {KindHost, l.Host}, {KindNetwork, l.Network},
		{KindSaaS, l.SaaS}, {KindRepo, l.Repo}, {KindCloud, l.Cloud},
	} {
		if kv.v != "" {
			kind, value = kv.k, kv.v
			n++
		}
	}
	switch n {
	case 1:
		return kind, value, nil
	case 0:
		return "", "", errors.New("needs exactly one of domain, url, host, network, saas, repo, cloud")
	default:
		return "", "", errors.New("sets more than one of domain, url, host, network, saas, repo, cloud")
	}
}

// ParseID reads a canonical id back into a Ref ("host:203.0.113.5:22",
// "repo:github:example-org/shop"): the form a report prints for an asset
// found under a root, which an accepted risk may name.
func ParseID(id string) (Ref, bool) {
	kind, rest, ok := strings.Cut(id, ":")
	if !ok {
		return Ref{}, false
	}
	r, err := parseLocator(Kind(kind), rest)
	if err != nil || r.ID != id {
		return Ref{}, false
	}
	return r, true
}

// parseLocator parses a value of the given kind into its canonical Ref.
func parseLocator(kind Kind, s string) (Ref, error) {
	var (
		r   Ref
		err error
	)
	switch kind {
	case KindDomain:
		r.name, err = parseDomain(s)
		r.ID = "domain:" + r.name
	case KindURL:
		r, err = parseURL(s)
	case KindHost:
		r, err = parseHost(s)
	case KindNetwork:
		r.prefix, err = parseNetwork(s)
		r.ID = "network:" + r.prefix.String()
	case KindSaaS:
		r, err = parseSaaS(s)
	case KindRepo:
		r, err = parseRepo(s)
	case KindCloud:
		r, err = parseCloud(s)
	}
	if err != nil {
		return Ref{}, err
	}
	r.Kind, r.Written = kind, s
	return r, nil
}

// parseDomain lowercases a DNS name and drops one trailing dot. It refuses
// wildcards, IP literals, schemes, ports and paths: a domain root covers its
// subdomains by itself.
func parseDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(s), ".")
	if _, err := netip.ParseAddr(d); err == nil {
		return "", fmt.Errorf("%q is an address, not a domain: use host or network", s)
	}
	if strings.ContainsAny(d, "/:@*") {
		return "", fmt.Errorf("%q is not a domain name: no scheme, port, path or wildcard (a domain covers its subdomains)", s)
	}
	if err := checkLabels(d, 2); err != nil {
		return "", fmt.Errorf("%q is not a domain name: %v", s, err)
	}
	return d, nil
}

// checkLabels validates a lowercase DNS name with at least min labels.
func checkLabels(d string, min int) error {
	if len(d) > 253 {
		return errors.New("longer than 253 characters")
	}
	labels := strings.Split(d, ".")
	if len(labels) < min {
		return fmt.Errorf("needs at least %d labels", min)
	}
	// A resolver reads an all-numeric last label as an address (inet_aton
	// takes 203.0.113.05 and 1234), so such a name is neither.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("looks like an address but is not one")
	}
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return fmt.Errorf("label %q is not a DNS label", l)
		}
	}
	return nil
}

// parseHostName validates a host's name or address literal. A single label
// is a name (an SSH config alias resolves the same way ssh resolves it).
func parseHostName(s string) (string, netip.Addr, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return "", netip.Addr{}, fmt.Errorf("%q: an address zone is not accepted", s)
		}
		// One address, one spelling: the scope gate compares the plain
		// form and refuses this one too.
		if a.Is4In6() {
			return "", netip.Addr{}, fmt.Errorf("%q: write an IPv4-mapped address as its IPv4 address, %s", s, a.Unmap())
		}
		if gate.NAT64Local.Contains(a) {
			return "", netip.Addr{}, fmt.Errorf("%q is in RFC 8215's local-use NAT64 prefix 64:ff9b:1::/48, which scheck never contacts: it cannot tell which IPv4 address it carries", s)
		}
		return "", a, nil
	}
	name := strings.ToLower(s)
	if err := checkLabels(name, 1); err != nil {
		return "", netip.Addr{}, fmt.Errorf("%q is neither an address nor a host name: %v", s, err)
	}
	return name, netip.Addr{}, nil
}

// parseHost parses `[user@]address[:port]`, IPv6 in brackets, or `local`.
// The id is host:address:port; the user is a connection setting.
func parseHost(s string) (Ref, error) {
	if s == LocalHost {
		return Ref{ID: "host:" + LocalHost, name: LocalHost}, nil
	}
	var r Ref
	rest := s
	if user, after, ok := strings.Cut(s, "@"); ok {
		// The part before @ is never quoted back: written user:password, it
		// is a secret the credential detector has no shape for.
		if strings.Contains(user, ":") {
			return Ref{}, errors.New("a host locator never carries a password: SSH authenticates with ssh-agent or identity")
		}
		if !sshUser.MatchString(user) {
			return Ref{}, errors.New("the part before @ is not an SSH user name")
		}
		r.User, rest = user, after
	}
	var addr, port string
	switch {
	case strings.HasPrefix(rest, "["):
		end := strings.Index(rest, "]")
		if end < 0 {
			return Ref{}, fmt.Errorf("%q: unclosed [ around an IPv6 address", s)
		}
		addr = rest[1:end]
		switch tail := rest[end+1:]; {
		case tail == "":
		case strings.HasPrefix(tail, ":"):
			port = tail[1:]
		default:
			return Ref{}, fmt.Errorf("%q: unexpected %q after the address", s, tail)
		}
		if a, err := netip.ParseAddr(addr); err != nil || !a.Is6() {
			return Ref{}, fmt.Errorf("%q: brackets hold an IPv6 address", s)
		}
	case strings.Count(rest, ":") > 1:
		return Ref{}, fmt.Errorf("%q: write an IPv6 address in brackets, [2001:db8::1]:22", s)
	default:
		addr, port, _ = strings.Cut(rest, ":")
	}
	r.Port = 22
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return Ref{}, fmt.Errorf("%q: port %q is not 1-65535", s, port)
		}
		r.Port = p
	}
	var err error
	if r.name, r.addr, err = parseHostName(addr); err != nil {
		return Ref{}, err
	}
	if r.name == LocalHost {
		return Ref{}, fmt.Errorf("%q: `local` takes no user or port", s)
	}
	host := r.name
	if r.addr.IsValid() {
		host = r.addr.String()
		if r.addr.Is6() {
			host = "[" + host + "]"
		}
	}
	r.ID = fmt.Sprintf("host:%s:%d", host, r.Port)
	return r, nil
}

// parseNetwork parses a CIDR whose host bits are zero.
func parseNetwork(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR network such as 203.0.113.0/28", s)
	}
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q: an address zone is not accepted", s)
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q: write an IPv4-mapped network in its IPv4 form", s)
	}
	// A wider network holding it is fine: the gate refuses those
	// addresses, and what such an exclude carries is decided by gate.Carried.
	if p.Bits() >= gate.NAT64Local.Bits() && gate.NAT64Local.Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("%q is inside RFC 8215's local-use NAT64 prefix 64:ff9b:1::/48, which scheck never contacts: it cannot tell which IPv4 addresses it carries", s)
	}
	if m := p.Masked(); m != p {
		return netip.Prefix{}, fmt.Errorf("%q has host bits set: the network is %s", s, m)
	}
	return p, nil
}

// parseURL canonicalizes an http or https URL: lowercase scheme and host,
// default port dropped, path kept, an empty path written as /. A URL is a
// prefix, so it takes no query or fragment, and it never carries
// credentials.
func parseURL(s string) (Ref, error) {
	u, err := url.Parse(s)
	if err != nil {
		// url.Parse quotes the fragment it failed on, which may be the
		// password of a user:password it could not split.
		return Ref{}, errors.New("not a URL such as https://shop.example.com/")
	}
	var r Ref
	r.scheme = strings.ToLower(u.Scheme)
	switch {
	// First, so that no later message quotes a URL holding a password.
	case u.User != nil || strings.Contains(u.Opaque, "@"):
		return Ref{}, errors.New("a URL here never carries a user or password; credentials come from the environment")
	case r.scheme != "http" && r.scheme != "https":
		return Ref{}, fmt.Errorf("%q: the scheme must be https or http", s)
	case u.Opaque != "" || u.Host == "":
		return Ref{}, fmt.Errorf("%q has no host", s)
	case u.RawQuery != "" || u.ForceQuery:
		return Ref{}, fmt.Errorf("%q: a URL here is a prefix and takes no query", s)
	case u.Fragment != "":
		return Ref{}, fmt.Errorf("%q: a URL here takes no fragment", s)
	}
	if r.name, r.addr, err = parseHostName(u.Hostname()); err != nil {
		return Ref{}, err
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Ref{}, fmt.Errorf("%q: port %q is not 1-65535", s, p)
		}
		if defaultPort := map[string]int{"https": 443, "http": 80}[r.scheme]; n != defaultPort {
			r.Port = n
		}
	}
	// Dot segments are removed and percent-encoding normalized, so that
	// /a/../checkout/ and /%63heckout/ are the same prefix as /checkout/.
	clean := "/"
	if u.Path != "" {
		clean = path.Clean(u.Path)
		if strings.HasSuffix(u.Path, "/") && clean != "/" {
			clean += "/"
		}
	}
	r.path = (&url.URL{Path: clean}).EscapedPath()
	host := r.name
	if r.addr.IsValid() {
		host = r.addr.String()
		if r.addr.Is6() {
			host = "[" + host + "]"
		}
	}
	if r.Port != 0 {
		host += ":" + strconv.Itoa(r.Port)
	}
	r.ID = "url:" + r.scheme + "://" + host + r.path
	return r, nil
}

// parseSaaS parses `github:org` or `google-workspace:domain`.
func parseSaaS(s string) (Ref, error) {
	provider, tenant, ok := strings.Cut(s, ":")
	if !ok {
		return Ref{}, fmt.Errorf("%q: write provider:tenant, github:example-org or google-workspace:example.com", s)
	}
	r := Ref{provider: provider}
	switch provider {
	case ProviderGitHub:
		r.tenant = strings.ToLower(tenant)
		if !githubName.MatchString(r.tenant) {
			return Ref{}, fmt.Errorf("%q: %q is not a GitHub organization name", s, tenant)
		}
	case ProviderGoogleWorkspace:
		d, err := parseDomain(tenant)
		if err != nil {
			return Ref{}, fmt.Errorf("%q: a Workspace tenant is its primary domain: %v", s, err)
		}
		r.tenant, r.name = d, d
	default:
		return Ref{}, fmt.Errorf("%q: provider %q has no locator; known: github, google-workspace", s, provider)
	}
	r.ID = "saas:" + provider + ":" + r.tenant
	return r, nil
}

// parseRepo parses `github:owner/name`. A local checkout is not a locator:
// it is a repository's `checkout` setting, its mirror, read from 0.0.2 E5
// (docs/spec/scope.md, "Repositories").
func parseRepo(s string) (Ref, error) {
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return Ref{}, errors.New("a local checkout is not a repository locator: write the repository as github:owner/name, " +
			"and its `git clone --mirror` as that asset's checkout setting, read from 0.0.2 E5")
	}
	provider, full, ok := strings.Cut(s, ":")
	if !ok || provider != ProviderGitHub {
		return Ref{}, fmt.Errorf("%q: write github:owner/name", s)
	}
	owner, name, ok := strings.Cut(strings.ToLower(full), "/")
	if !ok || !githubName.MatchString(owner) || !repoName.MatchString(name) || name == "." || name == ".." {
		return Ref{}, fmt.Errorf("%q: write github:owner/name", s)
	}
	return Ref{ID: "repo:github:" + owner + "/" + name, provider: provider, tenant: owner, repo: name}, nil
}

// parseCloud parses `gcp:project-id` or `gcp:organizations/N`.
func parseCloud(s string) (Ref, error) {
	provider, id, ok := strings.Cut(s, ":")
	if !ok || provider != ProviderGCP {
		return Ref{}, fmt.Errorf("%q: write gcp:project-id or gcp:organizations/123456789012; known providers: gcp", s)
	}
	if !gcpProject.MatchString(id) && !gcpOrg.MatchString(id) {
		return Ref{}, fmt.Errorf("%q: %q is neither a GCP project id nor organizations/N", s, id)
	}
	return Ref{ID: "cloud:" + provider + ":" + id, provider: provider, tenant: id}, nil
}

// cloudOrg reports whether the ref is a cloud organization.
func (r Ref) cloudOrg() bool {
	return r.Kind == KindCloud && strings.HasPrefix(r.tenant, "organizations/")
}

// domainUnder reports whether name equals d or is a subdomain of it.
func domainUnder(name, d string) bool {
	return name != "" && (name == d || strings.HasSuffix(name, "."+d))
}

// pathUnder reports whether p equals the prefix or lies under it, by whole
// path segments.
func pathUnder(p, prefix string) bool {
	if p == prefix || strings.HasSuffix(prefix, "/") && strings.HasPrefix(p, prefix) {
		return true
	}
	return strings.HasPrefix(p, prefix+"/")
}

// Under reports whether c equals root or falls under it by the root's own
// definition (docs/spec/scope.md, "What is in scope"). It reads only the
// locators: a name is never resolved, so a host named under a domain is
// under it and a host's address is under a network only when written as an
// address. A cloud project is under an organization root of its provider,
// since only inventory can say otherwise.
func Under(c, root Ref) bool {
	if c.ID == root.ID {
		return true
	}
	switch root.Kind {
	case KindDomain:
		switch c.Kind {
		case KindDomain, KindURL, KindHost:
			return domainUnder(c.name, root.name)
		}
	case KindNetwork:
		switch c.Kind {
		case KindHost, KindURL:
			return c.addr.IsValid() && root.prefix.Contains(c.addr)
		case KindNetwork:
			return root.prefix.Bits() <= c.prefix.Bits() && root.prefix.Contains(c.prefix.Addr())
		}
	case KindHost:
		if c.Kind == KindURL {
			return root.Address() == c.Address()
		}
	case KindURL:
		return c.Kind == KindURL && c.scheme == root.scheme && c.Address() == root.Address() &&
			c.Port == root.Port && pathUnder(c.path, root.path)
	case KindSaaS:
		return c.Kind == KindRepo && root.provider == ProviderGitHub && c.tenant == root.tenant
	case KindCloud:
		return c.Kind == KindCloud && !c.cloudOrg() && root.cloudOrg() && c.provider == root.provider
	}
	return false
}

// Excludes reports whether the exclude x covers c, the one test validation
// and the scope gate share (docs/spec/scope.md, "What is in scope": exclude
// always wins). It is Under, and also:
//
//   - a url exclude covers its site over both https and http, since every
//     discovered name is read over both, on the same port (as written, or
//     the one it is read on: https://x/ covers http://x:443/), and its path
//     by whole segments whether or not it ends in a slash: /checkout/
//     covers /checkout;
//   - an address exclude (a network, or a host written as an address, on
//     every port) covers a host, url or jump written as an address in any
//     of its forms, and a network it holds in any of them (addressExcluded).
//
// An organizational unit exclude narrows its tenant to users, which the
// gate drops from responses, so it covers nothing here.
func Excludes(x, c Ref) bool {
	switch {
	case x.OrgUnit != "":
		return false
	case x.Kind == KindURL && c.Kind == KindURL:
		prefix := strings.TrimSuffix(x.path, "/")
		return x.Address() == c.Address() && (x.Port == c.Port || x.urlPort() == c.urlPort()) &&
			(prefix == "" || c.path == prefix || strings.HasPrefix(c.path, prefix+"/"))
	case c.addr.IsValid() && addressExcluded(x, c.addr):
		return true
	case x.Kind == KindHost && c.Kind == KindHost && x.Address() == c.Address():
		// A host exclude covers its name or address on every port, as
		// the scope gate reads it for web.
		return true
	case c.Kind == KindNetwork:
		if p, ok := excludePrefix(x); ok && networkExcluded(p, c.prefix) {
			return true
		}
	}
	return Under(c, x)
}

// urlPort is the port a url is read on, written or its scheme's default.
func (r Ref) urlPort() int {
	if r.Port != 0 {
		return r.Port
	}
	return map[string]int{"https": 443, "http": 80}[r.scheme]
}

// excludesName reports whether the exclude x covers the DNS name n, a
// name the gate would query or a CNAME chain enters: a domain exclude it
// falls under, a host exclude written as that name, or a url exclude at
// the root of that name's site on its default port. Each is the excluded
// party's server or zone, which a query for the name reaches through its
// authoritative servers and a request through the chain reaches outright
// (docs/spec/scope.md, "Discovery"). A domain root's or asset's own
// standing is Excludes'; this is only the name.
func excludesName(x Ref, n string) bool {
	switch {
	case x.OrgUnit != "":
		return false
	case x.Kind == KindDomain:
		return domainUnder(n, x.name)
	case x.Kind == KindHost:
		return x.name == n
	case x.Kind == KindURL:
		return x.name == n && x.Port == 0 && strings.TrimSuffix(x.path, "/") == ""
	}
	return false
}

// excludeOf is the index of the first exclude in xs that covers c, or -1.
func excludeOf(xs []Ref, c Ref) int {
	return slices.IndexFunc(xs, func(x Ref) bool { return Excludes(x, c) })
}

// excludeEntry names an exclude as the audit log, scope.json and the gate
// do: exclude[i].
func excludeEntry(i int) string { return fmt.Sprintf("exclude[%d]", i) }

// excludePrefix is an address exclude as a network: a network, or a host
// written as an address.
func excludePrefix(x Ref) (netip.Prefix, bool) {
	switch {
	case x.Kind == KindNetwork:
		return x.prefix, true
	case x.Kind == KindHost && x.addr.IsValid():
		return netip.PrefixFrom(x.addr, x.addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// addressExcluded reports whether x, a network exclude or a host exclude
// written as an address, holds a in any of its forms, compared also with
// the IPv4 network x carries (gate.Carried) (docs/spec/scope.md,
// "Addresses"). A host exclude written as an address excludes that address
// on every port, as the scope gate reads it.
func addressExcluded(x Ref, a netip.Addr) bool {
	p, ok := excludePrefix(x)
	if !ok {
		return false
	}
	c, translated := gate.Carried(p)
	for _, f := range gate.Forms(a) {
		if p.Contains(f) || translated && c.Contains(f) {
			return true
		}
	}
	return false
}

// networkExcluded reports whether the exclude x holds the network n, each
// compared also in the IPv4 form it carries.
func networkExcluded(x, n netip.Prefix) bool {
	outer, inner := []netip.Prefix{x}, []netip.Prefix{n}
	if c, ok := gate.Carried(x); ok {
		outer = append(outer, c)
	}
	if c, ok := gate.Carried(n); ok {
		inner = append(inner, c)
	}
	for _, o := range outer {
		for _, i := range inner {
			if o.Bits() <= i.Bits() && o.Contains(i.Addr()) {
				return true
			}
		}
	}
	return false
}
