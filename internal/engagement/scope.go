package engagement

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
)

// wellKnown are the two files a first-party site reads beside its entry
// points: a fixed list, not "any .well-known" (docs/spec/scope.md,
// "Admission").
var wellKnown = []string{"/robots.txt", "/.well-known/security.txt"}

// GateScope is the engagement file's scope as the gate reads it, built from
// the validated file and nothing else: never from scope.json or another
// stage output, so an edit there cannot widen what is sent
// (docs/spec/scope.md, "Admission"; docs/spec/engagement.md, "Stop and
// resume"). at is the run's start, against which a confirmation's year is
// measured.
func (r *Resolved) GateScope(at time.Time) gate.Scope {
	s := &scope{res: r, at: at, assets: map[string]ResolvedAsset{}}
	for _, a := range r.Assets {
		s.assets[a.ID] = a
	}
	for _, list := range [][]Exposure{r.Intent.ExposedOnPurpose, r.Intent.NotExposed} {
		for _, e := range list {
			if u, err := parseURL(e.URL); err == nil { // validated
				s.intent = append(s.intent, u)
			}
		}
	}
	return s
}

type scope struct {
	res    *Resolved
	at     time.Time
	assets map[string]ResolvedAsset // by canonical id
	intent []Ref                    // the intent URLs, entry points of their site
}

// parse reads a subject id leniently: a GitHub login or repository, a host
// name and a URL are canonicalized as the file's locators are, so they are
// compared case-folded (docs/spec/scope.md, "Admission"). A Workspace
// per-user subject, `saas:google-workspace:<domain>/users/<key>`, is its
// tenant's: whether the user is excluded is the gate's excluded-subject
// set's to say. Anything else fails, and an unreadable subject is outside
// every root.
func parseSubject(id string) (Ref, bool) {
	kind, rest, ok := strings.Cut(id, ":")
	if !ok {
		return Ref{}, false
	}
	if Kind(kind) == KindSaaS && strings.HasPrefix(rest, ProviderGoogleWorkspace+":") {
		if tenant, user, found := strings.Cut(rest, "/users/"); found {
			if user == "" || strings.ContainsAny(user, "/?#") {
				return Ref{}, false
			}
			rest = tenant
		}
	}
	r, err := parseLocator(Kind(kind), rest)
	if err != nil && Kind(kind) == KindDomain {
		// A name whose records the gate reads may hold underscore labels
		// (_dmarc.example.com, s1._domainkey.example.com): it is placed by
		// its labels, as any name is (docs/spec/scope.md, "The resolver").
		d := strings.TrimSuffix(strings.ToLower(rest), ".")
		if recordDomain(d) {
			return Ref{Kind: KindDomain, ID: "domain:" + d, Written: rest, name: d}, true
		}
	}
	return r, err == nil
}

// underscoreLabel is a label of a name read from or for its records.
var underscoreLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// recordDomain reports whether d is a lowercase DNS name of two labels or
// more, any of which may hold underscores.
func recordDomain(d string) bool {
	labels := strings.Split(d, ".")
	if len(d) > 253 || len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, l := range labels {
		if !underscoreLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// under is Under, and also places a URL root's robots.txt and security.txt
// under it: they sit at the origin's root, outside a root such as
// https://example.com/app/, and a url root reads them (docs/spec/scope.md,
// "Admission").
func under(c, root Ref) bool {
	if Under(c, root) {
		return true
	}
	return c.Kind == KindURL && root.Kind == KindURL && sameOrigin(c, root) && slices.Contains(wellKnown, c.path)
}

func sameOrigin(a, b Ref) bool {
	return a.scheme == b.scheme && a.Address() == b.Address() && a.Port == b.Port
}

// excludedBy names the first exclude that covers c, as "exclude[i]".
func (s *scope) excludedBy(c Ref) string {
	if i := excludeOf(s.res.Exclude, c); i >= 0 {
		return excludeEntry(i)
	}
	return ""
}

// Subject reads the subject leniently and the asset strictly: the gate keys
// an asset's throttle, redirects, pages and excluded-subject set by the id
// as written, so a second spelling of one asset would be a second bucket
// that the operator's lower throttle never binds. A request's asset that is
// not a canonical id is outside every root.
func (s *scope) Subject(asset, id string) gate.Standing {
	a, ok := ParseID(asset)
	c, ok2 := parseSubject(id)
	if !ok || !ok2 {
		return gate.Standing{}
	}
	st := gate.Standing{UnderAsset: under(c, a)}
	if i := slices.IndexFunc(s.res.Roots, func(root Ref) bool { return under(c, root) }); i >= 0 {
		st.Root = s.res.Roots[i].ID
	}
	st.ExcludedBy = s.excludedBy(c)
	return st
}

// Name names the exclude that covers a DNS name (excludesName).
func (s *scope) Name(n string) string {
	if i := slices.IndexFunc(s.res.Exclude, func(x Ref) bool { return excludesName(x, n) }); i >= 0 {
		return excludeEntry(i)
	}
	return ""
}

// Address reports the exclude whose network, or whose host written as an
// address, holds a in any of its forms (addressExcluded), and whether a
// network root holds it (docs/spec/scope.md, "Addresses").
func (s *scope) Address(a netip.Addr) (string, bool) {
	excludedBy := ""
	if i := slices.IndexFunc(s.res.Exclude, func(x Ref) bool { return addressExcluded(x, a) }); i >= 0 {
		excludedBy = excludeEntry(i)
	}
	return excludedBy, s.res.networkRoot(a) != ""
}

// networkRoot is the network root holding a in any of its forms
// (gate.Forms), "" when none: a root written in IPv4 holds a translated
// address by the IPv4 address it carries, and a root written inside NAT64
// or 6to4 holds the IPv6 addresses written in it.
func (r *Resolved) networkRoot(a netip.Addr) string {
	f := gate.Forms(a)
	for _, root := range r.Roots {
		if root.Kind == KindNetwork && slices.ContainsFunc(f, root.prefix.Contains) {
			return root.ID
		}
	}
	return ""
}

// allowAddress refuses an address an exclude covers in any of its forms:
// what the SSH transport asks about every address a host's or jump host's
// name resolves to, and the one it dials (docs/spec/scope.md, "The scope
// gate").
func (r *Resolved) allowAddress(a netip.Addr) error {
	if i := slices.IndexFunc(r.Exclude, func(x Ref) bool { return addressExcluded(x, a) }); i >= 0 {
		return fmt.Errorf("resolves to %s, which %s (%s) covers", a, excludeEntry(i), r.Exclude[i].ID)
	}
	return nil
}

// sitePaths are the paths an origin may be read at, by the evidence each
// needs (docs/spec/scope.md, "Admission", "First-party evidence"). A path
// in both network and confirmed may be read when either holds.
type sitePaths struct {
	// paths need nothing more than the file.
	paths []string
	// firstParty says the file's own evidence (a root) admits paths, not
	// only a domain root's front page: what the report counts as a site
	// shown to be the operator's.
	firstParty bool
	// network need every address the name resolves to inside a network
	// root; confirmed need the name to point at the confirmation's target.
	network, confirmed []string
	// ev is the file's evidence for the origin, which confirmed rests on.
	ev *Evidence
}

// Admits decides whether path may be read at origin (docs/spec/scope.md,
// "Admission", steps 7 and 8): the one decision the gate makes before it
// resolves the name, with l nil, and again after, with the lookup as
// answered. It is the only check on a web op's port: an origin it admits
// no path at is refused, so a discovered name's other ports are never read.
func (s *scope) Admits(origin, path string, l *gate.Lookup) gate.Admission {
	sp := s.site(origin)
	switch {
	case slices.Contains(sp.paths, path):
		return gate.Admission{FirstParty: sp.firstParty}
	case !slices.Contains(sp.network, path) && !slices.Contains(sp.confirmed, path):
		return gate.Admission{Refused: "entry_point"}
	case l == nil:
		return gate.Admission{Resolve: true}
	}
	// A confirmation admits only the paths it lists; a network root
	// holding every address admits the rest, and a confirmation that moved.
	ev := sp.ev
	if !slices.Contains(sp.confirmed, path) {
		ev = nil
	}
	if !s.res.resolvedEvidence(ev, *l).counts() {
		return gate.Admission{Refused: "address_moved"}
	}
	return gate.Admission{FirstParty: true}
}

// site lists the paths an origin may be read at (docs/spec/scope.md,
// "Admission", "Levels in 0.0.2"):
//
//   - a name under a domain root, on the default port, has its front page;
//   - a first-party site also has its entry points (a url root or a
//     confirmed url entry, and the intent URLs on it), robots.txt and
//     security.txt: as paths when a root is the evidence, as confirmed
//     when only the operator's word is;
//   - when the file has a network root, those beyond the front page of a
//     site without root evidence are also network paths, which the gate
//     allows once every address the name resolves to is inside one.
//
// An origin not written canonically, or on another port, lists nothing.
func (s *scope) site(origin string) sitePaths {
	o, err := parseURL(origin + "/")
	if err != nil || o.path != "/" || o.ID != "url:"+origin+"/" {
		return sitePaths{}
	}
	front := false
	if o.Port == 0 {
		for _, root := range s.res.Roots {
			switch root.Kind {
			case KindDomain:
				front = front || domainUnder(o.name, root.name)
			case KindNetwork:
				front = front || o.addr.IsValid() && root.prefix.Contains(o.addr)
			case KindHost:
				front = front || !root.Local() && root.Address() == o.Address()
			}
		}
	}
	ev, entries := s.res.evidence(o, s.at)
	if !front && ev == nil {
		return sitePaths{}
	}
	sp := sitePaths{ev: ev}
	if front {
		sp.paths = append(sp.paths, "/")
	}
	more := append(slices.Clone(wellKnown), entries...)
	for _, u := range s.intent {
		if sameOrigin(u, o) {
			more = append(more, u.path)
		}
	}
	switch {
	case ev != nil && ev.Kind != "operator":
		sp.paths, sp.firstParty = append(sp.paths, more...), true
	case ev != nil:
		sp.confirmed = more
	}
	if (ev == nil || ev.Kind == "operator") && slices.ContainsFunc(s.res.Roots, func(r Ref) bool { return r.Kind == KindNetwork }) {
		// Evidence only a network root holding every address can give,
		// checked once the gate has resolved the name; with no network
		// root there is none to give.
		sp.network = slices.Clone(more)
	}
	for _, l := range []*[]string{&sp.paths, &sp.network, &sp.confirmed} {
		slices.Sort(*l)
		*l = slices.Compact(*l)
	}
	return sp
}

// resolvedEvidence is first-party evidence once the name is resolved
// (docs/spec/scope.md, "First-party evidence"), the decision the gate's
// Admits and discovery's listing share: a confirmation holds only while the
// name points at its target, and is "moved" otherwise; without evidence
// that holds, a name every address of which a network root holds has that
// root's.
func (r *Resolved) resolvedEvidence(ev *Evidence, l gate.Lookup) *Evidence {
	if ev != nil && ev.Kind == "operator" && !l.PointsAt(ev.Target) {
		ev = &Evidence{Kind: "moved", ConfirmedBy: ev.ConfirmedBy, Date: ev.Date, Target: ev.Target}
	}
	if ev.counts() || len(l.Addrs) == 0 {
		return ev
	}
	held := ""
	for _, a := range l.Addrs {
		root := r.networkRoot(a)
		if root == "" {
			return ev
		}
		if held == "" {
			held = root
		}
	}
	return &Evidence{Kind: "network_root", Root: held}
}

// evidence is an origin's first-party evidence from the file, nil when it
// has none, and the entry points it brings: the paths of the url roots and
// confirmed url entries on the origin (docs/spec/scope.md, "First-party
// evidence"). Admits and scope.json both read it, so what the Scope stage
// prints is what the gate admits. A root comes first, then a network root
// holding an address literal, then the operator's confirmation, which
// counts only through its year (at is the run's start); a name or address
// counts only on its scheme's default port.
func (r *Resolved) evidence(o Ref, at time.Time) (*Evidence, []string) {
	var ev *Evidence
	first := func(e *Evidence) {
		if ev == nil {
			ev = e
		}
	}
	var entries []string
	for _, root := range r.Roots {
		if root.Kind == KindURL && sameOrigin(root, o) {
			entries = append(entries, root.path)
			first(&Evidence{Kind: "url_root", Root: root.ID})
		}
	}
	if o.Port == 0 {
		for _, root := range r.Roots {
			if root.Kind == KindHost && !root.Local() && root.Address() == o.Address() {
				first(&Evidence{Kind: "host_root", Root: root.ID})
			}
		}
		for _, root := range r.Roots {
			if root.Kind == KindNetwork && o.addr.IsValid() && root.prefix.Contains(o.addr) {
				first(&Evidence{Kind: "network_root", Root: root.ID})
			}
		}
	}
	for _, a := range r.Assets {
		if a.FirstParty == nil || !r.current(a.FirstParty, at) {
			continue
		}
		if a.Kind == KindURL && sameOrigin(a.Ref, o) {
			entries = append(entries, a.path)
		} else if o.Port != 0 || a.Kind != KindDomain && a.Kind != KindHost || a.Address() != o.Address() {
			continue
		}
		target, _ := canonicalTarget(a.FirstParty.Target) // validated
		first(&Evidence{Kind: "operator", ConfirmedBy: a.FirstParty.ConfirmedBy, Date: a.FirstParty.Date, Target: target})
	}
	return ev, entries
}

// current reports whether a confirmation is inside its year at t: from its
// date through its date plus 365 days, until 24:00 in engagement.timezone
// (docs/spec/scope.md, "First-party evidence"). One dated after t, a typo
// for a year that has not come, is not evidence: it would outlast its year.
func (r *Resolved) current(fp *FirstParty, t time.Time) bool {
	d, err := time.ParseInLocation("2006-01-02", fp.Date, r.zone())
	if err != nil {
		return false
	}
	return !d.After(t) && t.Before(d.AddDate(0, 0, 366))
}

// zone is engagement.timezone.
func (r *Resolved) zone() *time.Location {
	if r.loc == nil {
		return time.UTC
	}
	return r.loc
}

// canonicalTarget reads a confirmation's target: a DNS name, lowercased
// without a trailing dot, or addresses in the form the gate compares
// (gate.JoinAddrs).
func canonicalTarget(t string) (string, bool) {
	var addrs []netip.Addr
	for part := range strings.SplitSeq(t, ",") {
		a, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			addrs = nil
			break
		}
		addrs = append(addrs, a)
	}
	if addrs != nil {
		return gate.JoinAddrs(addrs), true
	}
	d := strings.TrimSuffix(strings.ToLower(t), ".")
	if checkLabels(d, 2) != nil {
		return "", false
	}
	return d, true
}

// Throttle is the asset's throttle in requests per second. A web asset
// takes its assets entry's, or the defaults when it has none (a discovered
// name); a SaaS, repository or cloud asset takes only what its own entry
// sets, which can only lower the provider's ceiling (docs/spec/scope.md,
// "Throttle, timeouts and retries").
func (s *scope) Throttle(asset string) (float64, int) {
	ref, ok := ParseID(asset)
	if !ok {
		return 0, 0
	}
	a, declared := s.assets[ref.ID]
	switch ref.Kind {
	case KindDomain, KindURL, KindHost, KindNetwork:
		if !declared {
			return perSecond(s.res.Defaults.Throttle)
		}
		return perSecond(a.Throttle)
	}
	if !declared || a.ownThrottle == nil {
		return 0, 0
	}
	rate, _ := perSecond(*a.ownThrottle)
	return rate, a.ownThrottle.Concurrency
}

// perSecond reads a validated rate, `5/s` or `120/m`; an unset rate is 0.
func perSecond(t Throttle) (float64, int) {
	n, unit, ok := strings.Cut(t.Rate, "/")
	v, err := strconv.ParseFloat(n, 64)
	if !ok || err != nil {
		return 0, 0
	}
	if unit == "m" {
		v /= 60
	}
	return v, t.Concurrency
}

// OrgUnits lists the organizational units the file excludes under a
// Workspace tenant.
func (s *scope) OrgUnits(asset string) []gate.OrgUnit {
	ref, ok := ParseID(asset)
	if !ok {
		return nil
	}
	var out []gate.OrgUnit
	for i, x := range s.res.Exclude {
		if x.OrgUnit != "" && x.ID == ref.ID {
			out = append(out, gate.OrgUnit{Path: x.OrgUnit, ExcludedBy: excludeEntry(i)})
		}
	}
	return out
}

// firstParty is a domain, url or host asset's first-party evidence at t,
// as evidence finds it for the asset's own origin, or for either of a
// name's or an address's default origins; nil when it has none. A
// confirmation past its year is reported as expired, which is not
// evidence.
func (r *Resolved) firstParty(a ResolvedAsset, at time.Time) *Evidence {
	var origins []Ref
	switch a.Kind {
	case KindURL:
		origins = []Ref{a.Ref}
	case KindHost:
		if a.Local() {
			return &Evidence{Kind: "host_root", Root: a.Root}
		}
		fallthrough
	case KindDomain:
		for _, scheme := range []string{"https", "http"} {
			origins = append(origins, Ref{Kind: KindURL, scheme: scheme, name: a.name, addr: a.addr})
		}
	}
	for _, o := range origins {
		if ev, _ := r.evidence(o, at); ev != nil {
			return ev
		}
	}
	if a.FirstParty != nil && !r.current(a.FirstParty, at) {
		kind := "expired"
		if d, err := time.ParseInLocation("2006-01-02", a.FirstParty.Date, r.zone()); err == nil && d.After(at) {
			kind = "future"
		}
		return &Evidence{Kind: kind, ConfirmedBy: a.FirstParty.ConfirmedBy, Date: a.FirstParty.Date}
	}
	return nil
}
