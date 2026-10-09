package gate

import (
	"cmp"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Use is what one third-party source was sent, for the report's "What
// left this machine" (docs/spec/engagement.md, "The report"): the subjects
// of the requests the gate sent to it, which are what it learned, and how
// many. Only requests whose send line was written are counted.
type Use struct {
	Source   string
	Operator string // who runs a public source, from its declaration
	Host     string // the literal host, or the resolver's address for DNS
	Subjects []string
	Requests int
	// Credentials names the environment variables a credential came from.
	Credentials []string
	// For DNS: RootControls counts the control lookups under roots, and
	// InvalidControl says one under invalid. was sent, both among
	// Requests' lookups; ScopedResolversIgnored says the gate read the
	// system's main resolver on macOS, whose per-interface (VPN) resolvers
	// it did not ask.
	RootControls           int
	InvalidQueries         int
	InvalidControl         bool
	ScopedResolversIgnored bool
}

// Site is how many requests one web name was sent, by the asset they were
// for.
type Site struct {
	Name     string
	Asset    string
	Requests int
	// FirstParty says a request to it was admitted on first-party
	// evidence, beyond what any name under a domain root gets.
	FirstParty bool
}

type egress struct {
	mu             sync.Mutex
	uses           map[string]*Use
	sites          map[[3]string]*Site // {asset, name}
	dns            int
	controls       int
	invalid        bool
	invalidQueries int
}

func (x *egress) use(source string) *Use {
	if x.uses == nil {
		x.uses = map[string]*Use{}
	}
	u, ok := x.uses[source]
	if !ok {
		u = &Use{Source: source}
		x.uses[source] = u
	}
	return u
}

// countSend records a request whose send line was written.
func (g *Gate) countSend(a admitted, asset string) {
	g.egress.mu.Lock()
	defer g.egress.mu.Unlock()
	if a.prov.web {
		if g.egress.sites == nil {
			g.egress.sites = map[[3]string]*Site{}
		}
		k := [3]string{asset, a.b.name, strconv.FormatBool(a.firstParty)}
		st, ok := g.egress.sites[k]
		if !ok {
			st = &Site{Asset: asset, Name: a.b.name}
			g.egress.sites[k] = st
		}
		st.Requests++
		st.FirstParty = st.FirstParty || a.firstParty
		return
	}
	u := g.egress.use(a.prov.source)
	u.Operator, u.Host = a.prov.operator, a.b.name
	u.Requests++
	subject := a.b.subject
	if subject == "" {
		subject = asset
	}
	if !slices.Contains(u.Subjects, subject) {
		u.Subjects = append(u.Subjects, subject)
	}
	if a.cred != nil && !slices.Contains(u.Credentials, a.cred.Env) {
		u.Credentials = append(u.Credentials, a.cred.Env)
	}
}

func (g *Gate) countDNS(name string) {
	g.egress.mu.Lock()
	defer g.egress.mu.Unlock()
	g.egress.dns++
	if strings.HasSuffix(name, ".invalid") {
		g.egress.invalidQueries++
	}
}

// countControl records a control lookup the gate admitted.
func (g *Gate) countControl(invalid bool) {
	g.egress.mu.Lock()
	defer g.egress.mu.Unlock()
	if invalid {
		g.egress.invalid = true
	} else {
		g.egress.controls++
	}
}

// Resolver is the address of the nameserver the gate's DNS client asks,
// redacted as an answer's address is; "" when it found none.
func (g *Gate) Resolver() string {
	if !g.nameserver.IsValid() {
		return ""
	}
	return g.redact(g.nameserver.String())
}

// Egress is what left this machine through the gate so far: the third-party
// sources in a fixed order (DNS first), and the web names by asset.
func (g *Gate) Egress() ([]Use, []Site) {
	g.egress.mu.Lock()
	defer g.egress.mu.Unlock()
	var uses []Use
	if g.egress.dns > 0 {
		uses = append(uses, Use{Source: "dns", Host: g.Resolver(), Requests: g.egress.dns, RootControls: g.egress.controls,
			InvalidQueries: g.egress.invalidQueries, InvalidControl: g.egress.invalid, ScopedResolversIgnored: g.scopedResolvers})
	}
	for _, k := range slices.Sorted(maps.Keys(g.egress.uses)) {
		u := *g.egress.uses[k]
		u.Subjects, u.Credentials = slices.Sorted(slices.Values(u.Subjects)), slices.Sorted(slices.Values(u.Credentials))
		uses = append(uses, u)
	}
	var sites []Site
	for _, st := range g.egress.sites {
		sites = append(sites, *st)
	}
	slices.SortFunc(sites, func(a, b Site) int {
		return cmp.Or(cmp.Compare(a.Asset, b.Asset), cmp.Compare(a.Name, b.Name), cmp.Compare(strconv.FormatBool(a.FirstParty), strconv.FormatBool(b.FirstParty)))
	})
	return uses, sites
}
