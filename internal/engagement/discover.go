package engagement

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
)

// Discovery's caps and the control label's length (docs/spec/scope.md,
// "Discovery").
const (
	maxResolved   = 1000
	maxUnverified = 200
	controlLength = 20
)

// discoveryOps are the Scope stage's requests: certificate transparency,
// once per domain root. The names it returns are split, filtered and
// counted by the gate before anything is stored.
var discoveryOps = []gate.Op{{
	ID: "ct.search", Provider: "crt.sh", Method: gate.GET,
	URL:     "https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y",
	Subject: "domain:{domain}", Params: []gate.Param{{Name: "domain", Type: gate.DNSName}},
	Level: gate.Passive, Accept: []string{"application/json"},
	Keep: []string{"name_value", "not_after"}, MaxBytes: 16 << 20,
	List: &gate.List{Items: "$", Kind: gate.KindName, Names: "name_value"},
}}

// CTGaps is what certificate transparency cannot find, printed with every
// domain root's discovery (docs/spec/scope.md, "Discovery").
const CTGaps = "Subdomains were discovered from certificate transparency (crt.sh) and DNS only. Not found this way: " +
	"names that never had a publicly trusted certificate (internal, HTTP-only, or covered by a wildcard certificate " +
	"such as *.example.com). Your DNS zone was not read; your DNS provider can export every name."

// Name statuses in scope.json.
const (
	NameResolves        = "resolves"
	NameDangling        = "dangling"
	NameGone            = "no_longer_exists"
	NameNoAddress       = "no_address"
	NameInsufficient    = "insufficient_evidence"
	NameMatchesWildcard = "matches_wildcard"
	NameExcluded        = "excluded"
	NameNotChecked      = "not_checked"
)

// ScopeDomain is one domain root's discovery.
type ScopeDomain struct {
	Root string `json:"root"`
	// CT is ok, or the coverage reason crt.sh's answer was not read for.
	CT string `json:"certificate_transparency"`
	// Dropped counts what the gate dropped from crt.sh's answer: names an
	// exclude covers, by exclude, and identities that are not names.
	Dropped []gate.Drop `json:"dropped,omitempty"`
	// Wildcard is the control label's answer, when the root has wildcard
	// DNS.
	Wildcard []string `json:"wildcard,omitempty"`
	// WildcardCerts are the names a wildcard certificate covers (*.x).
	WildcardCerts []string    `json:"wildcard_certificates,omitempty"`
	Names         []ScopeName `json:"names"`
}

// ScopeName is one name under a domain root and what resolving it found.
type ScopeName struct {
	Name string `json:"name"`
	// From says where it came from: root, declared or certificate
	// transparency.
	From []string `json:"from"`
	// ExpiredOnly marks a name seen only in expired certificates.
	ExpiredOnly bool   `json:"expired_only,omitempty"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	// ExcludedBy is the exclude that covers the name, or that its chain
	// entered: exclude[i].
	ExcludedBy string   `json:"excluded_by,omitempty"`
	Chain      []string `json:"chain,omitempty"`
	Addresses  []string `json:"addresses,omitempty"`
	// Target is where the name points, as a first_party confirmation
	// records it.
	Target     string    `json:"target,omitempty"`
	FirstParty *Evidence `json:"first_party,omitempty"`
	// Read marks a name Recon reads (its front page and certificate, and
	// more with first-party evidence).
	Read bool `json:"read"`
}

// Resolver is the DNS resolver discovery asked, and whether it answers
// names that do not exist.
type Resolver struct {
	Address  string `json:"address"`
	Rewrites bool   `json:"rewrites_nxdomain"`
	// Controls counts the control lookups sent; Invalid is whether the one
	// under invalid. was.
	Controls int  `json:"control_lookups"`
	Invalid  bool `json:"control_invalid"`
}

// PointsAt is one service outside every root that names under a root
// point at, by CNAME.
type PointsAt struct {
	Target string   `json:"target"`
	Names  []string `json:"names"`
}

// discovery is the Scope stage's discovery against one gate.
type discovery struct {
	res *Resolved
	g   *gate.Gate
	at  time.Time
	log func(string, ...any)
}

// candidate is a name with what is known before resolving it.
type candidate struct {
	name     string
	from     []string
	notAfter time.Time
	declared bool
}

// run expands every domain root (docs/spec/scope.md, "Discovery").
func (d *discovery) run(ctx context.Context) ([]ScopeDomain, *Resolver, []PointsAt) {
	var roots []Ref
	for _, r := range d.res.Roots {
		if r.Kind == KindDomain {
			roots = append(roots, r)
		}
	}
	if len(roots) == 0 {
		return nil, nil, nil
	}
	resolver := &Resolver{Address: d.g.Resolver()}
	// One control under invalid., which names no one: an answer means the
	// resolver invents addresses for names that do not exist.
	ctl := d.g.Resolve(ctx, gate.Resolve{Asset: roots[0].ID, Name: randomLabel() + ".invalid", Stage: "scope", Control: true})
	resolver.Rewrites = ctl.Lookup.Outcome == gate.OutcomeAddresses
	if ctl.Decision == gate.DecisionSent {
		resolver.Controls, resolver.Invalid = 1, true
	}
	points := map[string][]string{}
	var out []ScopeDomain
	for _, root := range roots {
		out = append(out, d.domain(ctx, root, resolver, points))
	}
	var pa []PointsAt
	for _, t := range slices.Sorted(func(yield func(string) bool) {
		for k := range points {
			if !yield(k) {
				return
			}
		}
	}) {
		pa = append(pa, PointsAt{Target: t, Names: slices.Compact(slices.Sorted(slices.Values(points[t])))})
	}
	return out, resolver, pa
}

func (d *discovery) domain(ctx context.Context, root Ref, resolver *Resolver, points map[string][]string) ScopeDomain {
	rewrites := resolver.Rewrites
	sd := ScopeDomain{Root: root.ID, Names: []ScopeName{}}
	d.log("scope: discovering names under %s", root.name)
	ctl := d.g.Resolve(ctx, gate.Resolve{Asset: root.ID, Name: randomLabel() + "." + root.name, Stage: "scope", Control: true})
	if ctl.Decision == gate.DecisionSent {
		resolver.Controls++
	}
	var wildcard []string
	if ctl.Lookup.Outcome == gate.OutcomeAddresses {
		wildcard = addrStrings(ctl.Lookup.Addrs)
		sd.Wildcard = wildcard
	}

	cands := map[string]*candidate{}
	add := func(name, from string, notAfter time.Time, declared bool) {
		c, ok := cands[name]
		if !ok {
			c = &candidate{name: name}
			cands[name] = c
		}
		if !slices.Contains(c.from, from) {
			c.from = append(c.from, from)
		}
		if notAfter.After(c.notAfter) {
			c.notAfter = notAfter
		}
		c.declared = c.declared || declared
	}
	add(root.name, "root", time.Time{}, true)
	for _, a := range d.res.Assets {
		switch a.Kind {
		case KindDomain, KindURL, KindHost:
			if a.name != "" && !a.Local() && domainUnder(a.name, root.name) {
				add(a.name, "declared", time.Time{}, true)
			}
		}
	}

	res := d.g.Send(ctx, gate.Request{Op: "ct.search", Asset: root.ID, Stage: "scope", Params: map[string]string{"domain": root.name}})
	switch {
	case !res.OK():
		sd.CT = "unavailable:ct_source"
	default:
		sd.CT = "ok"
		if p := res.Response.Population; p != nil {
			sd.Dropped = p.Dropped
		}
		var records []struct {
			Names    []string `json:"name_value"`
			NotAfter string   `json:"not_after"`
		}
		if err := json.Unmarshal(res.Response.Body, &records); err != nil {
			sd.CT = "unavailable:ct_source"
			break
		}
		for _, rec := range records {
			na, _ := time.Parse("2006-01-02T15:04:05", rec.NotAfter)
			for _, n := range rec.Names {
				if base, ok := strings.CutPrefix(n, "*."); ok {
					if domainUnder(base, root.name) && !slices.Contains(sd.WildcardCerts, base) {
						sd.WildcardCerts = append(sd.WildcardCerts, base)
					}
					continue
				}
				if domainUnder(n, root.name) {
					add(n, "certificate_transparency", na, false)
				}
			}
		}
		slices.Sort(sd.WildcardCerts)
	}

	// Declared names first, then names in unexpired certificates by latest
	// not_after, then names seen only in expired ones; by name within each.
	list := make([]*candidate, 0, len(cands))
	for _, c := range cands {
		list = append(list, c)
	}
	group := func(c *candidate) int {
		switch {
		case c.declared:
			return 0
		case !c.notAfter.Before(d.at):
			return 1
		}
		return 2
	}
	slices.SortFunc(list, func(a, b *candidate) int {
		if c := cmp.Compare(group(a), group(b)); c != 0 {
			return c
		}
		if group(a) == 1 {
			if c := b.notAfter.Compare(a.notAfter); c != 0 {
				return c
			}
		}
		return cmp.Compare(a.name, b.name)
	})

	// The caps count names the gate looked up: one an exclude covers is
	// refused before any query, and counts toward neither.
	resolved, unverified := 0, 0
	for _, c := range list {
		sn := ScopeName{Name: c.name, From: c.from, ExpiredOnly: group(c) == 2}
		if resolved >= maxResolved {
			sn.Status, sn.Detail = NameNotChecked, fmt.Sprintf("past the first %d names under this root", maxResolved)
			sd.Names = append(sd.Names, sn)
			continue
		}
		r := d.g.Resolve(ctx, gate.Resolve{Asset: root.ID, Name: c.name, Stage: "scope"})
		switch {
		case r.Decision == "refused:excluded":
			sn.Status, sn.Detail, sn.ExcludedBy = NameExcluded, r.ExcludedBy, r.ExcludedBy
			sd.Names = append(sd.Names, sn)
			continue
		case r.Decision != gate.DecisionSent:
			sn.Status, sn.Detail = NameNotChecked, r.Decision
			sd.Names = append(sd.Names, sn)
			continue
		}
		resolved++
		l := r.Lookup
		sn.Chain, sn.Addresses = l.Chain, addrStrings(l.Addrs)
		d.classify(&sn, l, c.declared, wildcard, rewrites, points)
		if sn.Status == NameResolves {
			sn.FirstParty = d.evidence(c.name, l)
			hasEvidence := sn.FirstParty.counts()
			switch {
			case hasEvidence, c.declared:
				sn.Read = true
			case rewrites:
				sn.Detail = "not read: the resolver answers names that do not exist"
			case unverified >= maxUnverified:
				sn.Detail = fmt.Sprintf("not read: past the first %d names without first-party evidence", maxUnverified)
			default:
				sn.Read = true
				unverified++
			}
		}
		sd.Names = append(sd.Names, sn)
	}
	return sd
}

// evidence is a resolved name's first-party evidence as the gate will
// weigh it once the name is resolved (docs/spec/scope.md, "First-party
// evidence"): the file's, except that a confirmation whose name no longer
// points at its target is "moved", and a name every address of which a
// network root holds has that root's.
func (d *discovery) evidence(name string, l gate.Lookup) *Evidence {
	ev := d.res.firstParty(ResolvedAsset{Kind: KindDomain, ID: "domain:" + name, name: name}, d.at)
	if ev != nil && ev.Kind == "operator" && !l.PointsAt(ev.Target) {
		ev = &Evidence{Kind: "moved", ConfirmedBy: ev.ConfirmedBy, Date: ev.Date, Target: ev.Target}
	}
	if ev.counts() || len(l.Addrs) == 0 || !slices.ContainsFunc(d.res.Roots, func(r Ref) bool { return r.Kind == KindNetwork }) {
		return ev
	}
	held := ""
	for _, a := range l.Addrs {
		root := d.res.networkRoot(a)
		if root == "" {
			return ev
		}
		if held == "" {
			held = root
		}
	}
	return &Evidence{Kind: "network_root", Root: held}
}

// classify settles a resolved name's status (docs/spec/scope.md,
// "Discovery", step 4).
func (d *discovery) classify(sn *ScopeName, l gate.Lookup, declared bool, wildcard []string, rewrites bool, points map[string][]string) {
	// A chain that enters an excluded name stops there: the resolver
	// already followed it, and the gate went no further.
	if l.Outcome == gate.OutcomeExcluded {
		sn.Status, sn.Detail, sn.ExcludedBy = NameExcluded, "points into "+l.ExcludedBy, l.ExcludedBy
		sn.Addresses = nil
		return
	}
	sn.Target = l.Target()
	if l.Outside != "" {
		points[l.Outside] = append(points[l.Outside], sn.Name)
	}
	switch {
	case l.Insufficient():
		sn.Status, sn.Detail = NameInsufficient, string(l.Outcome)
	case (l.Outcome == gate.OutcomeNXDomain || l.Outcome == gate.OutcomeNoData) && len(l.Chain) > 0:
		sn.Status = NameDangling
		if rewrites {
			sn.Status, sn.Detail = NameInsufficient, "the resolver answers names that do not exist"
			break
		}
		where := "takeover candidate: its target is outside every root"
		if l.FinalInRoot {
			where = "stale record: its target is under a root"
		}
		sn.Detail = map[gate.Outcome]string{gate.OutcomeNXDomain: "the target does not exist; ",
			gate.OutcomeNoData: "the target exists but has no address; "}[l.Outcome] + where
	case l.Outcome == gate.OutcomeNXDomain:
		sn.Status = NameGone
	case l.Outcome == gate.OutcomeNoData:
		sn.Status = NameNoAddress
	case !declared && wildcard != nil && slices.Equal(addrStrings(l.Addrs), wildcard):
		sn.Status = NameMatchesWildcard
	default:
		sn.Status = NameResolves
	}
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// randomLabel is a control label: 20 random letters and digits, which no
// zone holds unless it answers everything.
func randomLabel() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, controlLength)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
