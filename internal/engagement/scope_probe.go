package engagement

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

// probeStanding is the first-party evidence a probe of the origin rests on,
// as the file gives it (docs/spec/scope.md, "Probes"). ok is false when
// there is none that covers the origin's own paths, where every probe sits:
// the front page of a name under a domain root is not evidence, a url root
// or a confirmed url that holds a path prefix holds nothing outside it, and
// a confirmation that is expired or suspended counts for nothing. resolve
// says the gate must still resolve the name to find evidence in the lookup:
// a confirmation's target, or a network root holding every address. The one
// predicate behind both the gate's decision and Plan's preview.
func (s *scope) probeStanding(origin string) (ev *Evidence, resolve, ok bool) {
	sp := s.site(origin)
	switch ev = sp.ev; {
	case ev != nil && ev.Kind == "url_root":
		i := slices.IndexFunc(s.res.Roots, func(r Ref) bool { return r.ID == ev.Root })
		return ev, false, i >= 0 && s.res.Roots[i].path == "/"
	case ev != nil && ev.Kind == "operator":
		return ev, true, s.confirmedWholeOrigin(origin)
	case ev != nil:
		return ev, false, true
	}
	return nil, true, len(sp.network) > 0
}

// confirmedWholeOrigin says a current confirmation vouches for the origin
// itself: a domain or host asset's, or a url asset's whose path is /. A url
// asset confirmed at /app/ vouches for /app/ and nothing else on a host
// that may be shared.
func (s *scope) confirmedWholeOrigin(origin string) bool {
	o, err := parseURL(origin + "/")
	if err != nil {
		return false
	}
	for _, a := range s.res.Assets {
		if a.FirstParty == nil || !s.res.current(a.FirstParty, s.at) {
			continue
		}
		switch {
		case a.Kind == KindURL && sameOrigin(a.Ref, o) && a.path == "/":
			return true
		case (a.Kind == KindDomain || a.Kind == KindHost) && o.Port == 0 && a.Address() == o.Address():
			return true
		}
	}
	return false
}

// AdmitsProbe is the gate's steps 7 and 8 for a probe: probeStanding from
// the file, or once the name is resolved, from the lookup.
func (s *scope) AdmitsProbe(origin, path string, l *gate.Lookup) gate.Admission {
	refused := gate.Admission{Refused: "first_party"}
	if !strings.HasPrefix(path, "/") {
		return refused
	}
	ev, resolve, ok := s.probeStanding(origin)
	switch {
	case !ok:
		return refused
	case !resolve:
		return gate.Admission{FirstParty: true}
	case l == nil:
		return gate.Admission{Resolve: true}
	case !s.res.resolvedEvidence(ev, *l).counts():
		if ev != nil {
			return gate.Admission{Refused: "address_moved"}
		}
		return refused
	}
	return gate.Admission{FirstParty: true}
}

// Allows is step 6 for a probe: the site's mode must be all, or confirm with
// the operator's approval of this request in this session
// (docs/spec/scope.md, "Running probes and scans"). Passive and observe are
// not asked.
func (s *scope) Allows(_ string, l gate.Level, origin, path string) string {
	if l < gate.Probe {
		return ""
	}
	host := originHost(origin)
	switch mode := s.probeMode(origin); mode {
	case "all":
		return ""
	case "confirm":
		if _, ok := s.approved.Load(origin + path); ok {
			return ""
		}
		return "the operator did not approve this probe of " + host + " from the preview"
	}
	return "probe mode is off for " + host
}

// Approve records the operator's approval of one previewed request. Only a
// live answer calls it; nothing read from a file does.
func (s *scope) Approve(origin, path string) { s.approved.Store(origin+path, true) }

// originHost is the host of scheme://host[:port].
func originHost(origin string) string {
	_, host, _ := strings.Cut(origin, "://")
	return host
}

// modeRank orders the probe modes by how much they allow.
var modeRank = map[string]int{"off": 0, "confirm": 1, "all": 2}

// probeMode is the probe mode of the site named by origin. A mode is per
// name, both schemes alike. The assets entries that name the site (a
// domain of that name, or a url on it) and set a mode of their own decide,
// and where they disagree the one that allows least wins; a site no entry
// sets a mode for takes defaults.probe. An inherited default never beats
// an explicit entry.
func (s *scope) probeMode(origin string) string {
	mode := ""
	for _, a := range s.siteAssets(origin) {
		if a.ProbeSet == "" {
			continue
		}
		if mode == "" || modeRank[a.ProbeSet] < modeRank[mode] {
			mode = a.ProbeSet
		}
	}
	if mode == "" {
		return s.res.Defaults.Probe
	}
	return mode
}

// frameworkOf is the frameworks declared for the site at origin: the first
// entry that names the site and declares any, else the default.
func (s *scope) frameworkOf(origin string) []string {
	for _, a := range s.siteAssets(origin) {
		if len(a.Framework) > 0 {
			return a.Framework
		}
	}
	return s.res.Defaults.Framework
}

// siteAssets are the declared domain and url assets that name the site at
// origin, by its host.
func (s *scope) siteAssets(origin string) []ResolvedAsset {
	o, err := parseURL(origin + "/")
	if err != nil {
		return nil
	}
	var out []ResolvedAsset
	for _, a := range s.res.Assets {
		switch {
		case a.Kind == KindURL && a.Address() == o.Address() && a.Port == o.Port:
			out = append(out, a)
		case a.Kind == KindDomain && o.Port == 0 && a.name == o.name:
			out = append(out, a)
		}
	}
	return out
}

// ProbeEvidence is the evidence a probe of the site named host would rest
// on, as the file gives it, and whether the gate must still resolve the name
// to find it. ok is false when there is none. The gate decides every
// request again at send time.
func (s *scope) ProbeEvidence(host string) (ev *Evidence, resolve, ok bool) {
	ev, resolve, ok = s.probeStanding("https://" + host)
	if !ok {
		ev, resolve, ok = s.probeStanding("http://" + host)
	}
	return ev, resolve, ok
}
