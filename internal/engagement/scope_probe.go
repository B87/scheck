package engagement

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

// AdmitsProbe is the gate's steps 7 and 8 for a probe (docs/spec/scope.md,
// "Probes"): the origin has first-party evidence, from the file or, once the
// name is resolved, from the lookup. The front page of a name under a
// domain root is not evidence: only a url or host root, a network root
// holding every address, or a current confirmation that the name still
// points at. A url root that holds a path prefix holds nothing at the
// origin's own paths, where every probe sits.
func (s *scope) AdmitsProbe(origin, path string, l *gate.Lookup) gate.Admission {
	refused := gate.Admission{Refused: "first_party"}
	if !strings.HasPrefix(path, "/") {
		return refused
	}
	sp := s.site(origin)
	ev := sp.ev
	switch {
	case ev != nil && ev.Kind != "operator":
		if ev.Kind == "url_root" {
			i := slices.IndexFunc(s.res.Roots, func(r Ref) bool { return r.ID == ev.Root })
			if i < 0 || s.res.Roots[i].path != "/" {
				return refused
			}
		}
		return gate.Admission{FirstParty: true}
	case ev == nil && len(sp.network) == 0:
		return refused
	case l == nil:
		return gate.Admission{Resolve: true}
	}
	if !s.res.resolvedEvidence(ev, *l).counts() {
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

// probeMode is the probe mode of the site at origin: its own assets entry
// when it has one, else defaults.probe. Only the exact name or the exact
// origin of an entry is its site.
func (s *scope) probeMode(origin string) string {
	if a, ok := s.siteAsset(origin); ok && a.Probe != "" {
		return a.Probe
	}
	return s.res.Defaults.Probe
}

// frameworkOf is the frameworks declared for the site at origin.
func (s *scope) frameworkOf(origin string) []string {
	if a, ok := s.siteAsset(origin); ok && len(a.Framework) > 0 {
		return a.Framework
	}
	return s.res.Defaults.Framework
}

// siteAsset is the declared domain or url asset that is the site at origin.
func (s *scope) siteAsset(origin string) (ResolvedAsset, bool) {
	o, err := parseURL(origin + "/")
	if err != nil {
		return ResolvedAsset{}, false
	}
	for _, a := range s.res.Assets {
		switch {
		case a.Kind == KindURL && sameOrigin(a.Ref, o) && a.path == "/":
			return a, true
		case a.Kind == KindDomain && o.Port == 0 && a.name == o.name:
			return a, true
		}
	}
	return ResolvedAsset{}, false
}

// ProbeEvidence is the evidence a probe of the site named host would rest
// on, as the file gives it, and whether the gate must still resolve the name
// to find it: a network root holding every address. nil, false when there
// is none. The gate decides every request again at send time.
func (s *scope) ProbeEvidence(host string) (*Evidence, bool) {
	sp := s.site("https://" + host)
	if sp.ev == nil {
		sp = s.site("http://" + host)
	}
	switch {
	case sp.ev != nil && sp.ev.Kind != "operator":
		return sp.ev, false
	case sp.ev != nil:
		return sp.ev, true
	case len(sp.network) > 0:
		return nil, true
	}
	return nil, false
}
