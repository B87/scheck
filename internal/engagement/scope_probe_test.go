package engagement

import (
	"fmt"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
)

// probeScope parses a file whose roots, defaults and assets are given, with
// an authorization window around now, and returns the scope the gate reads.
func probeScope(t *testing.T, body string) *scope {
	t.Helper()
	now := time.Now()
	file := fmt.Sprintf(`schema: 1
engagement: {name: probe-scope, timezone: Europe/Madrid, trigger: routine}
people: {alice: {kind: employee}}
authorization:
  by: CTO
  date: 2026-10-06
  windows:
    - {from: %s, to: %s}
%s`, now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), body)
	res, err := Parse("e.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	return res.GateScope(now).(*scope)
}

const confirmed = "first_party: {confirmed_by: alice, date: '2026-10-07', target: '198.51.100.12'}"

// An explicit mode on a site beats the inherited default whatever the order
// of the entries, and where entries disagree the one that allows least wins.
func TestProbeModeExplicitOffBeatsTheDefault(t *testing.T) {
	for name, assets := range map[string]string{
		"a domain entry off":           "  zzz: {domain: shop.example.com, probe: off}\n",
		"a url entry first, no mode":   "  aaa: {url: 'https://shop.example.com/'}\n  zzz: {domain: shop.example.com, probe: off}\n",
		"a url entry off, other http":  "  aaa: {url: 'http://shop.example.com/', probe: off}\n",
		"a domain entry beside one on": "  aaa: {domain: shop.example.com, probe: all}\n  zzz: {url: 'https://shop.example.com/', probe: off}\n",
	} {
		s := probeScope(t, "roots: [{domain: example.com}, {url: 'https://shop.example.com/'}]\ndefaults: {probe: all}\nassets:\n"+assets)
		if why := s.Allows("", gate.Probe, "https://shop.example.com", "/.env"); why == "" {
			t.Errorf("%s: a probe was allowed", name)
		}
	}
	s := probeScope(t, "roots: [{domain: example.com}, {url: 'https://shop.example.com/'}]\ndefaults: {probe: all}\nassets:\n  other: {domain: www.example.com, probe: off}\n")
	if why := s.Allows("", gate.Probe, "https://shop.example.com", "/.env"); why != "" {
		t.Errorf("the default did not apply to a site no entry names: %s", why)
	}
	if why := s.Allows("", gate.Probe, "https://www.example.com", "/.env"); why == "" {
		t.Error("an entry's own off did not hold")
	}
}

// Evidence must cover the origin's own paths: a confirmation or a root that
// holds a path prefix does not, a domain root's front page does not, a
// confirmation of the site or a url root at / does.
func TestProbeEvidenceMustCoverTheOrigin(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		origin string
		want   gate.Admission
	}{
		"a url root at /":              {"roots: [{url: 'https://shop.example.com/'}]\n", "https://shop.example.com", gate.Admission{FirstParty: true}},
		"a url root with a prefix":     {"roots: [{url: 'https://shop.example.com/app/'}]\n", "https://shop.example.com", gate.Admission{Refused: "first_party"}},
		"a domain root alone":          {"roots: [{domain: example.com}]\n", "https://shop.example.com", gate.Admission{Refused: "first_party"}},
		"a confirmed url with prefix":  {"roots: [{domain: example.com}]\nassets:\n  app: {url: 'https://shop.example.com/app/', " + confirmed + "}\n", "https://shop.example.com", gate.Admission{Refused: "first_party"}},
		"a confirmed url at /":         {"roots: [{domain: example.com}]\nassets:\n  app: {url: 'https://shop.example.com/', " + confirmed + "}\n", "https://shop.example.com", gate.Admission{Resolve: true}},
		"a confirmed domain":           {"roots: [{domain: example.com}]\nassets:\n  shop: {domain: shop.example.com, " + confirmed + "}\n", "https://shop.example.com", gate.Admission{Resolve: true}},
		"a confirmation of another":    {"roots: [{domain: example.com}]\nassets:\n  shop: {domain: www.example.com, " + confirmed + "}\n", "https://shop.example.com", gate.Admission{Refused: "first_party"}},
		"a network root, to be looked": {"roots: [{domain: example.com}, {network: 198.51.100.0/24}]\n", "https://shop.example.com", gate.Admission{Resolve: true}},
	} {
		s := probeScope(t, tc.body+"defaults: {probe: all}\n")
		if got := s.AdmitsProbe(tc.origin, "/.env", nil); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

// Plan previews only what the gate would admit.
func TestProbeStandingIsPlansToo(t *testing.T) {
	s := probeScope(t, "roots: [{domain: example.com}]\nassets:\n  app: {url: 'https://shop.example.com/app/', "+confirmed+"}\ndefaults: {probe: all}\n")
	if _, _, ok := s.ProbeEvidence("shop.example.com"); ok {
		t.Error("a confirmation of /app/ was previewed as evidence for the whole site")
	}
}
