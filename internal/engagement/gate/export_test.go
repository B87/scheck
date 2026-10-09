package gate

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// Harness exposes the test world to package gate_test, which drives the
// gate with the engagement's own Scope: engagement imports gate, so only an
// external test package can build one from a file.
type Harness struct{ w *world }

// NewHarness is a test world whose gate reads s instead of the fake scope.
func NewHarness(t *testing.T, s Scope) *Harness {
	w := newWorld(t)
	w.real = s
	return &Harness{w}
}

// Gate builds a gate in front of the world.
func (h *Harness) Gate() *Gate { return h.w.gate() }

// Setenv sets a variable the gate reads.
func (h *Harness) Setenv(k, v string) { h.w.env[k] = v }

// Dials counts the connections the gate opened.
func (h *Harness) Dials() int { return int(h.w.dials.Load()) }

// Site serves name at ip over https on 443 and http on 80, and returns what
// the two servers saw, as "scheme METHOD path".
func (h *Harness) Site(name, ip string) func() []string {
	cert := h.w.leaf([]string{name}, time.Now().Add(time.Hour), false)
	tlsSrv := h.w.serve(name, ip, 443, &cert, ok200("<html>"))
	plain := h.w.serve(name, ip, 80, nil, ok200("<html>"))
	return func() []string {
		var out []string
		for scheme, s := range map[string]*server{"https": tlsSrv, "http": plain} {
			for _, r := range s.requests() {
				out = append(out, scheme+" "+r.Method+" "+r.URL.Path)
			}
		}
		return out
	}
}

// Answer adds an address to name's DNS answer.
func (h *Harness) Answer(name, ip string) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	h.w.dns[name] = append(h.w.dns[name], netip.MustParseAddr(ip))
}

// GitHub serves api.github.com and returns its hit count.
func (h *Harness) GitHub(body string) func() int {
	s := h.w.github(ok200(body))
	return func() int { return int(s.hits.Load()) }
}

// Workspace serves admin.googleapis.com with two pages of users, in /Board,
// /board/Sub, /Boardroom and none, and returns the paths it saw.
func (h *Harness) Workspace() func() []string {
	s := h.w.google(workspaceReply(http.StatusOK))
	return func() []string {
		var out []string
		for _, r := range s.requests() {
			out = append(out, r.URL.Path)
		}
		return out
	}
}

// NewGate builds a gate from cfg with the world's seams: what a run's
// RunOptions.NewGate is set to.
func (h *Harness) NewGate(cfg Config) (*Gate, error) {
	cfg.Net = h.w.net()
	cfg.Getenv = func(k string) string { return h.w.env[k] }
	return New(cfg)
}

// DNS sets what the resolver answers: "cname:<target>", "addrs:<a>,<b>",
// "servfail", "refused" or "nodata", or "hidden:<target>", a CNAME an
// address query does not show when its target does not exist; a name not
// set is NXDOMAIN unless a server registered it.
func (h *Harness) DNS(names map[string]string) {
	z := map[string]record{}
	for n, v := range names {
		kind, val, _ := strings.Cut(v, ":")
		switch kind {
		case "cname":
			z[n] = record{cname: val}
		case "hidden":
			z[n] = record{cname: val, hidden: true}
		case "addrs":
			z[n] = record{addrs: strings.Split(val, ",")}
		case "servfail":
			z[n] = record{rcode: rcodeServFail}
		case "refused":
			z[n] = record{rcode: rcodeRefused}
		case "nodata":
			z[n] = record{}
		}
	}
	h.w.zone = newZone(z)
}

// TXT adds TXT records to a name the resolver answers; call it after DNS.
func (h *Harness) TXT(name string, records ...string) {
	r := h.w.zone.names[name]
	for _, t := range records {
		r.txt = append(r.txt, []string{t})
	}
	h.w.zone.names[name] = r
}

// MX adds a mail exchanger to a name; call it after DNS.
func (h *Harness) MX(name string, pref uint16, target string) {
	r := h.w.zone.names[name]
	r.mx = append(r.mx, mxRecord{pref, target})
	h.w.zone.names[name] = r
}

// NS adds name servers to a name; call it after DNS.
func (h *Harness) NS(name string, targets ...string) {
	r := h.w.zone.names[name]
	r.ns = append(r.ns, targets...)
	h.w.zone.names[name] = r
}

// CompactDenial answers a name that does not exist with NOERROR and no
// record, as a signed zone with compact denial of existence does; call it
// after DNS.
func (h *Harness) CompactDenial() { h.w.zone.compact = true }

// Queries lists the names the resolver was asked, with their trailing dot.
func (h *Harness) Queries() []string {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	return slices.Clone(h.w.queries)
}

// CrtSh serves crt.sh with body and returns the queries it saw.
func (h *Harness) CrtSh(body string) func() []string {
	cert := h.w.leaf([]string{"crt.sh"}, time.Now().Add(time.Hour), false)
	s := h.w.serve("crt.sh", "91.199.212.73", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(body))
	})
	return func() []string {
		var out []string
		for _, r := range s.requests() {
			out = append(out, r.URL.RawQuery)
		}
		return out
	}
}

// FingerprintSite serves a provider error from an in-scope name (or a
// wildcard certificate's concrete control host), counting every request.
func (h *Harness) FingerprintSite(name, ip string, status int, body string, configured ...string) func() []string {
	cert := h.w.leaf([]string{name}, time.Now().Add(time.Hour), false)
	reply := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if slices.Contains(configured, r.Host) {
			_, _ = w.Write([]byte("A configured site"))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	a := h.w.serve(name, ip, 443, &cert, reply)
	b := h.w.serve(name, ip, 80, nil, reply)
	return func() []string {
		var out []string
		for _, s := range []*server{a, b} {
			for _, r := range s.requests() {
				out = append(out, r.Host+r.URL.Path)
			}
		}
		return out
	}
}

// ResponseSite serves a fake site with a caller's offline handler on both ports.
func (h *Harness) ResponseSite(name, ip string, handler http.HandlerFunc) func() []string {
	cert := h.w.leaf([]string{name}, time.Now().Add(45*24*time.Hour), false)
	https := h.w.serve(name, ip, 443, &cert, handler)
	httpSrv := h.w.serve(name, ip, 80, nil, handler)
	return func() []string {
		var out []string
		for scheme, s := range map[string]*server{"https": https, "http": httpSrv} {
			for _, r := range s.requests() {
				out = append(out, scheme+" "+r.URL.Path)
			}
		}
		slices.Sort(out)
		return out
	}
}
