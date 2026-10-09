package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/b87/scheck/internal/policy"
)

// world is a gate in front of fake servers: a resolver that answers from a
// table, a dialer that maps public test addresses onto local listeners, a
// CA the gate trusts, and an audit log in memory.
type world struct {
	t *testing.T
	// tlsConfig, when set, changes the next servers' TLS settings.
	tlsConfig func(*tls.Config)
	// systemRoots leaves the gate's roots to New, as in production.
	systemRoots bool
	// http2 makes the next TLS servers offer HTTP/2.
	http2   bool
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	pool    *x509.CertPool
	dns     map[string][]netip.Addr
	queries []string
	routes  map[string]string // public ip:port → local listener
	dials   atomic.Int32
	sleeps  []time.Duration
	// block, when set, runs inside every sleep: a test that needs a
	// request to wait for real holds it there.
	block    func(context.Context, time.Duration) error
	env      map[string]string
	scope    *fakeScope
	real     Scope // the engagement's own, when a gate_test test sets one
	zone     zone  // what the gate's DNS client is answered (dns_test.go)
	audit    *lockedBuffer
	deadline time.Time
	windows  []Window
	prior    map[string]*Response
	ops      []Op
	extra    []string // redact_extra
	mu       sync.Mutex
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// entries parses the audit log.
func (l *lockedBuffer) entries(t *testing.T) []Entry {
	t.Helper()
	var out []Entry
	for line := range strings.SplitSeq(strings.TrimSpace(l.String()), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func newWorld(t *testing.T) *world {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scheck test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &world{
		t: t, ca: ca, caKey: key, pool: pool,
		dns: map[string][]netip.Addr{}, routes: map[string]string{}, env: map[string]string{},
		zone:  newZone(nil),
		scope: &fakeScope{roots: []string{"saas:github:example-org", "domain:example.com", "saas:google-workspace:example.com"}},
		audit: &lockedBuffer{},
		ops:   testOps,
		extra: []string{`internal\.example\.net`},
	}
}

// leaf issues a certificate for names, signed by the world's CA unless
// selfSigned.
func (w *world) leaf(names []string, notAfter time.Time, selfSigned bool) tls.Certificate {
	w.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := w.ca, any(w.caKey)
	if selfSigned {
		parent, signer = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		w.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// server is a fake server reachable at a public test address.
type server struct {
	*httptest.Server
	hits  atomic.Int32
	seen  []*http.Request
	mu    sync.Mutex
	reply http.HandlerFunc
}

func (s *server) requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.seen...)
}

// serve starts a server for name at ip:port, https with a certificate for
// cert (nil for plain http).
func (w *world) serve(name, ip string, port int, cert *tls.Certificate, reply http.HandlerFunc) *server {
	w.t.Helper()
	s := &server{reply: reply}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		s.seen = append(s.seen, r)
		s.mu.Unlock()
		s.reply(rw, r)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	if cert != nil {
		s.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
		if w.tlsConfig != nil {
			w.tlsConfig(s.TLS)
		}
		s.EnableHTTP2 = w.http2
		s.StartTLS()
	} else {
		s.Start()
	}
	w.t.Cleanup(s.Close)
	a := netip.MustParseAddr(ip)
	w.mu.Lock()
	if name != "" && !contains(w.dns[name], a) {
		w.dns[name] = append(w.dns[name], a)
	}
	w.routes[netip.AddrPortFrom(a, uint16(port)).String()] = s.Listener.Addr().String()
	w.mu.Unlock()
	return s
}

func contains(as []netip.Addr, a netip.Addr) bool {
	return slices.Contains(as, a)
}

// github serves api.github.com at a public test address.
func (w *world) github(reply http.HandlerFunc) *server {
	cert := w.leaf([]string{"api.github.com"}, time.Now().Add(time.Hour), false)
	return w.serve("api.github.com", "140.82.112.5", 443, &cert, reply)
}

// google serves admin.googleapis.com at a public test address.
func (w *world) google(reply http.HandlerFunc) *server {
	cert := w.leaf([]string{"admin.googleapis.com"}, time.Now().Add(time.Hour), false)
	return w.serve("admin.googleapis.com", "142.250.0.10", 443, &cert, reply)
}

// exchange answers the gate's DNS client from the zone a test set, then
// from the names its servers registered; anything else is NXDOMAIN. It
// records each name asked, with the trailing dot it is asked as.
func (w *world) exchange(ctx context.Context, server string, q []byte, tcp bool) ([]byte, error) {
	name, _, err := readName(q, 12)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.queries = append(w.queries, name+".")
	names := maps.Clone(w.zone.names)
	if names == nil {
		names = map[string]record{}
	}
	for n, as := range w.dns {
		if _, ok := names[n]; !ok {
			r := record{}
			for _, a := range as {
				r.addrs = append(r.addrs, a.String())
			}
			names[n] = r
		}
	}
	w.mu.Unlock()
	return zone{mu: w.zone.mu, names: names, queries: w.zone.queries, compact: w.zone.compact}.exchange(ctx, server, q, tcp)
}

func (w *world) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	w.dials.Add(1)
	w.mu.Lock()
	local, ok := w.routes[addr]
	w.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.AddrError{Err: "connection refused", Addr: addr}}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, local)
}

func (w *world) gate() *Gate {
	w.t.Helper()
	reg, err := NewRegistry(w.ops...)
	if err != nil {
		w.t.Fatal(err)
	}
	var scope Scope = w.scope
	if w.real != nil {
		scope = w.real
	}
	g, err := New(Config{
		Registry: reg, Scope: scope, RedactExtra: w.extra,
		Audit: policy.NewAudit(w.audit), Deadline: w.deadline, Windows: w.windows, Prior: w.prior, Version: "test",
		Getenv: func(k string) string { return w.env[k] },
		Net:    w.net(),
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

// net is the world's seams: its dialer, CA, resolver and sleep.
func (w *world) net() *Net {
	pool := w.pool
	if w.systemRoots {
		pool = nil
	}
	return &Net{Dial: w.dial, RootCAs: pool, Nameserver: netip.MustParseAddr("192.0.2.53"), Exchange: w.exchange,
		Sleep: func(ctx context.Context, d time.Duration) error {
			w.mu.Lock()
			w.sleeps = append(w.sleeps, d)
			w.mu.Unlock()
			if w.block != nil {
				return w.block(ctx, d)
			}
			return ctx.Err()
		}}
}

// fakeScope places ids by prefix: a GitHub organization holds its
// repositories, a domain its subdomains and their URLs.
type fakeScope struct {
	roots        []string
	excluded     map[string]string // id → exclude entry
	excludedNets map[string]netip.Prefix
	networks     []netip.Prefix
	sites        map[string]SitePaths
	throttles    map[string]throttle // asset → its own throttle; none when absent, as the engagement's Scope
	orgUnits     map[string][]OrgUnit
}

func under(id, root string) bool {
	if id == root {
		return true
	}
	kind, val, _ := strings.Cut(root, ":")
	switch kind {
	case "saas":
		return strings.HasPrefix(id, "repo:"+val+"/") || strings.HasPrefix(id, root+"/")
	case "domain":
		var host string
		if rest, ok := strings.CutPrefix(id, "url:"); ok {
			_, after, _ := strings.Cut(rest, "://")
			host, _, _ = strings.Cut(after, "/")
		} else if rest, ok := strings.CutPrefix(id, "domain:"); ok {
			host = rest
		} else {
			return false
		}
		return host == val || strings.HasSuffix(host, "."+val)
	}
	return false
}

func (s *fakeScope) Subject(asset, id string) Standing {
	st := Standing{UnderAsset: under(id, asset)}
	for _, r := range s.roots {
		if under(id, r) {
			st.Root = r
		}
	}
	for x, entry := range s.excluded {
		if under(id, x) {
			st.ExcludedBy = entry
		}
	}
	return st
}

func (s *fakeScope) Name(n string) string {
	return s.Subject("", "domain:"+n).ExcludedBy
}

// Address reads a in its forms, as the engagement's Scope does.
func (s *fakeScope) Address(a netip.Addr) (string, bool) {
	f := Forms(a)
	excludedBy := ""
	for entry, p := range s.excludedNets {
		if slices.ContainsFunc(f, p.Contains) {
			excludedBy = entry
		}
	}
	in := false
	for _, p := range s.networks {
		in = in || slices.ContainsFunc(f, p.Contains)
	}
	return excludedBy, in
}

// SitePaths are the paths a fake origin may be read at, by the evidence
// each needs, as the engagement's Scope lists them before it decides.
type SitePaths struct {
	Paths      []string
	FirstParty bool
	Network    []string
	Confirmed  []string
	Target     string
}

// Admits decides as the engagement's Scope does: Paths need nothing more,
// Network every address in a network root, Confirmed the name pointing at
// Target; either of the last two suffices.
func (s *fakeScope) Admits(origin, path string, l *Lookup) Admission {
	site, ok := s.sites[origin]
	if !ok {
		site = SitePaths{Paths: []string{"/"}}
	}
	network, confirmed := slices.Contains(site.Network, path), slices.Contains(site.Confirmed, path)
	switch {
	case slices.Contains(site.Paths, path):
		return Admission{FirstParty: site.FirstParty}
	case !network && !confirmed:
		return Admission{Refused: "entry_point"}
	case l == nil:
		return Admission{Resolve: true}
	}
	all := len(l.Addrs) > 0
	for _, a := range l.Addrs {
		_, in := s.Address(a)
		all = all && in
	}
	if network && all || confirmed && l.PointsAt(site.Target) {
		return Admission{FirstParty: true}
	}
	return Admission{Refused: "address_moved"}
}

// throttle is an asset's own rate and concurrency.
type throttle struct {
	rate float64
	conc int
}

func (s *fakeScope) Throttle(asset string) (float64, int) {
	t := s.throttles[asset]
	return t.rate, t.conc
}

func (s *fakeScope) OrgUnits(asset string) []OrgUnit { return s.orgUnits[asset] }

var testOps = []Op{
	{ID: "github.repo", Provider: "github", Method: GET, URL: "https://api.github.com/repos/{owner}/{repo}",
		Subject: "repo:github:{owner}/{repo}", Params: []Param{{Name: "owner", Type: Login}, {Name: "repo", Type: RepoName}},
		Level: Observe, Auth: GitHubToken, Accept: []string{"application/vnd.github+json"}, Keep: []string{"name"}, MaxBytes: 1 << 16},
	{ID: "github.user", Provider: "github", Method: GET, URL: "https://api.github.com/user", Class: Principal,
		Level: Observe, Auth: GitHubToken, Accept: []string{"application/vnd.github+json"}, Keep: []string{"id", "login", "type"}, MaxBytes: 1 << 16},
	{ID: "github.org_repos", Provider: "github", Method: GET, URL: "https://api.github.com/orgs/{org}/repos?per_page={per_page}&page={page}",
		Subject: "saas:github:{org}", Params: []Param{{Name: "org", Type: Login}, {Name: "per_page", Type: Count}, {Name: "page", Type: Count, Optional: true}},
		Level: Observe, Auth: GitHubToken, Accept: []string{"application/vnd.github+json"}, Keep: []string{"name"}, MaxBytes: 64,
		List: &List{Items: "$", Kind: KindRepo, Subject: "repo:github:{key}", ExcludeKey: "full_name", Next: &Pages{Param: "page"}, MaxPages: 3}},
	{ID: "web.get", Provider: "web", Method: GET, URL: "{scheme}://{host}{path}",
		Params: []Param{{Name: "scheme", Type: Scheme}, {Name: "host", Type: Host}, {Name: "path", Type: URLPath}},
		Level:  Observe, Accept: []string{"text/html", "*/*"}, MaxBytes: 256},
	{ID: "web.cert", Provider: "web", Method: TLS, URL: "https://{host}/",
		Params: []Param{{Name: "host", Type: Host}}, Level: Observe},
	{ID: "web.probe", Provider: "web", Method: GET, URL: "https://{host}/.git/HEAD",
		Params: []Param{{Name: "host", Type: Host}}, Level: Probe, Accept: []string{"*/*"}, MaxBytes: 256},
	{ID: "github.org", Provider: "github", Method: GET, URL: "https://api.github.com/orgs/{org}",
		Subject: "saas:github:{org}", Params: []Param{{Name: "org", Type: Login}},
		Level: Observe, Auth: GitHubToken, Accept: []string{"application/vnd.github+json"}, Keep: []string{"login", "access_token", "plan.name"}, MaxBytes: 1 << 12},
	{ID: "ws.users", Provider: "google", Method: GET,
		URL:     "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&pageToken={page_token}",
		Subject: "saas:google-workspace:example.com", Params: []Param{{Name: "page_token", Type: Cursor, Optional: true}},
		Level: Observe, Accept: []string{"application/json"}, Keep: []string{"primaryEmail", "isAdmin"}, MaxBytes: 1 << 14,
		List: &List{Items: "users", Kind: KindUser, ExcludeKey: "orgUnitPath", UserKeys: []string{"emails.address"}, UserIDs: []string{"id", "primaryEmail", "aliases"},
			Next: &Pages{Param: "page_token", Field: "nextPageToken"}, MaxPages: 3}},
	{ID: "ws.user_tokens", Provider: "google", Method: GET, URL: "https://admin.googleapis.com/admin/directory/v1/users/{user}/tokens",
		Subject: "saas:google-workspace:example.com/users/{user}", Params: []Param{{Name: "user", Type: UserKey}},
		Level: Observe, Accept: []string{"application/json"}, Keep: []string{"items.clientId"}, MaxBytes: 1 << 14},
	{ID: "ws.role_assignments", Provider: "google", Method: GET,
		URL:     "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments",
		Subject: "saas:google-workspace:example.com",
		Level:   Observe, Accept: []string{"application/json"}, Keep: []string{"roleId", "assignedTo"}, MaxBytes: 1 << 14,
		List: &List{Items: "items", Kind: KindOther, UserRef: "assignedTo"}},
}

func repo(owner, name string) Request {
	return Request{Op: "github.repo", Asset: "saas:github:example-org", Params: map[string]string{"owner": owner, "repo": name}}
}

func web(scheme, host, path string) Request {
	return Request{Op: "web.get", Asset: "domain:example.com", Params: map[string]string{"scheme": scheme, "host": host, "path": path}}
}

func ok200(body string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(body))
	}
}

// testToken is long enough to be taken for a GitHub token.
const testToken = "test-token-0123456789abcdef"
