package gate

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The registry's invariants name the rule an op breaks
// (docs/spec/scope.md, "Operations").
func TestRegistryInvariants(t *testing.T) {
	if _, err := NewRegistry(testOps...); err != nil {
		t.Fatalf("the test ops: %v", err)
	}
	good := testOps[0]
	for _, tc := range []struct {
		name string
		edit func(*Op)
		want string
	}{
		{"no id", func(o *Op) { o.ID = "" }, "no id"},
		{"unknown provider", func(o *Op) { o.Provider = "pastebin" }, "provider table"},
		{"no level", func(o *Op) { o.Level = 0 }, "no level"},
		{"a POST that is not a token exchange", func(o *Op) { o.Method = POST }, "POST is allowed only"},
		{"a token exchange elsewhere", func(o *Op) {
			o.Method, o.Class, o.Subject, o.Params, o.URL = POST, CredentialExchange, "", nil, "https://api.github.com/token"
		}, "declared token endpoint"},
		{"PUT", func(o *Op) { o.Method = "PUT" }, "not GET"},
		{"a host that is not the provider's", func(o *Op) { o.URL = "https://evil.example/repos/{owner}/{repo}" }, "not a literal host"},
		{"a host placeholder on an API op", func(o *Op) { o.URL = "https://{owner}/x/{repo}" }, "not a literal host"},
		{"http to an API", func(o *Op) { o.URL = "http://api.github.com/repos/{owner}/{repo}" }, "https"},
		{"an undeclared placeholder", func(o *Op) { o.URL = "https://api.github.com/repos/{owner}/{repo}/{branch}" }, "{branch}"},
		{"an unused parameter", func(o *Op) { o.Params = append(o.Params, Param{Name: "extra", Type: Cursor}) }, "not used"},
		{"an untyped parameter", func(o *Op) { o.Params = []Param{{Name: "owner"}, {Name: "repo", Type: RepoName}} }, "no type"},
		{"no subject", func(o *Op) { o.Subject = "" }, "no subject"},
		{"no content type", func(o *Op) { o.Accept = nil }, "content type"},
		{"no cap", func(o *Op) { o.MaxBytes = 0 }, "size cap"},
		{"no kept fields", func(o *Op) { o.Keep = nil }, "fields it keeps"},
		{"a repository list without an exclusion key", func(o *Op) { o.List = &List{Items: "$", Kind: KindRepo} }, "exclusion key"},
		{"a user list without an exclusion key", func(o *Op) { o.List = &List{Items: "users", Kind: KindUser} }, "exclusion key"},
		{"a credential on a web op", func(o *Op) { *o = testOps[3]; o.Auth = GitHubToken }, "never carries a credential"},
		{"a web op with a fixed host", func(o *Op) { *o = testOps[3]; o.URL = "https://example.com/x" }, "{host}"},
		{"an optional path parameter", func(o *Op) { o.Params[1].Optional = true }, "optional"},
		{"a principal op with parameters", func(o *Op) { o.Class, o.Subject = Principal, "" }, "takes no parameters"},
		{"a principal op on the web", func(o *Op) { *o = testOps[4]; o.Class = Principal }, "takes no parameters"},
		{"a literal subject over a varying target", func(o *Op) { o.Subject = "saas:github:example-org" }, "{owner} picks the target"},
		{"a subject naming another parameter", func(o *Op) { o.Subject = "repo:github:example-org/{repo}" }, "{owner} picks the target"},
		{"a web op that declares its subject", func(o *Op) { *o = testOps[3]; o.Subject = "url:https://example.com/" }, "declares none"},
		{"a web op with a query", func(o *Op) { *o = testOps[4]; o.URL = "https://{host}/?q=1" }, "no query"},
		{"a target in the query", func(o *Op) {
			o.URL, o.Subject = "https://api.github.com/search/repositories?q={owner}&page={repo}", "saas:github:example-org"
			o.Params = []Param{{Name: "owner", Type: Login}, {Name: "repo", Type: Count}}
		}, "{owner} in the query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := good
			op.Params = append([]Param(nil), good.Params...)
			tc.edit(&op)
			_, err := NewRegistry(op)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := NewRegistry(good, good); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a duplicate op: %v", err)
	}
}

// An unregistered op is refused before anything is resolved or dialled,
// audited, and reported as a defect (E4 test 1).
func TestUnknownOpIsRefused(t *testing.T) {
	w := newWorld(t)
	res := w.gate().Send(context.Background(), Request{Op: "github.delete_repo", Asset: "saas:github:example-org"})
	if res.Decision != "refused:unknown_op" || res.Reason != "unavailable:refused_by_gate" {
		t.Fatalf("%+v", res)
	}
	if w.dials.Load() != 0 || len(w.queries) != 0 {
		t.Error("an unknown op reached the network")
	}
	if es := w.audit.entries(t); len(es) != 1 || es[0].Decision != "refused:unknown_op" || es[0].Event != "refused" {
		t.Errorf("audit %+v", es)
	}
}

// Another organization's repository is out of scope, and an excluded
// repository is refused by its exclude entry; the server sees neither
// (E4 tests 2 and 3).
func TestScopeAndExclusion(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	gh := w.github(ok200(`{"name":"x"}`))
	w.scope.excluded = map[string]string{"repo:github:example-org/client-nda": "exclude[1]"}
	g := w.gate()

	if res := g.Send(context.Background(), repo("other-org", "x")); res.Decision != "refused:out_of_scope" || res.Reason != "unavailable:refused_by_gate" {
		t.Errorf("another organization: %+v", res)
	}
	res := g.Send(context.Background(), repo("Example-Org", "Client-NDA"))
	if res.Decision != "refused:excluded" || res.Reason != "excluded_by_operator" || res.Detail != "exclude[1]" {
		t.Errorf("excluded, compared case-folded: %+v", res)
	}
	if gh.hits.Load() != 0 || w.dials.Load() != 0 {
		t.Errorf("the server saw %d requests", gh.hits.Load())
	}
	if res := g.Send(context.Background(), repo("example-org", "shop")); !res.OK() || res.Response.Status != 200 {
		t.Errorf("an in-scope repository: %+v", res)
	}
}

// Parameters bind to their types; nothing else reaches a URL.
func TestUntypedValuesAreRefused(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	g := w.gate()
	for _, r := range []Request{
		repo("../admin", "x"),
		repo("example-org", "x/../../y"),
		repo("example-org", ".."),
		web("https", "www.example.com", "/a/../b"),
		web("https", "www.example.com", "/x?debug=1"),
		web("https", "www.example.com", "//x"),
		web("ftp", "www.example.com", "/"),
		web("https", "www.example.com/x", "/"),
		{Op: "github.repo", Asset: "saas:github:example-org", Params: map[string]string{"owner": "example-org"}},
		{Op: "github.repo", Asset: "saas:github:example-org", Params: map[string]string{"owner": "example-org", "repo": "x", "ref": "main"}},
	} {
		if res := g.Send(context.Background(), r); res.Decision != "refused:bind" {
			t.Errorf("%v: %+v", r.Params, res)
		}
	}
	if w.dials.Load() != 0 {
		t.Error("a request with a bad parameter was dialled")
	}
}

// Every address in the answer is checked at send time, not only the one
// dialled: one excluded address refuses the name, and loopback, link-local
// and metadata addresses are never contacted, whatever the roots (E4 tests
// 6 and 7).
func TestEveryAddressIsChecked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		want    string
	}{
		{"re-pointed into an excluded range", []string{"203.0.113.9"}, "refused:address_excluded"},
		{"one public, one excluded", []string{"198.51.100.20", "203.0.113.9"}, "refused:address_excluded"},
		{"an excluded address inside NAT64", []string{"64:ff9b::cb00:7109"}, "refused:address_excluded"},
		{"an IPv6 exclude over a NAT64 address", []string{"64:ff9b::c633:6499"}, "refused:address_excluded"},
		{"cloud metadata under a network root", []string{"169.254.169.254"}, "refused:address_not_public"},
		{"IPv4-mapped loopback", []string{"::ffff:127.0.0.1"}, "refused:address_not_public"},
		{"NAT64 of metadata", []string{"64:ff9b::a9fe:a9fe"}, "refused:address_not_public"},
		{"private, outside every network root", []string{"192.168.1.10"}, "refused:address_not_public"},
		{"private, inside a network root", []string{"10.20.0.5"}, "sent"},
		{"public", []string{"198.51.100.20"}, "sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.scope.excludedNets = map[string]netip.Prefix{"exclude[0]": netip.MustParsePrefix("203.0.113.9/32"),
				"exclude[1]": netip.MustParsePrefix("64:ff9b::c633:6400/120")}
			w.scope.networks = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("169.254.0.0/16"),
				netip.MustParsePrefix("127.0.0.0/8")}
			var srv *server
			for _, a := range tc.answers {
				cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
				srv = w.serve("www.example.com", a, 443, &cert, ok200("hi"))
			}
			res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
			if res.Decision != tc.want {
				t.Fatalf("%+v", res)
			}
			if tc.want != "sent" && (w.dials.Load() != 0 || srv.hits.Load() != 0) {
				t.Error("a refused name was dialled")
			}
		})
	}
}

// The address classes look through IPv4-mapped, NAT64 and 6to4 forms.
func TestClassify(t *testing.T) {
	for addr, want := range map[string]addrClass{
		"198.51.100.20": public, "2606:4700::1": public, "203.0.113.5": public,
		"127.0.0.1": never, "::1": never, "169.254.169.254": never, "fe80::1": never, "fd00:ec2::254": never,
		"::ffff:127.0.0.1": never, "64:ff9b::7f00:1": never, "2002:a9fe:a9fe::1": never,
		"10.0.0.1": notPublic, "172.16.0.1": notPublic, "192.168.0.1": notPublic, "100.64.0.1": notPublic,
		"fc00::1": notPublic, "224.1.2.3": notPublic, "224.0.0.1": never, "0.0.0.0": never, "::": never,
		"255.255.255.255": notPublic, "::ffff:198.51.100.20": notPublic, "64:ff9b::c633:6414": notPublic,
		"2002:c633:6414::1": notPublic, "64:ff9b:1::a9fe:a9fe": never, "64:ff9b:1::c633:6414": never,
		"100.100.100.200": never,
	} {
		if got := classify(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
}

// A dangling name is looked up as a fully qualified name, with no search
// domain appended, and nothing is dialled. An address query that finds no
// address and no CNAME is followed by a CNAME query for the name.
func TestNameThatDoesNotResolve(t *testing.T) {
	w := newWorld(t)
	res := w.gate().Send(context.Background(), web("https", "old.example.com", "/"))
	if res.Decision != "unavailable:nxdomain" || w.dials.Load() != 0 {
		t.Fatalf("%+v", res)
	}
	if !slices.Equal(w.queries, []string{"old.example.com.", "old.example.com."}) {
		t.Errorf("queries %q", w.queries)
	}
	es := w.audit.entries(t)
	if len(es) != 5 || es[4].Event != "refused" {
		t.Fatalf("audit %+v", es)
	}
	for i, typ := range []string{"A", "CNAME"} {
		if q, a := es[2*i], es[2*i+1]; q.Event != "dns" || q.Decision != "sent" || q.Params["type"] != typ ||
			a.Event != "dns_answer" || a.Decision != "unavailable:nxdomain" {
			t.Errorf("audit %d: %+v %+v", i, q, a)
		}
	}
}

// A discovered name without first-party evidence is read at its front page
// over https and http, and nothing else; a path its evidence allows only
// from a network root needs every address inside one (E4 tests 9 and 10).
func TestEntryPoints(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	tlsSrv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, ok200("<html>"))
	plain := w.serve("shop.example.com", "198.51.100.30", 80, nil, ok200("<html>"))
	g := w.gate()
	for _, scheme := range []string{"https", "http"} {
		if res := g.Send(context.Background(), web(scheme, "shop.example.com", "/")); !res.OK() {
			t.Errorf("%s front page: %+v", scheme, res)
		}
	}
	for _, p := range []string{"/robots.txt", "/.well-known/security.txt", "/admin"} {
		if res := g.Send(context.Background(), web("https", "shop.example.com", p)); res.Decision != "refused:entry_point" {
			t.Errorf("%s: %+v", p, res)
		}
	}
	if res := g.Send(context.Background(), Request{Op: "web.cert", Asset: "domain:example.com", Params: map[string]string{"host": "shop.example.com"}}); !res.OK() ||
		!res.Response.TLS.Verified || len(res.Response.TLS.Chain) == 0 || res.Response.TLS.Chain[0].DNSNames[0] != "shop.example.com" {
		t.Errorf("certificate read: %+v", res)
	}
	var paths []string
	for _, s := range []*server{tlsSrv, plain} {
		for _, r := range s.requests() {
			paths = append(paths, r.Method+" "+r.URL.Path)
		}
	}
	if strings.Join(paths, ",") != "GET /,GET /" {
		t.Errorf("the servers saw %v", paths)
	}

	// The same paths with evidence that holds only inside a network root.
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/"}, Network: []string{"/robots.txt", "/.well-known/security.txt"}}}
	if res := g.Send(context.Background(), web("https", "shop.example.com", "/robots.txt")); res.Decision != "refused:address_moved" {
		t.Errorf("outside every network root: %+v", res)
	}
	w.scope.networks = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	if res := g.Send(context.Background(), web("https", "shop.example.com", "/robots.txt")); !res.OK() {
		t.Errorf("inside a network root: %+v", res)
	}
	if res := g.Send(context.Background(), Request{Op: "web.probe", Asset: "domain:example.com", Params: map[string]string{"host": "shop.example.com"}}); res.Decision != "refused:level" {
		t.Errorf("a probe in this build: %+v", res)
	}
}

// A 3xx is evidence, never followed; its Location keeps no query value. A
// hop the collector asks for must follow a 3xx the gate received for the
// same asset, to exactly where it pointed, and is admitted from the first
// check; one out of scope is a coverage gap, not a defect; the fourth hop
// is refused (E4 test 11).
func TestRedirectsAreNotFollowed(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	next := map[string]string{"/": "/a", "/a": "/b?x=1", "/b": "https://WWW.example.com:443/c#top", "/c": "/", "/home": "/en/",
		"/login": "https://sso.example.org/login?session=abc123&next=/x"}
	srv := w.serve("www.example.com", "198.51.100.40", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Location", next[r.URL.Path])
		rw.WriteHeader(http.StatusFound)
	})
	w.scope.sites = map[string]SitePaths{"https://www.example.com": {Paths: []string{"/", "/a", "/b", "/c", "/login", "/home"}}}
	g := w.gate()

	res := g.Send(context.Background(), web("https", "www.example.com", "/login"))
	if !res.OK() || res.Response.Status != 302 || srv.hits.Load() != 1 {
		t.Fatalf("%+v, %d hits", res, srv.hits.Load())
	}
	loc := res.Response.Header.Get("Location")
	if strings.Contains(loc, "abc123") || !strings.Contains(loc, "session=[REDACTED:query:6 bytes]") {
		t.Errorf("Location %q", loc)
	}
	hop := web("https", "sso.example.org", "/login")
	hop.RedirectOf = res.RequestID
	if r := g.Send(context.Background(), hop); r.Decision != "unavailable:redirect_out_of_scope" || r.Reason != "unavailable:redirect_out_of_scope" {
		t.Errorf("a hop off scope: %+v", r)
	}

	// A hop to a page of the same site that is not an entry point is a
	// coverage gap: the 3xx is the evidence.
	home := g.Send(context.Background(), web("https", "www.example.com", "/home"))
	en := web("https", "www.example.com", "/en/")
	en.RedirectOf = home.RequestID
	if got := g.Send(context.Background(), en); got.Decision != "unavailable:redirect_not_entry_point" || got.Reason != got.Decision {
		t.Errorf("a same-site hop off the entry points: %+v", got)
	}

	// A hop that follows no redirect, or not to where it pointed, is a
	// collector's defect.
	for name, r := range map[string]Request{
		"an invented id":  {Op: "web.get", Asset: "domain:example.com", RedirectOf: "g999999", Params: map[string]string{"scheme": "https", "host": "evil.example.org", "path": "/"}},
		"another target":  {Op: "web.get", Asset: "domain:example.com", RedirectOf: res.RequestID, Params: map[string]string{"scheme": "https", "host": "sso.example.org", "path": "/other"}},
		"another asset's": {Op: "web.get", Asset: "domain:example.net", RedirectOf: res.RequestID, Params: map[string]string{"scheme": "https", "host": "sso.example.org", "path": "/login"}},
	} {
		if got := g.Send(context.Background(), r); got.Decision != "refused:redirect" || got.Reason != "unavailable:refused_by_gate" {
			t.Errorf("%s: %+v", name, got)
		}
	}

	// A chain of three hops on the site, with a query, a port and a
	// fragment that canonical comparison ignores; the fourth is refused.
	prev := g.Send(context.Background(), web("https", "www.example.com", "/"))
	for i, p := range []string{"/a", "/b", "/c"} {
		r := web("https", "www.example.com", p)
		r.RedirectOf = prev.RequestID
		got := g.Send(context.Background(), r)
		if got.Decision != "sent" {
			t.Fatalf("hop %d: %+v", i+1, got)
		}
		prev = got
	}
	r := web("https", "www.example.com", "/")
	r.RedirectOf = prev.RequestID
	if got := g.Send(context.Background(), r); got.Decision != "refused:redirect_depth" {
		t.Errorf("a fourth hop: %+v", got)
	}
}

// A certificate that does not verify is recorded with its chain and its
// typed class, and no HTTP byte is sent: the server's handler never runs
// (E4 test 12; docs/spec/scope.md, "Connections").
func TestInvalidCertificateSendsNoHTTP(t *testing.T) {
	for name, tc := range map[string]struct {
		cert  func(w *world) tls.Certificate
		class string
	}{
		"self-signed": {func(w *world) tls.Certificate {
			return w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), true)
		}, ClassUntrustedIssuer},
		"expired": {func(w *world) tls.Certificate {
			return w.leaf([]string{"www.example.com"}, time.Now().Add(-time.Hour), false)
		}, ClassExpired},
		"wrong name": {func(w *world) tls.Certificate {
			return w.leaf([]string{"other.example.net"}, time.Now().Add(time.Hour), false)
		}, ClassHostnameMismatch},
		"missing intermediate": {func(w *world) tls.Certificate {
			return w.intermediateLeaf("www.example.com", true)
		}, ClassMissingIntermediate},
		"a private CA's leaf alone": {func(w *world) tls.Certificate {
			return w.intermediateLeaf("www.example.com", false)
		}, ClassUntrustedIssuer},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			c := tc.cert(w)
			srv := w.serve("www.example.com", "198.51.100.50", 443, &c, ok200("hi"))
			res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
			if res.Decision != "unavailable:tls_invalid" || res.Response == nil || res.Response.TLS.Verified ||
				len(res.Response.TLS.Chain) == 0 || res.Response.TLS.Error == "" || res.Response.TLS.Class != tc.class {
				t.Fatalf("%+v %+v", res, res.Response.TLS)
			}
			if srv.hits.Load() != 0 {
				t.Error("the handler ran behind a certificate that did not verify")
			}
		})
	}
}

// The gate's own TLS dialer offers HTTP/2 as net/http does, and the
// response carries the verified handshake.
func TestHTTP2ThroughTheGatesDialer(t *testing.T) {
	w := newWorld(t)
	w.http2 = true
	c := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	proto := make(chan int, 1)
	w.serve("www.example.com", "198.51.100.55", 443, &c, func(rw http.ResponseWriter, r *http.Request) {
		proto <- r.ProtoMajor
		ok200("hi")(rw, r)
	})
	res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
	if !res.OK() || res.Response.TLS == nil || !res.Response.TLS.Verified || len(res.Response.TLS.Chain) == 0 {
		t.Fatalf("%+v", res)
	}
	if p := <-proto; p != 2 {
		t.Errorf("HTTP/%d", p)
	}
}

// failingSigner holds a certificate's public key and cannot sign.
type failingSigner struct{ pub crypto.PublicKey }

func (f failingSigner) Public() crypto.PublicKey { return f.pub }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("no key")
}

// intermediateLeaf is a leaf an intermediate signs, the intermediate one
// the test CA signs, served without the intermediate; aia says the leaf
// names where its issuer's certificate is published, as a public CA's do.
func (w *world) intermediateLeaf(name string, aia bool) tls.Certificate {
	w.t.Helper()
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	itmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ider, err := x509.CreateCertificate(rand.Reader, itmpl, w.ca, &ikey.PublicKey, w.caKey)
	if err != nil {
		w.t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(ider)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano() + 1), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if aia {
		tmpl.IssuingCertificateURL = []string{"http://ca.example/intermediate.crt"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &key.PublicKey, ikey)
	if err != nil {
		w.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A server that speaks only TLS versions older than 1.2 ends the handshake
// with a protocol_version alert: recorded as the evidence, not as a
// certificate failure, and nothing is read (docs/spec/web-collector.md,
// "TLS and certificate", tls.legacy_only).
func TestHandshakeAlertIsRecorded(t *testing.T) {
	w := newWorld(t)
	w.tlsConfig = func(c *tls.Config) { c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11 }
	c := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("www.example.com", "198.51.100.51", 443, &c, ok200("hi"))
	g := w.gate()
	for _, r := range []Request{web("https", "www.example.com", "/"),
		{Op: "web.cert", Asset: "domain:example.com", Params: map[string]string{"host": "www.example.com"}}} {
		res := g.Send(context.Background(), r)
		if res.Decision != "unavailable:tls_handshake" || res.Reason != "unavailable:tls_handshake" || res.Response == nil ||
			res.Response.TLS.Alert != "protocol_version" || res.Response.TLS.Class != "" {
			t.Fatalf("%s: %+v", r.Op, res)
		}
	}
	if srv.hits.Load() != 0 {
		t.Error("the handler ran")
	}
	for _, e := range w.audit.entries(t) {
		if e.Event == "result" && e.TLS != "alert:protocol_version" {
			t.Errorf("result line %+v", e)
		}
	}
	// A chain counts with an alert only once the handshake completed, which
	// proves the server holds its key. A server that requires a client
	// certificate alerts after that at TLS 1.3, so its chain is kept (the
	// certificate read succeeds; a page read is tls_refused), and during the
	// handshake at TLS 1.2, where nothing proves the key yet (a server may
	// skip its signed key exchange and ask for a certificate at once), so
	// no chain counts.
	for name, version := range map[string]uint16{"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13} {
		w := newWorld(t)
		w.tlsConfig = func(c *tls.Config) { c.ClientAuth, c.MaxVersion = tls.RequireAnyClientCert, version }
		c := w.leaf([]string{"mtls.example.com"}, time.Now().Add(time.Hour), false)
		w.serve("mtls.example.com", "198.51.100.52", 443, &c, ok200("hi"))
		g := w.gate()
		cert := g.Send(context.Background(), Request{Op: "web.cert", Asset: "domain:example.com", Params: map[string]string{"host": "mtls.example.com"}})
		page := g.Send(context.Background(), web("https", "mtls.example.com", "/"))
		if version == tls.VersionTLS13 {
			if !cert.OK() || cert.Response == nil || !cert.Response.TLS.Verified || len(cert.Response.TLS.Chain) == 0 {
				t.Errorf("%s certificate: %+v", name, cert)
			}
			if page.Decision != "unavailable:tls_refused" || page.Reason != "unavailable:tls_refused" || page.Response == nil ||
				!page.Response.TLS.Verified || len(page.Response.TLS.Chain) == 0 || page.Response.TLS.Alert != "certificate_required" {
				t.Errorf("%s page: %+v %+v", name, page, page.Response.TLS)
			}
			continue
		}
		for op, res := range map[string]Result{"certificate": cert, "page": page} {
			if res.Decision != "unavailable:tls_handshake" || res.Response == nil || res.Response.TLS.Verified ||
				len(res.Response.TLS.Chain) != 0 || res.Response.TLS.Alert != "handshake_failure" {
				t.Errorf("%s %s: %+v", name, op, res)
			}
		}
	}
	// A server that sends a valid certificate it cannot sign with, then an
	// alert, never proved it holds the key: no chain counts, at either
	// version, and nothing is verified.
	for name, version := range map[string]uint16{"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13} {
		w := newWorld(t)
		w.tlsConfig = func(c *tls.Config) { c.MaxVersion = version }
		c := w.leaf([]string{"keyless.example.com"}, time.Now().Add(time.Hour), false)
		c.PrivateKey = failingSigner{c.PrivateKey.(crypto.Signer).Public()}
		w.serve("keyless.example.com", "198.51.100.54", 443, &c, ok200("hi"))
		g := w.gate()
		for _, r := range []Request{web("https", "keyless.example.com", "/"),
			{Op: "web.cert", Asset: "domain:example.com", Params: map[string]string{"host": "keyless.example.com"}}} {
			res := g.Send(context.Background(), r)
			if res.Decision != "unavailable:tls_handshake" || res.Response == nil || res.Response.TLS.Verified || len(res.Response.TLS.Chain) != 0 {
				t.Errorf("%s %s: %+v", name, r.Op, res)
			}
		}
	}
	for err, want := range map[error]string{
		&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}:      "handshake_failure",
		&net.OpError{Op: "remote error", Err: errors.New("tls: alert(99)")}:              "alert",
		errors.New("tls: server selected unsupported protocol version 301"):              "protocol_version",
		&net.OpError{Op: "dial", Err: errors.New("tls: protocol version not supported")}: "",
		errors.New("connection refused"):                                                 "",
	} {
		if got := tlsAlert(err); got != want {
			t.Errorf("tlsAlert(%v) = %q; want %q", err, got, want)
		}
	}
}

// No file outside tests disables verification (E4 test 12), and no
// non-test file outside this package reaches the test seams.
func TestNoBypassAndNoSeamOutsideTests(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	here, _ := filepath.Abs(".")
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "Insecure"+"SkipVerify") {
			t.Errorf("%s disables certificate verification", p)
		}
		if filepath.Dir(p) != here && strings.Contains(string(b), "gate."+"Net") {
			t.Errorf("%s reaches the gate's test seams", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A proxy in the environment is ignored and named in a note (E4 test 12).
func TestProxyIsIgnored(t *testing.T) {
	w := newWorld(t)
	proxy := w.serve("", "198.51.100.99", 3128, nil, ok200("proxied"))
	w.env["HTTPS_PROXY"] = proxy.URL
	w.env["HTTP_PROXY"] = proxy.URL
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.51", 443, &cert, ok200("direct"))
	g := w.gate()
	res := g.Send(context.Background(), web("https", "www.example.com", "/"))
	if !res.OK() || string(res.Response.Body) != "direct" || proxy.hits.Load() != 0 {
		t.Fatalf("%+v, proxy saw %d", res, proxy.hits.Load())
	}
	if n := g.Notes(); len(n) != 1 || !strings.Contains(n[0], "HTTPS_PROXY, HTTP_PROXY is set") {
		t.Errorf("notes %q", n)
	}
}

// A path a confirmation allows is read only while the name points where
// the confirmation says: the first CNAME hop outside every root, or the
// sorted addresses (docs/spec/scope.md, "First-party evidence").
func TestConfirmationTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		zone   map[string]record
		target string
		want   string
	}{
		{"its CNAME target", map[string]record{"shop.example.com": {cname: "shops.myshopify.example"}, "shops.myshopify.example": {cname: "edge.shopify.example"},
			"edge.shopify.example": {addrs: []string{"198.51.100.40"}}}, "shops.myshopify.example", "sent"},
		{"repointed", map[string]record{"shop.example.com": {cname: "other.example.net"}, "other.example.net": {addrs: []string{"198.51.100.40"}}},
			"shops.myshopify.example", "refused:address_moved"},
		{"through a hop under a root", map[string]record{"shop.example.com": {cname: "lb.example.com"}, "lb.example.com": {cname: "shops.myshopify.example"},
			"shops.myshopify.example": {addrs: []string{"198.51.100.40"}}}, "shops.myshopify.example", "sent"},
		{"its addresses", map[string]record{"shop.example.com": {addrs: []string{"198.51.100.41", "198.51.100.40"}}}, "198.51.100.40,198.51.100.41", "sent"},
		{"an address moved", map[string]record{"shop.example.com": {addrs: []string{"198.51.100.40", "198.51.100.42"}}}, "198.51.100.40,198.51.100.41", "refused:address_moved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.zone = newZone(tc.zone)
			cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
			srv := w.serve("", "198.51.100.40", 443, &cert, ok200("x"))
			w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/"}, Confirmed: []string{"/robots.txt"}, Target: tc.target}}
			g := w.gate()
			if res := g.Send(context.Background(), web("https", "shop.example.com", "/robots.txt")); res.Decision != tc.want {
				t.Fatalf("%+v", res)
			}
			if tc.want != "sent" && srv.hits.Load() != 0 {
				t.Error("a name that moved was read")
			}
			if res := g.Send(context.Background(), web("https", "shop.example.com", "/")); res.Decision == "refused:address_moved" {
				t.Errorf("the front page needs no confirmation: %+v", res)
			}
		})
	}
}

// Workspace's verificationCodes.list returns users' backup sign-in codes:
// no op may declare it, however its path is spelled or filled, and no
// bound URL may reach it (docs/ROADMAP.md, E6).
func TestRegistryRefusesVerificationCodes(t *testing.T) {
	codes := func(url string, params ...Param) Op {
		return Op{ID: "workspace.codes", Provider: "google", Method: GET, URL: url,
			Subject: "saas:google-workspace:example.com/users/{user}", Params: append([]Param{{Name: "user", Type: UserKey}}, params...),
			Level: Observe, Accept: []string{"application/json"}, Keep: []string{"items"}, MaxBytes: 1 << 16}
	}
	base := "https://admin.googleapis.com/admin/directory/v1/users/{user}"
	// The op is valid but for the guard: the same op on another path is
	// accepted.
	if _, err := NewRegistry(codes(base + "/tokens")); err != nil {
		t.Fatalf("the control op: %v", err)
	}
	for _, url := range []string{base + "/verificationCodes", base + "/VERIFICATIONCODES?x=1", base + "/verification%43odes"} {
		if _, err := NewRegistry(codes(url)); err == nil || !strings.Contains(err.Error(), "never declared") {
			t.Errorf("%s: %v", url, err)
		}
	}
	if _, err := NewRegistry(codes(base+"{rest}", Param{Name: "rest", Type: URLPath})); err == nil || !strings.Contains(err.Error(), "only a web op") {
		t.Errorf("a URLPath on an API op: %v", err)
	}
	// A web op's path is supplied: the bound path is checked too.
	reg, err := NewRegistry(testOps...)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/verificationCodes", "/a/Verification%43odes"} {
		if _, err := reg.ops["web.get"].bind(map[string]string{"scheme": "https", "host": "www.example.com", "path": path}); err == nil ||
			!strings.Contains(err.Error(), "never sent") {
			t.Errorf("%s: %v", path, err)
		}
	}
}

// A redirect's Location is compared as the hop is bound: a path the server
// escaped where it need not (%7E, %61) is the same resource, and its hop
// is admitted.
func TestRedirectToAnEscapedPath(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	next := map[string]string{"/": "/%7Ejohn/", "/x": "/%61pp/"}
	w.serve("www.example.com", "198.51.100.40", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		if loc, ok := next[r.URL.Path]; ok {
			rw.Header().Set("Location", loc)
			rw.WriteHeader(http.StatusFound)
			return
		}
		_, _ = rw.Write([]byte("<html>"))
	})
	w.scope.sites = map[string]SitePaths{"https://www.example.com": {Paths: []string{"/", "/x", "/~john/", "/app/"}}}
	g := w.gate()
	for from, to := range map[string]string{"/": "/~john/", "/x": "/app/"} {
		prev := g.Send(context.Background(), web("https", "www.example.com", from))
		r := web("https", "www.example.com", to)
		r.RedirectOf = prev.RequestID
		if got := g.Send(context.Background(), r); got.Decision != "sent" {
			t.Errorf("the hop from %s to %s: %+v", from, to, got)
		}
	}
}

// With no nameserver to ask, a request is unavailable:no_resolver, as a
// name scope resolves is: nothing was asked, so it is no DNS error.
func TestNoResolver(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("www.example.com", "198.51.100.40", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("<html>"))
	})
	w.scope.sites = map[string]SitePaths{"https://www.example.com": {Paths: []string{"/"}}}
	g := w.gate()
	g.nameserver = netip.Addr{} // as a host with no nameserver in /etc/resolv.conf
	res := g.Send(context.Background(), web("https", "www.example.com", "/"))
	if res.Decision != "unavailable:no_resolver" || res.Reason != "unavailable:no_resolver" || srv.hits.Load() != 0 {
		t.Errorf("%+v", res)
	}
}

// A result's coverage reason comes from its decision by one table
// (docs/spec/scope.md, "Outcomes"); a sent request's comes from its
// status, so its decision gives none.
func TestReasonOfDecision(t *testing.T) {
	for decision, want := range map[string]string{
		DecisionSent: "", DecisionReused: "",
		"refused:excluded": "excluded_by_operator", "refused:address_excluded": "excluded_by_operator",
		"refused:address_moved": "unavailable:address_moved", "refused:no_credentials": "no_credentials",
		"refused:window": "limit_reached", "refused:rate_limit": "limit_reached",
		"refused:out_of_scope": "unavailable:refused_by_gate", "refused:bind": "unavailable:refused_by_gate",
		"unavailable:deadline": "limit_reached", "unavailable:canceled": "limit_reached", "unavailable:window_ended": "limit_reached",
		"unavailable:timeout": "unavailable:timeout", "unavailable:redirect_out_of_scope": "unavailable:redirect_out_of_scope",
	} {
		if got := reasonOf(decision); got != want {
			t.Errorf("reasonOf(%q) = %q; want %q", decision, got, want)
		}
	}
}
