package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/b87/scheck/internal/policy"
)

// A body the server stops sending is never a complete read: past the
// deadline it is limit_reached, after a reset it is unavailable and not
// retried, and in both the partial body is not kept.
func TestBodyCutShortIsNotARead(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		w := newWorld(t)
		w.deadline = time.Now().Add(400 * time.Millisecond)
		cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
		w.serve("www.example.com", "198.51.100.90", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Length", "100")
			_, _ = rw.Write([]byte("<html>part"))
			rw.(http.Flusher).Flush()
			<-r.Context().Done()
		})
		res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
		if res.Decision != "unavailable:deadline" || res.Reason != "limit_reached" || res.OK() ||
			res.Response == nil || res.Response.Status != 200 || res.Response.Body != nil {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("reset", func(t *testing.T) {
		w := newWorld(t)
		cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
		srv := w.serve("www.example.com", "198.51.100.91", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Length", "100")
			_, _ = rw.Write([]byte("<html>part"))
			rw.(http.Flusher).Flush()
			conn, _, err := rw.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.(interface{ CloseWrite() error }).CloseWrite()
				_ = conn.Close()
			}
		})
		res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
		if res.Decision != "unavailable:connection_reset" || res.OK() || res.Response == nil || res.Response.Body != nil {
			t.Fatalf("%+v", res)
		}
		if srv.hits.Load() != 1 {
			t.Errorf("a reset after the response was retried: %d attempts", srv.hits.Load())
		}
	})
}

// A reset before any response is retried, and when the retries run out the
// result's detail, a transport error naming the URL, is redacted as the
// audit line is: a redact_extra match in the path never reaches a collector.
func TestResetRetriesEndRedacted(t *testing.T) {
	w := newWorld(t)
	w.extra = []string{"zebrafish"}
	w.scope.sites = map[string]SitePaths{"https://www.example.com": {Paths: []string{"/", "/zebrafish/"}}}
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("www.example.com", "198.51.100.93", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		if conn, _, err := rw.(http.Hijacker).Hijack(); err == nil {
			_ = conn.Close()
		}
	})
	res := w.gate().Send(context.Background(), web("https", "www.example.com", "/zebrafish/"))
	if res.Decision != "unavailable:connection_reset" || res.OK() {
		t.Fatalf("%+v", res)
	}
	if n := srv.hits.Load(); n != int32(1+len(retryDelays)) {
		t.Errorf("%d attempts", n)
	}
	if strings.Contains(res.Detail, "zebrafish") || !strings.Contains(res.Detail, "[REDACTED:") {
		t.Errorf("detail %q", res.Detail)
	}
}

// A secret that straddles the cap is redacted whole before the cut, and the
// cut of a body larger than what was read is marked as a lower bound
// (AGENTS.md rule 5; docs/spec/host-collector.md §4.2).
func TestSecretStraddlingTheCap(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.92", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		_, _ = rw.Write([]byte(strings.Repeat("x", 240) + " AKIAIOSFODNN7EXAMPLE " + strings.Repeat("y", 1<<20)))
	})
	res := w.gate().Send(context.Background(), web("https", "www.example.com", "/"))
	body := string(res.Response.Body)
	if !res.OK() || strings.Contains(body, "AKIAIOSFODNN7") || !strings.Contains(body, "[REDACTED:aws-access-key:20 bytes]") {
		t.Fatalf("%q", body)
	}
	if !res.Response.Truncated || !strings.HasSuffix(body, "+ bytes]") {
		t.Errorf("the cut of a 1 MiB body: %q", body[len(body)-40:])
	}
}

// A URL in a kept header keeps its scheme, host and path; userinfo, every
// query component and the fragment become markers.
func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://app.example.com/cb#code=SPLxlOBeZQ&state=xyz": "https://app.example.com/cb#[REDACTED:fragment:25 bytes]",
		"https://github.com/orgs/x/sso?SECRETBARE":             "https://github.com/orgs/x/sso?[REDACTED:query:10 bytes]",
		"https://u:p@host.example/x":                           "https://[REDACTED:userinfo:3 bytes]@host.example/x",
		"/login?next=/a&debug":                                 "/login?next=[REDACTED:query:2 bytes]&[REDACTED:query:5 bytes]",
		"https://www.example.com/":                             "https://www.example.com/",
		"https://bad host/%zz?x=1":                             "https://bad host[REDACTED:url:8 bytes]",
		"https://user:hunter2pass@host.example/%zz":            "https://[REDACTED:userinfo:16 bytes]@host.example[REDACTED:url:4 bytes]",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
	red, _ := policy.NewRedactor(nil)
	h, _, _ := keepHeaders(http.Header{"X-Github-Sso": {"required; url=https://github.com/orgs/x/sso?authorization_request=ABC"}}, red)
	if got := h.Get("X-Github-Sso"); got != "required; url=https://github.com/orgs/x/sso?authorization_request=[REDACTED:query:3 bytes]" {
		t.Errorf("X-GitHub-SSO %q", got)
	}
}

// An address host is canonical, so a subject compares equal to a root or
// exclude written another way; an IPv4-mapped literal is refused.
func TestHostsAreCanonical(t *testing.T) {
	reg, err := NewRegistry(testOps...)
	if err != nil {
		t.Fatal(err)
	}
	op := reg.ops["web.get"]
	b, err := op.bind(map[string]string{"scheme": "https", "host": "[2001:DB8:0:0::1]:443", "path": "/"})
	if err != nil || b.subject != "url:https://[2001:db8::1]/" || b.url.String() != "https://[2001:db8::1]/" {
		t.Fatalf("%v %q %v", err, b.subject, b.url)
	}
	if _, err := op.bind(map[string]string{"scheme": "https", "host": "[::ffff:198.51.100.20]", "path": "/"}); err == nil {
		t.Error("an IPv4-mapped literal was accepted")
	}
}

// Each asset's own throttle binds only that asset; the provider's ceiling
// binds them all.
func TestThrottleIsPerAsset(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.scope.roots = append(w.scope.roots, "saas:github:slow-org")
	w.scope.throttles = map[string]throttle{"saas:github:slow-org": {rate: 1}}
	w.github(ok200(`{"name":"x"}`))
	g := w.gate()
	longest := func() time.Duration {
		var m time.Duration
		for _, d := range w.sleeps {
			m = max(m, d)
		}
		w.sleeps = nil
		return m
	}
	for range 3 {
		if res := g.Send(context.Background(), repo("example-org", "x")); !res.OK() {
			t.Fatalf("%+v", res)
		}
	}
	if d := longest(); d > 400*time.Millisecond {
		t.Errorf("an asset without a throttle of its own waited %s", d)
	}
	slow := func() Request {
		return Request{Op: "github.repo", Asset: "saas:github:slow-org", Params: map[string]string{"owner": "slow-org", "repo": "x"}}
	}
	for range 2 {
		if res := g.Send(context.Background(), slow()); !res.OK() {
			t.Fatalf("%+v", res)
		}
	}
	if d := longest(); d < 800*time.Millisecond {
		t.Errorf("an asset throttled to 1/s waited only %s", d)
	}
}

// An asset waiting for its own throttle's tick holds none of the
// provider's slots: with GitHub's concurrency of 1, another organization's
// request is sent while the slow one still waits.
func TestSlowAssetDoesNotHoldTheProvider(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.scope.roots = append(w.scope.roots, "saas:github:slow-org")
	w.scope.throttles = map[string]throttle{"saas:github:slow-org": {rate: 1}}
	w.github(ok200(`{"name":"x"}`))
	waiting, hold := make(chan struct{}), make(chan struct{})
	var once sync.Once
	w.block = func(ctx context.Context, d time.Duration) error {
		if d < 500*time.Millisecond {
			return ctx.Err() // the provider's own pacing
		}
		once.Do(func() { close(waiting) })
		select {
		case <-hold:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	g := w.gate()
	slow := Request{Op: "github.repo", Asset: "saas:github:slow-org", Params: map[string]string{"owner": "slow-org", "repo": "x"}}
	if res := g.Send(context.Background(), slow); !res.OK() {
		t.Fatalf("%+v", res)
	}
	second := make(chan Result, 1)
	go func() { second <- g.Send(context.Background(), slow) }()
	select {
	case <-waiting:
	case res := <-second:
		t.Fatalf("the second slow-org request did not wait for its throttle: %+v", res)
	case <-time.After(5 * time.Second):
		t.Fatal("the second slow-org request never waited for its throttle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if res := g.Send(ctx, repo("example-org", "x")); !res.OK() {
		t.Errorf("another organization waited for slow-org's throttle: %+v", res)
	}
	close(hold)
	if res := <-second; !res.OK() {
		t.Fatalf("%+v", res)
	}
}

// An asset's own throttle binds a limiter of its own only when it sets a
// rate or a concurrency: a concurrency alone bounds the requests in flight,
// a rate alone paces them within the provider's concurrency, and neither
// leaves the provider's ceiling alone.
func TestAssetThrottlePaths(t *testing.T) {
	const tenant = "saas:google-workspace:example.com"
	for _, tc := range []struct {
		name     string
		own      throttle
		inFlight int32
		paced    bool
	}{
		{"neither", throttle{}, 2, false},
		{"concurrency only", throttle{conc: 1}, 1, false},
		{"rate only", throttle{rate: 1.0 / 60}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.ops = append(slices.Clone(testOps), Op{ID: "ws.domains", Provider: "google", Method: GET,
				URL:     "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains",
				Subject: tenant, Level: Observe, Accept: []string{"application/json"}, Keep: []string{"domainName"}, MaxBytes: 1 << 12})
			w.scope.throttles = map[string]throttle{tenant: tc.own}
			var now, most atomic.Int32
			w.google(func(rw http.ResponseWriter, _ *http.Request) {
				n := now.Add(1)
				for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
				}
				// Long enough for every request the limiters let through to
				// arrive while this one is in flight.
				time.Sleep(200 * time.Millisecond)
				now.Add(-1)
				rw.Header().Set("Content-Type", "application/json")
				_, _ = rw.Write([]byte(`{"domainName":"example.com"}`))
			})
			g := w.gate()
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					if res := g.Send(context.Background(), Request{Op: "ws.domains", Asset: tenant}); !res.OK() {
						t.Errorf("%+v", res)
					}
				})
			}
			wg.Wait()
			if most.Load() != tc.inFlight {
				t.Errorf("%d requests in flight at once, want %d", most.Load(), tc.inFlight)
			}
			paced := false
			w.mu.Lock()
			for _, d := range w.sleeps {
				paced = paced || d > 30*time.Second
			}
			w.mu.Unlock()
			if paced != tc.paced {
				t.Errorf("paced by the asset's rate: %v, want %v (sleeps %v)", paced, tc.paced, w.sleeps)
			}
		})
	}
}

// A rate limit that holds through every retry stops the provider; a backoff
// that would pass the deadline ends the request without stopping it, and
// says why without inventing a Retry-After.
func TestRetryOutcomes(t *testing.T) {
	t.Run("rate limit held", func(t *testing.T) {
		w := newWorld(t)
		w.env["GITHUB_TOKEN"] = testToken
		gh := w.github(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusTooManyRequests) })
		g := w.gate()
		res := g.Send(context.Background(), repo("example-org", "x"))
		if res.Reason != "limit_reached" || gh.hits.Load() != 4 {
			t.Fatalf("%+v after %d attempts", res, gh.hits.Load())
		}
		if next := g.Send(context.Background(), repo("example-org", "y")); next.Decision != "refused:rate_limit" || gh.hits.Load() != 4 {
			t.Errorf("after the retries: %+v", next)
		}
	})
	t.Run("backoff past the deadline", func(t *testing.T) {
		w := newWorld(t)
		w.env["GITHUB_TOKEN"] = testToken
		w.deadline = time.Now().Add(3 * time.Second)
		var n atomic.Int32
		w.github(func(rw http.ResponseWriter, _ *http.Request) {
			if n.Add(1) <= 2 {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			ok200(`{"name":"x"}`)(rw, nil)
		})
		g := w.gate()
		res := g.Send(context.Background(), repo("example-org", "x"))
		if res.Decision != "refused:deadline" || res.Reason != "limit_reached" ||
			!strings.Contains(res.Detail, "would pass limits.timeout") || strings.Contains(res.Detail, "asked") {
			t.Fatalf("%+v", res)
		}
		if next := g.Send(context.Background(), repo("example-org", "y")); !next.OK() {
			t.Errorf("a server error stopped the provider: %+v", next)
		}
		es := w.audit.entries(t)
		var cut Entry
		for _, e := range es {
			if e.Event == "refused" {
				cut = e
			}
		}
		if cut.Decision != "refused:deadline" || cut.RetryOf != "g000001" || cut.Attempt != 3 {
			t.Errorf("the retry not sent: %+v", cut)
		}
	})
}

// Certificate fields are target-derived and redacted like a body.
func TestCertificateFieldsAreRedacted(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.example.com", "db.internal.example.net"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.93", 443, &cert, ok200("hi"))
	res := w.gate().Send(context.Background(), Request{Op: "web.cert", Asset: "domain:example.com", Params: map[string]string{"host": "www.example.com"}})
	if !res.OK() {
		t.Fatalf("%+v", res)
	}
	names := strings.Join(res.Response.TLS.Chain[0].DNSNames, ",")
	if strings.Contains(names, "internal.example.net") || !strings.Contains(names, "[REDACTED:extra:0:") {
		t.Errorf("DNS names %q", names)
	}

	w2 := newWorld(t)
	wrong := w2.leaf([]string{"internal.example.net"}, time.Now().Add(time.Hour), false)
	w2.serve("www.example.com", "198.51.100.94", 443, &wrong, ok200("hi"))
	res = w2.gate().Send(context.Background(), web("https", "www.example.com", "/"))
	if res.Decision != "unavailable:tls_invalid" || strings.Contains(res.Response.TLS.Error+res.Detail, "internal.example.net") ||
		!strings.Contains(res.Response.TLS.Error, "[REDACTED:extra:0:") {
		t.Errorf("%+v %q", res, res.Response.TLS.Error)
	}
}

// A token shorter than any GitHub token is a mistake, not a credential:
// redacting it by value would mangle every response.
func TestShortTokenIsRefused(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = "x"
	res := w.gate().Send(context.Background(), repo("example-org", "shop"))
	if res.Decision != "refused:no_credentials" || !strings.Contains(res.Detail, "too short") || w.dials.Load() != 0 {
		t.Errorf("%+v", res)
	}
}

// A gate cannot be built without an audit log: it could not write the line
// it must write before every send.
func TestGateNeedsAnAuditLog(t *testing.T) {
	reg, _ := NewRegistry(testOps...)
	for name, audit := range map[string]*policy.Audit{"none": nil, "io.Discard": policy.NewAudit(io.Discard), "nil writer": policy.NewAudit(nil)} {
		if _, err := New(Config{Registry: reg, Scope: &fakeScope{}, Audit: audit}); err == nil {
			t.Errorf("%s: a gate without an audit log that keeps its lines was built", name)
		}
	}
}

// failingWriter is an audit log whose writes fail.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// A request or lookup whose audit line cannot be written is not sent: the
// line comes before the send (docs/spec/scope.md, "Audit"; E4 test 22).
func TestFailedAuditWriteSendsNothing(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.7", 443, &cert, ok200("hi"))
	reg, _ := NewRegistry(testOps...)
	g, err := New(Config{Registry: reg, Scope: w.scope, Audit: policy.NewAudit(failingWriter{}), Version: "test",
		Getenv: func(k string) string { return w.env[k] }, Net: w.net()})
	if err != nil {
		t.Fatal(err)
	}
	queries := len(w.zone.asked())
	res := g.Send(context.Background(), web("https", "www.example.com", "/"))
	if res.Decision != "unavailable:audit_failed" || w.dials.Load() != 0 {
		t.Errorf("%+v, %d dials", res, w.dials.Load())
	}
	// Written as the address: no lookup, so the send line itself fails.
	w.scope.roots = append(w.scope.roots, "url:https://198.51.100.7/")
	lit := web("https", "198.51.100.7", "/")
	lit.Asset = "url:https://198.51.100.7/"
	if res := g.Send(context.Background(), lit); res.Decision != "unavailable:audit_failed" || w.dials.Load() != 0 {
		t.Errorf("literal: %+v, %d dials", res, w.dials.Load())
	}
	r := g.Resolve(context.Background(), Resolve{Asset: "domain:example.com", Name: "www.example.com", Stage: "scope"})
	if r.Lookup.Outcome != OutcomeAuditFailed || len(w.zone.asked()) != queries {
		t.Errorf("lookup %+v, %d queries", r.Lookup, len(w.zone.asked())-queries)
	}
}

// A name that matches redact_extra is redacted on every gate audit line,
// with its marker present: params, URL, DNS name and refusal detail.
func TestAuditLinesAreRedacted(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"www.internal.example.net"}, time.Now().Add(time.Hour), false)
	w.serve("www.internal.example.net", "198.51.100.95", 443, &cert, ok200("hi"))
	w.scope.roots = append(w.scope.roots, "domain:example.net")
	g := w.gate()
	r := Request{Op: "web.get", Asset: "domain:example.net", Params: map[string]string{"scheme": "https", "host": "www.internal.example.net", "path": "/"}}
	if res := g.Send(context.Background(), r); !res.OK() {
		t.Fatalf("%+v", res)
	}
	r.Params["path"] = "/admin"
	g.Send(context.Background(), r)
	log := w.audit.String()
	if strings.Contains(log, "internal.example.net") || strings.Count(log, "[REDACTED:extra:0:") < 4 {
		t.Errorf("audit log:\n%s", log)
	}
}

// An over-cap JSON body is not kept, but its status still decides: a 401 is
// a refusal of kind access, a 429 is retried as a rate limit.
func TestOverCapStatusIsClassified(t *testing.T) {
	big := `{"message":"` + strings.Repeat("z", 200) + `"}`
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	var n atomic.Int32
	w.github(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("per_page") == "1" {
			rw.WriteHeader(http.StatusUnauthorized)
		} else if n.Add(1) == 1 {
			rw.WriteHeader(http.StatusTooManyRequests)
		}
		_, _ = rw.Write([]byte(big))
	})
	g := w.gate()
	list := func(perPage string) Request {
		return Request{Op: "github.org_repos", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org", "per_page": perPage}}
	}
	if res := g.Send(context.Background(), list("1")); res.Reason != "refused" || res.Kind != "access" || res.Response.Body != nil {
		t.Errorf("an over-cap 401: %+v", res)
	}
	if res := g.Send(context.Background(), list("2")); res.Decision != "unavailable:response_too_large" || n.Load() != 2 {
		t.Errorf("an over-cap 429, then an over-cap 200: %+v after %d attempts", res, n.Load())
	}
}

// limits.timeout passing during a DNS lookup is limit_reached, as it is
// during a request.
func TestDeadlineDuringDNS(t *testing.T) {
	w := newWorld(t)
	w.deadline = time.Now().Add(150 * time.Millisecond)
	g := w.gate()
	g.exchange = func(ctx context.Context, _ string, _ []byte, _ bool) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	res := g.Send(context.Background(), web("https", "www.example.com", "/"))
	if res.Decision != "unavailable:deadline" || res.Reason != "limit_reached" {
		t.Errorf("%+v", res)
	}
}

// An address redact_extra matches is neither dialled nor written to the
// audit log's dest_ip: the request is unavailable, as the same name's
// discovery lookup is insufficient (AGENTS.md rule 5).
func TestRedactedAddressIsNotDialled(t *testing.T) {
	w := newWorld(t)
	w.extra = append(w.extra, `198\.51\.100\.96`)
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.96", 443, &cert, ok200("hi"))
	g := w.gate()
	res := g.Send(context.Background(), web("https", "www.example.com", "/"))
	if res.OK() || w.dials.Load() != 0 {
		t.Errorf("%+v, %d dials", res, w.dials.Load())
	}
	// Written as the address, in scope as its own url root.
	w.scope.roots = append(w.scope.roots, "url:https://198.51.100.96/")
	r := web("https", "198.51.100.96", "/")
	r.Asset = "url:https://198.51.100.96/"
	lit := g.Send(context.Background(), r)
	if lit.Decision != "unavailable:dns_error" || w.dials.Load() != 0 {
		t.Errorf("literal: %+v, %d dials", lit, w.dials.Load())
	}
	if r := g.Resolve(context.Background(), Resolve{Asset: "domain:example.com", Name: "www.example.com", Stage: "scope"}); r.Lookup.Outcome != OutcomeError {
		t.Errorf("discovery %+v", r.Lookup)
	}
	// The asset id is the operator's own, written in the file; what the
	// target answered and what was dialled are the gate's to redact.
	if log := w.audit.String(); strings.Contains(log, `"dest_ip":"198.51.100.96"`) || strings.Contains(log, `com 198.51.100.96"`) {
		t.Errorf("audit log:\n%s", log)
	}
}

// An anchored redact_extra pattern matches an answer's address or CNAME
// target on the audit line as it does when the gate judges it: each is
// redacted on its own.
func TestAnchoredRedactionOnAnswers(t *testing.T) {
	w := newWorld(t)
	w.extra = []string{`^198\.51\.100\.97$`, `^hidden-edge\.example\.net$`}
	w.zone = newZone(map[string]record{"www.example.com": {addrs: []string{"198.51.100.97"}},
		"cdn.example.com": {cname: "hidden-edge.example.net"}, "hidden-edge.example.net": {addrs: []string{"198.51.100.98"}}})
	g := w.gate()
	for _, name := range []string{"www.example.com", "cdn.example.com"} {
		g.Resolve(context.Background(), Resolve{Asset: "domain:example.com", Name: name, Stage: "scope"})
	}
	log := w.audit.String()
	if strings.Contains(log, "198.51.100.97") || strings.Contains(log, "hidden-edge") || !strings.Contains(log, "[REDACTED:extra:0:") ||
		!strings.Contains(log, "[REDACTED:extra:1:") {
		t.Errorf("audit log:\n%s", log)
	}
}

// The resolver's address is redacted where redact_extra matches it: on
// every dns line and wherever the gate names its resolver.
func TestResolverAddressIsRedacted(t *testing.T) {
	w := newWorld(t)
	w.extra = []string{`192\.0\.2\.53`}
	w.zone = newZone(map[string]record{"www.example.com": {addrs: []string{"198.51.100.7"}}})
	g := w.gate()
	g.Resolve(context.Background(), Resolve{Asset: "domain:example.com", Name: "www.example.com", Stage: "scope"})
	uses, _ := g.Egress()
	if log := w.audit.String(); strings.Contains(log, "192.0.2.53") || !strings.Contains(log, `"dest_ip":"[REDACTED:extra:0:`) ||
		len(uses) != 1 || !strings.HasPrefix(uses[0].Host, "[REDACTED:extra:0:") || g.Resolver() != uses[0].Host {
		t.Errorf("uses %+v, audit log:\n%s", uses, log)
	}
}

// The same JSON body reveals the same values whether it came back as a 2xx
// or as an error: an error body is redacted value by value too, so a
// number under a secret-shaped key is redacted in both, and each marker is
// written once (docs/spec/scope.md, "Responses"; E4 test 13).
func TestErrorBodyIsRedactedAsASuccessBody(t *testing.T) {
	body := `{"name":"shop","password":"yes","token":12345,"enabled":true}`
	hits := map[int][]string{}
	for _, status := range []int{http.StatusOK, http.StatusUnprocessableEntity} {
		w := newWorld(t)
		w.env["GITHUB_TOKEN"] = testToken
		w.github(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(status)
			_, _ = rw.Write([]byte(body))
		})
		res := w.gate().Send(context.Background(), repo("example-org", "shop"))
		if res.Response == nil {
			t.Fatalf("%d: %+v", status, res)
		}
		for _, h := range res.Response.Redactions {
			hits[status] = append(hits[status], fmt.Sprintf("%s:%d", h.Rule, h.Bytes))
		}
		if status != http.StatusOK {
			got := string(res.Response.Body)
			if strings.Contains(got, `"yes"`) || strings.Contains(got, "12345") || strings.Contains(got, "30 bytes") ||
				!strings.Contains(got, "[REDACTED:json-secret:3 bytes]") || !strings.Contains(got, "[REDACTED:json-secret:5 bytes]") {
				t.Errorf("error body %s", got)
			}
		}
	}
	if !slices.Equal(hits[http.StatusOK], hits[http.StatusUnprocessableEntity]) {
		t.Errorf("2xx redactions %v, error body's %v", hits[http.StatusOK], hits[http.StatusUnprocessableEntity])
	}
	// An error body that is not one JSON document (here a BOM before it)
	// is kept only as its hash: the text rules would miss the number.
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.github(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = rw.Write([]byte("\ufeff" + `{"token":12345}`))
	})
	res := w.gate().Send(context.Background(), repo("example-org", "shop"))
	if res.Response == nil || res.Response.Body != nil || res.Response.Status != http.StatusUnprocessableEntity ||
		strings.Contains(w.audit.String(), "12345") {
		t.Errorf("%+v", res.Response)
	}
}

// A web site's 503 or 429 is retried like an API's; a transient one reads
// the page, and one that holds through every retry is kept as evidence of
// that page, never a failed read, without stopping other sites.
func TestWebRetries(t *testing.T) {
	w := newWorld(t)
	var flaky atomic.Int32
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/flaky" && flaky.Add(1) == 1:
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		case r.URL.Path == "/busy":
			rw.WriteHeader(http.StatusTooManyRequests)
			return
		}
		rw.Header().Set("Content-Type", "text/html")
		_, _ = rw.Write([]byte("<html>" + r.URL.Path))
	})
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/", "/flaky", "/busy"}}}
	g := w.gate()
	if res := g.Send(context.Background(), web("https", "shop.example.com", "/flaky")); !res.OK() || res.Response.Status != 200 || flaky.Load() != 2 {
		t.Errorf("a transient 503: %+v, %d attempts", res, flaky.Load())
	}
	before := srv.hits.Load()
	if res := g.Send(context.Background(), web("https", "shop.example.com", "/busy")); !res.OK() || res.Response.Status != 429 || srv.hits.Load()-before != int32(len(retryDelays)+1) {
		t.Errorf("a 429 that holds: %+v after %d attempts", res, srv.hits.Load()-before)
	}
	if res := g.Send(context.Background(), web("https", "shop.example.com", "/")); !res.OK() || res.Response.Status != 200 {
		t.Errorf("a site's 429 stopped the next page: %+v", res)
	}
}
