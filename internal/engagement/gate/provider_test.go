package gate

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The token is attached by the gate, only to the provider's ops, and
// redacted by its value wherever the provider echoes it: in a body, a kept
// header and the audit log (E4 tests 13 and 14).
func TestCredentialIsAttachedAndRedacted(t *testing.T) {
	const token = "opaque-token-0123456789"
	w := newWorld(t)
	w.env["GH_TOKEN"] = token
	gh := w.github(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-OAuth-Scopes", "repo, "+token)
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"name":"shop","echo":"` + r.Header.Get("Authorization") + `"}`))
	})
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	site := w.serve("www.example.com", "198.51.100.60", 443, &cert, ok200("<html>"))
	g := w.gate()

	res := g.Send(context.Background(), repo("example-org", "shop"))
	if !res.OK() {
		t.Fatalf("%+v", res)
	}
	if got := gh.requests()[0].Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("Authorization %q", got)
	}
	if s := string(res.Response.Body) + strings.Join(res.Response.Header["X-Oauth-Scopes"], ""); strings.Contains(s, token) ||
		!strings.Contains(s, "[REDACTED:credential:") {
		t.Errorf("the token reached the response: %s", s)
	}
	if res := g.Send(context.Background(), web("https", "www.example.com", "/")); !res.OK() {
		t.Fatalf("%+v", res)
	}
	if got := site.requests()[0].Header.Get("Authorization"); got != "" {
		t.Errorf("a web asset was sent %q", got)
	}
	if strings.Contains(w.audit.String(), token) {
		t.Error("the token reached the audit log")
	}
}

// No credential refuses the op before contact, naming the fix; a
// credential the provider rejects is a refusal of kind access, naming the
// variable, never the value (E4 test 24).
func TestMissingAndRejectedCredential(t *testing.T) {
	w := newWorld(t)
	gh := w.github(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusUnauthorized) })
	res := w.gate().Send(context.Background(), repo("example-org", "shop"))
	if res.Decision != "refused:no_credentials" || res.Reason != "no_credentials" || !strings.Contains(res.Detail, "GITHUB_TOKEN nor GH_TOKEN") {
		t.Errorf("no token: %+v", res)
	}
	if gh.hits.Load() != 0 || w.dials.Load() != 0 {
		t.Error("a request without its credential was sent")
	}
	w.env["GITHUB_TOKEN"] = "revoked-token-value-0123"
	res = w.gate().Send(context.Background(), repo("example-org", "shop"))
	if res.Reason != "refused" || res.Kind != "access" || !strings.Contains(res.Detail, "GITHUB_TOKEN") ||
		strings.Contains(res.Detail, "revoked-token-value-0123") {
		t.Errorf("rejected: %+v", res)
	}
}

// A rate limit is not a permission error: a used-up GitHub limit stops the
// provider, and every later request is refused without contact; a
// Retry-After past the deadline ends at once; the remaining floor stops
// GitHub before it is used up (E4 test 16).
func TestRateLimits(t *testing.T) {
	t.Run("used up", func(t *testing.T) {
		w := newWorld(t)
		w.env["GITHUB_TOKEN"] = testToken
		reset := time.Now().Add(20 * time.Minute).Unix()
		gh := w.github(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("X-RateLimit-Remaining", "0")
			rw.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
			rw.WriteHeader(http.StatusForbidden)
		})
		g := w.gate()
		res := g.Send(context.Background(), repo("example-org", "shop"))
		if res.Reason != "limit_reached" || res.Until.Unix() != reset {
			t.Fatalf("%+v", res)
		}
		next := g.Send(context.Background(), repo("example-org", "web"))
		if next.Decision != "refused:rate_limit" || next.Reason != "limit_reached" || gh.hits.Load() != 1 {
			t.Errorf("after the limit: %+v, %d hits", next, gh.hits.Load())
		}
	})
	t.Run("Retry-After past the deadline", func(t *testing.T) {
		w := newWorld(t)
		w.env["GITHUB_TOKEN"] = testToken
		w.deadline = time.Now().Add(time.Minute)
		w.github(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Retry-After", "120")
			rw.WriteHeader(http.StatusTooManyRequests)
		})
		res := w.gate().Send(context.Background(), repo("example-org", "shop"))
		if res.Reason != "limit_reached" || !strings.Contains(res.Detail, "past limits.timeout") {
			t.Fatalf("%+v", res)
		}
		for _, d := range w.sleeps {
			if d >= time.Second {
				t.Errorf("waited %s for a Retry-After past the deadline", d)
			}
		}
	})
	t.Run("floor", func(t *testing.T) {
		w := newWorld(t)
		w.env["GITHUB_TOKEN"] = testToken
		gh := w.github(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("X-RateLimit-Limit", "5000")
			rw.Header().Set("X-RateLimit-Remaining", "999")
			ok200(`{"name":"shop"}`)(rw, nil)
		})
		g := w.gate()
		if res := g.Send(context.Background(), repo("example-org", "shop")); !res.OK() {
			t.Fatalf("%+v", res)
		}
		next := g.Send(context.Background(), repo("example-org", "web"))
		if next.Decision != "refused:rate_limit" || !strings.Contains(next.Detail, "leave a fifth") || gh.hits.Load() != 1 {
			t.Errorf("%+v", next)
		}
	})
}

// 429 and 502–504 are retried after 1, 4 and 16 s, each attempt admitted
// again and audited with retry_of; what is still failing ends as a limit
// or a server error.
func TestRetries(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	var n atomic.Int32
	w.github(func(rw http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= 2 {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ok200(`{"name":"shop"}`)(rw, nil)
	})
	res := w.gate().Send(context.Background(), repo("example-org", "shop"))
	if !res.OK() || n.Load() != 3 {
		t.Fatalf("%+v after %d attempts", res, n.Load())
	}
	var waits []time.Duration
	for _, d := range w.sleeps {
		if d >= 500*time.Millisecond {
			waits = append(waits, d)
		}
	}
	if len(waits) != 2 || waits[0] < 800*time.Millisecond || waits[0] > 1200*time.Millisecond ||
		waits[1] < 3200*time.Millisecond || waits[1] > 4800*time.Millisecond {
		t.Errorf("backoff %v", waits)
	}
	var sends []Entry
	for _, e := range w.audit.entries(t) {
		if e.Event == "send" {
			sends = append(sends, e)
		}
	}
	if len(sends) != 3 || sends[1].RetryOf != sends[0].RequestID || sends[2].Attempt != 3 {
		t.Errorf("send lines %+v", sends)
	}

	w2 := newWorld(t)
	w2.env["GITHUB_TOKEN"] = testToken
	w2.github(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusBadGateway) })
	if res := w2.gate().Send(context.Background(), repo("example-org", "shop")); res.Decision != "unavailable:server_error" {
		t.Errorf("still failing: %+v", res)
	}
}

// Statuses that mislead: a 404 on a subject a list returned is a
// permission gap, a 404 otherwise is evidence, and GitHub's SSO 403 names
// the authorization it needs (E4 test 17).
func TestPermissionTraps(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	w.github(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sso") {
			rw.Header().Set("X-GitHub-SSO", "required; url=https://github.com/orgs/example-org/sso?authorization_request=SECRETREQ")
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		rw.WriteHeader(http.StatusNotFound)
	})
	g := w.gate()
	known := repo("example-org", "shop")
	known.Exists = true
	if res := g.Send(context.Background(), known); res.Reason != "insufficient_permission" {
		t.Errorf("404 on a known repository: %+v", res)
	}
	if res := g.Send(context.Background(), repo("example-org", "maybe")); !res.OK() || res.Response.Status != 404 {
		t.Errorf("404 on an unknown one: %+v", res)
	}
	res := g.Send(context.Background(), repo("example-org", "sso"))
	if res.Reason != "insufficient_permission:sso_authorization" || !strings.Contains(res.Detail, "single sign-on") {
		t.Errorf("SSO: %+v", res)
	}
	if strings.Contains(strings.Join(res.Response.Header["X-Github-Sso"], ""), "SECRETREQ") {
		t.Error("the SSO URL kept its query")
	}
}

// limits.timeout cancels the request in flight and refuses the rest; the
// send line was written before the dial, so a request in flight is in the
// audit log (E4 tests 18 and 22).
func TestDeadlineAndAuditBeforeSend(t *testing.T) {
	w := newWorld(t)
	w.deadline = time.Now().Add(400 * time.Millisecond)
	inFlight := make(chan struct{})
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	w.serve("www.example.com", "198.51.100.70", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		close(inFlight)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	g := w.gate()
	done := make(chan Result)
	start := time.Now()
	go func() { done <- g.Send(context.Background(), web("https", "www.example.com", "/")) }()
	<-inFlight
	es := w.audit.entries(t)
	// The A and AAAA queries, each with its answer, then the send line.
	if len(es) != 5 || es[0].Event != "dns" || es[1].Event != "dns_answer" || es[2].Event != "dns" || es[3].Event != "dns_answer" ||
		es[4].Event != "send" || es[4].Decision != "sent" || es[4].URL != "https://www.example.com/" {
		t.Fatalf("while in flight, the audit log holds %+v", es)
	}
	send := es[4]
	res := <-done
	if res.Decision != "unavailable:deadline" || res.Reason != "limit_reached" || time.Since(start) > 3*time.Second {
		t.Fatalf("%+v after %s", res, time.Since(start))
	}
	if next := g.Send(context.Background(), web("https", "www.example.com", "/")); next.Decision != "refused:deadline" || next.Reason != "limit_reached" {
		t.Errorf("after the deadline: %+v", next)
	}
	last := w.audit.entries(t)
	if r := last[5]; r.Event != "result" || r.RequestID != send.RequestID || r.Decision != "unavailable:deadline" {
		t.Errorf("result line %+v", r)
	}
}

// Only allowlisted headers are kept, a cookie without its value; the
// engagement's redact_extra applies to bodies and headers; the User-Agent
// is scheck's own; a text body over its cap is cut and marked, JSON over
// its cap is not kept at all (E4 test 13, in part).
func TestResponseIsRedactedAndCut(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	cert := w.leaf([]string{"www.example.com"}, time.Now().Add(time.Hour), false)
	site := w.serve("www.example.com", "198.51.100.80", 443, &cert, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Set-Cookie", "session=COOKIEVALUE; Path=/; Secure; HttpOnly")
		rw.Header().Set("X-Internal-Debug", "db=prod-1")
		rw.Header().Set("Server", "nginx (internal.example.net)")
		rw.Header().Set("Content-Type", "text/html")
		_, _ = rw.Write([]byte("<html>see internal.example.net " + strings.Repeat("x", 400) + "</html>"))
	})
	w.github(ok200(`{"name":"` + strings.Repeat("y", 100) + `"}`))
	g := w.gate()
	res := g.Send(context.Background(), web("https", "www.example.com", "/"))
	if !res.OK() {
		t.Fatalf("%+v", res)
	}
	h, body := res.Response.Header, string(res.Response.Body)
	if h.Get("X-Internal-Debug") != "" || h.Get("Set-Cookie") != "session=[REDACTED:cookie:11 bytes]; Path=/; Secure; HttpOnly" {
		t.Errorf("headers %v", h)
	}
	if strings.Contains(h.Get("Server")+body, "internal.example.net") || !strings.Contains(body, "[REDACTED:extra:0:") ||
		!strings.Contains(h.Get("Server"), "[REDACTED:extra:0:") {
		t.Errorf("redact_extra: %q %q", h.Get("Server"), body)
	}
	if !res.Response.Truncated || !strings.HasSuffix(body, "bytes]") || !strings.Contains(body, "[TRUNCATED:") {
		t.Errorf("cut: %q", body)
	}
	if ua := site.requests()[0].Header.Get("User-Agent"); ua != "scheck/test (security self-assessment)" {
		t.Errorf("User-Agent %q", ua)
	}
	if strings.Contains(w.audit.String(), "COOKIEVALUE") || strings.Contains(w.audit.String(), "internal.example.net") {
		t.Error("the audit log holds what was redacted")
	}
	big := Request{Op: "github.org_repos", Asset: "saas:github:example-org", Params: map[string]string{"org": "example-org", "per_page": "100"}}
	if res := g.Send(context.Background(), big); res.Decision != "unavailable:response_too_large" || res.Response.Body != nil {
		t.Errorf("JSON over its cap: %+v", res)
	}
}

// A principal op reads the credential's own identity: its asset must be
// in scope, it has no subject of its own, and its URL takes no parameter.
func TestPrincipalOp(t *testing.T) {
	w := newWorld(t)
	w.env["GITHUB_TOKEN"] = testToken
	gh := w.github(ok200(`{"login":"ci-bot"}`))
	g := w.gate()
	if res := g.Send(context.Background(), Request{Op: "github.user", Asset: "saas:github:example-org"}); !res.OK() {
		t.Fatalf("%+v", res)
	}
	if res := g.Send(context.Background(), Request{Op: "github.user", Asset: "saas:github:other-org"}); res.Decision != "refused:out_of_scope" {
		t.Errorf("for an asset outside every root: %+v", res)
	}
	if p := gh.requests()[0].URL.Path; p != "/user" {
		t.Errorf("path %q", p)
	}
}
