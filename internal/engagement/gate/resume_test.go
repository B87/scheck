package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/b87/scheck/internal/policy"
)

// A resume reuses only a success with the same identity, and admits it
// again first: a request rate-limited before is sent again and kept, one
// refused under the file is refused again even with a success on record,
// a success is not resent, and a request whose principal is not the one on
// record is sent (E4 test 20).
func TestResume(t *testing.T) {
	w := newWorld(t)
	var limited atomic.Bool
	limited.Store(true)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		if limited.Load() {
			switch r.URL.Path {
			case "/busy":
				rw.WriteHeader(http.StatusTooManyRequests)
				return
			case "/down":
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		rw.Header().Set("Content-Type", "text/html")
		_, _ = rw.Write([]byte("<html>" + r.URL.Path))
	})
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/", "/busy", "/down"}}}

	// The first run: one success; a 429 and a 503, which a web page keeps
	// as evidence of a page that was not read.
	first := w.gate()
	front := first.Send(context.Background(), web("https", "shop.example.com", "/"))
	if !front.OK() || front.Identity == "" {
		t.Fatalf("front page: %+v", front)
	}
	for _, p := range []string{"/busy", "/down"} {
		if res := first.Send(context.Background(), web("https", "shop.example.com", p)); res.Response == nil || res.Response.Status < 429 || res.Identity != "" {
			t.Fatalf("%s: %+v", p, res)
		}
	}
	hits := srv.hits.Load()

	// The resume: what succeeded is on record, nothing else.
	limited.Store(false)
	w.prior = map[string]*Response{front.Identity: front.Response}
	w.audit.b.Reset()
	again := w.gate()
	dials := w.dials.Load()
	w.mu.Lock()
	asked := len(w.queries)
	w.mu.Unlock()
	if res := again.Send(context.Background(), web("https", "shop.example.com", "/")); res.Decision != DecisionReused ||
		res.Identity != front.Identity || string(res.Response.Body) != "<html>/" {
		t.Errorf("a success is reused: %+v", res)
	}
	if srv.hits.Load() != hits || w.dials.Load() != dials {
		t.Errorf("a reused success was sent: %d hits, %d before; %d dials, %d before", srv.hits.Load(), hits, w.dials.Load(), dials)
	}
	// Its name is resolved again, and only that.
	w.mu.Lock()
	lookups := slices.Clone(w.queries[asked:])
	w.mu.Unlock()
	if len(lookups) == 0 || slices.ContainsFunc(lookups, func(q string) bool { return q != "shop.example.com." }) {
		t.Errorf("a reused request looked up %v", lookups)
	}
	for _, p := range []string{"/busy", "/down"} {
		if res := again.Send(context.Background(), web("https", "shop.example.com", p)); !res.OK() || res.Decision == DecisionReused ||
			string(res.Response.Body) != "<html>"+p || res.Identity == "" {
			t.Errorf("%s is sent again and kept: %+v", p, res)
		}
	}
	var reused []string
	sent := map[string]bool{}
	for _, e := range w.audit.entries(t) {
		switch e.Event {
		case DecisionReused:
			reused = append(reused, e.RequestID)
			if e.Decision != DecisionReused || e.OutputHash != hash([]byte("<html>/")) || e.Op != "web.get" || e.URL != "https://shop.example.com/" {
				t.Errorf("reused line %+v", e)
			}
		case "send", "result":
			sent[e.RequestID] = true
		}
	}
	if len(reused) != 1 || sent[reused[0]] {
		t.Errorf("reused lines %v, sent %v", reused, sent)
	}

	// A redact_extra added since reuses nothing: the page is read again
	// and redacted by today's rules.
	w.extra = append(slices.Clone(w.extra), `html>/`)
	if res := w.gate().Send(context.Background(), web("https", "shop.example.com", "/")); res.Decision == DecisionReused ||
		!res.OK() || strings.Contains(string(res.Response.Body), "html>/") || !strings.Contains(string(res.Response.Body), "[REDACTED:") {
		t.Errorf("a changed redact_extra: %+v", res)
	}
	w.extra = w.extra[:len(w.extra)-1]

	// A record that is not a page that was read (a redirect, a 429, a
	// 5xx), as a hand edit could leave one, is sent again.
	for _, status := range []int{http.StatusFound, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		edited := front.Response.clone()
		edited.Status = status
		w.prior = map[string]*Response{front.Identity: edited}
		hits = srv.hits.Load()
		if res := w.gate().Send(context.Background(), web("https", "shop.example.com", "/")); res.Decision == DecisionReused || srv.hits.Load() != hits+1 {
			t.Errorf("a %d on record: %+v", status, res)
		}
	}
	w.prior = map[string]*Response{front.Identity: front.Response}

	// The name now resolves into an excluded network: live resolution
	// refuses the success on record.
	w.scope.excludedNets = map[string]netip.Prefix{"exclude[1]": netip.MustParsePrefix("198.51.100.0/24")}
	hits = srv.hits.Load()
	if res := w.gate().Send(context.Background(), web("https", "shop.example.com", "/")); res.Decision != "refused:address_excluded" || res.Response != nil {
		t.Errorf("an address excluded since: %+v", res)
	}
	if srv.hits.Load() != hits {
		t.Error("an address excluded since was sent to")
	}
	w.scope.excludedNets = nil

	// The file now excludes the name: the success on record is refused
	// again, never handed back.
	w.scope.excluded = map[string]string{"domain:shop.example.com": "exclude[0]"}
	hits = srv.hits.Load()
	if res := w.gate().Send(context.Background(), web("https", "shop.example.com", "/")); res.Decision != "refused:excluded" || res.Response != nil {
		t.Errorf("a refused request is refused again: %+v", res)
	}
	if srv.hits.Load() != hits {
		t.Error("an excluded request was sent")
	}
}

// An answer that moved away from its first-party confirmation is refused
// on resume as on a fresh run.
func TestResumeChecksFirstPartyEvidence(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.40", 443, &cert, ok200("<html>"))
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/"}, Confirmed: []string{"/robots.txt"}, Target: "198.51.100.40"}}
	res := w.gate().Send(context.Background(), web("https", "shop.example.com", "/robots.txt"))
	if !res.OK() || res.Identity == "" {
		t.Fatalf("%+v", res)
	}
	w.prior = map[string]*Response{res.Identity: res.Response}
	w.serve("shop.example.com", "198.51.100.41", 443, &cert, ok200("<html>"))
	hits := srv.hits.Load()
	if again := w.gate().Send(context.Background(), web("https", "shop.example.com", "/robots.txt")); again.Decision != "refused:address_moved" || again.Response != nil {
		t.Errorf("moved since: %+v", again)
	}
	if srv.hits.Load() != hits {
		t.Error("a moved name was sent to")
	}
}

// A request's identity is its op as compiled, asset, bound parameters,
// whether its subject is known to exist, principal and redaction rules,
// never the token. A list, an op that names users and a request whose
// principal is not known have none, so they are always sent.
func TestIdentity(t *testing.T) {
	w := newWorld(t)
	g := w.gate()
	repoOp, webOp := g.reg.ops["github.repo"], g.reg.ops["web.get"]
	asset := "saas:github:example-org"
	params := map[string]string{"owner": "example-org", "repo": "app"}
	req := Request{Op: "github.repo", Asset: asset}
	alice := &Credential{Principal: "alice", Scopes: []string{"repo", "read:org"}, secret: testToken}
	base := g.identity(repoOp, req, params, alice)
	if base == "" {
		t.Fatal("a known principal has an identity")
	}
	same := &Credential{Principal: "alice", Scopes: []string{"read:org", "repo"}, secret: "another-token-0123456789"}
	if got := g.identity(repoOp, req, params, same); got != base {
		t.Error("the token, or the order of scopes, changed the identity")
	}
	w.extra = append(slices.Clone(w.extra), "tangerine")
	otherRules := w.gate()
	changedOp := *repoOp
	changedOp.Keep = []string{"name", "private"}
	for name, got := range map[string]string{
		"another principal": g.identity(repoOp, req, params, &Credential{Principal: "bob", Scopes: alice.Scopes}),
		"other scopes":      g.identity(repoOp, req, params, &Credential{Principal: "alice", Scopes: []string{"repo"}}),
		"another repo":      g.identity(repoOp, req, map[string]string{"owner": "example-org", "repo": "web"}, alice),
		"another asset":     g.identity(repoOp, Request{Op: "github.repo", Asset: "saas:github:other-org"}, params, alice),
		"known to exist":    g.identity(repoOp, Request{Op: "github.repo", Asset: asset, Exists: true}, params, alice),
		"redact_extra":      otherRules.identity(repoOp, req, params, alice),
		"the op's fields":   g.identity(&changedOp, req, params, alice),
	} {
		if got == base || got == "" {
			t.Errorf("%s: identity %q", name, got)
		}
	}
	if got := g.identity(repoOp, req, params, &Credential{secret: testToken}); got != "" {
		t.Errorf("an unknown principal: %q", got)
	}
	// A build that names no commit, or carries uncommitted changes, cannot
	// be told from another: nothing it reads is reused.
	for _, v := range []string{"dev", "v0.0.1-25-g36101ea-dirty", ""} {
		if rulesFingerprint(v, nil) != "" {
			t.Errorf("version %q has a rules fingerprint", v)
		}
	}
	if rulesFingerprint("v0.0.1-25-g36101ea", nil) == "" || rulesFingerprint("v0.0.2", nil) == rulesFingerprint("v0.0.1", nil) {
		t.Error("a release build's rules fingerprint")
	}
	rules := g.rules
	g.rules = rulesFingerprint("dev", w.extra)
	if got := g.identity(repoOp, req, params, alice); got != "" {
		t.Errorf("a dev build: %q", got)
	}
	g.rules = rules
	for _, id := range []string{"github.org_repos", "ws.role_assignments", "ws.user_tokens", "ws.users"} {
		if got := g.identity(g.reg.ops[id], Request{Op: id, Asset: asset}, nil, alice); got != "" {
			t.Errorf("%s, filtered by what the gate finds now: %q", id, got)
		}
	}
	if got := g.identity(webOp, Request{Op: "web.get", Asset: "domain:example.com"}, map[string]string{"scheme": "https", "host": "example.com", "path": "/"}, nil); got == "" {
		t.Error("an anonymous read has an identity")
	}

	// Through the gate, a GitHub token's principal is not known in this
	// build, so a success on record is sent again whoever it was read as.
	// This proves an unknown principal resends; a changed one is proved by
	// the identity above, and through the gate once E5 reads the principal.
	w.env["GITHUB_TOKEN"] = testToken
	gh := w.github(ok200(`{"name":"app"}`))
	res := w.gate().Send(context.Background(), repo("example-org", "app"))
	if !res.OK() || res.Identity != "" {
		t.Fatalf("%+v", res)
	}
	w.prior = map[string]*Response{base: res.Response}
	if res := w.gate().Send(context.Background(), repo("example-org", "app")); res.Decision == DecisionReused || gh.hits.Load() != 2 {
		t.Errorf("an unknown principal resends: %+v after %d hits", res, gh.hits.Load())
	}
}

// A probe admitted inside its window whose wait for the throttle outlasts
// the window is refused before anything is dialled.
func TestWindowEndsDuringThrottleWait(t *testing.T) {
	ceiling = Probe
	t.Cleanup(func() { ceiling = Observe })
	w := newWorld(t)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, ok200("<html>"))
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/", "/.git/HEAD"}}}
	w.scope.throttles = map[string]throttle{"domain:example.com": {rate: 1, conc: 1}}
	var mu sync.Mutex
	clock := time.Now()
	w.windows = []Window{{From: clock.Add(-time.Minute), To: clock.Add(500 * time.Millisecond)}}
	g := w.gate()
	g.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	g.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		clock = clock.Add(d)
		mu.Unlock()
		return ctx.Err()
	}
	if res := g.Send(context.Background(), web("https", "shop.example.com", "/")); !res.OK() {
		t.Fatalf("the read that takes the throttle's slot: %+v", res)
	}
	dials := w.dials.Load()
	w.audit.b.Reset()
	res := g.Send(context.Background(), Request{Op: "web.probe", Asset: "domain:example.com", Params: map[string]string{"host": "shop.example.com"}})
	if res.Decision != "refused:window" || res.Reason != "limit_reached" {
		t.Errorf("%+v", res)
	}
	if w.dials.Load() != dials || srv.hits.Load() != 1 {
		t.Errorf("the probe was dialled: %d dials, %d before", w.dials.Load(), dials)
	}
	var refused []Entry
	for _, e := range w.audit.entries(t) {
		if e.Event == "refused" {
			refused = append(refused, e)
		}
	}
	if len(refused) != 1 || refused[0].Window == nil || *refused[0].Window != 0 {
		t.Errorf("refused lines %+v", refused)
	}
}

// Probe and above are admitted only inside an authorization window, checked
// per request, and the window's end cuts a request in flight; passive and
// observe are never checked (E4 test 21). The build admits no probe, so the
// test raises the ceiling for a test-only op.
func TestAuthorizationWindows(t *testing.T) {
	ceiling = Probe
	t.Cleanup(func() { ceiling = Observe })
	w := newWorld(t)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		_, _ = rw.Write([]byte("<html>"))
	})
	w.scope.sites = map[string]SitePaths{"https://shop.example.com": {Paths: []string{"/", "/.git/HEAD"}}}
	probe := Request{Op: "web.probe", Asset: "domain:example.com", Params: map[string]string{"host": "shop.example.com"}}

	now := time.Now()
	for name, windows := range map[string][]Window{
		"no window":    nil,
		"a past one":   {{From: now.Add(-2 * time.Hour), To: now.Add(-time.Hour)}},
		"a future one": {{From: now.Add(time.Hour), To: now.Add(2 * time.Hour)}},
	} {
		w.windows = windows
		if res := w.gate().Send(context.Background(), probe); res.Decision != "refused:window" || res.Reason != "limit_reached" {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if srv.hits.Load() != 0 || w.dials.Load() != 0 {
		t.Fatalf("a probe outside every window reached the server: %d hits, %d dials", srv.hits.Load(), w.dials.Load())
	}
	if res := w.gate().Send(context.Background(), web("https", "shop.example.com", "/")); !res.OK() {
		t.Errorf("an observe read outside every window: %+v", res)
	}

	w.windows = []Window{{From: now.Add(-2 * time.Hour), To: now.Add(-time.Hour)}, {From: now.Add(-time.Minute), To: time.Now().Add(300 * time.Millisecond)}}
	w.audit.b.Reset()
	start := time.Now()
	res := w.gate().Send(context.Background(), probe)
	if res.Decision != "unavailable:window_ended" || res.Reason != "limit_reached" {
		t.Errorf("inside a window: %+v", res)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the window's end did not cut the request: %s", d)
	}
	sent, probes := false, 0
	for _, r := range srv.requests() {
		if r.URL.Path == "/.git/HEAD" {
			probes++
		}
	}
	for _, e := range w.audit.entries(t) {
		if e.Event == "send" {
			sent = true
			if e.Window == nil || *e.Window != 1 {
				t.Errorf("send line %+v names window %v, want 1", e, e.Window)
			}
		}
	}
	if !sent || probes != 1 {
		t.Errorf("the probe was not sent once inside its window: %d probes", probes)
	}
}

// What a run directory keeps of a success reads back as the same answer, and
// a resumed session numbers its requests apart from the first's in the
// run's one audit log.
func TestKeptSuccessRoundTrip(t *testing.T) {
	w := newWorld(t)
	cert := w.leaf([]string{"shop.example.com"}, time.Now().Add(time.Hour), false)
	srv := w.serve("shop.example.com", "198.51.100.30", 443, &cert, ok200("<html>"))
	g := w.gate()
	res := g.Send(context.Background(), web("https", "shop.example.com", "/"))
	kept := g.Successes()
	if !res.OK() || len(kept) != 1 || kept[res.Identity] == nil {
		t.Fatalf("%+v, kept %v", res, kept)
	}
	b, err := json.Marshal(kept[res.Identity])
	if err != nil {
		t.Fatal(err)
	}
	var back Response
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	w.prior = map[string]*Response{res.Identity: &back}
	again, err := New(Config{Registry: g.reg, Scope: w.scope, RedactExtra: w.extra, Audit: policy.NewAudit(w.audit),
		Version: "test", Getenv: func(string) string { return "" }, Net: w.net(), Prior: w.prior, Session: 2})
	if err != nil {
		t.Fatal(err)
	}
	r := again.Send(context.Background(), web("https", "shop.example.com", "/"))
	if r.Decision != DecisionReused || string(r.Response.Body) != string(res.Response.Body) || r.Response.Status != res.Response.Status ||
		r.Response.Header.Get("Content-Type") != res.Response.Header.Get("Content-Type") || srv.hits.Load() != 1 {
		t.Errorf("read back: %+v", r)
	}
	if !strings.HasPrefix(r.RequestID, "g2-") || strings.HasPrefix(res.RequestID, "g2-") {
		t.Errorf("request ids %s and %s", res.RequestID, r.RequestID)
	}
	if len(again.Successes()) != 0 {
		t.Error("a reused answer is kept again")
	}
	if got := again.Reused(); len(got) != 1 || got[0] != res.Identity {
		t.Errorf("reused identities %v", got)
	}
}
