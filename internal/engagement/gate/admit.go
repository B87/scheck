package gate

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// admitted is a request that passed every check up to the send.
type admitted struct {
	b     *bound
	prov  provider
	cred  *Credential
	addrs []netip.Addr
	depth int // redirect hops behind the request
	// firstParty says a web request was admitted on first-party evidence,
	// not only as a domain root's front page.
	firstParty bool
	// prev is the list page this request follows, for its number and the
	// excluded-subject set a users list is building.
	prev *page
	// windowEnd is the end of the authorization window a probe was
	// admitted in, which cuts it in flight; zero below probe.
	windowEnd time.Time
}

// ceiling is the highest level admitted in this build, whatever the
// registry declares (docs/spec/scope.md, "Admission"). Only a test raises
// it, to prove the window check on a test-only probe op.
var ceiling = Observe

// retry says an attempt may be tried again, and what it ends as if it is
// not.
type retry struct {
	provider string
	// after is the provider's Retry-After; 0 backs off.
	after time.Duration
	// rateLimit says the provider asked scheck to slow down; when the
	// retries run out, or the wait is longer than the gate honours, the
	// provider stops (docs/spec/scope.md, "Throttle, timeouts and retries").
	rateLimit bool
	// code is the unavailable code when the retries of anything else run
	// out.
	code   string
	detail string
	// evidence keeps the last answer when the retries run out: a web
	// site's status is what the site serves, not a failed read.
	evidence bool
}

// exhausted ends a request whose retries ran out.
func (g *Gate) exhausted(res Result, r *retry) Result {
	if r.evidence {
		return res
	}
	if r.rateLimit {
		detail := fmt.Sprintf("%s's rate limit held through %d retries", sourceName(r.provider), len(retryDelays))
		g.stopProvider(r.provider, detail, time.Time{})
		res.Reason, res.Detail = "limit_reached", detail
		return res
	}
	// The detail is a transport error's text, which names the URL: redacted
	// as the result line's was.
	res.end("unavailable:"+r.code, g.redact(r.detail))
	return res
}

// cutRetry ends a request whose next wait would pass limits.timeout or the
// longest Retry-After the gate honours. The retry that is not sent gets its
// own refused line, so the audit log says how the request ended.
func (g *Gate) cutRetry(r Request, first string, n int, res Result, rt *retry, wait time.Duration, asked bool) Result {
	past := g.pastDeadline(g.now().Add(wait))
	var detail string
	switch {
	case asked && past:
		detail = fmt.Sprintf("%s asked scheck to wait %s, past limits.timeout", sourceName(rt.provider), wait.Round(time.Second))
	case asked:
		detail = fmt.Sprintf("%s asked scheck to wait %s, longer than the %s it waits", sourceName(rt.provider), wait.Round(time.Second), maxRetryAfter)
	default:
		detail = fmt.Sprintf("retrying after %s would pass limits.timeout", wait.Round(time.Second))
	}
	rule := "deadline"
	if !past {
		if !rt.rateLimit {
			return g.exhausted(res, rt)
		}
		rule = "rate_limit"
	}
	if rt.rateLimit {
		g.stopProvider(rt.provider, detail, g.now().Add(wait))
	}
	e := Entry{Event: "refused", RequestID: g.nextID(), Stage: r.Stage, Asset: r.Asset, Op: r.Op, Attempt: n, RetryOf: first,
		Decision: "refused:" + rule, Detail: detail}
	_ = g.record(e)
	out := Result{RequestID: e.RequestID, Response: res.Response}
	out.end(e.Decision, detail)
	if asked {
		out.Until = g.now().Add(wait)
	}
	return out
}

func (g *Gate) stopProvider(p, detail string, until time.Time) {
	if providers[p].web {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.stopped[p]; !ok {
		g.stopped[p] = stop{detail: detail, until: until}
	}
}

func sourceName(p string) string {
	if name := providers[p].display; name != "" {
		return name
	}
	return p
}

// reasons is the table a decision's coverage reason comes from
// (docs/spec/scope.md, "Outcomes"), for every decision but sent, whose
// reason its status decides (classify). A decision it does not list is its
// own reason when unavailable, and a refusal a collector should never trip
// is a defect, reported as refused_by_gate.
var reasons = map[string]string{
	"refused:excluded":           "excluded_by_operator",
	"refused:address_excluded":   "excluded_by_operator",
	"refused:address_not_public": "unavailable:address_not_public",
	"refused:address_moved":      "unavailable:address_moved",
	"refused:no_credentials":     "no_credentials",
	// A window bounds probes as limits.timeout bounds the run.
	"refused:deadline":         "limit_reached",
	"refused:rate_limit":       "limit_reached",
	"refused:canceled":         "limit_reached",
	"refused:window":           "limit_reached",
	"unavailable:deadline":     "limit_reached",
	"unavailable:window_ended": "limit_reached",
	"unavailable:canceled":     "limit_reached",
}

// ReasonOf is a decision's coverage reason, "" for one that read something:
// what a collector reports for a read the gate refused or could not make.
func ReasonOf(decision string) string { return reasonOf(decision) }

// reasonOf is a decision's coverage reason, "" for one that read something.
func reasonOf(decision string) string {
	if r, ok := reasons[decision]; ok {
		return r
	}
	switch {
	case strings.HasPrefix(decision, "unavailable:"):
		return decision
	case strings.HasPrefix(decision, "refused:"):
		return "unavailable:refused_by_gate"
	}
	return ""
}

// end sets a result's decision, its reason from the table, and its detail.
func (r *Result) end(decision, detail string) {
	r.Decision, r.Reason, r.Detail = decision, reasonOf(decision), detail
}

// pending is a request on its way through admission: what each step
// found, for the steps after it.
type pending struct {
	r    Request
	e    Entry
	op   *compiled
	prov provider
	b    *bound
	// prev is the list page the request follows; hopDepth the redirect
	// hops behind it.
	prev     *page
	hopDepth int
	// site is a web request's admission at steps 7 and 8, settled again
	// at step 12 when it waits on the lookup.
	site      Admission
	windowEnd time.Time
	cred      *Credential
	addrs     []netip.Addr
	// key is the request's identity for resume.
	key string
	// cleanup runs when the attempt ends, in reverse.
	cleanup []func()
}

// halt ends a request before it is sent: decision is refused:<rule> or
// unavailable:<code>, as the audit line has it.
type halt struct {
	decision, detail string
	// until is when a stopped provider's rate limit resets.
	until time.Time
}

func refused(rule, detail string) *halt { return &halt{decision: "refused:" + rule, detail: detail} }

// attempt admits one attempt in the order of docs/spec/scope.md,
// "Admission", and sends it. The first failed check ends it with an audit
// line. On a resume, a request with a success on record is answered from
// it after step 12 and is not sent.
func (g *Gate) attempt(ctx context.Context, r Request, id, retryOf string, n int) (Result, *retry) {
	p := &pending{r: r, e: Entry{RequestID: id, Stage: r.Stage, Asset: r.Asset, Op: r.Op, Attempt: n, RetryOf: retryOf,
		RedirectOf: r.RedirectOf, NextOf: r.NextOf}}
	defer func() {
		for _, f := range slices.Backward(p.cleanup) {
			f()
		}
	}()
	for _, step := range []func(context.Context, *pending) *halt{
		g.registered,       // 1
		g.bindParams,       // 2
		g.followHop,        // a redirect hop goes where its 3xx pointed
		g.admitSubject,     // 3–5
		g.admitUsers,       // the excluded-subject set is known
		g.admitLevel,       // 6
		g.admitPath,        // 7–8
		g.admitWindow,      // 9
		g.attachCredential, // 10
		g.admitTime,        // 11
		g.admitAddresses,   // 12
	} {
		if h := step(ctx, p); h != nil {
			return g.halted(p, h), nil
		}
	}
	if res, ok := g.answerFromPrior(p); ok {
		return res, nil
	}
	if h := g.waitThrottle(ctx, p); h != nil { // 13
		return g.halted(p, h), nil
	}
	// 14. The audit line is written, then the request is sent.
	res, rt := g.send(ctx, p.e, admitted{b: p.b, prov: p.prov, cred: p.cred, addrs: p.addrs, depth: p.hopDepth, prev: p.prev,
		firstParty: p.site.FirstParty, windowEnd: p.windowEnd}, r)
	g.bindPrincipal(p.op, p.cred, res)
	if reusable(res) && p.key != "" {
		res.Identity = p.key
		g.mu.Lock()
		g.kept[p.key] = res.Response.clone()
		g.mu.Unlock()
	}
	return res, rt
}

// halted writes a halted request's audit line and its result. A genuine
// hop off scope is where an SSO login or a hosted storefront leads: a
// coverage gap, not a collector's defect; an excluded hop stays excluded.
func (g *Gate) halted(p *pending, h *halt) Result {
	decision := h.decision
	if p.r.RedirectOf != "" {
		switch decision {
		case "refused:out_of_scope":
			decision = "unavailable:redirect_out_of_scope"
		case "refused:entry_point":
			// The commonest redirect there is (/ → /en/): the 3xx is the
			// evidence, and the page it leads to is not an entry point.
			decision = "unavailable:redirect_not_entry_point"
		}
	}
	p.e.Event = "refused"
	res := Result{RequestID: p.e.RequestID, Until: h.until}
	res.end(decision, g.redact(h.detail))
	p.e.Decision, p.e.Detail = res.Decision, res.Detail
	_ = g.record(p.e)
	return res
}

// registered is step 1: the op is registered.
func (g *Gate) registered(_ context.Context, p *pending) *halt {
	op, ok := g.reg.ops[p.r.Op]
	if !ok {
		return refused("unknown_op", "the op is not registered")
	}
	p.op, p.prov = op, providers[op.Provider]
	p.e.Level, p.e.Method = op.Level.String(), string(op.Method)
	if !p.prov.web {
		p.e.Source = p.prov.source
	}
	return nil
}

// bindParams is step 2: the parameters bind to their types. A list's
// cursor is never a collector's: the gate fills it from the page before,
// and the request repeats that page's parameters.
func (g *Gate) bindParams(_ context.Context, p *pending) *halt {
	op, r := p.op, p.r
	params := r.Params
	if l := op.List; l != nil && l.Next != nil {
		if _, set := r.Params[l.Next.Param]; set {
			return refused("bind", fmt.Sprintf("parameter %q is filled by the gate from the page before", l.Next.Param))
		}
	}
	if r.NextOf != "" {
		g.mu.Lock()
		prev := g.pages[r.NextOf]
		mine := prev != nil && prev.asset == r.Asset && prev.op == r.Op
		busy := mine && prev.reading
		if mine && !busy {
			prev.reading = true
		}
		g.mu.Unlock()
		if !mine {
			return refused("bind", "next_of names no page this gate returned for the op and asset")
		}
		if busy {
			return refused("bind", "the page after it is already being read")
		}
		// Released when this attempt ends; a kept page has deleted it.
		p.prev = prev
		p.cleanup = append(p.cleanup, func() {
			g.mu.Lock()
			prev.reading = false
			g.mu.Unlock()
		})
		params = maps.Clone(r.Params)
		if params == nil {
			params = map[string]string{}
		}
		params[op.List.Next.Param] = prev.cursor
	}
	b, err := op.bind(params)
	if err != nil {
		return refused("bind", err.Error())
	}
	p.b = b
	p.e.Params, p.e.URL = b.params, auditURL(b)
	if p.prev != nil {
		p.e.Page = p.prev.n + 1
		rest := maps.Clone(b.params)
		delete(rest, op.List.Next.Param)
		if !maps.Equal(rest, p.prev.params) {
			return refused("bind", "a next page repeats the parameters of the page before")
		}
	}
	if op.Class == CredentialExchange {
		// Sent only by a credential source, which arrives with the
		// Workspace collector (0.0.2 E6).
		return refused("method", "a credential exchange is not a collector's request")
	}
	return nil
}

// followHop admits a redirect hop: it follows a 3xx the gate itself
// received for the same asset, to exactly where it pointed; a collector
// cannot invent one.
func (g *Gate) followHop(_ context.Context, p *pending) *halt {
	if p.r.RedirectOf == "" {
		return nil
	}
	g.mu.Lock()
	from, ok := g.redirects[p.r.RedirectOf]
	g.mu.Unlock()
	switch {
	case !ok || from.asset != p.r.Asset:
		return refused("redirect", "redirect_of names no redirect this gate received for the asset")
	case from.target != canonicalURL(p.b.url):
		return refused("redirect", "the hop is not where the redirect pointed")
	case from.depth+1 > maxRedirects:
		return refused("redirect_depth", fmt.Sprintf("more than %d redirects", maxRedirects))
	}
	p.hopDepth = from.depth + 1
	return nil
}

// admitSubject is steps 3–5: the destination is classed by its provider;
// the subject falls under a root and no exclude. A principal op reads the
// credential, so its asset is what must be in scope.
func (g *Gate) admitSubject(_ context.Context, p *pending) *halt {
	subject := p.b.subject
	if subject == "" {
		subject = p.r.Asset
	}
	if rule, detail := g.placeSubject(p.r.Asset, subject); rule != "" {
		return refused(rule, detail)
	}
	return nil
}

// admitUsers holds a request that names or lists users until the
// excluded-subject set is known: unknown, nothing it returned could be
// filtered, so it is not sent (docs/spec/scope.md, "Exclusion in
// responses"). A user the set excludes is refused.
func (g *Gate) admitUsers(_ context.Context, p *pending) *halt {
	if !p.op.users {
		return nil
	}
	if !g.usersKnown(p.r.Asset) {
		return &halt{decision: "unavailable:" + codeExclusionUnkn, detail: codeDetail(codeExclusionUnkn, 0)}
	}
	set := g.excludedUsers(p.r.Asset)
	for name, prm := range p.op.types {
		if prm.Type != UserKey {
			continue
		}
		switch rule := set.rule(p.b.params[name]); rule {
		case "":
		case "unattributable":
			return refused("excluded", "the users list did not place this user in a unit, so it may be excluded")
		default:
			return refused("excluded", rule)
		}
	}
	return nil
}

// admitLevel is step 6: only passive and observe are admitted in 0.0.2,
// whatever the registry declares (docs/spec/scope.md, "Admission").
func (g *Gate) admitLevel(_ context.Context, p *pending) *halt {
	if p.op.Level > ceiling {
		return refused("level", p.op.Level.String()+" is not admitted in this build")
	}
	return nil
}

// admitPath is steps 7 and 8: a web request reads an entry point, and a
// path beyond the front page has the first-party evidence it needs, from
// the file or, at step 12, from the lookup (Scope.Admits).
func (g *Gate) admitPath(_ context.Context, p *pending) *halt {
	if !p.prov.web {
		return nil
	}
	path := p.b.url.EscapedPath()
	p.site = g.scope.Admits(origin(p.b), path, nil)
	if p.site.Refused != "" {
		return refused(p.site.Refused, path+" is not an entry point of "+p.b.url.Host)
	}
	return nil
}

// origin is a web request's scheme://host[:port], as Scope.Admits takes it.
func origin(b *bound) string { return b.url.Scheme + "://" + b.url.Host }

// admitWindow is step 9: probe and above are inside an authorization
// window, checked on every request (docs/spec/scope.md, "Authorization
// windows").
func (g *Gate) admitWindow(_ context.Context, p *pending) *halt {
	if p.op.Level < Probe {
		return nil
	}
	i := g.window(g.now())
	if i < 0 {
		return refused("window", "the time is outside every authorization window")
	}
	p.e.Window, p.windowEnd = &i, g.windows[i].To
	return nil
}

// attachCredential is step 10: a credential is present when the op binds
// one.
func (g *Gate) attachCredential(_ context.Context, p *pending) *halt {
	if p.op.Auth == NoAuth {
		return nil
	}
	cred, hint := g.credential(p.op.Auth)
	if cred == nil {
		return refused("no_credentials", hint)
	}
	if p.op.Class == Principal {
		g.mu.Lock()
		delete(g.principals, cred.secret)
		g.mu.Unlock()
		cred.Principal, cred.Scopes = "", nil
	}
	if p.op.Class == Principal && p.op.Provider == "github" && strings.HasPrefix(cred.secret, "ghs_") {
		return &halt{decision: "unavailable:unsupported_principal", detail: "GitHub installation-token principal resolution is not supported"}
	}
	p.cred, p.e.Principal = cred, cred.Principal
	return nil
}

// admitTime is step 11: time is left under limits.timeout, and the
// provider was not stopped for its rate limit.
func (g *Gate) admitTime(_ context.Context, p *pending) *halt {
	if g.pastDeadline(g.now()) {
		return refused("deadline", "limits.timeout passed")
	}
	g.mu.Lock()
	s, stopped := g.stopped[p.op.Provider]
	g.mu.Unlock()
	if stopped {
		h := refused("rate_limit", s.detail)
		h.until = s.until
		return h
	}
	return nil
}

// admitAddresses is step 12: the name is resolved now, and every address
// passes; a path that waits on the lookup for its evidence is settled.
func (g *Gate) admitAddresses(ctx context.Context, p *pending) *halt {
	l, h := g.addresses(ctx, p.e, p.b)
	if h != nil {
		return h
	}
	p.addrs = sortAddrs(l.Addrs)
	if p.site.Resolve {
		path := p.b.url.EscapedPath()
		p.site = g.scope.Admits(origin(p.b), path, &l)
		switch {
		case p.site.Refused == "address_moved", p.site.Resolve && p.site.Refused == "":
			// An answer that still waits on the lookup holds no evidence.
			return refused("address_moved", p.b.name+" no longer points where its first-party evidence says")
		case p.site.Refused != "":
			return refused(p.site.Refused, path+" is not an entry point of "+p.b.url.Host)
		}
	}
	return nil
}

// answerFromPrior answers a request from the earlier run's success with the
// same identity, once every check above, live resolution included, has
// admitted it again: a request refused before is refused again, and
// nothing is sent to the target (docs/spec/scope.md, "Resume").
func (g *Gate) answerFromPrior(p *pending) (Result, bool) {
	p.key = g.identity(p.op, p.r, p.b.params, p.cred)
	// A record is checked as a send is before it is kept: a resume's
	// records come from stage files the operator may have edited.
	prior, ok := g.prior[p.key]
	if !ok || p.key == "" || prior == nil || (p.op.Provider == "web" && prior.Vantage != g.vantage) || !reusable(Result{Response: prior}) {
		return Result{}, false
	}
	e := p.e
	e.Event, e.Decision, e.Status, e.OutputHash = DecisionReused, DecisionReused, prior.Status, prior.hash
	if prior.Body != nil {
		e.OutputHash = hash(prior.Body)
	}
	if err := g.record(e); err != nil {
		res := Result{RequestID: e.RequestID}
		res.end("unavailable:audit_failed", "the audit log could not be written")
		return res, true
	}
	g.mu.Lock()
	g.reused[p.key] = true
	g.observations[e.RequestID] = Observation{CollectedAt: prior.CollectedAt, Vantage: prior.Vantage}
	g.mu.Unlock()
	return Result{RequestID: e.RequestID, Decision: DecisionReused, Response: prior.clone(), Identity: p.key}, true
}

// waitThrottle is step 13: the throttle admits the request; the address's
// own throttle is taken at the dial, for the address actually dialled.
func (g *Gate) waitThrottle(ctx context.Context, p *pending) *halt {
	release, err := g.throttle(ctx, p.r.Asset, p.op, p.prov)
	if err != nil {
		if g.pastDeadline(g.now()) {
			return refused("deadline", "limits.timeout passed while waiting for the throttle")
		}
		return refused("canceled", "the run was cancelled while waiting for the throttle")
	}
	p.cleanup = append(p.cleanup, release)
	// The wait for the throttle, and the lookup before it, may have
	// outlasted the window.
	if !p.windowEnd.IsZero() && !g.now().Before(p.windowEnd) {
		return refused("window", "the authorization window ended before the request was sent")
	}
	return nil
}

// placeSubject places a request's or a lookup's subject: it falls under a
// root and under the request's asset, and no exclude covers it. It returns
// the refusal rule and its detail, or "".
func (g *Gate) placeSubject(asset, subject string) (string, string) {
	st := g.scope.Subject(asset, subject)
	switch {
	case !st.UnderAsset || st.Root == "":
		return "out_of_scope", subject + " is outside every root or the request's asset"
	case st.ExcludedBy != "":
		return "excluded", st.ExcludedBy
	}
	return "", ""
}

// addresses resolves the request's name, unless it is an address literal,
// and checks every address in the answer, not only the one it will dial
// (docs/spec/scope.md, "Addresses"). It returns the lookup as answered, or
// what halted the request: a refusal, or unavailable when the name did not
// resolve.
func (g *Gate) addresses(ctx context.Context, e Entry, b *bound) (Lookup, *halt) {
	var l Lookup
	if a, err := netip.ParseAddr(b.name); err == nil {
		if g.redactsAddr([]netip.Addr{a}) {
			return l, &halt{decision: "unavailable:dns_error"}
		}
		l = Lookup{Name: b.name, Addrs: []netip.Addr{a}, Outcome: OutcomeAddresses}
		l.target = l.Target()
	} else {
		var code string
		l, code = g.resolve(ctx, e, b.name)
		if l.Outcome == OutcomeExcluded {
			return l, refused("excluded", b.name+" points into "+l.ExcludedBy)
		}
		if code != "" {
			return l, &halt{decision: "unavailable:" + code}
		}
	}
	for _, a := range sortAddrs(l.Addrs) {
		excludedBy, inNetwork := g.scope.Address(a)
		switch class := classify(a); {
		case class == never:
			return l, refused("address_not_public", b.name+" resolves to "+a.String()+", which scheck never contacts")
		case excludedBy != "":
			return l, refused("address_excluded", b.name+" resolves into "+excludedBy)
		case class == notPublic && !inNetwork:
			return l, refused("address_not_public", b.name+" resolves to "+a.String()+", outside every network root")
		}
	}
	return l, nil
}

// resolve looks a request's name up with the gate's DNS client
// (docs/spec/scope.md, "The resolver"), as discovery does: the address it
// checks is the address it dials, and the query is counted where the report
// says what left the machine. A name that does not resolve is nxdomain,
// whether it is gone or has no address.
func (g *Gate) resolve(ctx context.Context, e Entry, name string) (Lookup, string) {
	l := g.lookup(ctx, e, name)
	switch l.Outcome {
	case OutcomeAddresses:
		return l, ""
	case OutcomeNXDomain, OutcomeNoData:
		return l, "nxdomain"
	case OutcomeTimeout:
		return l, "dns_timeout"
	case OutcomeDeadline, OutcomeCanceled, OutcomeAuditFailed, OutcomeNoResolver:
		return l, string(l.Outcome)
	}
	return l, "dns_error"
}

// throttle waits for the provider's compiled ceiling and, when the asset
// sets its own throttle, for that too: one asset's lower throttle never
// binds another's (docs/spec/scope.md, "Throttle, timeouts and retries").
// A web asset without a throttle of its own takes the default.
func (g *Gate) throttle(ctx context.Context, asset string, op *compiled, prov provider) (func(), error) {
	ctx, cancel := g.withDeadline(ctx, 0)
	defer cancel()
	rate, conc := g.scope.Throttle(asset)
	if prov.web && rate <= 0 {
		rate, conc = 5, 2
	}
	var releases []func()
	done := func() {
		for _, release := range slices.Backward(releases) {
			release()
		}
	}
	// The asset's own throttle first: waiting for its tick while holding the
	// provider's slot would make every other asset of that provider wait too.
	if rate > 0 || conc > 0 {
		if conc <= 0 {
			// A rate alone bounds no more requests in flight than the
			// provider's ceiling already does.
			conc = max(prov.concurrency, 1)
		}
		rel, err := g.limits.get("asset:"+asset, rate, conc).acquire(ctx, g.now, g.sleep)
		if err != nil {
			return nil, err
		}
		releases = append(releases, rel)
	}
	if !prov.web {
		rel, err := g.limits.get("provider:"+op.Provider, prov.rate, prov.concurrency).acquire(ctx, g.now, g.sleep)
		if err != nil {
			done()
			return nil, err
		}
		releases = append(releases, rel)
	}
	return done, nil
}

// withDeadline bounds ctx by the run's deadline and, when d > 0, by d.
func (g *Gate) withDeadline(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	end := g.deadline
	if d > 0 && (end.IsZero() || g.now().Add(d).Before(end)) {
		end = g.now().Add(d)
	}
	if end.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, end)
}

// auditURL is the URL as the audit line shows it: scheme, host and path,
// and the query, whose values are all declared typed parameters.
func auditURL(b *bound) string {
	return strings.TrimSuffix(b.url.String(), "?")
}
