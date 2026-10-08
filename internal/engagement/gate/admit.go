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
	res.Decision, res.Reason, res.Detail = "unavailable:"+r.code, "unavailable:"+r.code, r.detail
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
	out := Result{RequestID: e.RequestID, Decision: e.Decision, Reason: "limit_reached", Detail: detail, Response: res.Response}
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
	switch p {
	case "github":
		return "GitHub"
	case "google":
		return "Google"
	}
	return p
}

// refusalReason maps a refusal rule to its coverage reason
// (docs/spec/scope.md, "Outcomes"). A rule a collector should never trip is
// a defect, reported as refused_by_gate.
func refusalReason(rule string) string {
	switch rule {
	case "excluded", "address_excluded":
		return "excluded_by_operator"
	case "address_not_public", "address_moved":
		return "unavailable:" + rule
	case "no_credentials":
		return "no_credentials"
	case "deadline", "rate_limit", "canceled", "window":
		// A window bounds probes as limits.timeout bounds the run.
		return "limit_reached"
	}
	return "unavailable:refused_by_gate"
}

// attempt admits one attempt in the order of docs/spec/scope.md,
// "Admission", and sends it. The first failed check ends it with an audit
// line.
func (g *Gate) attempt(ctx context.Context, r Request, id, retryOf string, n int) (Result, *retry) {
	e := Entry{RequestID: id, Stage: r.Stage, Asset: r.Asset, Op: r.Op, Attempt: n, RetryOf: retryOf, RedirectOf: r.RedirectOf, NextOf: r.NextOf}
	hopDepth := 0
	refuse := func(rule, detail string) (Result, *retry) {
		decision, reason := "refused:"+rule, refusalReason(rule)
		// A genuine hop off scope is where an SSO login or a hosted
		// storefront leads: a coverage gap, not a collector's defect. An
		// excluded hop stays excluded.
		switch {
		case r.RedirectOf != "" && rule == "out_of_scope":
			decision, reason = "unavailable:redirect_out_of_scope", "unavailable:redirect_out_of_scope"
		case r.RedirectOf != "" && rule == "entry_point":
			// The commonest redirect there is (/ → /en/): the 3xx is the
			// evidence, and the page it leads to is not an entry point.
			decision, reason = "unavailable:redirect_not_entry_point", "unavailable:redirect_not_entry_point"
		}
		detail, _ = g.redactor.RedactString(detail)
		e.Event, e.Decision, e.Detail = "refused", decision, detail
		_ = g.record(e)
		return Result{RequestID: id, Decision: decision, Reason: reason, Detail: detail}, nil
	}
	// unavailable ends a request that is not sent for want of something
	// the run did not get, not for a rule it broke.
	unavailable := func(code, reason, detail string) (Result, *retry) {
		e.Event, e.Decision, e.Detail = "refused", "unavailable:"+code, detail
		_ = g.record(e)
		return Result{RequestID: id, Decision: e.Decision, Reason: reason, Detail: detail}, nil
	}

	// 1. The op is registered.
	op, ok := g.reg.ops[r.Op]
	if !ok {
		return refuse("unknown_op", "the op is not registered")
	}
	e.Level, e.Method = op.Level.String(), string(op.Method)
	prov := providers[op.Provider]
	if !prov.web {
		e.Source = prov.source
	}
	// 2. Its parameters bind to their types. A list's cursor is never a
	// collector's: the gate fills it from the page before, and the request
	// repeats that page's parameters.
	params, prev := r.Params, (*page)(nil)
	if l := op.List; l != nil && l.Next != nil {
		if _, set := r.Params[l.Next.Param]; set {
			return refuse("bind", fmt.Sprintf("parameter %q is filled by the gate from the page before", l.Next.Param))
		}
	}
	if r.NextOf != "" {
		g.mu.Lock()
		prev = g.pages[r.NextOf]
		mine := prev != nil && prev.asset == r.Asset && prev.op == r.Op
		busy := mine && prev.reading
		if mine && !busy {
			prev.reading = true
		}
		g.mu.Unlock()
		if !mine {
			return refuse("bind", "next_of names no page this gate returned for the op and asset")
		}
		if busy {
			return refuse("bind", "the page after it is already being read")
		}
		// Released when this attempt ends; a kept page has deleted it.
		defer func() {
			g.mu.Lock()
			prev.reading = false
			g.mu.Unlock()
		}()
		params = maps.Clone(r.Params)
		if params == nil {
			params = map[string]string{}
		}
		params[op.List.Next.Param] = prev.cursor
	}
	b, err := op.bind(params)
	if err != nil {
		return refuse("bind", err.Error())
	}
	e.Params, e.URL = b.params, auditURL(b)
	if prev != nil {
		e.Page = prev.n + 1
		rest := maps.Clone(b.params)
		delete(rest, op.List.Next.Param)
		if !maps.Equal(rest, prev.params) {
			return refuse("bind", "a next page repeats the parameters of the page before")
		}
	}
	if op.Class == CredentialExchange {
		// Sent only by a credential source, which arrives with the
		// Workspace collector (0.0.2 E6).
		return refuse("method", "a credential exchange is not a collector's request")
	}
	// A hop follows a 3xx the gate itself received for the same asset, to
	// exactly where it pointed; a collector cannot invent one.
	if r.RedirectOf != "" {
		g.mu.Lock()
		from, ok := g.redirects[r.RedirectOf]
		g.mu.Unlock()
		switch {
		case !ok || from.asset != r.Asset:
			return refuse("redirect", "redirect_of names no redirect this gate received for the asset")
		case from.target != canonicalURL(b.url):
			return refuse("redirect", "the hop is not where the redirect pointed")
		case from.depth+1 > maxRedirects:
			return refuse("redirect_depth", fmt.Sprintf("more than %d redirects", maxRedirects))
		}
		hopDepth = from.depth + 1
	}
	// 3–5. The destination is classed by its provider; the subject falls
	// under a root and no exclude. A principal op reads the credential,
	// so its asset is what must be in scope.
	subject := b.subject
	if subject == "" {
		subject = r.Asset
	}
	if rule, detail := g.admitSubject(r.Asset, subject); rule != "" {
		return refuse(rule, detail)
	}
	// A request that names or lists users waits for the excluded-subject
	// set: unknown, nothing it returned could be filtered, so it is not
	// sent (docs/spec/scope.md, "Exclusion in responses").
	if op.users {
		if !g.usersKnown(r.Asset) {
			return unavailable(codeExclusionUnkn, "unavailable:"+codeExclusionUnkn, codeDetail(codeExclusionUnkn, 0))
		}
		set := g.excludedUsers(r.Asset)
		for name, p := range op.types {
			if p.Type != UserKey {
				continue
			}
			switch rule := set.rule(b.params[name]); rule {
			case "":
			case "unattributable":
				return refuse("excluded", "the users list did not place this user in a unit, so it may be excluded")
			default:
				return refuse("excluded", rule)
			}
		}
	}
	// 6. Only passive and observe are admitted in 0.0.2, whatever the
	// registry declares (docs/spec/scope.md, "Admission").
	if op.Level > ceiling {
		return refuse("level", op.Level.String()+" is not admitted in this build")
	}
	// 7–8. A web request reads an entry point; a path beyond the front
	// page needs first-party evidence, from the file or, at step 12, from
	// a network root holding every address.
	var need evidenceNeed
	firstParty := false
	if prov.web {
		site := g.scope.Site(b.url.Scheme + "://" + b.url.Host)
		p := b.url.EscapedPath()
		switch {
		case slices.Contains(site.Paths, p):
			firstParty = site.FirstParty
		case slices.Contains(site.Network, p) || slices.Contains(site.Confirmed, p):
			// Held once step 12 has checked it.
			firstParty = true
			need.network = slices.Contains(site.Network, p)
			if slices.Contains(site.Confirmed, p) {
				need.target = site.Target
			}
		default:
			return refuse("entry_point", p+" is not an entry point of "+b.url.Host)
		}
	}
	// 9. Probe and above are inside an authorization window, checked on
	// every request (docs/spec/scope.md, "Authorization windows").
	var windowEnd time.Time
	if op.Level >= Probe {
		i := g.window(g.now())
		if i < 0 {
			return refuse("window", "the time is outside every authorization window")
		}
		e.Window, windowEnd = &i, g.windows[i].To
	}
	// 10. A credential is present when the op binds one.
	var cred *Credential
	if op.Auth != NoAuth {
		var hint string
		if cred, hint = g.credential(op.Auth); cred == nil {
			return refuse("no_credentials", hint)
		}
		e.Principal = cred.Principal
	}
	// 11. Time is left under limits.timeout, and the provider was not
	// stopped for its rate limit.
	if g.pastDeadline(g.now()) {
		return refuse("deadline", "limits.timeout passed")
	}
	g.mu.Lock()
	s, stopped := g.stopped[op.Provider]
	g.mu.Unlock()
	if stopped {
		res, _ := refuse("rate_limit", s.detail)
		res.Until = s.until
		return res, nil
	}
	// 12. The name is resolved now, and every address passes.
	addrs, rule, detail := g.addresses(ctx, e, b, need)
	if rule != "" {
		if rule == "unavailable" {
			reason := "unavailable:" + detail
			if detail == string(OutcomeDeadline) || detail == string(OutcomeCanceled) {
				reason = "limit_reached"
			}
			return unavailable(detail, reason, "")
		}
		return refuse(rule, detail)
	}
	// A resume answers a request from the earlier run's success with the
	// same identity, once every check above, live resolution included, has
	// admitted it again: a request refused before is refused again, and
	// nothing is sent to the target (docs/spec/scope.md, "Resume").
	key := g.identity(op, r, b.params, cred)
	// A record is checked as a send is before it is kept: a resume's
	// records come from stage files the operator may have edited.
	if prior, ok := g.prior[key]; ok && key != "" && prior != nil && reusable(Result{Response: prior}) {
		e.Event, e.Decision, e.Status, e.OutputHash = DecisionReused, DecisionReused, prior.Status, prior.hash
		if prior.Body != nil {
			e.OutputHash = hash(prior.Body)
		}
		if err := g.record(e); err != nil {
			return Result{RequestID: id, Decision: "unavailable:audit_failed", Reason: "unavailable:audit_failed",
				Detail: "the audit log could not be written"}, nil
		}
		g.mu.Lock()
		g.reused[key] = true
		g.mu.Unlock()
		return Result{RequestID: id, Decision: DecisionReused, Response: prior.clone(), Identity: key}, nil
	}
	// 13. The throttle admits it; the address's own throttle is taken at
	// the dial, for the address actually dialled.
	release, err := g.throttle(ctx, r.Asset, op, prov)
	if err != nil {
		if g.pastDeadline(g.now()) {
			return refuse("deadline", "limits.timeout passed while waiting for the throttle")
		}
		return refuse("canceled", "the run was cancelled while waiting for the throttle")
	}
	defer release()
	// The wait for the throttle, and the lookup before it, may have
	// outlasted the window.
	if !windowEnd.IsZero() && !g.now().Before(windowEnd) {
		return refuse("window", "the authorization window ended before the request was sent")
	}
	// 14. The audit line is written, then the request is sent.
	res, rt := g.send(ctx, e, admitted{b: b, prov: prov, cred: cred, addrs: addrs, depth: hopDepth, prev: prev,
		firstParty: firstParty, windowEnd: windowEnd}, r)
	if reusable(res) && key != "" {
		res.Identity = key
		g.mu.Lock()
		g.kept[key] = res.Response.clone()
		g.mu.Unlock()
	}
	return res, rt
}

// admitSubject is steps 4–5 for a request's or a lookup's subject: it
// falls under a root and under the request's asset, and no exclude covers
// it. It returns the refusal rule and its detail, or "".
func (g *Gate) admitSubject(asset, subject string) (string, string) {
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
// (docs/spec/scope.md, "Addresses"). It returns the addresses in the order
// they will be dialled, or the refusal rule and its detail; rule
// "unavailable" means the name did not resolve, with the code as detail.
func (g *Gate) addresses(ctx context.Context, e Entry, b *bound, need evidenceNeed) ([]netip.Addr, string, string) {
	var l Lookup
	if a, err := netip.ParseAddr(b.name); err == nil {
		if g.redactsAddr([]netip.Addr{a}) {
			return nil, "unavailable", "dns_error"
		}
		l = Lookup{Name: b.name, Addrs: []netip.Addr{a}, Outcome: OutcomeAddresses}
		l.target = l.Target()
	} else {
		var code string
		l, code = g.resolve(ctx, e, b.name)
		if l.Outcome == OutcomeExcluded {
			return nil, "excluded", b.name + " points into " + l.ExcludedBy
		}
		if code != "" {
			return nil, "unavailable", code
		}
	}
	addrs := sortAddrs(l.Addrs)
	allInNetwork := true
	for _, a := range addrs {
		excludedBy, inNetwork := g.scope.Address(a)
		allInNetwork = allInNetwork && inNetwork
		switch class := classify(a); {
		case class == never:
			return nil, "address_not_public", b.name + " resolves to " + a.String() + ", which scheck never contacts"
		case excludedBy != "":
			return nil, "address_excluded", b.name + " resolves into " + excludedBy
		case class == notPublic && !inNetwork:
			return nil, "address_not_public", b.name + " resolves to " + a.String() + ", outside every network root"
		}
	}
	if need.network || need.target != "" {
		held := need.network && allInNetwork || l.PointsAt(need.target)
		if !held {
			return nil, "address_moved", b.name + " no longer points where its first-party evidence says"
		}
	}
	return addrs, "", ""
}

// evidenceNeed is what a path beyond an origin's front page needs once its
// name is resolved: every address in a network root, or the name pointing
// at its confirmation's target; either suffices when both are set.
type evidenceNeed struct {
	network bool
	target  string
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
