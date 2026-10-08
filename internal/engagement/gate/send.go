package gate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/b87/scheck/internal/policy"
)

// Per-request timeouts (docs/spec/scope.md, "Throttle, timeouts and
// retries"), each cut to what is left of limits.timeout.
const (
	dialTimeout    = 10 * time.Second
	tlsTimeout     = 10 * time.Second
	headersTimeout = 20 * time.Second
	totalTimeout   = 30 * time.Second
)

// Response is what the gate hands back: the status, the kept headers and
// the body, all redacted, the body cut at the op's cap.
type Response struct {
	Status int
	// Header holds only the allowlisted headers, redacted; set-cookie as
	// its name and attributes, never its value.
	Header http.Header
	// Body is the redacted body: for a JSON op, the projection to its
	// declared fields (for a list, the array of kept items); otherwise the
	// text, cut at the op's cap. Nil when the pipeline kept nothing.
	Body       []byte
	Truncated  bool
	Redactions []policy.Hit
	TLS        *TLSInfo
	DestIP     string
	// Population is set for a list: what the page held and what reached
	// Body.
	Population *Population
	// hash is the hash of a redacted body that was not kept.
	hash string
}

// TLSInfo is what a handshake showed: the verification result and the
// chain, recorded whether or not it verified.
type TLSInfo struct {
	Version  string
	Verified bool
	// Error is why verification failed.
	Error string
	Chain []Cert
}

// Cert is one certificate of a chain, as rules read it.
type Cert struct {
	Subject   string
	Issuer    string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	SHA256    string
}

// send writes the send line, then dials the checked addresses in order and
// sends the request; a send line that cannot be written stops it.
func (g *Gate) send(ctx context.Context, e Entry, a admitted, r Request) (Result, *retry) {
	red := g.redactFor(a)
	e.Event, e.Decision, e.Port = "send", "sent", int(a.b.port)
	if err := g.record(e); err != nil {
		return Result{RequestID: e.RequestID, Decision: "unavailable:audit_failed", Reason: "unavailable:audit_failed",
			Detail: "the audit log could not be written, so nothing was sent"}, nil
	}
	total := totalTimeout
	if a.prov.timeout > 0 {
		total = a.prov.timeout
	}
	ctx, cancel := g.withDeadline(ctx, total)
	defer cancel()
	if !a.windowEnd.IsZero() {
		// The window's end cuts a probe in flight (docs/spec/scope.md,
		// "Authorization windows").
		var wcancel context.CancelFunc
		ctx, wcancel = context.WithDeadline(ctx, a.windowEnd)
		defer wcancel()
	}
	start := g.now()

	var (
		destIP   string
		dialMu   sync.Mutex
		releases []func()
		// closed is set when the request ends: the transport dials on a
		// context of its own, so a dial may still be looping, and a slot it
		// takes after this point is released at once rather than leaked.
		closed bool
	)
	defer func() {
		dialMu.Lock()
		defer dialMu.Unlock()
		closed = true
		for _, rel := range releases {
			rel()
		}
	}()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var errs []error
		for _, ip := range a.addrs {
			// The per-address throttle is taken for the address dialled:
			// CDNs share addresses across assets.
			if a.prov.web {
				rel, err := g.limits.get("addr:"+ip.String(), addrRate, 2).acquire(ctx, g.now, g.sleep)
				if err != nil {
					return nil, err
				}
				dialMu.Lock()
				if closed || ctx.Err() != nil {
					dialMu.Unlock()
					rel()
					return nil, errors.Join(append(errs, context.Canceled)...)
				}
				releases = append(releases, rel)
				dialMu.Unlock()
			}
			dctx, dcancel := context.WithTimeout(ctx, dialTimeout)
			c, err := g.dial(dctx, "tcp", netip.AddrPortFrom(ip, a.b.port).String())
			dcancel()
			if err == nil {
				dialMu.Lock()
				destIP = ip.String()
				dialMu.Unlock()
				return c, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
	tlsConf := &tls.Config{ServerName: a.b.name, MinVersion: tls.VersionTLS12, RootCAs: g.roots}

	res := Result{RequestID: e.RequestID, Decision: "sent"}
	e.Event = "result"
	finish := func(resp *Response, rt *retry) (Result, *retry) {
		e.DurationMS = g.now().Sub(start).Milliseconds()
		dialMu.Lock()
		e.DestIP = destIP
		dialMu.Unlock()
		// It left this machine once a connection was made.
		if e.DestIP != "" {
			g.countSend(a, r.Asset)
		}
		if resp != nil {
			resp.DestIP = e.DestIP
			res.Response = resp
			e.Status, e.Stored, e.Truncated = resp.Status, len(resp.Body), resp.Truncated
			e.Redactions = len(resp.Redactions)
			if resp.TLS != nil {
				e.TLS = resp.TLS.Version
				if !resp.TLS.Verified {
					e.TLS = "invalid"
				}
			}
			if resp.Body != nil {
				e.OutputHash = hash(resp.Body)
			} else {
				e.OutputHash = resp.hash
			}
			if p := resp.Population; p != nil {
				e.Dropped = p.Dropped
			}
		}
		res.Detail, _ = red.RedactString(res.Detail)
		e.Decision, e.Detail = res.Decision, res.Detail
		_ = g.record(e)
		return res, rt
	}
	// outcome names a transport error; beforeResponse says nothing came
	// back yet, the only case a reset is retried in.
	outcome := func(err error, beforeResponse bool, resp *Response) (Result, *retry) {
		var verr *tls.CertificateVerificationError
		var nerr net.Error
		switch {
		case errors.As(err, &verr):
			res.Decision, res.Reason = "unavailable:tls_invalid", "unavailable:tls_invalid"
			res.Detail = verr.Err.Error()
			return finish(&Response{TLS: tlsInfo(red, nil, verr)}, nil)
		case g.pastDeadline(g.now()):
			res.Decision, res.Reason, res.Detail = "unavailable:deadline", "limit_reached", "limits.timeout ended the request in flight"
		case !a.windowEnd.IsZero() && !g.now().Before(a.windowEnd):
			res.Decision, res.Reason, res.Detail = "unavailable:window_ended", "limit_reached", "the authorization window ended with the request in flight"
		case errors.Is(err, context.Canceled):
			res.Decision, res.Reason, res.Detail = "unavailable:canceled", "limit_reached", "the run was cancelled with the request in flight"
		case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
			res.Decision, res.Reason, res.Detail = "unavailable:connection_reset", "unavailable:connection_reset", err.Error()
			if beforeResponse {
				return finish(resp, &retry{provider: a.b.op.Provider, code: "connection_reset", detail: err.Error()})
			}
		case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &nerr) && nerr.Timeout():
			res.Decision, res.Reason, res.Detail = "unavailable:timeout", "unavailable:timeout", err.Error()
		default:
			res.Decision, res.Reason, res.Detail = "unavailable:unreachable", "unavailable:unreachable", err.Error()
		}
		return finish(resp, nil)
	}

	if a.b.op.Method == TLS {
		raw, err := dial(ctx, "tcp", "")
		if err != nil {
			return outcome(err, true, nil)
		}
		defer func() { _ = raw.Close() }()
		hctx, hcancel := context.WithTimeout(ctx, tlsTimeout)
		defer hcancel()
		conn := tls.Client(raw, tlsConf)
		if err := conn.HandshakeContext(hctx); err != nil {
			return outcome(err, true, nil)
		}
		st := conn.ConnectionState()
		return finish(&Response{TLS: tlsInfo(red, &st, nil)}, nil)
	}

	tr := &http.Transport{
		// No proxy: a proxy resolves names itself and sees every URL.
		Proxy:                 nil,
		DialContext:           dial,
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: headersTimeout,
		// One connection per request: a pooled connection would go to an
		// address checked for an earlier request.
		DisableKeepAlives:  true,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		// A 3xx is evidence, never followed (docs/spec/scope.md,
		// "Connections").
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, string(a.b.op.Method), a.b.url.String(), nil)
	if err != nil {
		return outcome(err, true, nil)
	}
	req.Header.Set("User-Agent", g.ua)
	req.Header.Set("Accept", strings.Join(a.b.op.Accept, ", "))
	// gzip only, decompressed under a cap (docs/spec/scope.md, "Responses").
	req.Header.Set("Accept-Encoding", "gzip")
	if a.cred != nil {
		req.Header.Set(a.cred.header, a.cred.value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return outcome(err, true, nil)
	}
	defer func() { _ = resp.Body.Close() }()

	out := &Response{Status: resp.StatusCode}
	if resp.TLS != nil {
		out.TLS = tlsInfo(red, resp.TLS, nil)
	}
	out.Header, e.Headers, out.Redactions = keepHeaders(resp.Header, red)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		g.noteRedirect(e.RequestID, r.Asset, a, req.URL, resp.Header.Get("Location"))
	}
	body, rt := g.pipeline(&res, out, a, r, resp, &e)
	if body.kept {
		g.mu.Lock()
		if body.next != nil {
			g.pages[e.RequestID] = body.next
		}
		if body.done != nil {
			g.users[r.Asset] = body.done
		}
		// The page before is read; its cursor is spent. A page that was
		// not kept leaves it, so the collector may ask again.
		delete(g.pages, r.NextOf)
		g.mu.Unlock()
	}
	if body.err != nil {
		// A body cut short is never a complete read: the status and the
		// headers stay, the partial body is not kept, and it is not
		// retried, since a response came back.
		return outcome(body.err, false, out)
	}
	return finish(out, rt)
}

// piped is what the pipeline left for send: a transport error mid-body,
// the next page's state, and a users list's finished set.
type piped struct {
	err  error
	kept bool // a 2xx list page reached Body
	next *page
	done *userSet
}

// pipeline reads, checks, redacts, parses, filters, projects and cuts the
// body into out, in the order of docs/spec/scope.md, "Responses", and
// classifies the status. A 2xx whose body cannot be kept is unavailable;
// any other status is decided by the status, with the body kept only when
// it could be.
func (g *Gate) pipeline(res *Result, out *Response, a admitted, r Request, resp *http.Response, e *Entry) (piped, *retry) {
	op := a.b.op
	red := g.redactFor(a)
	limit := int(op.MaxBytes)
	// 1. Read past the cap by the redaction slack, so a secret straddling
	// the cap is whole when it is redacted (AGENTS.md rule 5).
	raw, wire, code, err := readBody(resp, limit+policy.RedactSlack)
	e.BytesIn = wire
	if err != nil {
		return piped{err: err}, nil
	}
	sourceCut := len(raw) > limit+policy.RedactSlack
	if sourceCut {
		raw = raw[:limit+policy.RedactSlack]
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	var p piped
	switch {
	case code != "":
	// 2. A body of a type the op does not take is hashed, redacted, and
	// not kept.
	case len(raw) > 0 && !accepts(op.Accept, resp.Header.Get("Content-Type")):
		code = codeContentType
		redacted, _ := red.Redact(raw)
		out.hash = hash(redacted)
	// 7. JSON is never parsed cut, so JSON over its cap is not kept; its
	// status and headers still decide the outcome (a 401, a rate limit).
	case op.json && len(raw) > limit:
		code = codeTooLarge
	// A 2xx with no body (a 204) is kept as its status: for an op that
	// answers "enabled" with 204 and "disabled" with 404, the status is the
	// evidence. A list always has a body.
	case op.json && ok && len(raw) == 0 && op.List == nil:
	// 3–6. A 2xx JSON body is redacted value by value, parsed from the
	// redacted bytes, filtered and projected.
	case op.json && ok:
		redacted, hits, err := red.RedactJSON(raw)
		if err != nil {
			code = codeMalformed // not JSON before redaction touched it
			break
		}
		out.Redactions = append(out.Redactions, hits...)
		sh := g.shape(r, a, redacted, resp.Header)
		if code = sh.code; code == "" {
			out.Body, out.Population = sh.body, sh.pop
			p.kept, p.next, p.done = sh.pop != nil, sh.next, sh.done
		} else {
			out.hash = hash(redacted)
		}
	// 3, 7. Text, and an API's error body, is redacted, then cut. An error
	// body that is JSON is first redacted value by value, as a 2xx body
	// is, so the same body reveals no more as an error.
	default:
		if op.json {
			redacted, hits, err := red.RedactJSON(raw)
			if err != nil {
				// Not one JSON document (a BOM, two documents, HTML from a
				// proxy): the text rules miss a number or an array under
				// a secret-shaped key, so only its hash is kept, as for a
				// malformed 2xx. Its status still decides.
				redacted, _ = red.Redact(raw)
				out.hash = hash(redacted)
				break
			}
			// Cut only: RedactJSON ran every rule value by value.
			out.Body, out.Truncated = policy.Truncate(redacted, sourceCut, limit)
			out.Redactions = append(out.Redactions, hits...)
			break
		}
		body, truncated, hits := red.Finish(raw, sourceCut, limit)
		out.Body, out.Truncated = body, truncated
		out.Redactions = append(out.Redactions, hits...)
	}
	rt := g.classify(res, a, r, resp, out)
	if code != "" && ok && res.Reason == "" {
		res.Decision, res.Reason = "unavailable:"+code, "unavailable:"+code
		res.Detail = codeDetail(code, limit)
	}
	return p, rt
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// noteRedirect records a 3xx so that a collector may ask for the hop: the
// asset, where it pointed, resolved against the request and canonical, and
// the hops behind it. Only the gate holds the raw Location.
func (g *Gate) noteRedirect(id, asset string, a admitted, base *url.URL, location string) {
	if location == "" {
		return
	}
	to, err := base.Parse(location)
	if err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.redirects[id] = redirect{asset: asset, target: canonicalURL(to), depth: a.depth}
}

// canonicalURL is scheme://host/path as a url id writes it: lowercase, the
// default port dropped, an address canonical, the path escaped as a bound
// URLPath escapes it (not as the server wrote it), and no query, fragment
// or userinfo. Two URLs that reach the same resource compare equal; one
// that does not parse as a host compares equal to none.
func canonicalURL(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host, err := hostValue(u.Host)
	if err != nil {
		return "\x00"
	}
	if def := map[string]string{"https": ":443", "http": ":80"}[scheme]; def != "" {
		host = strings.TrimSuffix(host, def)
	}
	p := (&url.URL{Path: u.Path}).EscapedPath()
	if p == "" {
		p = "/"
	}
	return scheme + "://" + host + p
}

// classify turns a provider's status into an outcome (docs/spec/scope.md,
// "Throttle, timeouts and retries", "Outcomes"). A web site's status is
// evidence; an API's may be a refusal, a permission gap or a rate limit,
// and some codes mislead.
func (g *Gate) classify(res *Result, a admitted, r Request, resp *http.Response, out *Response) *retry {
	p := a.b.op.Provider
	s := resp.StatusCode
	h := resp.Header
	retryAfter, hasRetryAfter := parseRetryAfter(h.Get("Retry-After"), g.now())
	if a.prov.web {
		// A site is retried on what may pass, and its last answer is kept
		// as evidence when the retries run out. A site's 429 never stops
		// the web provider: it binds that site only.
		if s == 429 || s == 502 || s == 503 || s == 504 {
			return &retry{provider: p, after: retryAfter, evidence: true}
		}
		return nil
	}
	if s == 502 || s == 503 || s == 504 {
		res.Decision, res.Reason = "unavailable:server_error", "unavailable:server_error"
		return &retry{provider: p, after: retryAfter, code: "server_error", detail: fmt.Sprintf("%s answered %d", sourceName(p), s)}
	}
	if p == "github" && (s == 403 || s == 429) && h.Get("X-RateLimit-Remaining") == "0" && !hasRetryAfter {
		until := resetTime(h)
		detail := "GitHub's rate limit for this token is used up"
		g.stopProvider(p, detail, until)
		res.Reason, res.Detail, res.Until = "limit_reached", detail, until
		return nil
	}
	if s == 429 || s == 403 && (hasRetryAfter || p == "google" && googleRateLimited(out.Body)) {
		res.Reason = "limit_reached"
		return &retry{provider: p, after: retryAfter, rateLimit: true, detail: fmt.Sprintf("%s's rate limit", sourceName(p))}
	}
	switch {
	case s == 401:
		res.Reason, res.Kind = "refused", "access"
		res.Detail = fmt.Sprintf("%s did not accept the credential", sourceName(p))
		if a.cred != nil {
			res.Detail = fmt.Sprintf("%s did not accept the token in %s (expired, revoked or mistyped)", sourceName(p), a.cred.Env)
		}
	case s == 403 && h.Get("X-GitHub-SSO") != "":
		res.Reason = "insufficient_permission:sso_authorization"
		res.Detail = "authorize the token for SAML single sign-on"
	case s == 403, s == 404 && r.Exists:
		res.Reason = "insufficient_permission"
	case s >= 500:
		res.Decision, res.Reason = "unavailable:server_error", "unavailable:server_error"
	}
	if a.prov.floor && s < 400 {
		g.checkFloor(p, h)
	}
	return nil
}

// checkFloor stops a provider once less than max(100, a fifth of its limit)
// is left.
func (g *Gate) checkFloor(p string, h http.Header) {
	remaining, err1 := strconv.Atoi(h.Get("X-RateLimit-Remaining"))
	limit, err2 := strconv.Atoi(h.Get("X-RateLimit-Limit"))
	if err1 != nil || err2 != nil {
		return
	}
	if remaining < max(100, limit/5) {
		g.stopProvider(p, fmt.Sprintf("scheck stopped to leave a fifth of this token's %s rate limit for its other uses", sourceName(p)), resetTime(h))
	}
}

func resetTime(h http.Header) time.Time {
	if n, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// googleRateLimited reads the reason of a Google API error from the
// redacted body.
func googleRateLimited(body []byte) bool {
	var e struct {
		Error struct {
			Errors []struct{ Reason string } `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	for _, x := range e.Error.Errors {
		if x.Reason == "rateLimitExceeded" || x.Reason == "userRateLimitExceeded" {
			return true
		}
	}
	return false
}

// keptHeaders are the only response headers that reach evidence
// (docs/spec/scope.md, "Responses"); everything else is dropped and
// counted.
var keptHeaders = []string{
	"Content-Type", "Location", "Server", "X-Powered-By",
	"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
	"Set-Cookie", "Retry-After",
	"X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset", "X-Ratelimit-Used", "X-Ratelimit-Resource",
	"X-Oauth-Scopes", "X-Accepted-Oauth-Scopes", "Github-Authentication-Token-Expiration", "X-Github-Sso",
}

// keepHeaders keeps the allowlisted headers, redacted: a URL's query values
// are replaced by markers, and a cookie keeps its name and attributes.
func keepHeaders(in http.Header, red *policy.Redactor) (http.Header, int, []policy.Hit) {
	out := http.Header{}
	var hits []policy.Hit
	dropped := 0
	for k, vs := range in {
		ck := http.CanonicalHeaderKey(k)
		keep := false
		for _, kh := range keptHeaders {
			if http.CanonicalHeaderKey(kh) == ck {
				keep = true
			}
		}
		if !keep {
			dropped += len(vs)
			continue
		}
		for _, v := range vs {
			switch ck {
			case "Location":
				v = redactURL(v)
			case "X-Github-Sso":
				v = urlInText.ReplaceAllStringFunc(v, redactURL)
			case "Set-Cookie":
				v = cookieShape(v)
			}
			v, h := red.RedactString(v)
			hits = append(hits, h...)
			out.Add(ck, v)
		}
	}
	return out, dropped, hits
}

// urlInText finds absolute URLs inside a header value such as
// X-GitHub-SSO's "required; url=https://…".
var urlInText = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s;,]+`)

// redactURL keeps a URL's scheme, host and path and replaces its userinfo,
// every query component (with or without a value) and its fragment with
// markers: an OAuth code or a session id travels in exactly those. What
// does not parse keeps nothing after its host.
func redactURL(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Opaque != "" {
		i := strings.Index(v, "://")
		if i < 0 {
			return policy.Marker("url", len(v))
		}
		authority, rest := v[i+3:], ""
		if j := strings.IndexAny(authority, "/?#"); j >= 0 {
			authority, rest = authority[:j], authority[j:]
		}
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			authority = policy.Marker("userinfo", at) + authority[at:]
		}
		if rest != "" {
			rest = policy.Marker("url", len(rest))
		}
		return v[:i+3] + authority + rest
	}
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteString(":")
	}
	if u.Host != "" || u.User != nil {
		b.WriteString("//")
		if u.User != nil {
			b.WriteString(policy.Marker("userinfo", len(u.User.String())))
			b.WriteString("@")
		}
		b.WriteString(u.Host)
	}
	b.WriteString(u.EscapedPath())
	if u.RawQuery != "" || u.ForceQuery {
		parts := strings.Split(u.RawQuery, "&")
		for i, kv := range parts {
			if k, val, ok := strings.Cut(kv, "="); ok {
				if val != "" {
					parts[i] = k + "=" + policy.Marker("query", len(val))
				}
			} else if kv != "" {
				parts[i] = policy.Marker("query", len(kv))
			}
		}
		b.WriteString("?")
		b.WriteString(strings.Join(parts, "&"))
	}
	if f := u.EscapedFragment(); f != "" {
		b.WriteString("#")
		b.WriteString(policy.Marker("fragment", len(f)))
	}
	return b.String()
}

// cookieShape keeps a Set-Cookie's name and attributes, never its value.
func cookieShape(v string) string {
	first, attrs, _ := strings.Cut(v, ";")
	name, val, _ := strings.Cut(first, "=")
	out := strings.TrimSpace(name) + "=" + policy.Marker("cookie", len(strings.TrimSpace(val)))
	if attrs != "" {
		out += ";" + attrs
	}
	return out
}

// tlsInfo records a handshake. Certificate fields are target-derived, so
// they are redacted like a body: an operator's redact_extra may name an
// internal host a certificate lists.
func tlsInfo(red *policy.Redactor, st *tls.ConnectionState, verr *tls.CertificateVerificationError) *TLSInfo {
	str := func(v string) string { out, _ := red.RedactString(v); return out }
	info := &TLSInfo{Verified: verr == nil}
	var certs []*x509.Certificate
	if verr != nil {
		certs = verr.UnverifiedCertificates
		info.Error = str(verr.Err.Error())
	}
	if st != nil {
		info.Version = tls.VersionName(st.Version)
		certs = st.PeerCertificates
	}
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		cert := Cert{Subject: str(c.Subject.String()), Issuer: str(c.Issuer.String()),
			NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), SHA256: hex.EncodeToString(sum[:])}
		for _, n := range c.DNSNames {
			cert.DNSNames = append(cert.DNSNames, str(n))
		}
		info.Chain = append(info.Chain, cert)
	}
	return info
}
