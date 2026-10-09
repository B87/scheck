package gate

import (
	"bytes"
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
	"sync/atomic"
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
	// Error is why verification failed, as text.
	Error string
	// Class is why verification failed, typed for the certificate rules
	// (docs/spec/scope.md, "Connections"): one of the Class* values.
	Class string
	// Alert names the TLS alert the server ended TLS with
	// (protocol_version, handshake_failure, ...): before the handshake
	// completed, with no chain, or after, with the chain.
	Alert string
	Chain []Cert
}

// The verification classes (docs/spec/web-collector.md, "TLS and
// certificate").
const (
	ClassExpired             = "expired"
	ClassHostnameMismatch    = "hostname_mismatch"
	ClassUntrustedIssuer     = "untrusted_issuer"
	ClassMissingIntermediate = "missing_intermediate"
	// ClassUnclassified is a failure scheck does not type, on which the
	// certificate rules abstain.
	ClassUnclassified = "unclassified"
)

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
	e.Event, e.Decision, e.Port = "send", DecisionSent, int(a.b.port)
	if err := g.record(e); err != nil {
		res := Result{RequestID: e.RequestID}
		res.end("unavailable:audit_failed", "the audit log could not be written, so nothing was sent")
		return res, nil
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
	d := &dialer{g: g, a: a}
	defer d.close()
	e.Event = "result"
	s := &sending{g: g, e: e, a: a, r: r, red: g.redactFor(a), d: d, start: g.now(),
		res: Result{RequestID: e.RequestID, Decision: DecisionSent}}
	if a.b.op.Method == TLS {
		return s.handshake(ctx)
	}
	return s.roundTrip(ctx)
}

// dialer dials a request's checked addresses in order. The transport dials
// on a context of its own, so a dial may still be looping when the request
// ends: a throttle slot it takes after close is released at once rather
// than leaked.
type dialer struct {
	g        *Gate
	a        admitted
	mu       sync.Mutex
	destIP   string
	releases []func()
	closed   bool
}

func (d *dialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var errs []error
	for _, ip := range d.a.addrs {
		// The per-address throttle is taken for the address dialled: CDNs
		// share addresses across assets.
		if d.a.prov.web {
			rel, err := d.g.limits.get("addr:"+ip.String(), addrRate, 2).acquire(ctx, d.g.now, d.g.sleep)
			if err != nil {
				return nil, err
			}
			d.mu.Lock()
			if d.closed || ctx.Err() != nil {
				d.mu.Unlock()
				rel()
				return nil, errors.Join(append(errs, context.Canceled)...)
			}
			d.releases = append(d.releases, rel)
			d.mu.Unlock()
		}
		dctx, dcancel := context.WithTimeout(ctx, dialTimeout)
		c, err := d.g.dial(dctx, "tcp", netip.AddrPortFrom(ip, d.a.b.port).String())
		dcancel()
		if err == nil {
			d.mu.Lock()
			d.destIP = ip.String()
			d.mu.Unlock()
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// dialled is the address a connection was made to, "" when none was.
func (d *dialer) dialled() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.destIP
}

func (d *dialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, rel := range d.releases {
		rel()
	}
}

// sending is one request in flight: its result line and what it read.
type sending struct {
	g     *Gate
	e     Entry
	a     admitted
	r     Request
	red   *policy.Redactor
	d     *dialer
	start time.Time
	res   Result
	// shook is the state of a TLS handshake that completed: the server
	// proved it holds its certificate's key (its signature over the
	// handshake, then its Finished). Only then does a chain count when an
	// alert follows; Go verifies a chain before that proof, and at TLS 1.2
	// it asks for a client certificate before it too, so neither shows
	// that the server holds the key.
	shook atomic.Pointer[tls.ConnectionState]
}

func (s *sending) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: s.a.b.name, MinVersion: tls.VersionTLS12, RootCAs: s.g.roots,
		// What net/http offers when it makes the connection itself.
		NextProtos: []string{"h2", "http/1.1"}}
}

// dialTLS dials a checked address and completes the TLS handshake, for the
// TLS op and as the HTTP transport's TLS dialer, so the gate knows the
// handshake completed (shook).
func (s *sending) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	// net/http may dial again within one request (an HTTP/2 GOAWAY): what
	// counts is the last connection's handshake, so an earlier one's is
	// forgotten first.
	s.shook.Store(nil)
	raw, err := s.d.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	hctx, hcancel := context.WithTimeout(ctx, tlsTimeout)
	defer hcancel()
	conn := tls.Client(raw, s.tlsConfig())
	if err := conn.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	st := conn.ConnectionState()
	s.shook.Store(&st)
	return conn, nil
}

// tlsInfo is tlsInfo with the gate's roots: with none, a failure is not
// classed, since every chain fails alike.
func (s *sending) tlsInfo(st *tls.ConnectionState, verr *tls.CertificateVerificationError) *TLSInfo {
	info := tlsInfo(s.red, st, verr, s.g.now())
	if verr != nil && s.g.noRoots {
		info.Class = ClassUnclassified
	}
	return info
}

// finish writes the result line and returns the result.
func (s *sending) finish(resp *Response, rt *retry) (Result, *retry) {
	e := &s.e
	e.DurationMS = s.g.now().Sub(s.start).Milliseconds()
	e.DestIP = s.d.dialled()
	// It left this machine once a connection was made.
	if e.DestIP != "" {
		s.g.countSend(s.a, s.r.Asset)
	}
	if resp != nil {
		resp.DestIP = e.DestIP
		s.res.Response = resp
		e.Status, e.Stored, e.Truncated = resp.Status, len(resp.Body), resp.Truncated
		e.Redactions = len(resp.Redactions)
		if t := resp.TLS; t != nil {
			switch {
			case t.Alert != "":
				e.TLS = "alert:" + t.Alert
			case !t.Verified:
				e.TLS = "invalid"
			default:
				e.TLS = t.Version
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
	s.res.Detail, _ = s.red.RedactString(s.res.Detail)
	e.Decision, e.Detail = s.res.Decision, s.res.Detail
	_ = s.g.record(*e)
	return s.res, rt
}

// failed ends a request on a transport error (docs/spec/scope.md,
// "Outcomes"); beforeResponse says nothing came back yet, the only case a
// reset is retried in.
func (s *sending) failed(err error, beforeResponse bool, resp *Response) (Result, *retry) {
	var verr *tls.CertificateVerificationError
	var nerr net.Error
	var rt *retry
	switch {
	case errors.As(err, &verr):
		s.res.end("unavailable:tls_invalid", verr.Err.Error())
		return s.finish(&Response{TLS: s.tlsInfo(nil, verr)}, nil)
	case resp == nil && tlsAlert(err) != "" && s.shook.Load() == nil:
		// The server ended the handshake before it completed: what it
		// refused is the evidence (tls.legacy_only reads
		// protocol_version), no chain counts, and nothing was read
		// (docs/spec/scope.md, "Connections").
		s.res.end("unavailable:tls_handshake", err.Error())
		return s.finish(&Response{TLS: &TLSInfo{Alert: tlsAlert(err)}}, nil)
	case resp == nil && tlsAlert(err) != "":
		// The server ended TLS after the handshake completed, as one that
		// requires a client certificate does at TLS 1.3: it answered, with
		// the chain kept, and nothing was read.
		info := s.tlsInfo(s.shook.Load(), nil)
		info.Alert = tlsAlert(err)
		s.res.end("unavailable:tls_refused", err.Error())
		return s.finish(&Response{TLS: info}, nil)
	case s.g.pastDeadline(s.g.now()):
		s.res.end("unavailable:deadline", "limits.timeout ended the request in flight")
	case !s.a.windowEnd.IsZero() && !s.g.now().Before(s.a.windowEnd):
		s.res.end("unavailable:window_ended", "the authorization window ended with the request in flight")
	case errors.Is(err, context.Canceled):
		s.res.end("unavailable:canceled", "the run was cancelled with the request in flight")
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
		s.res.end("unavailable:connection_reset", err.Error())
		if beforeResponse {
			// Kept for when the retries run out: redacted now, since the
			// error's text names the URL.
			detail, _ := s.red.RedactString(err.Error())
			rt = &retry{provider: s.a.b.op.Provider, code: "connection_reset", detail: detail}
		}
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &nerr) && nerr.Timeout():
		s.res.end("unavailable:timeout", err.Error())
	default:
		s.res.end("unavailable:unreachable", err.Error())
	}
	return s.finish(resp, rt)
}

// handshake is a TLS op: the handshake and nothing after it.
func (s *sending) handshake(ctx context.Context) (Result, *retry) {
	conn, err := s.dialTLS(ctx, "tcp", "")
	if err != nil {
		return s.failed(err, true, nil)
	}
	defer func() { _ = conn.Close() }()
	return s.finish(&Response{TLS: s.tlsInfo(s.shook.Load(), nil)}, nil)
}

// roundTrip sends an HTTP request on one fresh connection and reads its
// answer through the pipeline.
func (s *sending) roundTrip(ctx context.Context) (Result, *retry) {
	g, a := s.g, s.a
	tr := &http.Transport{
		// No proxy: a proxy resolves names itself and sees every URL.
		Proxy:       nil,
		DialContext: s.d.dial,
		// The gate makes the TLS connection itself (dialTLS), with the
		// same settings and timeout net/http would use.
		DialTLSContext:        s.dialTLS,
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
		return s.failed(err, true, nil)
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
		return s.failed(err, true, nil)
	}
	defer func() { _ = resp.Body.Close() }()

	out := &Response{Status: resp.StatusCode}
	if resp.TLS != nil {
		out.TLS = s.tlsInfo(resp.TLS, nil)
	}
	out.Header, s.e.Headers, out.Redactions = keepHeaders(resp.Header, s.red)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		g.noteRedirect(s.e.RequestID, s.r.Asset, a, req.URL, resp.Header.Get("Location"))
	}
	body, rt := g.pipeline(&s.res, out, a, s.r, resp, &s.e)
	if body.kept {
		g.keepPage(s.e.RequestID, s.r, body)
	}
	if body.err != nil {
		// A body cut short is never a complete read: the status and the
		// headers stay, the partial body is not kept, and it is not
		// retried, since a response came back.
		return s.failed(body.err, false, out)
	}
	return s.finish(out, rt)
}

// keepPage stores what a kept list page leaves for the next: its page
// state and a users list's finished set. The page before is read; its
// cursor is spent. A page that was not kept leaves it, so the collector
// may ask again.
func (g *Gate) keepPage(id string, r Request, body piped) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if body.next != nil {
		g.pages[id] = body.next
	}
	if body.done != nil {
		g.users[r.Asset] = body.done
	}
	delete(g.pages, r.NextOf)
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
		res.end("unavailable:"+code, codeDetail(code, limit))
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
		res.end("unavailable:server_error", res.Detail)
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
		res.end("unavailable:server_error", res.Detail)
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
func tlsInfo(red *policy.Redactor, st *tls.ConnectionState, verr *tls.CertificateVerificationError, now time.Time) *TLSInfo {
	str := func(v string) string { out, _ := red.RedactString(v); return out }
	info := &TLSInfo{Verified: verr == nil}
	var certs []*x509.Certificate
	if verr != nil {
		certs = verr.UnverifiedCertificates
		info.Error = str(verr.Err.Error())
		info.Class = verificationClass(verr.Err, certs, now)
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

// verificationClass types a verification failure. A chain no trusted root
// signs is missing its intermediate when the server sent one certificate,
// not self-signed, that names where its issuer's certificate is published
// (AIA), as a public CA's always does: browsers may fetch it themselves,
// and scheck fetches nothing. Any other untrusted chain, a self-signed
// certificate or a private CA's, is from an untrusted issuer.
func verificationClass(err error, served []*x509.Certificate, now time.Time) string {
	var inv x509.CertificateInvalidError
	var host x509.HostnameError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &host):
		return ClassHostnameMismatch
	case errors.As(err, &inv) && inv.Reason == x509.Expired && inv.Cert != nil && now.After(inv.Cert.NotAfter):
		return ClassExpired
	case errors.As(err, &unknown) && len(served) == 1 && !selfSigned(served[0]) && len(served[0].IssuingCertificateURL) > 0:
		return ClassMissingIntermediate
	case errors.As(err, &unknown) && len(served) > 0:
		return ClassUntrustedIssuer
	}
	return ClassUnclassified
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// alertNames are the TLS alerts a server may end a handshake with, by the
// text crypto/tls gives a received alert (RFC 8446 §6).
var alertNames = map[string]string{
	"tls: handshake failure": "handshake_failure", "tls: bad certificate": "bad_certificate",
	"tls: illegal parameter": "illegal_parameter", "tls: protocol version not supported": "protocol_version",
	"tls: insufficient security level": "insufficient_security", "tls: internal error": "internal_error",
	"tls: unrecognized name": "unrecognized_name", "tls: no application protocol": "no_application_protocol",
	"tls: certificate required": "certificate_required",
}

// tlsAlert names the alert a server ended the handshake with, "" when it
// did not end with one; "alert" for one scheck does not name. crypto/tls
// reports a received alert as a "remote error"; a server that answers with
// a version below the client's minimum gets the client's own
// protocol_version alert, which it reports as text.
func tlsAlert(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" && op.Err != nil {
		if n, ok := alertNames[op.Err.Error()]; ok {
			return n
		}
		return "alert"
	}
	if err != nil && strings.Contains(err.Error(), "tls: server selected unsupported protocol version") {
		return "protocol_version"
	}
	return ""
}
