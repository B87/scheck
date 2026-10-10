// Package gate is the scope gate: the one place an HTTP request, an API call
// or a DNS query for a web, domain or SaaS asset is sent
// (docs/spec/scope.md, "The scope gate"), as runner.Runner.Run is for host
// commands. A collector names a registered op and its typed parameters; the
// gate admits it in a fixed order, sends it to an address it checked, and
// hands back only what redaction and the header allowlist let through.
// Every decision is a line in the audit log, written before anything is
// sent.
package gate

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/b87/scheck/internal/policy"
)

// Scope is the engagement file's scope as the gate reads it. The
// engagement implements it from the validated file and nothing else: never
// from scope.json or another stage output, so an edit there cannot widen
// what is sent (docs/spec/runs.md, "Stop and resume").
type Scope interface {
	// Subject places a canonical id against the asset a request is for:
	// whether it is that asset or falls under it, the root it falls under
	// ("" when none) and the exclude entry covering it ("" when none).
	Subject(asset, id string) Standing
	// Name is the exclude entry covering a DNS name ("" when none): a name
	// the gate would query, or one a CNAME chain enters. It is wider than
	// a domain subject's exclusion: a host or url exclude written as the
	// name covers it too.
	Name(name string) (excludedBy string)
	// Address reports the exclude entry holding a in any of its forms
	// (Forms) ("" when none), and whether a declared network root holds
	// the form it carries.
	Address(a netip.Addr) (excludedBy string, inNetworkRoot bool)
	// Admits decides whether path may be read at origin
	// (scheme://host[:port]) (docs/spec/scope.md, "Admission", steps 7 and
	// 8). The gate asks before it resolves the name, with l nil, and when
	// the answer is Resolve, again with the lookup as answered. It is the
	// only check on a web op's port: an origin it admits no path at is
	// refused, so a discovered name's other ports are never read.
	Admits(origin, path string, l *Lookup) Admission
	// Throttle is the asset's own throttle in requests per second and
	// concurrency; 0 for either means it sets none. For a SaaS asset it is
	// only what its own assets entry sets, which can only lower the
	// provider's ceiling.
	Throttle(asset string) (rate float64, concurrency int)
	// OrgUnits lists the organizational units excluded under a tenant
	// asset. The gate matches unit paths against them by segment, and
	// builds the excluded-subject set from the users it drops; with none,
	// the set is known to be empty.
	OrgUnits(asset string) []OrgUnit
}

// Admission is Scope.Admits' answer for one path (docs/spec/scope.md,
// "Admission", "First-party evidence").
type Admission struct {
	// Refused is the rule a path is refused by: entry_point when it is not
	// one of the origin's, address_moved when the lookup did not hold the
	// evidence it needs. "" admits it.
	Refused string
	// Resolve says the path needs evidence only the lookup can give: every
	// address inside a network root, or the name pointing at its
	// confirmation's target.
	Resolve bool
	// FirstParty says the path is read on first-party evidence, not only
	// as a domain root's front page: what the report counts as a site
	// shown to be the operator's.
	FirstParty bool
}

// OrgUnit is an organizational unit an exclude names, with the exclude
// entry ("exclude[2]").
type OrgUnit struct {
	Path       string
	ExcludedBy string
}

// Standing is where a subject stands in the engagement's scope.
type Standing struct {
	UnderAsset bool
	Root       string
	ExcludedBy string
}

// Net holds the test seams: the DNS client's resolver and exchange, a
// dialer, the roots TLS verifies against and the sleep between retries. Nil fields are the system's. No
// flag or file reaches it, and a test asserts that no non-test file outside
// this package names it. Special-purpose addresses stay refused under every
// seam, so a test reaches its fake server through a dialer that maps a
// public test address to it.
type Net struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs *x509.CertPool
	Sleep   func(ctx context.Context, d time.Duration) error
	// Nameserver is the resolver the gate's DNS client asks; zero reads
	// /etc/resolv.conf. Exchange sends it one query, over TCP when tcp is
	// set; nil sends it over the network.
	Nameserver netip.Addr
	Exchange   func(ctx context.Context, server string, query []byte, tcp bool) ([]byte, error)
}

// Config builds a gate.
type Config struct {
	Registry *Registry
	Vantage  string
	// Inputs fingerprint declarations by canonical mail domain and exact URL.
	DNSInputs map[string]string
	WebInputs map[string]string
	Scope     Scope
	// RedactExtra is the engagement's redact_extra, applied to every
	// response as to host output.
	RedactExtra []string
	Audit       *policy.Audit
	// Deadline is when limits.timeout ends the run; zero for none.
	Deadline time.Time
	// Windows are the engagement's authorization windows, which bound
	// probe and above (docs/spec/scope.md, "Authorization windows").
	Windows []Window
	// Prior are the successes of the run being resumed, by identity
	// (Result.Identity). A request with the same identity is admitted
	// again through the credential step and answered from it, never sent
	// (docs/spec/scope.md, "Resume").
	Prior map[string]*Response
	// Session numbers the run's sessions, 1 for its first; a resumed
	// session's request ids carry it, so ids stay unique in the run's one
	// audit log.
	Session int
	// Version goes into the User-Agent.
	Version string
	// Getenv reads credentials and proxy settings; nil is os.Getenv.
	Getenv func(string) string
	Net    *Net
}

// Gate sends admitted requests. It is safe for concurrent use.
type Gate struct {
	reg      *Registry
	scope    Scope
	audit    *policy.Audit
	redactor *policy.Redactor
	deadline time.Time
	windows  []Window
	prior    map[string]*Response
	session  int
	// kept are this session's successes a later resume may reuse, by
	// identity; reused the identities it answered from Prior.
	kept   map[string]*Response
	reused map[string]bool
	// rules fingerprints the redaction rules for a request's identity.
	vantage              string
	dnsInputs, webInputs map[string]string
	rules                string
	ua                   string
	getenv               func(string) string
	notes                []string

	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// nameserver and exchange are the gate's DNS client (dns.go).
	nameserver      netip.Addr
	scopedResolvers bool
	exchange        func(ctx context.Context, server string, query []byte, tcp bool) ([]byte, error)
	roots           *x509.CertPool
	// noRoots says no root could be read: every chain fails to verify, and
	// none is classed (docs/spec/scope.md, "Connections").
	noRoots bool
	sleep   func(ctx context.Context, d time.Duration) error
	now     func() time.Time

	limits limiters
	dns    *limiter
	egress egress

	mu           sync.Mutex
	entries      []Entry
	observations map[string]Observation
	seq          int
	stopped      map[string]stop       // provider → why it stopped
	redirects    map[string]redirect   // request id → the 3xx it received
	pages        map[string]*page      // request id → the page after it
	principals   map[string]Credential // exact credential → freshly resolved identity, memory only
	users        map[string]*userSet   // asset → its excluded-subject set, once known
	// pointed is what each records read's answer pointed at, by its
	// request id; spfLookups counts the include: and redirect= reads of
	// each SPF evaluation (dns.go).
	pointed    map[string]*pointed
	spfLookups map[string]int
}

// redirect is a 3xx the gate received: the asset it was for, where it
// pointed (canonical, without query or fragment), and the hops behind it.
type redirect struct {
	asset, target string
	depth         int
}

// stop records a provider the gate stopped sending to.
type stop struct {
	detail string
	until  time.Time
}

// New builds a gate. An invalid redact_extra pattern is an error, though
// validation has already refused one.
func New(cfg Config) (*Gate, error) {
	if cfg.Registry == nil || cfg.Scope == nil || !cfg.Audit.Keeps() {
		// Without an audit log that keeps its lines, the gate could not
		// leave the record it must write before every send
		// (docs/spec/scope.md, "Audit").
		return nil, errors.New("gate: a registry, a scope and an audit log that keeps its lines are required")
	}
	red, err := policy.NewRedactor(cfg.RedactExtra)
	if err != nil {
		return nil, err
	}
	g := &Gate{
		reg: cfg.Registry, scope: cfg.Scope, audit: cfg.Audit, redactor: red,
		vantage: cfg.Vantage, dnsInputs: cfg.DNSInputs, webInputs: cfg.WebInputs,
		deadline: cfg.Deadline, getenv: cfg.Getenv,
		windows: cfg.Windows, prior: cfg.Prior, rules: rulesFingerprint(cfg.Version, cfg.RedactExtra),
		session: cfg.Session, kept: map[string]*Response{}, observations: map[string]Observation{}, reused: map[string]bool{},
		ua:         UserAgent(cfg.Version),
		dial:       (&net.Dialer{}).DialContext,
		nameserver: systemNameserver(), exchange: exchange,
		// macOS writes only its main resolver to resolv.conf; per-interface
		// (VPN) resolvers live in its configuration database, which the
		// gate does not read.
		scopedResolvers: runtime.GOOS == "darwin",
		sleep:           sleepCtx, now: time.Now,
		dns:     newLimiter(dnsRate, 4),
		stopped: map[string]stop{}, redirects: map[string]redirect{},
		pages: map[string]*page{}, users: map[string]*userSet{},
		pointed: map[string]*pointed{}, spfLookups: map[string]int{},
	}
	if g.getenv == nil {
		g.getenv = os.Getenv
	}
	var rootsNote string
	g.roots, rootsNote = systemRoots()
	if n := cfg.Net; n != nil {
		if n.Dial != nil {
			g.dial = n.Dial
		}
		if n.Sleep != nil {
			g.sleep = n.Sleep
		}
		if n.Nameserver.IsValid() {
			g.nameserver, g.scopedResolvers = n.Nameserver, false
		}
		if n.Exchange != nil {
			g.exchange = n.Exchange
		}
		if n.RootCAs != nil {
			g.roots, rootsNote = n.RootCAs, ""
		}
	}
	if rootsNote != "" {
		g.notes, g.noRoots = append(g.notes, rootsNote), true
	}
	// A proxy resolves names itself, which defeats the address checks, and
	// it sees every URL (docs/spec/scope.md, "Connections").
	var set []string
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if g.getenv(k) != "" {
			set = append(set, k)
		}
	}
	if len(set) > 0 {
		g.notes = append(g.notes, strings.Join(set, ", ")+" is set; scheck ignores proxies and connects directly")
	}
	return g, nil
}

// UserAgent is the User-Agent every web request the gate sends carries,
// which the report quotes.
func UserAgent(version string) string {
	return fmt.Sprintf("scheck/%s (security self-assessment)", version)
}

// Notes are for the operator, on stderr and in the report's notes.
func (g *Gate) Notes() []string { return append([]string(nil), g.notes...) }

// Request is one request a collector asks for.
type Request struct {
	Op     string
	Asset  string // the canonical id of the asset the request reads
	Params map[string]string
	Stage  string
	// Exists says the subject is known to exist (a list returned it), so a
	// 404 on it means the credential cannot see it, not that it is absent.
	Exists bool
	// RedirectOf is the request id whose 3xx this request follows; the
	// gate allows three hops.
	RedirectOf string
	// NextOf is the request id of the list page before this one. The
	// request repeats that page's parameters without the cursor, which
	// the gate holds and fills in.
	NextOf string
}

// Result is what came of a request.
type Result struct {
	RequestID string
	// Decision is sent, refused:<rule> or unavailable:<code>, as the audit
	// line has it.
	Decision string
	// Reason is the coverage reason (docs/spec/report.md, "Coverage"),
	// empty when the read succeeded.
	Reason string
	// Kind is a refusal's kind, "access" for a credential the provider did
	// not accept.
	Kind   string
	Detail string
	// Until is when a provider's rate limit resets, when it stopped one.
	Until time.Time
	// Response is what came back; never nil when OK.
	Response *Response
	// Identity is what a resume finds the success under, "" when it is
	// never reused (docs/spec/scope.md, "Resume").
	Identity string
}

// OK reports whether the read succeeded.
func (r Result) OK() bool { return r.Reason == "" }

const maxRedirects = 3

// retryDelays are the waits before each retry, jittered by up to a fifth.
var retryDelays = []time.Duration{time.Second, 4 * time.Second, 16 * time.Second}

const maxRetryAfter = 300 * time.Second

// Send admits a request and sends it, retrying an idempotent request on
// 429, 502, 503, 504 or a reset before the response. Every attempt is
// admitted again from the first check.
func (g *Gate) Send(ctx context.Context, r Request) Result {
	first := g.nextID()
	res, rt := g.attempt(ctx, r, first, "", 1)
	for i := 0; rt != nil && i < len(retryDelays); i++ {
		wait, asked := rt.after, rt.after > 0
		if !asked {
			wait = jitter(retryDelays[i])
		}
		if wait > maxRetryAfter || g.pastDeadline(g.now().Add(wait)) {
			return g.cutRetry(r, first, i+2, res, rt, wait, asked)
		}
		if err := g.sleep(ctx, wait); err != nil {
			// The run was cancelled during the wait: the retry that was not
			// sent gets its line, like one the deadline cut.
			e := Entry{Event: "refused", RequestID: g.nextID(), Stage: r.Stage, Asset: r.Asset, Op: r.Op, Attempt: i + 2,
				RetryOf: first, Decision: "refused:canceled", Detail: "the run was cancelled before the retry"}
			_ = g.record(e)
			out := Result{RequestID: e.RequestID, Response: res.Response}
			out.end(e.Decision, e.Detail)
			return out
		}
		res, rt = g.attempt(ctx, r, g.nextID(), first, i+2)
	}
	if rt != nil {
		return g.exhausted(res, rt)
	}
	return res
}

func (g *Gate) nextID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	if g.session > 1 {
		return fmt.Sprintf("g%d-%06d", g.session, g.seq)
	}
	return fmt.Sprintf("g%06d", g.seq)
}

func (g *Gate) pastDeadline(t time.Time) bool {
	return !g.deadline.IsZero() && !t.Before(g.deadline)
}

func jitter(d time.Duration) time.Duration {
	// Deterministic enough for a throttle, without a random source: the
	// low bits of the clock.
	n := time.Now().UnixNano() % 41
	return d + d*time.Duration(n-20)/100
}
