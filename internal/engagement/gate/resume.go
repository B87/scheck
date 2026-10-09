package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
)

// DecisionReused is the decision of a request a resume answered from the
// earlier run's success: admitted again through the credential step, and
// not sent (docs/spec/scope.md, "Resume").
const DecisionReused = "reused"

// Window is one authorization window: probe and above are admitted from
// From until To (docs/spec/scope.md, "Authorization windows").
type Window struct{ From, To time.Time }

// window is the index of the authorization window now falls in, or -1.
func (g *Gate) window(now time.Time) int {
	for i, w := range g.windows {
		if !now.Before(w.From) && now.Before(w.To) {
			return i
		}
	}
	return -1
}

// identity is a request's identity for resume (docs/spec/scope.md,
// "Resume"): its op as this build compiled it, asset, bound parameters,
// whether its subject is known to exist, the principal fingerprint and the
// redaction rules, hashed. A changed build, op or redact_extra reuses
// nothing, so a stored body is never one today's rules would redact
// differently. It is "" for a request that is never reused:
//   - a list, and any op that names users, whose answer the gate filters by
//     the engagement's excludes and the users it finds now (and a
//     paginated list is read again whole, since its cursors expire);
//   - a request whose credential's principal is not known, which may be
//     another one.
func (g *Gate) identity(op *compiled, r Request, params map[string]string, cred *Credential) string {
	if op.List != nil || op.users || g.rules == "" {
		return ""
	}
	principal := ""
	if op.Auth != NoAuth {
		if cred == nil || cred.Principal == "" {
			return ""
		}
		// The principal's identity and scopes, never the token.
		principal = fingerprint(cred)
	}
	def, err := json.Marshal(op.Op)
	if err != nil {
		return ""
	}
	path := params["path"]
	if path == "" {
		path = "/"
	}
	inputs := g.webInputs[params["scheme"]+"://"+params["host"]+path]
	keys := slices.Sorted(maps.Keys(params))
	pairs := make([][2]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, [2]string{k, params[k]})
	}
	b, err := json.Marshal(struct {
		Op        json.RawMessage `json:"op"`
		Asset     string          `json:"asset"`
		Params    [][2]string     `json:"params"`
		Exists    bool            `json:"exists"`
		Principal string          `json:"principal"`
		Rules     string          `json:"rules"`
		Vantage   string          `json:"vantage"`
		Inputs    string          `json:"inputs"`
	}{def, r.Asset, pairs, r.Exists, principal, g.rules, g.requestVantage(op), inputs})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// rulesFingerprint hashes what decides how a body is redacted: the build,
// whose compiled rules it carries, and redact_extra. A build whose version
// names no commit (dev) or carries uncommitted changes (-dirty) cannot be
// told from another one, so it has none and reuses nothing.
func rulesFingerprint(version string, extra []string) string {
	if !KnownBuild(version) {
		return ""
	}
	b, _ := json.Marshal(struct {
		Version string   `json:"version"`
		Extra   []string `json:"redact_extra"`
	}{version, extra})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fingerprint hashes who a credential is and what it may read.
func fingerprint(c *Credential) string {
	b, _ := json.Marshal(struct {
		Principal string   `json:"principal"`
		Scopes    []string `json:"scopes"`
	}{c.Principal, slices.Sorted(slices.Values(c.Scopes))})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// KnownBuild says a version names one build: not dev, which names no
// commit, and not -dirty, which carries uncommitted changes. A resume keeps
// nothing an unknown build read, since another build may read or redact it
// differently.
func KnownBuild(version string) bool {
	return version != "" && version != "dev" && !strings.HasSuffix(version, "-dirty")
}

// Successes are this session's successes a later resume may reuse, by
// identity: what the run directory keeps under evidence/requests/.
func (g *Gate) Successes() map[string]*Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]*Response, len(g.kept))
	for k, v := range g.kept {
		out[k] = v.clone()
	}
	return out
}

// Reused are the identities this session answered from Prior, sorted: the
// run names any whose record changed since it was written.
func (g *Gate) Reused() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Sorted(maps.Keys(g.reused))
}

// reusable says a success may answer a resume. A web page's every status
// is evidence, but a 429 or a 5xx is a page that was not read, which a
// resume sends again; a redirect is sent again too, since the hop after it
// needs the gate's own record of the 3xx.
func reusable(res Result) bool {
	if !res.OK() || res.Response == nil || res.Response.Population != nil {
		return false
	}
	s := res.Response.Status
	return (s < 300 || s > 399) && s != http.StatusTooManyRequests && s < 500
}

// clone is a reused response the collector may change without touching the
// record another request with the same identity is answered from.
func (r *Response) clone() *Response {
	c := *r
	c.Header = r.Header.Clone()
	c.Body = slices.Clone(r.Body)
	c.Redactions = slices.Clone(r.Redactions)
	if r.Population != nil {
		p := *r.Population
		p.Dropped = slices.Clone(p.Dropped)
		c.Population = &p
	}
	if r.TLS != nil {
		t := *r.TLS
		t.Chain = slices.Clone(r.TLS.Chain)
		for i := range t.Chain {
			t.Chain[i].DNSNames = slices.Clone(t.Chain[i].DNSNames)
		}
		c.TLS = &t
	}
	return &c
}
