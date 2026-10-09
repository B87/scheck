package web

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// Restriction is an exact declared entry and the audience it is meant for.
type Restriction struct{ URL, Audience, Source string }

// restricted judges only the original response of an exact intent entry.
// It never turns a redirect destination into a new request
// (docs/spec/web-collector.md, "Headers and cookies").
func (j *judging) restricted() {
	for _, r := range j.in.Restricted {
		var ps []Page
		for _, s := range j.in.Evidence.Sites {
			for _, p := range allPages(s) {
				if p.URL == r.URL && p.RedirectOf == "" {
					ps = append(ps, p)
				}
			}
		}
		x := j.webVerdict(finding.IDWebRestrictedReachable, r.URL, "url", "unavailable:not_read", "", ps)
		x.Context = r.Source
		x.Details = map[string]any{"audience": r.Audience, "vantage": j.in.Vantage}
		switch {
		case j.in.Vantage == "":
			x.Reason = "unavailable:vantage_unknown"
		case j.in.Vantage != "internet":
			x.Reason = "unavailable:vantage_inside"
		case r.Audience == "internet":
			x.Reason = "unavailable:audience_internet"
		default:
			for _, p := range ps {
				reason := p.Reason
				if reason == "" {
					reason = gate.ReasonOf(p.Decision)
				}
				if (p.Decision == "unavailable:connection_refused" || p.Decision == "unavailable:timeout") && p.Status == 0 {
					x.Verdict, x.Reason, x.Excerpt = Disproved, "", "did not answer from here; scheck cannot tell a firewall from a server that is down"
				} else if p.Decision == gate.DecisionSent || p.Decision == gate.DecisionReused {
					switch {
					case blocked(p) != "":
						x.Reason = "unavailable:blocked"
					case p.TLS != nil && inspection(p.TLS):
						x.Reason = "unavailable:tls_interception"
					case strings.HasPrefix(p.URL, "https:") && (p.TLS == nil || !p.TLS.Verified):
						x.Reason = "unavailable:certificate"
					case p.Status >= 200 && p.Status < 300 || p.Status == 401 || p.Status >= 300 && p.Status < 400 && loginRedirect(p):
						x.Verdict, x.Reason = Fired, ""
						x.Attributes = []string{"contradiction"}
						x.Excerpt = fmt.Sprintf("%s answered HTTP %d from the declared internet vantage, outside every permitted source, including office allowlists and VPN; declared audience: %s. Authentication was not tested", r.URL, p.Status, r.Audience)
					default:
						x.Reason = "unavailable:http_status"
					}
				} else if reason != "" {
					x.Reason = reason
				}
			}
		}
		if x.Verdict == Disproved {
			x.Details["observation"] = x.Excerpt
		}
		j.add(x)
	}
}

// LoginRedirectVersion pins the minimal recognized IdP destinations. Location
// is inspected only; no identity provider is contacted.
const LoginRedirectVersion = "2026-10-09.1"

func loginRedirect(p Page) bool {
	loc := header(p, "Location")
	if loc == "" || marked(loc) {
		return false
	}
	base, err := url.Parse(p.URL)
	if err != nil {
		return false
	}
	to, err := base.Parse(loc)
	if err != nil || to.User != nil || (to.Scheme != "https" && to.Scheme != "http") {
		return false
	}
	if to.Scheme == base.Scheme && strings.EqualFold(to.Host, base.Host) {
		for seg := range strings.SplitSeq(to.Path, "/") {
			switch strings.ToLower(seg) {
			case "login", "signin", "sign-in", "log-in":
				return true
			}
		}
	}
	if to.Scheme != "https" || to.Port() != "" && to.Port() != "443" || to.RawPath != "" {
		return false
	}
	switch strings.ToLower(to.Hostname()) {
	case "accounts.google.com":
		return to.Path == "/o/oauth2/auth" || to.Path == "/o/oauth2/v2/auth"
	case "login.microsoftonline.com":
		parts := strings.Split(strings.TrimPrefix(to.Path, "/"), "/")
		if len(parts) < 3 || parts[0] == "" || parts[0] == "." || parts[0] == ".." || strings.Contains(parts[0], "\\") {
			return false
		}
		suffix := strings.Join(parts[1:], "/")
		return suffix == "oauth2/authorize" || suffix == "oauth2/v2.0/authorize"
	}
	return false
}
