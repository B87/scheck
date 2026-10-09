package web

import (
	"fmt"
	"strings"

	"github.com/b87/scheck/internal/policy"
)

type SiteNote struct{ Source, Detail string }

// SiteNotes reports facts and the limits of these entry-point reads.
// Robots paths, contact destinations and script URLs never become reads.
func SiteNotes(in Input) []SiteNote {
	notes := []SiteNote{{Source: in.Asset, Detail: "One TLS negotiation per connection was observed; other versions, ciphers and revocation were not tested. Entry points only: no authenticated login flow or loaded scripts were read"},
		{Source: in.Asset, Detail: "Only whole domain endings (such as .page, .dev, .app) were looked up in browsers' built-in HTTPS-only list; whether your own domain is on it was not checked"}}
	unjudged := 0
	for _, s := range in.Evidence.Sites {
		eligible := s.Declared
		for _, p := range allPages(s) {
			eligible = eligible || p.FirstParty
			if v := blocked(p); v != "" {
				notes = append(notes, SiteNote{p.URL, fmt.Sprintf("Blocked by %s (HTTP %d); response rules were not assessed", v, p.Status)})
			}
			if p.RobotsCount != nil {
				prefix := ""
				if p.Truncated {
					prefix = "at least "
				}
				notes = append(notes, SiteNote{p.URL, fmt.Sprintf("robots.txt contained %s%d Disallow entries; their paths were not retained or requested", prefix, *p.RobotsCount)})
			}
			if pageReason(p) != "" {
				continue
			}
			for _, field := range []string{"Server", "X-Powered-By"} {
				v := strings.ToLower(header(p, field))
				for _, product := range []string{"nginx", "apache", "php", "express", "asp.net", "gunicorn"} {
					if strings.Contains(v, product) {
						notes = append(notes, SiteNote{p.URL, "Technology fingerprint: " + product + " (" + field + " header)"})
					}
				}
			}
			for _, v := range headers(p, "Set-Cookie") {
				name, _, _ := strings.Cut(v, "=")
				name = strings.ToLower(strings.TrimSpace(name))
				product := map[string]string{"phpsessid": "PHP", "jsessionid": "Java servlet", "laravel_session": "Laravel"}[name]
				if product != "" {
					notes = append(notes, SiteNote{p.URL, "Technology fingerprint: " + product + " (cookie name " + name + ")"})
				}
			}
			for _, tag := range htmlTags(p.Body) {
				if tag.name == "meta" && strings.EqualFold(tag.attrs["name"], "generator") && !marked(tag.attrs["content"]) {
					notes = append(notes, SiteNote{p.URL, "Generator metadata: " + tag.attrs["content"] + " (meta name=generator)"})
				}
			}
			server := header(p, "Server")
			low := strings.ToLower(server)
			for _, cdn := range []string{"cloudflare", "cloudfront", "akamai", "fastly", "vercel"} {
				if strings.Contains(low, cdn) {
					notes = append(notes, SiteNote{p.URL, "CDN fingerprint: " + cdn + " (Server header); application software was not inferred"})
				}
			}
			for _, t := range []struct{ marker, name string }{{"/wp-content/", "WordPress"}, {"__NEXT_DATA__", "Next.js"}, {"ng-version", "Angular"}, {"csrfmiddlewaretoken", "Django"}} {
				if strings.Contains(p.Body, t.marker) {
					notes = append(notes, SiteNote{p.URL, "Technology fingerprint: " + t.name + " (body marker " + t.marker + ")"})
				}
			}
		}
		if !eligible {
			unjudged++
		}
	}
	if unjudged > 0 {
		notes = append(notes, SiteNote{in.Asset, fmt.Sprintf("%d read name(s) had no declared site or first-party evidence; header, cookie, HTTP and security contact rules did not judge them", unjudged)})
	}
	return notes
}

// RedactionHits counts trusted gate hits once per captured request, never
// marker-shaped strings in target output (docs/spec/scope.md, "Responses").
func RedactionHits(ev Evidence) []policy.Hit {
	seen := map[string]bool{}
	var hits []policy.Hit
	for _, s := range ev.Sites {
		for _, p := range allPages(s) {
			if p.RequestID == "" || seen[p.RequestID] {
				continue
			}
			seen[p.RequestID] = true
			hits = append(hits, p.Redactions...)
		}
	}
	return hits
}
