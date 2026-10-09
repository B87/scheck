package web

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

// Entry is a declared entry point, never a path harvested from a page.
type Entry struct{ Scheme, Host, Path string }

// SitePlan describes reads beside a name's front-page pair. The gate still
// decides every path's admission (docs/spec/scope.md, "Admission").
type SitePlan struct {
	Host     string
	Declared bool
	Entries  []Entry
}

func entryURL(e Entry) string {
	return (&url.URL{Scheme: e.Scheme, Host: e.Host, Path: e.Path}).String()
}

// Enrich reads a site's declared entries and two well-known files, after
// takeover judgments have suspended stale confirmations. It follows at
// most one same-host redirect per initial read, through the gate.
func Enrich(ctx context.Context, g Gate, d Domain, ev Evidence) Evidence {
	c := collector{g: g, d: d}
	cache := map[string]Page{}
	for i := range ev.Sites {
		s := &ev.Sites[i]
		s.HTTPS.URL = "https://" + s.Name + "/"
		s.HTTP.URL = "http://" + s.Name + "/"
		cache[s.HTTPS.URL] = s.HTTPS
		cache[s.HTTP.URL] = s.HTTP
	}
	for _, plan := range d.Sites {
		i := slices.IndexFunc(ev.Sites, func(s Site) bool { return s.Name == plan.Host })
		if i < 0 {
			ev.Sites = append(ev.Sites, Site{Name: plan.Host})
			i = len(ev.Sites) - 1
		}
		s := &ev.Sites[i]
		s.Declared = plan.Declared
		entries := slices.Clone(plan.Entries)
		// Files are requested only on the schemes this declared origin uses,
		// or https for a discovered first-party name. Scope rechecks evidence.
		schemes := []string{}
		for _, e := range entries {
			if !slices.Contains(schemes, e.Scheme) {
				schemes = append(schemes, e.Scheme)
			}
		}
		if len(schemes) == 0 {
			schemes = []string{"https"}
		}
		for _, scheme := range schemes {
			for _, path := range []string{"/robots.txt", "/.well-known/security.txt"} {
				entries = append(entries, Entry{scheme, plan.Host, path})
			}
		}
		// A first-party front may redirect too; unconfirmed names never do.
		for _, p := range []Page{s.HTTPS, s.HTTP} {
			if p.URL != "" && (plan.Declared || p.FirstParty) {
				entries = append(entries, entryOf(p.URL))
			}
		}
		for _, e := range entries {
			u := entryURL(e)
			p, ok := cache[u]
			// A halted redirect did not read this entry. Its ordinary
			// declared read must be admitted independently by the gate.
			if ok && p.RedirectOf != "" && p.Decision != gate.DecisionSent && p.Decision != gate.DecisionReused {
				ok = false
			}
			if !ok {
				p = c.entry(ctx, e, "")
				cache[u] = p
			}
			if !slices.ContainsFunc(s.Pages, func(x Page) bool { return x.RequestID == p.RequestID }) {
				s.Pages = append(s.Pages, p)
			}
			if p.Status < 300 || p.Status >= 400 {
				continue
			}
			base, _ := url.Parse(u)
			loc := header(p, "Location")
			to, err := base.Parse(loc)
			if err != nil || loc == "" || to.User != nil || !strings.EqualFold(to.Host, base.Host) || (to.Scheme != "https" && to.Scheme != "http") {
				continue
			}
			hop := Entry{to.Scheme, to.Host, to.Path}
			if hop.Path == "" {
				hop.Path = "/"
			}
			hu := entryURL(hop)
			if _, ok = cache[hu]; ok {
				continue
			}
			q := c.entry(ctx, hop, p.RequestID)
			cache[hu] = q
			s.Pages = append(s.Pages, q)
		}
	}
	return ev
}
func entryOf(raw string) Entry { u, _ := url.Parse(raw); return Entry{u.Scheme, u.Host, u.Path} }
func (c collector) entry(ctx context.Context, e Entry, from string) Page {
	p := page(c.g.Send(ctx, gate.Request{Op: OpEntry, Asset: c.d.Asset, Stage: c.d.Stage, RedirectOf: from,
		Params: map[string]string{"scheme": e.Scheme, "host": e.Host, "path": e.Path}}))
	p.URL = entryURL(e)
	p.RedirectOf = from
	p.BlockedVendor = blocked(p)
	if e.Path == "/robots.txt" {
		if pageReason(p) == "" {
			n := 0
			for l := range strings.SplitSeq(p.Body, "\n") {
				k, v, ok := strings.Cut(l, ":")
				if ok && strings.EqualFold(strings.TrimSpace(k), "Disallow") && strings.TrimSpace(v) != "" {
					n++
				}
			}
			p.RobotsCount = &n
		}
		p.Body = ""
	}
	return p
}
func (c collector) sites(ctx context.Context) []Site {
	var out []Site
	for _, name := range c.d.Names {
		s := c.site(ctx, name)
		s.HTTPS.URL = "https://" + name + "/"
		s.HTTP.URL = "http://" + name + "/"
		out = append(out, s)
	}
	return out
}

// allPages deduplicates front-page evidence reused as an entry point.
func allPages(s Site) []Page {
	var out []Page
	for _, p := range append([]Page{s.HTTPS, s.HTTP}, s.Pages...) {
		if p.URL == "" {
			continue
		}
		if !slices.ContainsFunc(out, func(q Page) bool {
			return q.RequestID != "" && q.RequestID == p.RequestID || q.RequestID == "" && p.RequestID == "" && q.URL == p.URL
		}) {
			out = append(out, p)
		}
	}
	return out
}
func header(p Page, key string) string {
	vs := headers(p, key)
	if len(vs) > 0 {
		return vs[0]
	}
	return ""
}
func headers(p Page, key string) []string {
	for k, v := range p.Header {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// MergeSites joins reads already made on the same host, so an origin-wide
// rule sees every response across roots without sending another request.
func MergeSites(primary, other Evidence) Evidence {
	primary.Sites = slices.Clone(primary.Sites)
	for i := range primary.Sites {
		primary.Sites[i].Pages = slices.Clone(primary.Sites[i].Pages)
		for _, s := range other.Sites {
			if s.Name == primary.Sites[i].Name {
				primary.Sites[i].Declared = primary.Sites[i].Declared || s.Declared
				primary.Sites[i].Pages = append(primary.Sites[i].Pages, allPages(s)...)
			}
		}
	}
	return primary
}
