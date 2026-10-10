package engagement

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

func (r *run) collectDomain(ctx context.Context, a ResolvedAsset, ra ReconAsset) ReconAsset {
	if ctx.Err() != nil {
		ra.Status, ra.Reason = StatusNotCollected, ReasonLimitReached
		ra.Detail = "limits.timeout ended the engagement before this asset was read"
		r.incomplete(a, ra)
		return ra
	}
	g, err := r.gateFor(ctx)
	if err != nil {
		ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
		r.incomplete(a, ra)
		return ra
	}
	r.o.Log("recon: %s (%s)", a.Name, a.ID)
	r.checkResolver(ctx, g, a)
	ev := web.Collect(ctx, g, r.webDomain(a))
	ra.Web = &ev
	ra.Judged = web.Judge(r.webInput(a, ev))
	r.suspendConfirmations(ra.Judged)
	ev = web.Enrich(ctx, g, r.webDomain(a), ev)
	ra.Web = &ev
	ra.Judged = web.Judge(r.webInput(a, ev))
	ra.Status = StatusCollected
	if ctx.Err() != nil || ev.Cut() {
		ra.Status, ra.Reason = StatusIncomplete, ReasonLimitReached
		ra.Detail = fmt.Sprintf("limits.timeout (%s) ended the engagement while it was read", r.res.Limits.Timeout)
		r.incomplete(a, ra)
	}
	return ra
}

// webInput is what the web collector's rules judge under a domain root:
// the names Scope looked up, what it could not list, whether the resolver
// invents answers, and what Recon read.
func (r *run) webInput(a ResolvedAsset, ev web.Evidence) web.Input {
	view := web.ScopeView{Now: r.session, Vantage: r.o.Vantage}
	root := a.name
	for _, plan := range r.webPlans(a) {
		for _, entry := range plan.Entries {
			raw := entry.Scheme + "://" + entry.Host + entry.Path
			for i, e := range r.res.Intent.NotExposed {
				ref, _ := parseURL(e.URL)
				if raw == strings.TrimPrefix(ref.ID, "url:") {
					view.Restricted = append(view.Restricted, web.Restriction{URL: raw, Audience: e.Audience, Source: fmt.Sprintf("intent.not_exposed[%d]", i)})
				}
			}
		}
	}
	if a.Kind == KindURL {
		root = ""
	}
	for _, b := range r.res.Assets {
		if b.Kind == KindURL {
			view.URLAssets = append(view.URLAssets, web.URLAsset{ID: b.ID, URL: strings.TrimPrefix(b.ID, "url:")})
		}
	}
	for _, sender := range r.res.Mail.Senders {
		view.Senders = append(view.Senders, web.SenderDeclaration{Domain: sender.Domain, Service: sender.Service, Selectors: sender.DKIMSelectors})
	}
	view.NoMail = r.res.Mail.NoMail
	if r.recon != nil {
		for _, ra := range r.recon.Assets {
			if ra.Web != nil && ra.ID != a.ID {
				view.OtherEvidence = append(view.OtherEvidence, *ra.Web)
			}
		}
	}
	if r.scoped == nil {
		view.Gaps = append(view.Gaps, web.Gap{Reason: "unavailable:not_listed", Detail: "Scope did not run"})
		return web.InputFrom(a.ID, root, ev, view)
	}
	// Scope's names were answered by the resolver Scope asked, Recon's
	// reads by this session's: each must be known not to invent answers
	// (a resumed session may be on another network).
	view.Doubt = cmp.Or(resolverDoubt(r.scoped.Resolver), resolverDoubt(r.reconResolver))
	for _, sd := range r.scoped.Domains {
		if sd.Root != a.ID {
			continue
		}
		if sd.Control != nil {
			n := webName(*sd.Control)
			view.Wildcard = &n
		}
		if sd.CT != "ok" {
			view.Gaps = append(view.Gaps, web.Gap{Reason: "unavailable:ct_source", Detail: "certificate transparency did not answer"})
		}
		for _, d := range sd.Dropped {
			// An excluded name or a non-name was never part of the root's
			// names; anything else dropped hides names.
			if !strings.HasPrefix(d.Rule, "exclude[") && d.Rule != "not_a_name" {
				view.Gaps = append(view.Gaps, web.Gap{Reason: "unavailable:" + d.Rule, Detail: fmt.Sprintf("%d dropped (%s)", d.Count, d.Rule)})
			}
		}
		for _, sn := range sd.Names {
			// A name under a more specific domain root is that root's.
			if r.innerRoot(a, sn.Name) {
				continue
			}
			view.Names = append(view.Names, webName(sn))
		}
	}
	return web.InputFrom(a.ID, root, ev, view)
}

// resolverDoubt is why no answer of a resolver stands, "" when it is known
// not to invent them.
func resolverDoubt(res *Resolver) string {
	switch {
	case res == nil:
		return "unavailable:resolver_unchecked"
	case res.Rewrites:
		return "unavailable:resolver_rewrites"
	case !res.Known():
		return "unavailable:resolver_unchecked"
	}
	return ""
}

// checkResolver sends this session's control lookup under invalid., once,
// before Recon reads any domain root through the gate's resolver.
func (r *run) checkResolver(ctx context.Context, g *gate.Gate, a ResolvedAsset) {
	if r.reconResolver != nil {
		return
	}
	ctl := g.Resolve(ctx, gate.Resolve{Asset: a.ID, Name: randomLabel() + ".invalid", Stage: "recon", Control: true})
	r.reconResolver = &Resolver{Address: g.Resolver(), Rewrites: ctl.Lookup.Outcome == gate.OutcomeAddresses,
		Control: string(ctl.Lookup.Outcome)}
	if ctl.Decision != gate.DecisionSent {
		r.reconResolver.Control = ctl.Decision
	}
	if r.recon != nil {
		r.recon.Resolver = r.reconResolver
	}
}

// innerRoot reports a name under a domain root more specific than a.
func (r *run) innerRoot(a ResolvedAsset, name string) bool {
	return slices.ContainsFunc(r.res.Roots, func(o Ref) bool {
		return o.Kind == KindDomain && o.name != a.name && domainUnder(o.name, a.name) && domainUnder(name, o.name)
	})
}

// webDomain is what the web collector reads under a domain root: the mail
// domains under it, the root first, with the DKIM selectors declared for
// each, and the names Scope chose to read.
func (r *run) webDomain(a ResolvedAsset) web.Domain {
	d := web.Domain{Asset: a.ID, Name: a.name, Stage: "recon", Sites: r.webPlans(a)}
	selectors := map[string][]string{}
	order := []string{a.name}
	// A mail domain is read under the most specific root holding it, once.
	add := func(name string) {
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if domainUnder(name, a.name) && !r.innerRoot(a, name) && !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	for _, s := range r.res.Mail.Senders {
		add(s.Domain)
		dom := strings.TrimSuffix(strings.ToLower(s.Domain), ".")
		for _, sel := range s.DKIMSelectors {
			if sel = strings.ToLower(sel); !slices.Contains(selectors[dom], sel) {
				selectors[dom] = append(selectors[dom], sel)
			}
		}
	}
	for _, n := range r.res.Mail.NoMail {
		add(n)
	}
	for _, name := range order {
		d.Mail = append(d.Mail, web.MailDomain{Name: name, Selectors: selectors[name]})
	}
	if r.scoped != nil {
		for _, sd := range r.scoped.Domains {
			if sd.Root != a.ID {
				continue
			}
			if sd.Control != nil && resolverDoubt(r.scoped.Resolver) == "" && resolverDoubt(r.reconResolver) == "" &&
				web.NeedsWildcardPage(webName(*sd.Control)) {
				d.Names = append(d.Names, sd.Control.Name)
			}
			for _, sn := range sd.Names {
				if sn.Read && !r.innerRoot(a, sn.Name) {
					d.Names = append(d.Names, sn.Name)
				}
			}
		}
	}
	return d
}

func webName(sn ScopeName) web.Name {
	return web.Name{Name: sn.Name, Status: sn.Status, Detail: sn.Detail, Outcome: sn.Outcome,
		Chain: sn.Chain, Addresses: sn.Addresses, FinalInRoot: sn.FinalInRoot, Request: sn.RequestID}
}

// Positive fingerprints narrow the live scope and mark the persisted
// confirmation as suspended (docs/spec/web-collector.md, "Never claim a name").
func (r *run) suspendConfirmations(judged []finding.Judgment) {
	for _, j := range judged {
		if j.Verdict != web.Fired || (j.ID != finding.IDDNSTakeoverCandidate && j.ID != finding.IDDNSUnclaimedAtProvider) {
			continue
		}
		names := append([]string{j.Subject.Key}, j.Members...)
		for _, name := range names {
			if strings.HasPrefix(name, "*.") {
				continue
			}
			if r.webScope != nil {
				r.webScope.suspended.Store(name, true)
			}
			if r.scoped == nil {
				continue
			}
			suspend := func(e *Evidence) {
				if e != nil && e.Kind == "operator" {
					e.Kind = "suspended"
				}
			}
			for i := range r.scoped.Assets {
				a := &r.scoped.Assets[i]
				if ref, ok := parseSubject(a.ID); ok && ref.name == name {
					suspend(a.FirstParty)
				}
			}
			for i := range r.scoped.Domains {
				for k := range r.scoped.Domains[i].Names {
					n := &r.scoped.Domains[i].Names[k]
					if n.Name == name {
						suspend(n.FirstParty)
					}
				}
			}
		}
	}
}

// sessionSites totals hosts across assets without reclassifying requests whose
// admission did not use first-party evidence (docs/spec/scope.md, "Resume").
