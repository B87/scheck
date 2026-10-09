package engagement

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/collector/web"
)

// webPlans describes the file's entries and first-party names. It does not
// grant permission: every read rechecks live scope through the gate.
func (r *run) webPlans(a ResolvedAsset) []web.SitePlan {
	var plans []web.SitePlan
	add := func(ref Ref, declared bool) {
		u, _ := url.Parse(strings.TrimPrefix(ref.ID, "url:"))
		if u == nil {
			return
		}
		i := slices.IndexFunc(plans, func(p web.SitePlan) bool { return p.Host == u.Host })
		if i < 0 {
			plans = append(plans, web.SitePlan{Host: u.Host})
			i = len(plans) - 1
		}
		plans[i].Declared = plans[i].Declared || declared
		e := web.Entry{Scheme: u.Scheme, Host: u.Host, Path: ref.path}
		if !slices.Contains(plans[i].Entries, e) {
			plans[i].Entries = append(plans[i].Entries, e)
		}
	}
	holds := func(ref Ref) bool {
		return a.Kind == KindURL && sameOrigin(a.Ref, ref) && (ref.path == a.path || strings.HasPrefix(ref.path, strings.TrimSuffix(a.path, "/")+"/")) || a.Kind == KindDomain && domainUnder(ref.name, a.name) && !r.innerRoot(a, ref.name)
	}
	for _, b := range r.res.Assets {
		if b.Kind == KindURL && holds(b.Ref) {
			add(b.Ref, true)
		}
	}
	for _, list := range [][]Exposure{r.res.Intent.ExposedOnPurpose, r.res.Intent.NotExposed} {
		for _, e := range list {
			ref, _ := parseURL(e.URL)
			if holds(ref) {
				add(ref, false)
			}
		}
	}
	if a.Kind == KindDomain && r.scoped != nil {
		for _, d := range r.scoped.Domains {
			if d.Root != a.ID {
				continue
			}
			for _, n := range d.Names {
				if n.Read && n.FirstParty.counts() && !r.innerRoot(a, n.Name) {
					ref, _ := parseURL("https://" + n.Name + "/")
					add(ref, false)
				}
			}
		}
	}
	return plans
}
func (r *run) collectURL(ctx context.Context, a ResolvedAsset, ra ReconAsset) ReconAsset {
	if ctx.Err() != nil {
		ra.Status, ra.Reason = StatusNotCollected, ReasonLimitReached
		r.incomplete(a, ra)
		return ra
	}
	g, err := r.gateFor(ctx)
	if err != nil {
		ra.Status, ra.Reason, ra.Detail = StatusFailed, ReasonFailed, err.Error()
		r.incomplete(a, ra)
		return ra
	}
	ev := web.Collect(ctx, g, web.Domain{Asset: a.ID, Name: a.name, Stage: "recon", URLOnly: true, Sites: r.webPlans(a)})
	ra.Web = &ev
	ra.Judged = web.Judge(r.webInput(a, ev))
	ra.Status = StatusCollected
	if ctx.Err() != nil || ev.Cut() {
		ra.Status, ra.Reason = StatusIncomplete, ReasonLimitReached
		r.incomplete(a, ra)
	}
	return ra
}
