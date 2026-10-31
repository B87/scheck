package engagement

import (
	"context"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/collector/web"
)

// ProbePlan is Plan's preview of one site's probes: every request that
// would be sent, its method and URL, and the count, before anything is
// (docs/spec/scope.md, "Probes"; docs/spec/engagement.md, "Probes").
type ProbePlan struct {
	// Asset is the root the site was read under; Site its name.
	Asset  string `json:"asset"`
	Site   string `json:"site"`
	Scheme string `json:"scheme"`
	// Mode is the site's probe mode, confirm or all.
	Mode string `json:"mode"`
	// Evidence is the first-party evidence the probes rest on.
	Evidence  string   `json:"evidence"`
	Framework []string `json:"framework,omitempty"`
	// Requests are the requests the plan would send; Count their number.
	Requests []ProbeRequest `json:"requests"`
	Count    int            `json:"count"`
	// FrameworkSkipped are the probes of a framework not declared for the
	// site, which are not sent.
	FrameworkSkipped []string `json:"framework_skipped,omitempty"`
	// NotRun is why nothing will be sent: the site answered neither over
	// https nor over http.
	NotRun string `json:"not_run,omitempty"`

	apply  []web.Probe
	origin string
}

// ProbeRequest is one planned request.
type ProbeRequest struct {
	Probe  string `json:"probe"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// ProbePreviewSite is what the operator is asked to approve for one site
// in confirm mode: the same requests Plan listed.
type ProbePreviewSite struct {
	Site     string
	Evidence string
	Requests []ProbeRequest
}

// planProbes lists, from what Recon read, the sites a probe could run on:
// those whose mode is confirm or all and that rest on first-party
// evidence. A site in a probing mode with no evidence is named apart, since
// it is not probed. It sends nothing.
func (r *run) planProbes() (plans []ProbePlan, unevidenced []string) {
	sc := r.siteScope()
	seen := map[string]bool{}
	for _, ra := range r.recon.Assets {
		if ra.Web == nil {
			continue
		}
		for _, site := range ra.Web.Sites {
			if seen[site.Name] {
				continue
			}
			seen[site.Name] = true
			origin := "https://" + site.Name
			mode := sc.probeMode(origin)
			if mode != "confirm" && mode != "all" {
				continue
			}
			ev, _, ok := sc.ProbeEvidence(site.Name)
			if !ok {
				unevidenced = append(unevidenced, site.Name)
				continue
			}
			evidence := "a network root, once every address the name resolves to is checked"
			if ev != nil {
				evidence = ev.String()
			}
			p := ProbePlan{Asset: ra.ID, Site: site.Name, Mode: mode, Evidence: evidence, Framework: sc.frameworkOf(origin), Requests: []ProbeRequest{}}
			switch {
			case answeredOver(site, "https"):
				p.Scheme = "https"
			case answeredOver(site, "http"):
				p.Scheme = "http"
			default:
				p.Scheme, p.NotRun = "https", web.NotRunNoAnswer
			}
			p.origin = p.Scheme + "://" + site.Name
			apply, skipped := web.SelectProbes(p.Framework)
			p.apply = apply
			for _, s := range skipped {
				p.FrameworkSkipped = append(p.FrameworkSkipped, s.ID)
			}
			for _, pr := range apply {
				p.Requests = append(p.Requests, ProbeRequest{Probe: pr.ID, Method: "GET", URL: p.origin + pr.Path})
			}
			if p.NotRun == "" {
				p.Count = len(p.Requests)
			}
			plans = append(plans, p)
		}
	}
	slices.Sort(unevidenced)
	return plans, unevidenced
}

// probeFrameworkGaps counts, by finding id, the probes left unsent under a
// root because no framework was declared for a probed site, or it was
// declared unknown. `none` is a declaration: nothing framework-specific
// applies, and the sub-items stay decided.
func (r *run) probeFrameworkGaps(root string) map[string]int {
	var out map[string]int
	for _, p := range r.probePlan {
		if p.Asset != root || len(p.Framework) > 0 && !slices.Equal(p.Framework, []string{"unknown"}) {
			continue
		}
		for _, id := range p.FrameworkSkipped {
			for _, pr := range web.Probes {
				if pr.ID == id {
					if out == nil {
						out = map[string]int{}
					}
					out[pr.Finding]++
				}
			}
		}
	}
	return out
}

// answeredOver says Recon got an HTTP answer from the site over the scheme:
// its front page, or any entry point it read.
func answeredOver(s web.Site, scheme string) bool {
	front := s.HTTPS
	if scheme == "http" {
		front = s.HTTP
	}
	return front.Status > 0 || slices.ContainsFunc(s.Pages, func(p web.Page) bool {
		return p.Status > 0 && strings.HasPrefix(p.URL, scheme+"://")
	})
}

// siteScope is the engagement file's scope as the gate reads it, built
// once for the run.
func (r *run) siteScope() *scope {
	if r.webScope == nil {
		r.webScope = r.res.GateScope(r.session).(*scope)
	}
	return r.webScope
}

// checkProbes sends the probes the sites' modes allow, through the gate.
// A confirm site is sent only what the operator approved from the preview
// in this session; with no terminal to ask, or on a no, it is not run. A
// probe that is not run is recorded with its reason, never as clean.
func (r *run) checkProbes(ctx context.Context, doc *CheckDoc) error {
	if len(r.probePlan) == 0 {
		return nil
	}
	g, err := r.gateFor(ctx)
	if err != nil {
		return err
	}
	sc := r.siteScope()
	var ask []ProbePreviewSite
	for _, p := range r.probePlan {
		if p.Mode == "confirm" && p.NotRun == "" && len(p.Requests) > 0 {
			ask = append(ask, ProbePreviewSite{Site: p.Site, Evidence: p.Evidence, Requests: p.Requests})
		}
	}
	approved := map[string]bool{}
	if len(ask) > 0 && r.o.ConfirmProbes != nil {
		for _, name := range r.o.ConfirmProbes(ctx, ask) {
			approved[name] = true
		}
	}
	byAsset := map[string][]web.ProbeTarget{}
	var order []string
	for _, p := range r.probePlan {
		t := web.ProbeTarget{Name: p.Site, Scheme: p.Scheme, Mode: p.Mode, Evidence: p.Evidence}
		why := p.NotRun
		if why == "" && p.Mode == "confirm" {
			switch {
			case approved[p.Site]:
				for _, pr := range p.apply {
					sc.Approve(p.origin, pr.Path)
				}
			case r.o.ConfirmProbes == nil:
				why = web.NotRunNoTTY
			default:
				why = web.NotRunDeclined
			}
		}
		for _, pr := range p.apply {
			if why != "" {
				t.Skip = append(t.Skip, web.ProbeSkip{Probe: pr, Why: why})
			} else {
				t.Send = append(t.Send, pr)
			}
		}
		if _, ok := byAsset[p.Asset]; !ok {
			order = append(order, p.Asset)
		}
		byAsset[p.Asset] = append(byAsset[p.Asset], t)
	}
	for _, id := range order {
		ev := web.CollectProbes(ctx, g, id, byAsset[id])
		i := slices.IndexFunc(doc.Assets, func(c CheckAsset) bool { return c.ID == id })
		if i < 0 {
			name := id
			if a, ok := r.assetByID(id); ok {
				name = a.Name
			}
			doc.Assets = append(doc.Assets, CheckAsset{Name: name, ID: id})
			i = len(doc.Assets) - 1
		}
		doc.Assets[i].Probes = &ev
		r.probesCut(id, ev)
	}
	return nil
}

// probesFor is what Check read of the probes under a root, nil when none ran
// or were planned.
func (r *run) probesFor(id string) *web.ProbeEvidence {
	if r.checked == nil {
		return nil
	}
	for _, c := range r.checked.Assets {
		if c.ID == id {
			return c.Probes
		}
	}
	return nil
}

// probesCut records the asset incomplete when a limit ended its probes: the
// authorization window, limits.timeout, or a cancelled run. A window that
// had closed before Check is the same cut, so the run is never a clean exit
// for probes that did not run (docs/spec/scope.md, "Authorization windows").
func (r *run) probesCut(id string, ev web.ProbeEvidence) {
	cut := ""
	for _, s := range ev.Sites {
		for _, rd := range s.Reads {
			switch {
			case rd.NotRun == web.NotRunWindow || rd.Decision == "refused:window" || rd.Decision == "unavailable:window_ended":
				cut = "the authorization window did not cover the probes of " + s.Name
			case rd.NotRun == web.NotRunCancelled || strings.HasSuffix(rd.Decision, ":deadline") || rd.Decision == "unavailable:canceled":
				cut = "limits.timeout ended the probes of " + s.Name
			}
		}
	}
	if cut == "" {
		return
	}
	// The report marks an asset from its Recon entry, as Recon's own cut does.
	for i := range r.recon.Assets {
		if ra := &r.recon.Assets[i]; ra.ID == id && ra.Status == StatusCollected {
			ra.Status, ra.Reason, ra.Detail = StatusIncomplete, ReasonLimitReached, cut
			if a, ok := r.assetByID(id); ok {
				r.incomplete(a, *ra)
			}
		}
	}
}

// probeSent says some probe left this machine in the run.
func (r *run) probeSent() bool {
	if r.checked == nil {
		return false
	}
	for _, c := range r.checked.Assets {
		if c.Probes == nil {
			continue
		}
		for _, s := range c.Probes.Sites {
			for _, rd := range s.Reads {
				if rd.RequestID != "" && !strings.HasPrefix(rd.Decision, "refused:") {
					return true
				}
			}
		}
	}
	return false
}
