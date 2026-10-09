package engagement

import (
	"github.com/b87/scheck/internal/collector/web"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

// webShortfalls applies the declared-read transport obligations and the exact
// restricted-URL negative-evidence exception (docs/spec/scope.md, "Outcomes").
func (r *run) webShortfalls(a ResolvedAsset, ev web.Evidence) []ereport.Shortfall {
	var out []ereport.Shortfall
	seen := map[string]bool{}
	add := func(subject, decision string) {
		transport := decision == "unavailable:connection_refused" || decision == "unavailable:connection_reset" || decision == "unavailable:timeout" || decision == "unavailable:unreachable" || decision == "unavailable:no_resolver" || decision == "unavailable:dns_timeout" || decision == "unavailable:dns_servfail" || decision == "unavailable:dns_refused" || decision == "unavailable:dns_"
		if transport && !seen[subject] {
			seen[subject] = true
			out = append(out, ereport.Shortfall{Asset: a.ID, AssetName: a.Name, Reason: "failed", Detail: subject + ": " + decision})
		}
	}
	checkDNS := func(subject string, read web.RecordRead) {
		if read.Insufficient() && read.Decision != "refused:excluded" && (read.Outcome == "timeout" || read.Outcome == "servfail" || read.Outcome == "refused" || read.Decision == "unavailable:no_resolver") {
			add(subject, "unavailable:dns_"+read.Outcome)
		}
	}
	if a.Kind == KindDomain {
		checkDNS(a.name, ev.NS)
	}
	for _, m := range ev.Mail {
		for _, read := range []web.RecordRead{m.TXT, m.DMARC, m.MX} {
			checkDNS(m.Domain, read)
		}
	}
	in := r.webInput(a, ev)
	negatives := map[string]bool{}
	for _, j := range web.Judge(in) {
		if j.ID == "web.restricted_reachable" && j.Verdict == web.Disproved {
			negatives[j.Subject.Key] = true
		}
	}
	for _, plan := range r.webPlans(a) {
		for _, entry := range plan.Entries {
			raw := entry.Scheme + "://" + entry.Host + entry.Path
			if negatives[raw] {
				continue
			}
			for _, site := range ev.Sites {
				for _, p := range append([]web.Page{site.HTTPS, site.HTTP}, site.Pages...) {
					if p.URL == raw && p.RedirectOf == "" {
						add(raw, p.Decision)
						break
					}
				}
			}
		}
	}
	return out
}
