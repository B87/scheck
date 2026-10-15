package engagement

import (
	"fmt"
	"strings"

	"github.com/b87/scheck/internal/collector/web"
)

// notJudged is Plan's closed list of what will not be decided for lack of a
// declaration: rules that will not judge, then raises and orders that cannot
// apply, each only when its condition holds on what Recon read
// (docs/spec/engagement.md, "The not-judged list"). The wording is the
// spec's.
func (r *run) notJudged() []string {
	out := []string{}
	var github, workspace, hosts, webRoots []ResolvedAsset
	for _, a := range r.res.Assets {
		switch {
		case a.Kind == KindSaaS && strings.HasPrefix(a.ID, "saas:github:") && a.Root == a.ID:
			github = append(github, a)
		case a.Kind == KindSaaS && strings.HasPrefix(a.ID, "saas:google-workspace:") && a.Root == a.ID:
			workspace = append(workspace, a)
		case a.Kind == KindHost:
			if _, read := r.hosts[a.Name]; read {
				hosts = append(hosts, a)
			}
		case (a.Kind == KindDomain || a.Kind == KindURL) && a.Root == a.ID:
			webRoots = append(webRoots, a)
		}
	}
	identity := append(append([]ResolvedAsset{}, workspace...), github...)
	kindOf := func(a ResolvedAsset) (tenant, identifier string, ids func(Person) []string) {
		if strings.HasPrefix(a.ID, "saas:github:") {
			return "GitHub organization", "GitHub login", func(p Person) []string { return p.GitHub }
		}
		return "Workspace tenant", "Workspace address", func(p Person) []string { return p.Workspace }
	}
	anyLeft := false
	for _, p := range r.res.People {
		anyLeft = anyLeft || p.Left != ""
	}
	if len(identity) > 0 && !anyLeft {
		out = append(out, "`identity.former_person_has_access` will not be judged on any account: no `people` entry has a `left` date, so scheck cannot tell a former employee's account from a current one.")
		if len(github) > 0 {
			out = append(out, "`identity.former_person_invited` will not be judged on any account: no `people` entry has a `left` date, so scheck cannot tell a former employee's account from a current one.")
		}
	}
	for _, a := range identity {
		tenant, identifier, ids := kindOf(a)
		named := false
		for _, handle := range sortedKeys(r.res.People) {
			p := r.res.People[handle]
			named = named || len(ids(p)) > 0
			if p.Left != "" && len(ids(p)) == 0 {
				out = append(out, fmt.Sprintf("`identity.former_person_has_access` on `%s` will not be judged for `%s`: their `people` entry gives no %s.", a.ID, handle, identifier))
			}
		}
		if _, declared := r.res.AdminsFor(a.ID); !declared {
			out = append(out, fmt.Sprintf("`identity.unexpected_admin` on `%s` will not be judged: `access.admins` lists nobody for this %s, so scheck cannot tell an expected admin from an unexpected one.", a.ID, tenant))
		}
		if !named {
			out = append(out, fmt.Sprintf("`identity.unattributed_admin` on `%s` will not be judged: no `people` entry gives a %s, so scheck cannot say whose the admin accounts are.", a.ID, identifier))
		}
	}
	anyProduction := false
	for _, org := range github {
		production := false
		for _, repo := range r.res.Assets {
			production = production || repo.Kind == KindRepo && repo.Root == org.ID && repo.DeploysTo == "production"
		}
		anyProduction = anyProduction || production
		if !production {
			out = append(out, fmt.Sprintf("`github.outside_admin_on_production` on `%s` will not be judged: no repository in this organization declares `deploys_to: production`.", org.ID))
		}
	}
	for _, use := range r.mailUse() {
		if use.NoMail {
			continue
		}
		selectors := false
		for _, s := range use.Senders {
			selectors = selectors || len(s.Selectors) > 0
		}
		if !selectors {
			out = append(out, fmt.Sprintf("`email.dkim_missing` on `%s` will not be judged: no DKIM selector is declared for it under `mail.senders`, and DNS cannot list selectors.", use.Domain))
		}
		if len(use.Senders) == 0 {
			out = append(out, fmt.Sprintf("`email.spf_undeclared_sender` on `%s` will not be judged: `mail.senders` names no service that sends as this domain.", use.Domain))
		}
	}
	if n := len(r.res.Intent.NotExposed); n > 0 && r.o.Vantage != "internet" {
		out = append(out, fmt.Sprintf("`web.restricted_reachable` will not be judged for %d %s under `intent.not_exposed`: this run's vantage is %s; run with `--vantage internet` from a network outside your VPN and office.",
			n, plural(n, "URL", "URLs"), cmpOr(r.o.Vantage, "not given")))
	}
	for _, h := range hosts {
		if h.Context == nil || len(h.Context.ExpectedServices) == 0 {
			out = append(out, fmt.Sprintf("`svc.listens_beyond_declared` on `%s` will not be judged: `expected_services` is empty for this host.", h.Name))
		}
	}
	for _, a := range workspace {
		if v := r.workspaceView(a); v.MailApproval == nil || !v.MailApproval.Current {
			out = append(out, fmt.Sprintf("`workspace.external_forwarding` on `%s` will not be judged: `authorization.mailboxes` authorizes no mailbox, so no forwarding settings are read.", a.ID))
		}
	}
	if len(github) > 0 && !anyProduction {
		out = append(out, "No repository declares `deploys_to: production`: no finding is raised for reaching production, a departed person's push to production cannot be raised, and no repository is read first for it.")
	}
	if len(r.res.Assets) > 0 && len(r.res.Data.MattersMost) == 0 {
		out = append(out, "`data.matters_most` is empty: no finding is raised for the data that matters most, and nothing is read or ranked first for it.")
	}
	for _, a := range identity {
		if enforced, _ := r.res.MFAFor(a.ID); enforced == "" || enforced == "unknown" {
			out = append(out, fmt.Sprintf("`access.mfa` does not say who must use 2-step verification in `%s`: scheck reports what it reads, but cannot raise a gap as a contradiction of what you believe.", a.ID))
		}
	}
	if len(webRoots) > 0 && len(r.res.Intent.NotExposed) == 0 {
		out = append(out, "`intent.not_exposed` lists no URL: nothing is checked for answering from the internet when it should not.")
	}
	return out
}

// mailUse is each mail domain Recon read under a domain root, as the
// email rules will treat it.
func (r *run) mailUse() []web.MailDomainUse {
	var out []web.MailDomainUse
	for _, ra := range r.recon.Assets {
		a, ok := r.asset(ra.Name)
		if !ok || ra.Web == nil || a.Kind != KindDomain {
			continue
		}
		out = append(out, web.MailUse(r.webInput(a, *ra.Web))...)
	}
	return out
}

func cmpOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
