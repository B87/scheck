package web

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// TakeoverVersion identifies the reviewed data, not a claim made against a
// provider. Changing it invalidates recall comparisons (docs/spec/web-collector.md,
// "Takeover fingerprints"). No request is made to a provider account or API.
const TakeoverVersion = "2026-10-09.1"
const takeoverSource = "https://github.com/EdOverflow/can-i-take-over-xyz/blob/5bd4e12837911c8475486f1da922c9b9c706e632/fingerprints.json"
const takeoverSourceDate = "2025-02-08"

type fingerprint struct {
	Provider                        string
	Target                          *regexp.Regexp
	NXDomain                        bool
	Ownership                       bool
	HTTPOnly                        bool
	Status                          int
	Body, Server                    string
	Source, Caveat, OwnershipSource string
	CaveatSuffix                    string
}

// Suffixes are anchored DNS label patterns: never substring matches. Body
// entries require the status too, and S3 also requires its server header.
// Only independently recognizable error pages are enabled; the other planned
// providers have no fingerprint until their evidence is verified.
var fingerprints = []fingerprint{
	{Provider: "GitHub Pages", Target: regexp.MustCompile(`^.+\.github\.io$`), HTTPOnly: true, Status: 404, Body: "There isn't a GitHub Pages site here.", Source: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages", Caveat: "Whether your organization verified this domain at GitHub was not checked; verification can prevent another account from claiming it."},
	{Provider: "AWS S3", Target: regexp.MustCompile(`^.+\.s3(?:-website[-.][a-z0-9-]+|[.-][a-z0-9-]+)?\.amazonaws\.com$`), Status: 404, Body: "NoSuchBucket", Server: "AmazonS3", Source: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html"},
	{Provider: "Elastic Beanstalk", Target: regexp.MustCompile(`^.+\.[a-z0-9-]+\.elasticbeanstalk\.com$`), NXDomain: true, Source: "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html"},
	{Provider: "Azure", CaveatSuffix: ".azurewebsites.net", Target: regexp.MustCompile(`^.+\.(?:azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azure-api\.net)$`), NXDomain: true, Source: "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover", Caveat: "Azure App Service's asuid TXT ownership record was not checked; it can prevent another account from binding this domain."},
	{Provider: "Vercel", Target: regexp.MustCompile(`^cname\.vercel-dns(?:-0)?\.com$`), Ownership: true, Status: 404, Body: "DEPLOYMENT_NOT_FOUND", Source: "https://vercel.com/docs/errors/deployment_not_found", OwnershipSource: "https://vercel.com/docs/domains/working-with-domains/claim-domain-ownership"},
}

func provider(n Name) *fingerprint {
	if n.FinalInRoot || len(n.Chain) == 0 {
		return nil
	}
	target := strings.TrimSuffix(strings.ToLower(n.Chain[len(n.Chain)-1]), ".")
	for i := range fingerprints {
		if fingerprints[i].Target.MatchString(target) {
			return &fingerprints[i]
		}
	}
	return nil
}

// NeedsWildcardPage says whether the root control needs its one front-page
// pair. A dangling chain is judged from DNS; an unknown provider needs no page.
func NeedsWildcardPage(n Name) bool {
	p := provider(n)
	return p != nil && !p.NXDomain && n.Status == StatusResolves
}

func takeoverID(p *fingerprint) string {
	if p.Ownership {
		return finding.IDDNSUnclaimedAtProvider
	}
	return finding.IDDNSTakeoverCandidate
}

// takeover decides only the table entry's rule. The returned bool means a
// positive fingerprint replaced dns.dangling_external; an abstention never
// consumes a known dangling DNS record ("DNS and takeover").
func (j *judging) takeover(n Name, base Judgment) bool {
	p := provider(n)
	if p == nil {
		return false
	}
	x := base
	x.ID, x.Verdict, x.Reason = takeoverID(p), Abstained, "unavailable:provider_response"
	x.NotChecked = []string{"Whether someone has already claimed this name was not checked"}
	if p.Caveat != "" && (p.CaveatSuffix == "" || strings.HasSuffix(n.Chain[len(n.Chain)-1], p.CaveatSuffix)) {
		x.NotChecked = append(x.NotChecked, p.Caveat)
	}
	x.Excerpt = n.Name + " → " + strings.Join(n.Chain, " → ") + ": " + n.Outcome + "; provider: " + p.Provider
	if n.Status == StatusNotChecked || n.Status == StatusInsufficient {
		x.Reason = unknown(n)
	} else if p.NXDomain && n.Outcome == string(gate.OutcomeNXDomain) {
		x.Verdict, x.Reason = Fired, ""
	} else if n.Outcome == string(gate.OutcomeNoData) || n.Outcome == string(gate.OutcomeNXDomain) {
		x.Reason = "unavailable:provider_evidence"
	} else {
		j.providerPages(n, p, &x)
	}
	if x.Verdict == Fired {
		if p.Ownership {
			x.Excerpt += "; the provider says nothing is set up there; its policy requires ownership verification when moving a domain from another account; this binding's ownership was not checked"
		} else {
			x.Excerpt += "; the provider says nothing is set up there; another account may be able to claim it"
		}
	}
	j.add(x)
	return x.Verdict == Fired && j.in.Doubt == ""
}

func (j *judging) providerPages(n Name, p *fingerprint, x *Judgment) {
	for _, site := range j.in.Evidence.Sites {
		if site.Name != n.Name {
			continue
		}
		for i, page := range []Page{site.HTTPS, site.HTTP} {
			if page.RequestID != "" && !slices.Contains(x.Reads, page.RequestID) {
				x.Reads = append(x.Reads, page.RequestID)
			}
			if p.HTTPOnly && i == 0 {
				continue
			}
			if page.Decision != gate.DecisionSent || page.Status == 429 || page.Status >= 500 {
				if x.Verdict == Abstained && page.Reason != "" {
					x.Reason = page.Reason
				}
				continue
			}
			marker := p.Body != "" && strings.Contains(page.Body, p.Body)
			server := p.Server == "" || slices.Contains(page.Header["Server"], p.Server)
			if page.Status == p.Status && marker && server {
				x.Verdict, x.Reason = Fired, ""
				x.Excerpt += fmt.Sprintf("; %s status %d, marker %q", []string{"https", "http"}[i], page.Status, p.Body)
				return
			}
			// Marked or cut bodies cannot prove the marker is absent. A generic
			// 4xx page says neither configured nor unclaimed.
			if page.Status >= 200 && page.Status < 400 && !marker && !page.Truncated &&
				!strings.Contains(page.Body, "[REDACTED:") && !strings.Contains(page.Body, "[TRUNCATED:") {
				x.Verdict, x.Reason = Disproved, ""
				x.Excerpt += "; the provider serves a site for this name; whose site it is was not checked"
			}
		}
	}
}

// Unfingerprinted lists external targets whose provider has no verified
// fingerprint. These are not applicable to takeover rules, never cleared.
func Unfingerprinted(in Input) []string {
	names := slices.Clone(in.Names)
	if in.Wildcard != nil {
		n := *in.Wildcard
		n.Name = "*." + in.Root
		names = append(names, n)
	}
	var out []string
	for _, n := range names {
		if n.Status == StatusExcluded || n.Status == StatusWildcard || n.FinalInRoot || len(n.Chain) == 0 || provider(n) != nil {
			continue
		}
		out = append(out, n.Name+" → "+n.Chain[len(n.Chain)-1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}
