package web

import (
	"strings"
	"time"
)

// SenderDeclaration is operator context, not observed sending activity.
type SenderDeclaration struct {
	Domain, Service string
	Selectors       []string
}

// ScopeView supplies the names and declarations selected by engagement.
// Engagement owns asset boundaries, exclusions, URL interpretation and resolver
// trust. InputFrom owns normalization and assembly for the web rules
// (docs/spec/web-collector.md, "Subjects", "Email").
type ScopeView struct {
	Names         []Name
	Wildcard      *Name
	Gaps          []Gap
	Doubt         string
	Restricted    []Restriction
	URLAssets     []URLAsset
	Senders       []SenderDeclaration
	NoMail        []string
	OtherEvidence []Evidence
	Now           time.Time
	Vantage       string
}

// InputFrom assembles rule input without interpreting engagement-file types or
// deciding which roots own names. It performs no reads.
func InputFrom(asset, root string, evidence Evidence, view ScopeView) Input {
	in := Input{Asset: asset, Root: root, Evidence: evidence, Now: view.Now,
		Vantage: view.Vantage, Names: view.Names, Wildcard: view.Wildcard,
		Gaps: view.Gaps, Doubt: view.Doubt, Restricted: view.Restricted, URLAssets: view.URLAssets}
	for _, m := range evidence.Mail {
		context := MailContext{Domain: m.Domain}
		for _, sender := range view.Senders {
			if strings.TrimSuffix(strings.ToLower(sender.Domain), ".") != m.Domain {
				continue
			}
			selectors := []string{}
			for _, sel := range sender.Selectors {
				selectors = append(selectors, strings.ToLower(sel))
			}
			context.Senders = append(context.Senders, MailSender{Service: sender.Service, Selectors: selectors})
		}
		for _, domain := range view.NoMail {
			if strings.TrimSuffix(strings.ToLower(domain), ".") == m.Domain {
				context.NoMail = true
			}
		}
		in.MailContext = append(in.MailContext, context)
	}
	for _, other := range view.OtherEvidence {
		in.MailPolicies = append(in.MailPolicies, other.Mail...)
		in.Evidence = MergeSites(in.Evidence, other)
	}
	return in
}
