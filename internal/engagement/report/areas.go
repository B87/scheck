package report

import (
	"slices"
	"strings"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/policy"
)

// feeds says whether an asset's kind is read for an area once its
// collector exists: Workspace and GitHub tenants for identity, a GitHub
// organization and repositories for secrets and CI/CD, cloud projects for
// cloud and data, domains and URLs for the external surface, web and email
// (docs/spec/engagement.md, "Coverage").
func feeds(area finding.Area, a AssetInput) bool {
	github := strings.HasPrefix(a.ID, "saas:github:")
	switch area {
	case finding.AreaIdentity:
		return a.Kind == "saas"
	case finding.AreaSecrets:
		return a.Kind == "domain" || a.Kind == "url" || a.Kind == "repo" || github
	case finding.AreaCICD:
		return a.Kind == "repo" || github
	case finding.AreaCloud, finding.AreaData:
		return a.Kind == "cloud"
	case finding.AreaExternal:
		return a.Kind == "domain" || a.Kind == "url" || a.Kind == "network"
	case finding.AreaWeb:
		return a.Kind == "url" || a.Kind == "domain"
	case finding.AreaHosts:
		return a.Kind == "host"
	case finding.AreaEmail:
		return a.Kind == "domain"
	case finding.AreaLogging:
		return a.Kind == "cloud" || (a.Kind == "saas" && !github)
	}
	return false
}

// outside are the rows scheck covers in no mode; they print on every run
// and never fold (docs/spec/engagement.md, "Coverage").
var outside = []Row{
	{Area: "endpoints", Mark: "outside_scheck", Reasons: []ReasonDetail{},
		Detail: "scheck reads the settings of the hosts you list; it does not look for malware, infostealers or signs of " +
			"compromise on any of them, and laptops you did not list were not looked at"},
	{Area: "application_logic", Mark: "outside_scheck", Reasons: []ReasonDetail{},
		Detail: "authenticated testing of access control and business rules"},
	{Area: "processes", Mark: "outside_scheck", Reasons: []ReasonDetail{},
		Detail: "whether offboarding, incident response and vendor reviews are done as written"},
	{Area: "lookalike_domains", Mark: "outside_scheck", Reasons: []ReasonDetail{},
		Detail: "registrations of names you do not own"},
}

func (b *builder) coverage() []Row {
	var rows []Row
	for _, area := range finding.Areas {
		var row Row
		switch {
		case slices.Contains(b.in.NotUsed, string(area)):
			row = Row{Area: string(area), Mark: "not_applicable", Reasons: []ReasonDetail{},
				Detail: "you declared it does not apply (not_used)"}
		case area == finding.AreaHosts:
			row = b.hostsRow()
		case len(b.judged(area)) > 0:
			row = b.judgedRow(area, b.judged(area))
		default:
			row = b.areaRow(area)
		}
		for _, d := range b.in.Declarations {
			if d.Area == string(area) {
				row.DeclaredNotVerified = append(row.DeclaredNotVerified, Note{Kind: "declared_not_verified", Source: d.Source, Detail: d.Detail})
			}
		}
		rows = append(rows, row)
	}
	for _, tool := range b.in.OtherTools {
		rows = append(rows, Row{Area: "other_saas", Tool: tool, Mark: "not_assessed",
			Reasons: []ReasonDetail{{Reason: "collector_not_built"}}})
	}
	return append(rows, outside...)
}

// judged are the assets feeding area that a network collector read: the
// domain collector feeds the external and email rows.
func (b *builder) judged(area finding.Area) []AssetInput {
	var out []AssetInput
	for _, a := range b.in.Assets {
		if a.Collector != "" && feeds(area, a) && (area == finding.AreaExternal || area == finding.AreaEmail || area == finding.AreaWeb || area == finding.AreaSecrets) {
			out = append(out, a)
		}
	}
	return out
}

// areaRow is an area no collector in this build reads: not declared, or
// declared and not read.
func (b *builder) areaRow(area finding.Area) Row {
	row := Row{Area: string(area), Mark: "not_assessed", Reasons: []ReasonDetail{}}
	var fed []string
	for _, a := range b.in.Assets {
		if feeds(area, a) {
			fed = append(fed, a.Name)
		}
	}
	if len(fed) == 0 {
		row.Reasons = append(row.Reasons, ReasonDetail{Reason: "not_declared"})
		return row
	}
	row.Population = &Population{Kind: "assets", InScope: len(fed), Read: 0}
	row.Reasons = append(row.Reasons, ReasonDetail{Reason: "collector_not_built", Detail: strings.Join(fed, ", ")})
	return row
}

// hostsRow aggregates every host asset: one block of domains per host,
// marked from the rules that decided, never from the checks that ran
// (docs/spec/engagement.md, "Coverage", "The Hosts row").
func (b *builder) hostsRow() Row {
	row := Row{Area: string(finding.AreaHosts), Reasons: []ReasonDetail{}}
	var hosts, read int
	assessed, some := true, false
	for _, a := range b.in.Assets {
		if a.Kind != "host" {
			continue
		}
		hosts++
		v := b.hosts[a.ID]
		if v == nil {
			assessed = false
			reason := a.Reason
			if a.Status == statusRefused {
				reason = "refused"
			}
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: reason, Detail: a.Name})
			continue
		}
		read++
		row.AssetsCovered = append(row.AssetsCovered, a.ID)
		row.Principals = append(row.Principals, Principal{Identity: v.h.User, Elevation: v.env.Host.Elevation, ScopesSource: "provider"})
		if a.Status == statusIncomplete {
			assessed = false
			reason := "limit_reached"
			if v.h.Lost != "" {
				reason = "failed"
			}
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: reason, Detail: a.Name})
		}
		for _, si := range v.domains() {
			row.SubItems = append(row.SubItems, si)
			if si.Mark != "assessed" && si.Mark != "not_applicable" {
				assessed = false
			}
			if si.Mark == "assessed" || si.Mark == "partial" {
				some = true
			}
			for _, r := range si.Reasons {
				row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: r.Reason})
			}
		}
		if len(v.domains()) == 0 {
			// A collected host the report cannot place in any domain read
			// nothing a rule or a person could use: never "checked".
			assessed = false
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "unavailable:empty_plan", Detail: a.Name})
		}
		row.Narrowing = append(row.Narrowing, b.narrowing(v)...)
		if v.h.ExpectedServices > 0 {
			row.DeclaredNotVerified = append(row.DeclaredNotVerified, Note{Kind: "declared_not_verified", Source: v.h.ExpectedSource,
				Detail: "expected_services are not compared with listeners in this version"})
		}
	}
	switch {
	case hosts == 0:
		row.Mark = "not_assessed"
		row.Reasons = append(row.Reasons, ReasonDetail{Reason: "not_declared"})
		return row
	case assessed && len(row.SubItems) > 0:
		row.Mark = "assessed"
	case some:
		row.Mark = "partial"
	default:
		row.Mark = "not_assessed"
	}
	row.Population = &Population{Kind: "hosts", InScope: hosts, Read: read}
	return row
}

// under reports whether path is prefix or inside it.
func under(path, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// narrowing names each of the asset's narrowing entries and what it
// removed, so a narrowed run never reads as a clean one.
func (b *builder) narrowing(v *hostView) []Narrowing {
	var out []Narrowing
	for _, e := range v.h.Disabled {
		n := Narrowing{Entry: e.Source, Removed: []string{}}
		if _, ok := check.Lookup(e.Value, v.platform); ok {
			n.Removed = append(n.Removed, e.Value)
		}
		out = append(out, n)
	}
	// A read the operator's deny_paths refused names the path as
	// requested; the policy decided on its real path. Each denial goes to
	// the longest entry the requested path falls under, once, and one that
	// none accounts for (a symlink into a denied prefix) is counted under
	// deny_paths as a whole, never dropped.
	if len(v.h.DenyPaths) == 0 {
		return out
	}
	counts := make([]int, len(v.h.DenyPaths))
	unattributed := 0
	for _, o := range v.env.Observations {
		path, ok := strings.CutPrefix(o.Reason, policy.RuleConfigDeny+": ")
		if o.ReasonCode != "path_denied" || !ok {
			continue
		}
		best := -1
		for i, e := range v.h.DenyPaths {
			if under(path, e.Value) && (best < 0 || len(e.Value) > len(v.h.DenyPaths[best].Value)) {
				best = i
			}
		}
		if best < 0 {
			unattributed++
			continue
		}
		counts[best]++
	}
	for i, e := range v.h.DenyPaths {
		n := counts[i]
		out = append(out, Narrowing{Entry: e.Source, Removed: []string{}, DeniedReads: &n})
	}
	if unattributed > 0 {
		entry, _, _ := strings.Cut(v.h.DenyPaths[0].Source, "[")
		out = append(out, Narrowing{Entry: entry, Removed: []string{}, DeniedReads: &unattributed})
	}
	return out
}
