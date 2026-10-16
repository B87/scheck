package engagement

import (
	"fmt"
	"strings"

	ereport "github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/engagement/severity"
	"github.com/b87/scheck/internal/finding"
)

// declarations are what the severity table reads of the engagement file,
// each with the key it cites (docs/spec/engagement.md, "Severity in
// context").
func (r *run) declarations() severity.Declarations {
	d := severity.Declarations{Production: map[string]severity.Production{}}
	for i, e := range r.res.Intent.ExposedOnPurpose {
		if ref, err := parseURL(e.URL); err == nil {
			d.Exposed = append(d.Exposed, severity.Exposed{URL: strings.TrimPrefix(ref.ID, "url:"), Reason: e.Reason,
				Key: fmt.Sprintf("intent.exposed_on_purpose[%d]", i)})
		}
	}
	for i, m := range r.res.Data.MattersMost {
		id, ok := r.res.AssetID(m.Asset)
		if !ok {
			continue
		}
		name := id
		if a, ok := r.assetByID(id); ok {
			name = a.Name
		}
		d.MattersMost = append(d.MattersMost, severity.Matter{Asset: id, Name: name, What: m.What,
			Key: fmt.Sprintf("data.matters_most[%d]", i)})
	}
	d.Internet = map[string]string{}
	for _, a := range r.res.Assets {
		if a.Context != nil && a.Context.Exposure == "internet" {
			d.Internet[a.ID] = "assets." + a.Name + ".context.exposure"
		}
		if a.DeploysTo == "production" {
			d.Production[a.ID] = severity.Production{Name: a.Name, Key: "assets." + a.Name + ".deploys_to"}
		}
	}
	return d
}

// gradeAssets gives each fired judgment its chain under the asset that
// owns it, after partitionGitHubJudgments moved each to its repository,
// and each host posture finding the engagement's steps after the host
// collector's table: the report renders the chains and decides none.
func (r *run) gradeAssets(assets []ereport.AssetInput) {
	d := r.declarations()
	for i := range assets {
		severity.GradeAll(assets[i].Judged, assets[i].ID, d)
		h := assets[i].Host
		if h == nil {
			continue
		}
		h.Chains = nil
		for _, f := range h.Envelope.Findings {
			if c := severity.GradeHost(f.ID, f.Severity, assets[i].ID, d); c != nil {
				if h.Chains == nil {
					h.Chains = map[string]*finding.Chain{}
				}
				h.Chains[f.ID] = c
			}
		}
	}
}

// assetByID is the declared asset with the canonical id.
func (r *run) assetByID(id string) (ResolvedAsset, bool) {
	for _, a := range r.res.Assets {
		if a.ID == id {
			return a, true
		}
	}
	return ResolvedAsset{}, false
}
