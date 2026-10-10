package engagement

import (
	"fmt"

	githubc "github.com/b87/scheck/internal/collector/github"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

func githubCINotes(e githubc.Evidence) []ereport.Note {
	notes := []ereport.Note{}
	add := func(asset, detail string) {
		notes = append(notes, ereport.Note{Kind: "github_ci", Source: asset, Detail: detail})
	}
	for _, ci := range e.RepositoriesCI {
		add(ci.Asset, "CI evidence is configuration at default-branch commit "+ci.Branch.SHA+". Required-review strength, bypass access, runtime policies, checkout protection, approvals and actual execution were not assessed.")
		if ci.Default.Setting != nil && ci.Default.Setting.Approve != nil {
			add(ci.Asset, fmt.Sprintf("Workflow PR-approval setting: %t; this does not establish token defaults or effective branch review requirements.", *ci.Default.Setting.Approve))
		}
		for _, gap := range ci.Gaps {
			add(ci.Asset, "CI coverage gap: "+gap)
		}
		for _, w := range ci.Workflows {
			if w.Gap != "" {
				add(ci.Asset, w.Path+": "+w.Gap)
			}
			for _, j := range e.Judgments {
				if j.Asset == ci.Asset && j.Subject != nil && j.Subject.Key == w.Path && j.ID == "github.pr_target_unsafe_checkout" {
					if requests, ok := j.Details["runner_requests"].([]string); ok {
						for _, request := range requests {
							add(ci.Asset, w.Path+": "+request)
						}
					}
					if gaps, ok := j.Details["syntax_gaps"].([]string); ok {
						for _, gap := range gaps {
							add(ci.Asset, w.Path+": "+gap)
						}
					}
				}
			}
		}
		add(ci.Asset, "Job container and service images, runner access/isolation, App grants, reusable/composite internals, transitive dependencies and OIDC cloud access remain unassessed.")
	}
	return notes
}
