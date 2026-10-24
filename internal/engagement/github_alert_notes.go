package engagement

import (
	"fmt"
	"strings"

	githubc "github.com/b87/scheck/internal/collector/github"
	ereport "github.com/b87/scheck/internal/engagement/report"
)

func githubAlertNotes(e githubc.Evidence) []ereport.Note {
	notes := []ereport.Note{}
	add := func(asset, detail string) {
		notes = append(notes, ereport.Note{Kind: "github_alerts", Source: asset, Detail: detail})
	}
	for _, s := range e.OrganizationSecrets.Items {
		visibility := "unknown"
		if s.Visibility != nil {
			visibility = *s.Visibility
		}
		add("saas:github:"+strings.ToLower(e.Organization.Login), fmt.Sprintf("Organization Actions secret %s: visibility %s. Names and timestamps are metadata; no value was read and production use was not established.", s.Name, visibility))
	}
	for _, s := range e.SelectedSecrets {
		add("saas:github:"+strings.ToLower(e.Organization.Login), fmt.Sprintf("Actions secret %s: %s. Excluded or out-of-scope repositories were dropped; completing this list does not authorize reading them.", s.Name, inventoryCount("selected repositories", s.Repositories)))
	}
	for _, r := range e.RepositoriesAlerts {
		add(r.Asset, inventoryCount("repository Actions secret names", r.Secrets)+". Names are not evidence of leakage; values were not read.")
		add(r.Asset, inventoryCount("provider Dependabot alerts", r.Dependencies)+"; "+inventoryCount("provider secret-scanning alerts", r.SecretAlerts)+". These are provider reports, not a complete repository scan. Deployed dependencies and credential usability were not tested.")
		for _, s := range r.SecretAlerts.Items {
			if s.Validity != nil && *s.Validity == "inactive" {
				add(r.Asset, fmt.Sprintf("Secret alert %d: provider marked inactive; rotation was not verified.", s.Number))
			}
			if s.State == "resolved" && s.Resolution != nil {
				detail := fmt.Sprintf("Secret alert %d: provider resolution %s. Closing an alert does not establish rotation.", s.Number, *s.Resolution)
				if *s.Resolution == "wont_fix" && s.Validity != nil && *s.Validity == "active" {
					notes = append(notes, ereport.Note{Kind: "github_alert_followup", Source: r.Asset, Detail: fmt.Sprintf("Review secret alert %d: GitHub marks this alert closed because someone chose not to fix it (wont_fix), but still reports the credential active. Revocation was not verified. Check with the credential owner; this needs follow-up even though scheck could not reach a finding.", s.Number)})
					continue
				}
				add(r.Asset, detail)
			}
		}
		for _, located := range r.Located {
			if len(located.Locations.Gaps) > 0 {
				add(r.Asset, fmt.Sprintf("Secret alert %d location gaps: %s. Only recognized commit locations were assessed.", located.Alert.Number, strings.Join(located.Locations.Gaps, ", ")))
			}
		}
	}
	return notes
}
