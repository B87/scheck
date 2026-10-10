package github

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

var alertLimits = []string{"Provider patterns and alerts are not a complete secret scan; repository history and unsupported locations were not scanned", "Credential authenticity, usability, rotation and dependency runtime exploitability were not tested", "Repositories hidden from this credential remain unassessed"}

func alertJudgment(id, asset string, s *Subject, reads []string) Judgment {
	j := judgment(id, asset, s, reads)
	j.NotChecked = slices.Clone(alertLimits)
	if slices.Contains(finding.GitHubAlertIDs()[1:4], id) {
		j.NotChecked = []string{"Deployed dependency versions, runtime exploitability and development-dependency safety were not verified", "Provider dependency alerts do not cover every vulnerability; hidden repositories and unavailable provider evidence remain unassessed"}
	}
	if id == finding.IDGitHubOrgSecretAll {
		j.NotChecked = []string{"Secret values, production use, workflow access to the value and rotation were not verified", "Repositories hidden from this credential remain unassessed"}
	}
	return j
}
func JudgeAlerts(e Evidence, c Context) []Judgment {
	out := []Judgment{}
	p := e.OrganizationSecrets
	for _, s := range p.Items {
		j := alertJudgment(finding.IDGitHubOrgSecretAll, c.OrganizationAsset, &Subject{Kind: "secret_location", Key: "actions:" + strings.ToLower(s.Name), Label: "Actions secret " + s.Name}, readIDs(p.Reads))
		j.Details = map[string]any{"secret_name": s.Name, "provider_visibility": s.Visibility}
		if s.Visibility != nil {
			v := *s.Visibility
			known := secretNameKey(s) != "" && metadataObserved(p) && slices.Contains([]string{"all", "private", "selected"}, v)
			settle(&j, known && v == "all", known && (v == "all" || metadataComplete(p)), fmt.Sprintf("Actions secret %s; provider visibility: %s; names only, no value read", s.Name, v))
		}
		out = append(out, j)
	}
	if len(p.Items) == 0 && len(p.Reads) > 0 {
		j := alertJudgment(finding.IDGitHubOrgSecretAll, c.OrganizationAsset, nil, readIDs(p.Reads))
		j.Details = map[string]any{"recognized_secret_names": 0}
		settle(&j, false, metadataComplete(p), "Complete organization Actions secret metadata list is empty; values were not read")
		out = append(out, j)
	}
	if len(p.Items) > 0 && !metadataComplete(p) {
		out = append(out, populationAlertGap(finding.IDGitHubOrgSecretAll, c.OrganizationAsset, p))
	}
	for _, r := range e.RepositoriesAlerts {
		out = append(out, judgeDependencies(r)...)
		for _, located := range r.Located {
			out = append(out, judgeLocatedSecret(r, located)...)
		}
		if len(r.SecretAlerts.Items) == 0 {
			j := alertJudgment(finding.IDGitHubSecretScanningOpen, r.Asset, nil, readIDs(r.SecretAlerts.Reads))
			j.Details = map[string]any{"recognized_provider_alerts": 0}
			settle(&j, false, metadataComplete(r.SecretAlerts), "Complete provider secret-alert list is empty; this is not a repository secret scan")
			out = append(out, j)
		}
		if len(r.SecretAlerts.Items) > 0 && !metadataComplete(r.SecretAlerts) {
			out = append(out, populationAlertGap(finding.IDGitHubSecretScanningOpen, r.Asset, r.SecretAlerts))
		}
		if len(r.SecretAlerts.Items) > len(r.Located) {
			j := alertJudgment(finding.IDGitHubSecretScanningOpen, r.Asset, nil, readIDs(r.SecretAlerts.Reads))
			j.NotChecked = append(j.NotChecked, "Some provider alert locations were not read because the follow-up limit was reached")
			out = append(out, j)
		}
	}
	return out
}
func judgeDependencies(r RepositoryAlerts) []Judgment {
	out := []Judgment{}
	for _, d := range r.Dependencies.Items {
		knownState := slices.Contains([]string{"open", "fixed", "dismissed", "auto_dismissed"}, d.State)
		sev := d.Vulnerability.Severity
		knownSev := slices.Contains([]string{"low", "medium", "high", "critical"}, sev) && (d.Advisory.Severity == "" || d.Advisory.Severity == sev)
		var subject *Subject
		if manifestOK(d.Dependency.ManifestPath) {
			subject = &Subject{Kind: "dependency_alert", Key: "dependabot:" + numberKey(d.Number) + ":" + url.PathEscape(d.Dependency.ManifestPath), Label: fmt.Sprintf("Dependabot alert %d in %s", d.Number, d.Dependency.ManifestPath), ProviderID: numberKey(d.Number)}
		}
		for _, rule := range []struct {
			id         string
			severities []string
		}{{finding.IDGitHubDependabotHigh, []string{"high", "critical"}}, {finding.IDGitHubDependabotMedium, []string{"medium"}}, {finding.IDGitHubDependabotLow, []string{"low"}}} {
			j := alertJudgment(rule.id, r.Asset, subject, readIDs(r.Dependencies.Reads))
			fires := metadataObserved(r.Dependencies) && knownState && d.State == "open" && knownSev && subject != nil && slices.Contains(rule.severities, sev)
			known := knownState && subject != nil && knownSev && (fires || metadataComplete(r.Dependencies))
			settle(&j, fires, known, fmt.Sprintf("Provider Dependabot alert %d: state=%s; severity=%s; manifest=%s; dependency scope=%s. Dismissal closes the alert; it does not prove the vulnerability was fixed.", d.Number, d.State, sev, d.Dependency.ManifestPath, d.Dependency.Scope))
			j.Details = map[string]any{"provider_severity": sev, "provider_state": d.State, "dependency_scope": d.Dependency.Scope, "manifest_path": d.Dependency.ManifestPath, "package": d.Dependency.Package.Name, "ecosystem": d.Dependency.Package.Ecosystem, "ghsa_id": d.Advisory.GHSA}
			j.Context = "GitHub's vulnerability severity is retained as provider evidence; deployed versions and exploitability were not verified. Provider critical is rated high by scheck."
			out = append(out, j)
		}
	}
	if len(r.Dependencies.Items) == 0 {
		for _, id := range finding.GitHubAlertIDs()[1:4] {
			j := alertJudgment(id, r.Asset, nil, readIDs(r.Dependencies.Reads))
			j.Details = map[string]any{"recognized_dependency_alerts": 0}
			settle(&j, false, metadataComplete(r.Dependencies), "Complete provider Dependabot list is empty; unreported dependency vulnerabilities remain unassessed")
			out = append(out, j)
		}
	}
	if len(r.Dependencies.Items) > 0 && !metadataComplete(r.Dependencies) {
		for _, id := range finding.GitHubAlertIDs()[1:4] {
			out = append(out, populationAlertGap(id, r.Asset, r.Dependencies))
		}
	}
	return out
}
func judgeLocatedSecret(r RepositoryAlerts, l LocatedSecret) []Judgment {
	s := l.Alert
	reads := readIDs(r.SecretAlerts.Reads, l.Locations.Reads, []Read{r.RepositoryRead})
	out := []Judgment{}
	for _, loc := range l.Locations.Items {
		key := locationKey(loc)
		if key == "" {
			continue
		}
		subject := &Subject{Kind: "secret_location", Key: "secret-scanning:" + numberKey(s.Number) + ":" + key, Label: fmt.Sprintf("Secret alert %d in %s:%d at %s", s.Number, loc.Details.Path, loc.Details.StartLine, loc.Details.SHA), ProviderID: numberKey(s.Number)}
		j := alertJudgment(finding.IDGitHubSecretScanningOpen, r.Asset, subject, reads)
		validity := "not_checked"
		if s.Validity != nil {
			validity = *s.Validity
		}
		supportedValidity := s.Validity == nil || slices.Contains([]string{"active", "unknown"}, validity)
		fires := metadataObserved(r.SecretAlerts) && metadataObserved(l.Locations) && s.State == "open" && plainTypeRE.MatchString(s.Type) && supportedValidity
		revoked := plainTypeRE.MatchString(s.Type) && s.State == "resolved" && s.Resolution != nil && *s.Resolution == "revoked"
		settle(&j, fires, fires || revoked && metadataComplete(r.SecretAlerts) && metadataComplete(l.Locations), fmt.Sprintf("Provider secret alert %d: state=%s; type=%s; validity=%s; location=%s:%d at %s. Provider-reported evidence; credential usability was not tested.", s.Number, s.State, s.Type, validity, loc.Details.Path, loc.Details.StartLine, loc.Details.SHA))
		j.Details = map[string]any{"provider_state": s.State, "provider_validity": validity, "secret_type": s.Type, "redaction_marker": s.RedactionMarker, "commit_sha": loc.Details.SHA, "path": loc.Details.Path, "start_line": loc.Details.StartLine, "end_line": loc.Details.EndLine, "start_column": loc.Details.StartColumn, "end_column": loc.Details.EndColumn}
		if s.Resolution != nil {
			j.Details["provider_resolution"] = *s.Resolution
		}
		if metadataReadOK(r.RepositoryRead) && r.Visibility != nil && *r.Visibility == "public" {
			j.Attributes = []string{"observed_public"}
			j.Excerpt += " Observed repository visibility: public."
			j.Details["repository_visibility"] = "public"
			j.Details["repository_read"] = r.RepositoryRead.RequestID
		}
		// Leave Context empty so existing important-data adjustment still applies.
		out = append(out, j)
	}
	if len(out) == 0 || !metadataComplete(l.Locations) {
		j := alertJudgment(finding.IDGitHubSecretScanningOpen, r.Asset, nil, reads)
		j.NotChecked = append(j.NotChecked, "Some alert locations are unsupported, missing or incomplete")
		out = append(out, j)
	}
	return out
}

func populationAlertGap[T any](id, asset string, p Population[T]) Judgment {
	j := alertJudgment(id, asset, nil, readIDs(p.Reads))
	j.Details = map[string]any{"population_gaps": p.Gaps, "pagination_complete": p.Complete, "visibility_complete": p.VisibilityComplete}
	j.Excerpt = "The owning provider population is incomplete. Observed positives are retained; absence was not established."
	return j
}
