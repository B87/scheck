package report

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func githubAlertsReport(t *testing.T, verdict string) Input {
	in := githubAccessReport(t, verdict)
	in.Name = "GitHub secret metadata and provider alert review"
	for i := range in.Assets {
		in.Assets[i].Judged = nil
		in.Assets[i].InventoryNotes = nil
	}
	org, repo := &in.Assets[0], &in.Assets[1]
	org.Judged = []Judgment{{ID: finding.IDGitHubOrgSecretAll, Asset: org.ID, Subject: Subject{Kind: "secret_location", Key: "actions:prod_key", Label: "Actions secret PROD_KEY"}, Reads: []string{"organization-secrets"}, Excerpt: "Actions secret PROD_KEY: provider visibility all; names only, no value read"}}
	for i, id := range finding.GitHubAlertIDs()[1:] {
		subject := Subject{Kind: "dependency_alert", Key: "dependabot:" + string(rune('3'+i)) + ":App%2Fpackage-lock.json", Label: "Dependabot alert in App/package-lock.json"}
		j := Judgment{ID: id, Asset: repo.ID, Subject: subject, Reads: []string{"dependabot-alerts"}, Excerpt: "GitHub reports an open dependency alert in App/package-lock.json. Deployed versions and exploitability were not established.", Context: "Provider-reported vulnerability severity; runtime exploitability was not verified."}
		if id == finding.IDGitHubSecretScanningOpen {
			j.Subject = Subject{Kind: "secret_location", Key: "secret-scanning:7:commit:" + strings.Repeat("a", 40) + ":config%2FProd.env:2:1", Label: "Secret alert 7 in config/Prod.env:2"}
			j.Reads = []string{"secret-alerts", "secret-locations", "repository"}
			j.Context = ""
			j.Attributes = []string{"observed_public"}
			j.Excerpt = "Provider secret alert 7: open; validity unknown; config/Prod.env:2 at " + strings.Repeat("a", 40) + ". Credential usability was not tested."
			j.Details = map[string]any{"redaction_marker": "[REDACTED:json-secret:31 bytes]", "provider_validity": "unknown", "repository_read": "repository"}
		}
		j.NotChecked = []string{"Deployed dependency versions and runtime exploitability were not verified; provider alerts do not cover every vulnerability"}
		if id == finding.IDGitHubSecretScanningOpen {
			j.NotChecked = []string{"Provider patterns are not a complete repository secret scan; history and unsupported locations were not scanned; credential usability and rotation were not verified"}
		}
		repo.Judged = append(repo.Judged, j)
	}
	for _, asset := range []*AssetInput{org, repo} {
		for i := range asset.Judged {
			j := &asset.Judged[i]
			j.Verdict = verdict
			if verdict == verdictDisproved {
				j.Excerpt = "Recognized complete provider evidence disproved this narrow open-alert or sharing condition. Dismissal does not prove a vulnerability was fixed; revoked means provider-reported."
			}
			if verdict == verdictAbstained {
				j.Reason = "unavailable:github_evidence"
				j.Excerpt = "Required provider evidence was denied or unsupported"
			}
		}
	}
	repo.InventoryNotes = []Note{{Kind: "github_alerts", Source: repo.ID, Detail: "Provider alerts are not a complete repository scan. Names are metadata; values were not read. Credential usability and deployed dependency exploitability were not tested."}}
	if verdict == verdictAbstained {
		repo.InventoryNotes = append(repo.InventoryNotes, Note{Kind: "github_alerts", Source: repo.ID, Detail: "Secret alert 9: provider marked inactive; rotation was not verified."}, Note{Kind: "github_alert_followup", Source: repo.ID, Detail: "Review secret alert 10: GitHub marks this alert closed because someone chose not to fix it (wont_fix), but still reports the credential active. Revocation was not verified. Check with the credential owner; this needs follow-up even though scheck could not reach a finding."}, Note{Kind: "github_alerts", Source: repo.ID, Detail: "Ask the repository owner to authorize Secret scanning alerts read and Dependabot alerts read for this repository, then resume. History and unsupported locations remain unassessed."})
	}
	in.Observations = map[string]Observation{}
	for _, a := range in.Assets {
		for _, j := range a.Judged {
			for _, r := range j.Reads {
				in.Observations[r] = Observation{CollectedAt: in.Started}
			}
		}
	}
	return in
}
func githubAlertsFiredReport(t *testing.T) Input     { return githubAlertsReport(t, verdictFired) }
func githubAlertsDisprovedReport(t *testing.T) Input { return githubAlertsReport(t, verdictDisproved) }
func githubAlertsAbstainedReport(t *testing.T) Input { return githubAlertsReport(t, verdictAbstained) }
func TestGitHubAlertsSeveritySubjectsAndCoverage(t *testing.T) {
	in := githubAlertsFiredReport(t)
	r := Build(in)
	validate(t, schema(t), r)
	wants := map[string]string{finding.IDGitHubOrgSecretAll: "medium", finding.IDGitHubDependabotHigh: "high", finding.IDGitHubDependabotMedium: "medium", finding.IDGitHubDependabotLow: "low", finding.IDGitHubSecretScanningOpen: "critical"}
	for _, f := range r.Findings {
		if f.Severity != wants[f.ID] || f.Subject == nil || f.AcceptTemplate == nil || f.AcceptTemplate.Subject == "" {
			t.Fatalf("severity or instance %+v", f)
		}
	}
	if len(r.Findings) != 5 {
		t.Fatal("missing findings")
	}
	for _, row := range r.Coverage {
		if row.Area == "secrets" || row.Area == "cicd" {
			if row.Mark != "partial" {
				t.Fatalf("coverage overclaim %+v", row)
			}
		}
	}
	in.DataMattersMost = []string{in.Assets[0].ID}
	r = Build(in)
	for _, f := range r.Findings {
		if f.ID == finding.IDGitHubOrgSecretAll && f.Severity != "high" {
			t.Fatal("important data adjustment lost")
		}
	}
}

func TestPartialAlertPopulationsKeepCoveragePartial(t *testing.T) {
	in := githubAlertsFiredReport(t)
	for i := range in.Assets {
		a := &in.Assets[i]
		id := finding.IDGitHubSecretScanningOpen
		if i == 0 {
			id = finding.IDGitHubOrgSecretAll
		}
		a.Judged = append(a.Judged, Judgment{ID: id, Asset: a.ID, Verdict: verdictAbstained, Reason: "unavailable:github_evidence", Details: map[string]any{"population_gaps": []string{"page_limit"}}, Excerpt: "Owning provider population is incomplete; positives remain"})
	}
	r := Build(in)
	for _, row := range r.Coverage {
		if row.Area != "secrets" {
			continue
		}
		for _, s := range row.SubItems {
			if s.Name == "organization Actions secret sharing" || s.Name == "provider secret-scanning alerts at commit locations" {
				if s.Mark != "partial" {
					t.Fatalf("partial family labeled complete %+v", s)
				}
			}
		}
	}
	if len(r.Findings) != 5 {
		t.Fatal("positive lost")
	}
	for _, a := range r.Assessments {
		if a.ID == finding.IDGitHubOrgSecretAll || a.ID == finding.IDGitHubSecretScanningOpen {
			if a.Complete {
				t.Fatal("assessment complete")
			}
		}
	}
}
func TestPublicSecretAdjustmentCitesRepositoryVisibility(t *testing.T) {
	r := Build(githubAlertsFiredReport(t))
	for _, f := range r.Findings {
		if f.ID != finding.IDGitHubSecretScanningOpen {
			continue
		}
		if len(f.Adjustments) != 1 || f.Adjustments[0].Source.Observation != "repository" || f.Adjustments[0].Source.Excerpt != "Observed repository visibility: public" {
			t.Fatalf("wrong public evidence %+v", f.Adjustments)
		}
	}
}
func TestActiveClosedSecretFollowupAppearsBeforeRanking(t *testing.T) {
	r := Build(githubAlertsAbstainedReport(t))
	var b strings.Builder
	if err := WriteText(&b, r, Options{Width: 100}); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	follow := strings.Index(text, "Follow-up needed:")
	ranking := strings.Index(text, "Fix these first:")
	if follow < 0 || follow >= ranking || !strings.Contains(text, "still reports the credential active") {
		t.Fatal("follow-up buried")
	}
	if len(r.Findings) != 0 {
		t.Fatal("follow-up invented a finding")
	}
}
