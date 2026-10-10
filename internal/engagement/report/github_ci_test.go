package report

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func githubCIReport(t *testing.T, verdict string) Input {
	in := githubAccessReport(t, verdict)
	in.Name = "GitHub CI configuration review"
	in.Assets[0].Judged = nil
	in.Assets[1].Judged = nil
	org, repo := &in.Assets[0], &in.Assets[1]
	org.InventoryNotes = nil
	org.Judged = []Judgment{{ID: finding.IDGitHubOrganizationWorkflowWrite, Asset: org.ID, Reads: []string{"organization"}, Excerpt: "default_workflow_permissions: write"}}
	for _, id := range finding.GitHubCIIDs()[1:] {
		subject := Subject{Kind: "workflow", Key: ".github/workflows/release.yml", Label: ".github/workflows/release.yml"}
		if id == finding.IDGitHubRepositoryWorkflowWrite {
			subject = Subject{Kind: "repository", Key: "example-org/production", Label: "example-org/production"}
		}
		if id == finding.IDGitHubDefaultBranchUnprotected {
			subject = Subject{Kind: "branch", Key: "Release/v1", Label: "Release/v1"}
		}
		j := Judgment{ID: id, Asset: repo.ID, Subject: subject, Reads: []string{"repository", "keys"}, Excerpt: ".github/workflows/release.yml at default-branch commit " + strings.Repeat("a", 40), Details: map[string]any{"assessed_sha": strings.Repeat("a", 40)}}
		if id == finding.IDGitHubMutableAction {
			j.Excerpt = "release: actions/checkout@v4"
			if verdict == verdictFired {
				j.Details["superseded_by"] = finding.IDGitHubMutableActionWrite
			}
		}
		if id == finding.IDGitHubMutableActionWrite {
			j.Excerpt = "release: actions/checkout@v4; job contents: write"
		}
		if id == finding.IDGitHubPRTargetUnsafe {
			j.Context = "Configuration requests only; runtime policy, checkout protection, approvals and actual execution were not verified."
			j.Excerpt = "pull_request_target; checkout ref: github.event.pull_request.head.sha; npm ci; contents: write"
		}
		if id == finding.IDGitHubRepositoryWorkflowWrite || id == finding.IDGitHubDefaultBranchUnprotected || id == finding.IDGitHubPRTargetUnsafe {
			j.Attributes = []string{"production"}
			j.Sources = []string{"assets.production"}
			j.Context += " This repository is declared to deploy to production, so this rating rises one step."
		}
		switch id {
		case finding.IDGitHubRepositoryWorkflowWrite:
			j.Excerpt = "default_workflow_permissions: write"
		case finding.IDGitHubDefaultBranchUnprotected:
			j.Excerpt = "Default branch Release/v1: protected=false; complete active rules=[]"
		}
		j.NotChecked = []string{"PR review strength and bypass access; actual execution and runtime policies; runner access and job container/service images were not assessed"}
		repo.Judged = append(repo.Judged, j)
	}
	for _, a := range []*AssetInput{org, repo} {
		for i := range a.Judged {
			a.Judged[i].Verdict = verdict
			if verdict == verdictAbstained {
				a.Judged[i].Reason = "unavailable:github_evidence"
				a.Judged[i].Excerpt = "Required CI evidence was unavailable"
			}
			if verdict == verdictDisproved {
				a.Judged[i].Excerpt = "Recognized configuration evidence disproved this narrow condition"
			}
		}
	}
	repo.InventoryNotes = []Note{{Kind: "github_ci", Source: repo.ID, Detail: "Workflow configuration was read at default-branch commit " + strings.Repeat("a", 40) + ". Requests self-hosted runner labels; repository access, availability and isolation were not assessed."}}
	if verdict == verdictAbstained {
		repo.InventoryNotes = []Note{}
		repo.InventoryNotes = append(repo.InventoryNotes, Note{Kind: "github_ci", Source: repo.ID, Detail: "GitHub denied the workflow contents and branch-rule reads. Ask the repository owner to authorize Contents read and Metadata read for the intended repository, then resume."})
	}
	return in
}
func githubCIFiredReport(t *testing.T) Input     { return githubCIReport(t, verdictFired) }
func githubCIDisprovedReport(t *testing.T) Input { return githubCIReport(t, verdictDisproved) }
func githubCIAbstainedReport(t *testing.T) Input { return githubCIReport(t, verdictAbstained) }
func TestGitHubCIReportSeveritySubjectsAndSuppression(t *testing.T) {
	r := Build(githubCIFiredReport(t))
	validate(t, schema(t), r)
	found := map[string]bool{}
	for _, f := range r.Findings {
		found[f.ID] = true
		want := "high"
		if f.ID == finding.IDGitHubOrganizationWorkflowWrite {
			want = "medium"
			if f.Subject != nil {
				t.Fatal("organization subject")
			}
		} else if f.Subject == nil {
			t.Fatal("missing instance")
		}
		if f.Severity != want {
			t.Fatalf("%s severity%s", f.ID, f.Severity)
		}
		if len(f.Adjustments) > 1 {
			t.Fatal("double raised")
		}
	}
	if found[finding.IDGitHubMutableAction] || !found[finding.IDGitHubMutableActionWrite] || !found[finding.IDGitHubPRTargetUnsafe] {
		t.Fatal("duplicate or missing findings")
	}
	for _, assessment := range r.Assessments {
		if assessment.ID == finding.IDGitHubMutableAction && assessment.Outcomes[0].Outcome != verdictFired {
			t.Fatal("suppression erased assessment")
		}
	}
}
