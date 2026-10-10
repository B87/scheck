package github

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/finding"
)

var ciLimits = []string{"PR review strength and bypass access", "Actions runtime policies, checkout protection, approvals and actual execution", "Job container and service images, reusable and composite internals, transitive dependency trust, OIDC cloud grants and runner access/isolation"}

func JudgeCI(e Evidence, c Context) []Judgment {
	out := []Judgment{}
	if e.OrganizationWorkflow.Read.Op != "" {
		out = append(out, defaultJudgment(finding.IDGitHubOrganizationWorkflowWrite, c.OrganizationAsset, nil, e.OrganizationWorkflow))
	}
	for _, ci := range e.RepositoriesCI {
		repoSubject := &Subject{Kind: "repository", Key: repoKey(ci.Asset), Label: repoKey(ci.Asset)}
		j := defaultJudgment(finding.IDGitHubRepositoryWorkflowWrite, ci.Asset, repoSubject, ci.Default)
		productionCI(&j, c)
		out = append(out, j)
		var branchSubject *Subject
		if ci.Branch.Name != "" {
			branchSubject = &Subject{Kind: "branch", Key: ci.Branch.Name, Label: ci.Branch.Name}
		}
		j = judgment(finding.IDGitHubDefaultBranchUnprotected, ci.Asset, branchSubject, readIDs([]Read{ci.Branch.Read}, ci.Branch.Rules.Reads))
		j.NotChecked = slices.Clone(ciLimits)
		if ci.Branch.Name != "" && usableRead(ci.Branch.Read) {
			positiveProtection := ci.Branch.Protected != nil && *ci.Branch.Protected || len(ci.Branch.Rules.Items) > 0 && slices.ContainsFunc(ci.Branch.Rules.Reads, usableRead)
			absent := ci.Branch.Protected != nil && !*ci.Branch.Protected && complete(ci.Branch.Rules) && len(ci.Branch.Rules.Items) == 0
			settle(&j, absent, positiveProtection || absent, fmt.Sprintf("Default branch %s at %s; protected=%v; recognized active rules=%v (protection presence only)", ci.Branch.Name, ci.Branch.SHA, branchProtectionText(ci.Branch.Protected), ci.Branch.Rules.Items))
		}
		productionCI(&j, c)
		out = append(out, j)
		for _, w := range ci.Workflows {
			inspected := inspectWorkflow(w, ci.Default)
			subject := &Subject{Kind: "workflow", Key: w.Path, Label: w.Path}
			for _, rule := range []struct {
				id           string
				fires, known bool
			}{{finding.IDGitHubMutableAction, inspected.Mutable, inspected.PinKnown}, {finding.IDGitHubMutableActionWrite, inspected.Joined, inspected.JoinKnown}, {finding.IDGitHubPRTargetUnsafe, inspected.PRUnsafe, inspected.PRKnown}} {
				j = judgment(rule.id, ci.Asset, subject, readIDs([]Read{ci.Directory, w.Read, ci.Default.Read, ci.Branch.Read}))
				j.NotChecked = slices.Clone(ciLimits)
				// Partial populations keep recognized positives, never a workflow-wide negative.
				settle(&j, rule.fires, rule.fires || rule.known && ci.Complete, ciDetail(w.Path, w.SHA)+"; "+strings.Join(inspected.Evidence, "; "))
				j.Details = map[string]any{"assessed_sha": w.SHA, "redaction_marker": w.RedactionMarker, "unsafe_checkout_opt_out": inspected.UnsafeCheckoutOptOut, "references": inspected.Evidence, "runner_requests": inspected.RunnerNotes, "syntax_gaps": inspected.Gaps, "workflow_syntax_version": WorkflowSyntaxVersion, "workflow_execution_version": WorkflowExecutionVersion}
				if rule.id == finding.IDGitHubMutableAction && inspected.Joined {
					j.Details["superseded_by"] = finding.IDGitHubMutableActionWrite
				}
				if rule.id == finding.IDGitHubPRTargetUnsafe {
					j.Context = "Configuration requests only; runtime policy, checkout protection, approvals and actual execution were not verified."
					productionCI(&j, c)
				}
				if inspected.Limit {
					j.NotChecked = append(j.NotChecked, "A run field exceeded the compiled execution-analysis limit")
				}
				out = append(out, j)
			}
		}
		if len(ci.Workflows) == 0 {
			for _, id := range []string{finding.IDGitHubMutableAction, finding.IDGitHubMutableActionWrite, finding.IDGitHubPRTargetUnsafe} {
				j = judgment(id, ci.Asset, nil, readIDs([]Read{ci.Directory, ci.Branch.Read}))
				j.NotChecked = slices.Clone(ciLimits)
				settle(&j, false, ci.Complete && usableRead(ci.Directory), "Complete assessed workflow directory contains no supported workflow files")
				out = append(out, j)
			}
		}
	}
	return out
}
func repoKey(asset string) string {
	const prefix = "repo:github:"
	if len(asset) >= len(prefix) {
		return asset[len(prefix):]
	}
	return asset
}
func defaultJudgment(id, asset string, subject *Subject, d DefaultEvidence) Judgment {
	j := judgment(id, asset, subject, readIDs([]Read{d.Read}))
	j.NotChecked = slices.Clone(ciLimits)
	if d.Setting != nil && d.Setting.Permissions != nil {
		v := *d.Setting.Permissions
		settle(&j, v == "write", usableRead(d.Read) && (v == "read" || v == "write"), "default_workflow_permissions: "+v)
	}
	return j
}
func productionCI(j *Judgment, c Context) {
	if production(c, j.Asset) {
		j.Attributes = append(j.Attributes, "production")
		j.Sources = append(j.Sources, c.RepositoryContexts[j.Asset].Source)
		j.Context += " This repository is declared to deploy to production, so this rating rises one step."
	}
}

func branchProtectionText(v *bool) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprint(*v)
}
