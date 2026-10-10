package report

import (
	"slices"

	"github.com/b87/scheck/internal/finding"
)

// GitHub coverage retains unbuilt practitioner subitems rather than equating
// decided rules with complete identity or CI coverage (docs/spec/github-collector.md,
// "Reporting and coverage").
func (b *builder) githubCoverage(row *Row, area finding.Area, a AssetInput) bool {
	if a.NetworkPrincipal != nil {
		row.Principals = append(row.Principals, *a.NetworkPrincipal)
	}
	if a.Reason != "" {
		row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: a.Reason, Detail: a.Name})
	}
	if len(a.Judged) == 0 {
		row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: a.Name + ": inventory only; no GitHub security control was assessed"})
		row.SubItems = append(row.SubItems, SubItem{Name: "GitHub security controls", Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{{Reason: "no_rule", Detail: a.Name + ": inventory only; no GitHub security control was assessed"}}})
		return false
	}
	type family struct {
		name string
		ids  []string
	}
	families := []family{}
	switch area {
	case finding.AreaIdentity:
		families = []family{
			{"GitHub MFA", []string{finding.IDGitHubMFANotRequired, finding.IDGitHubOwnerWithoutMFA, finding.IDGitHubMemberWithoutMFA}},
			{"owners and attribution", []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin, finding.IDGitHubTooManyOwners}},
			{"departed people", []string{finding.IDIdentityFormerPersonHasAccess, finding.IDIdentityFormerPersonInvited}},
			{"repository access", []string{finding.IDGitHubBroadDefaultMemberPermission, finding.IDGitHubOutsideAdminOnProduction}},
		}
	case finding.AreaSecrets:
		families = []family{
			{"organization Actions secret sharing", []string{finding.IDGitHubOrgSecretAll}},
			{"provider secret-scanning alerts at commit locations", []string{finding.IDGitHubSecretScanningOpen}},
		}
	case finding.AreaCICD:
		families = []family{
			{"repository public intent and deploy keys", []string{finding.IDGitHubUndeclaredPublicRepository, finding.IDGitHubWritableDeployKey}},
			{"workflow token defaults", []string{finding.IDGitHubOrganizationWorkflowWrite, finding.IDGitHubRepositoryWorkflowWrite}},
			{"default-branch protection presence", []string{finding.IDGitHubDefaultBranchUnprotected}},
			{"workflow dependency references", []string{finding.IDGitHubMutableAction}},
			{"mutable dependencies with write permission", []string{finding.IDGitHubMutableActionWrite}},
			{"PR-controlled execution requests", []string{finding.IDGitHubPRTargetUnsafe}},
			{"provider dependency alerts", []string{finding.IDGitHubDependabotHigh, finding.IDGitHubDependabotMedium, finding.IDGitHubDependabotLow}},
		}
	}
	some := false
	for _, fam := range families {
		si := SubItem{Name: fam.name, Asset: a.ID, Mark: "not_assessed", Rules: fam.ids, Reasons: []ReasonDetail{}}
		decided, unknown := 0, 0
		for _, j := range a.Judged {
			if !slices.Contains(fam.ids, j.ID) {
				continue
			}
			if j.Verdict == verdictAbstained || j.Reason != "" {
				unknown++
				si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: j.Reason, Detail: j.Subject.Label})
			} else {
				decided++
			}
		}
		if decided > 0 {
			some = true
			si.Mark = "assessed"
			si.Judged = []string{fam.name}
			if unknown > 0 {
				si.Mark = "partial"
			}
		}
		if decided == 0 && unknown == 0 {
			continue
		}
		for _, reason := range si.Reasons {
			row.Reasons = appendReason(row.Reasons, reason)
		}
		row.SubItems = append(row.SubItems, si)
	}
	unknown := "Actions secret values, credential usability/rotation, unsupported secret locations, unreported patterns and repository history are not assessed"
	if area == finding.AreaIdentity {
		unknown = "Delegated organization roles, repository invitations, sign-in history, selected-repository visibility and unobserved repository administrators are not assessed"
	}
	if area == finding.AreaCICD {
		unknown = "PR review strength and bypass, Actions runtime policies, execution, reusable/composite internals, runner access, OIDC trust, App grants and dependency runtime exploitability are not assessed"
	}
	row.SubItems = append(row.SubItems, SubItem{Name: unknown, Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{{Reason: "no_rule", Detail: unknown}}})
	row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: unknown})
	return some
}
