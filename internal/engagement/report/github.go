package report

import (
	"fmt"
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
		// "Inventory only" is a limit on an inventory that was read; an
		// unread one keeps its own reason.
		if a.InventoryRead {
			row.Reasons = appendReason(row.Reasons, ReasonDetail{Reason: "no_rule", Detail: a.Name + ": inventory only; no GitHub security control was assessed"})
		}
		why := unreadInventory(a, ReasonDetail{Reason: "no_rule", Detail: a.Name + ": inventory only; no GitHub security control was assessed"})
		row.SubItems = append(row.SubItems, SubItem{Name: "GitHub security controls", Asset: a.ID, Mark: "not_assessed", Reasons: []ReasonDetail{why}})
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
			{"supported mirror history credential detection", []string{finding.IDGitHubHistoryCredential}},
			{"mirror origin credential detection", []string{finding.IDGitHubRemoteCredential}},
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
		cut := selectionFor(&si, a.Selections)
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
		if cut != "" {
			// The request budget left this kind unread on some repositories:
			// sampled, never limit_reached, and the exit code is unchanged
			// (docs/spec/report.md, "Coverage").
			p := si.Population
			si.Reasons = appendReason(si.Reasons, ReasonDetail{Reason: "sampled", Detail: fmt.Sprintf("%d of %d repositories read (%s)", p.Read, p.InScope, cut)})
			if si.Mark == "assessed" {
				si.Mark = "partial"
			}
		} else if decided == 0 && unknown == 0 {
			continue
		}
		if fam.name == "departed people" {
			si.Detail = permissionAsksText(a.PermissionAsks)
		}
		for _, reason := range si.Reasons {
			row.Reasons = appendReason(row.Reasons, reason)
		}
		row.SubItems = append(row.SubItems, si)
	}
	unknown := "Actions secret values, credential usability/rotation, unsupported secret locations, unreported patterns and history outside the supported mirror traversal are not assessed"
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

// selectionFor gives a sub-item the population of the least-reached kind
// its rules rest on, and returns that kind's cut, if the budget cut it.
func selectionFor(si *SubItem, kinds []finding.KindSelection) string {
	var pick *finding.KindSelection
	for i, k := range kinds {
		if !slices.ContainsFunc(k.Rules, func(id string) bool { return slices.Contains(si.Rules, id) }) {
			continue
		}
		if pick == nil || k.Selection.Read < pick.Selection.Read || k.Selection.Read == pick.Selection.Read && k.Cut != "" && pick.Cut == "" {
			pick = &kinds[i]
		}
	}
	if pick == nil {
		return ""
	}
	sel := pick.Selection
	si.Population = &Population{Kind: sel.Unit, InScope: sel.InScope, Read: sel.Read, Selection: &sel}
	return pick.Cut
}

// permissionAsksText is the departed-people line of the permission
// follow-up (docs/spec/report.md, "Coverage"), empty when no pair was open.
func permissionAsksText(n *FollowUpCount) string {
	if n == nil || n.Opened == 0 {
		return ""
	}
	s := fmt.Sprintf("Departed people's access to production repositories: asked GitHub for %d of %d (login, repository) pairs", n.Asked, n.Opened)
	switch {
	case n.Stopped != "":
		s += "; the run stopped before the rest (" + n.Stopped + ")"
	case n.Capped:
		s += "; the cap of 20 per run stopped the rest"
	}
	return s + "."
}
