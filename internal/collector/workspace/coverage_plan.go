package workspace

import (
	"fmt"
	"slices"

	"github.com/b87/scheck/internal/finding"
)

const (
	// reasonUnclassified is an app's abstention when it holds no broad scope
	// but scopes outside the table; coverage prints them as one line.
	reasonUnclassified = "unavailable:oauth_unclassified"
	oauthLimit         = "Checked: the apps each account authorized with its Google account and the access Google reports they hold. Not checked: domain-wide delegation, service-account keys, apps an administrator installed for everyone from Marketplace (they may not appear as a person's grant), app passwords, when each app was authorized or last used, and what any app did with its access"
	twoStepLimit       = "Checked: each account's 2-step verification enforcement and enrollment as Google reports it. Not checked: organizational-unit policy, grace periods, sign-in through another identity provider, verification methods and phishing resistance"
)

// Coverage is the tenant's coverage plan: every rule id in exactly one group
// (coverage_plan_test.go), worded here and marked by the engagement report
// (docs/spec/workspace-collector.md, "Reporting and coverage").
func (e Evidence) Coverage() []finding.CoveragePlan {
	evidence := finding.CoverageReason{Reason: "unavailable:workspace_evidence"}
	assignments := finding.CoverageGroup{Name: "Workspace administrator assignments and counts", Rules: []string{IDTooManySuperAdmins, IDSuspendedAdminAssignment}}
	if !e.Access.AdministrationComplete {
		gap := evidence
		gap.Detail = "Required role or assignment evidence was incomplete; observed account flags do not establish absence of delegated privilege"
		assignments.Gap = &gap
	}
	twoStep := finding.CoverageGroup{Name: "Workspace 2-step verification (Google's enforcement and enrollment flags)", Rules: []string{IDTwoStepNotEnforced, IDAdminWithoutTwoStep}, Always: true, Limit: twoStepLimit}
	twoStep.Empty = evidence
	twoStep.Empty.Detail = "No 2-step verification outcome was recorded for this tenant"
	oauth := finding.CoverageGroup{Name: "Workspace OAuth grants (third-party app access)", Rules: []string{IDOAuthBroadScope}, Always: true, Limit: oauthLimit, Unassessed: "OAuth grants"}
	oauth.Empty = evidence
	oauth.Empty.Detail = "No OAuth grant outcome was recorded for this tenant"
	if e.Binding.CustomerID != "" && !e.OAuth.Selected {
		which := "The default Workspace profile, directory,"
		if e.Binding.Profile != "directory" {
			which = "The selected Workspace profile, " + e.Binding.Profile + ","
		}
		oauth.NotOnPlan = &finding.CoverageReason{Reason: "not_on_plan:profile=" + e.Binding.Profile,
			Detail: which + " does not read third-party app access; it needs SCHECK_WORKSPACE_PROFILE=directory_oauth and the admin.directory.user.security permission"}
	}
	// Most tenants hold many unclassified apps: one line, the JSON and the
	// readout list each.
	if n := len(slices.DeleteFunc(slices.Clone(e.Judgments), func(j finding.Judgment) bool { return j.Reason != reasonUnclassified })); n > 0 {
		holds := "apps hold"
		if n == 1 {
			holds = "app holds"
		}
		oauth.Collapse = &finding.CoverageReason{Reason: reasonUnclassified, Detail: fmt.Sprintf("%d %s scopes scheck does not classify and none it classifies as broad; listed in the JSON report and the readout", n, holds)}
	}
	return []finding.CoveragePlan{{
		Area:  finding.AreaIdentity,
		Label: "Workspace",
		Groups: []finding.CoverageGroup{
			{Name: "Workspace administrator identity", Rules: []string{finding.IDIdentityUnexpectedAdmin, finding.IDIdentityUnattributedAdmin, finding.IDIdentityExternalAdmin, finding.IDIdentitySharedAdmin}},
			{Name: "Workspace offboarding", Rules: []string{finding.IDIdentityFormerPersonHasAccess}},
			assignments,
			{Name: "Workspace account sign-in", Rules: []string{IDStaleAccount, IDNeverSignedIn}},
			twoStep,
			oauth,
		},
		Incomplete: finding.CoverageReason{Reason: "unavailable:workspace_inventory", Detail: "Current population is incomplete"},
		Unread: []finding.CoverageUnread{{Name: "Workspace domain-wide delegation", Unassessed: "domain-wide delegation",
			Detail: "Nothing was read: Google offers no Directory read for it. Review it in the Admin console at Security → Access and data control → API controls → Manage Domain Wide Delegation. With a service-account credential, scheck's own delegation is listed there"}},
		RowAlso: "2-step verification policy, grace periods and other sign-in services were not assessed",
	}}
}

// OutcomeStatus is how collection ended, before the engagement names it.
type OutcomeStatus string

// The collection outcomes.
const (
	OutcomeComplete   OutcomeStatus = "complete"
	OutcomeIncomplete OutcomeStatus = "incomplete"
)

// Outcome is the asset's collection result as the engagement records it,
// worded by the collector.
type Outcome struct {
	Status OutcomeStatus
	// Reason is "limit_reached" or "no_credentials" when known; empty is a
	// failure the notes describe.
	Reason, Detail string
}

// Outcome says whether collection completed. A limit cuts collection
// wherever it struck; a refused optional permission is a coverage gap only
// (docs/spec/scope.md, "Outcomes").
func (e Evidence) Outcome() Outcome {
	reads := e.Reads()
	limited := slices.ContainsFunc(reads, func(read Read) bool { return read.Reason == "limit_reached" })
	if e.InventoryComplete && e.Access.Complete && !limited {
		detail := "Workspace inventory, identity/administrator and 2-step verification checks collected; notes and coverage show any unresolved evidence."
		if e.OAuth.Selected {
			detail = "Workspace inventory, identity/administrator, 2-step verification and OAuth grant checks collected; notes and coverage show any unresolved evidence."
		}
		return Outcome{Status: OutcomeComplete, Detail: detail}
	}
	o := Outcome{Status: OutcomeIncomplete, Detail: "Workspace evidence is incomplete; notes show what was read and what remains unknown."}
	for _, read := range reads {
		if read.Reason == "limit_reached" {
			o.Reason = read.Reason
		}
		if read.Reason == "no_credentials" {
			o.Reason, o.Detail = read.Reason, read.Detail
		}
	}
	return o
}
