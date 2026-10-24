package workspace

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
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
// (docs/spec/workspace-collector.md, "Reporting and coverage"). judged are
// Judge's verdicts on e, which Analyze gives: the unclassified apps fold
// into one line. c's sign-in declaration words the 2-step limit.
func (e Evidence) Coverage(judged []finding.Judgment, c Context) []finding.CoveragePlan {
	evidence := finding.CoverageReason{Reason: "unavailable:workspace_evidence"}
	assignments := finding.CoverageGroup{Name: "Workspace administrator assignments and counts", Rules: []string{IDTooManySuperAdmins, IDSuspendedAdminAssignment}}
	if !e.Access.AdministrationComplete {
		gap := evidence
		gap.Detail = "Required role or assignment evidence was incomplete; observed account flags do not establish absence of delegated privilege"
		assignments.Gap = &gap
	}
	twoStep := finding.CoverageGroup{Name: "Workspace 2-step verification (Google's enforcement and enrollment flags)", Rules: []string{IDTwoStepNotEnforced, IDAdminWithoutTwoStep}, Always: true, Limit: twoStepLimit}
	if c.SignIn == signInProvider {
		twoStep.Limit += ". You declared that people sign in through another identity provider (`" + c.SignInSource + "`); scheck did not read it, so for those people Google's flags show only that Google does not require its own 2-step verification"
	}
	twoStep.Empty = evidence
	twoStep.Empty.Detail = "No 2-step verification outcome was recorded for this tenant"
	oauth := finding.CoverageGroup{Name: "Workspace OAuth grants (third-party app access)", Rules: []string{IDOAuthBroadScope}, Always: true, Limit: oauthLimit, Unassessed: "OAuth grants"}
	oauth.Empty = evidence
	oauth.Empty.Detail = "No OAuth grant outcome was recorded for this tenant"
	oauth.Selection = e.OAuth.Selection
	if e.Binding.CustomerID != "" && !e.OAuth.Selected {
		which := "The default Workspace profile, directory,"
		if e.Binding.Profile != "directory" {
			which = "The selected Workspace profile, " + e.Binding.Profile + ","
		}
		oauth.NotOnPlan = &finding.CoverageReason{Reason: "not_on_plan:profile=" + e.Binding.Profile,
			Detail: which + " does not read third-party app access; it needs SCHECK_WORKSPACE_PROFILE=" + e.Binding.offer(gate.WorkspaceOAuthGrants, "directory_oauth") + " and the admin.directory.user.security permission"}
	}
	// Most tenants hold many unclassified apps: one line, the JSON and the
	// readout list each.
	if n := len(slices.DeleteFunc(slices.Clone(judged), func(j finding.Judgment) bool { return j.Reason != reasonUnclassified })); n > 0 {
		holds := "apps hold"
		if n == 1 {
			holds = "app holds"
		}
		oauth.Collapse = &finding.CoverageReason{Reason: reasonUnclassified, Detail: fmt.Sprintf("%d %s scopes scheck does not classify and none it classifies as broad; listed in the JSON report and the readout", n, holds)}
	}
	identity := finding.CoveragePlan{
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
		Unread: []finding.CoverageUnread{{Name: "Workspace domain-wide delegation", Unassessed: "domain-wide delegation", Fixed: "identity.delegation",
			Detail: "Nothing was read: Google offers no Directory read for it. Review it in the Admin console at Security → Access and data control → API controls → Manage Domain Wide Delegation. With a service-account credential, scheck's own delegation is listed there"}},
		RowAlso: "2-step verification policy, grace periods and other sign-in services were not assessed",
	}
	return []finding.CoveragePlan{identity, e.mailCoverage()}
}

// mailCoverage is the forwarding surface's coverage in the email area
// (docs/spec/workspace-collector.md, "Reporting and coverage").
func (e Evidence) mailCoverage() finding.CoveragePlan {
	forwarding := finding.CoverageGroup{Name: "Workspace mail forwarding", Rules: []string{IDExternalForwarding}, Always: true, Limit: mailLimit, Unassessed: "mail forwarding"}
	forwarding.Empty = finding.CoverageReason{Reason: "unavailable:workspace_evidence", Detail: "No mail forwarding outcome was recorded for this tenant"}
	forwarding.Selection = e.Mail.Selection
	if e.Binding.CustomerID != "" && !e.Mail.Selected {
		which := "The default Workspace profile, directory,"
		if e.Binding.Profile != "directory" {
			which = "The selected Workspace profile, " + e.Binding.Profile + ","
		}
		forwarding.NotOnPlan = &finding.CoverageReason{Reason: "not_on_plan:profile=" + e.Binding.Profile,
			Detail: which + " does not read mail forwarding; it needs SCHECK_WORKSPACE_PROFILE=" + e.Binding.offer(gate.WorkspaceGmailForwarding, "directory_mail") + " and a service account whose domain-wide delegation includes gmail.readonly, which can read every message"}
	}
	// The surface's own refusal is the group's gap, never a result.
	if r := e.Mail.refusal(); r != nil {
		gap, _ := refusalWording(*r, len(e.Mail.Accounts))
		forwarding.Gap = &gap
	}
	plan := finding.CoveragePlan{Area: finding.AreaEmail, Label: "Workspace", Groups: []finding.CoverageGroup{forwarding},
		Incomplete: finding.CoverageReason{Reason: "unavailable:workspace_inventory", Detail: "Current population is incomplete"}}
	if e.Mail.Selected {
		plan.RowAlso = "the Admin console's forwarding setting, mail delegates and POP/IMAP were not assessed"
	}
	return plan
}

// checksCollected lists the baseline checks and each selected surface's.
func (e Evidence) checksCollected() string {
	checks := []string{"inventory", "identity/administrator", "2-step verification"}
	for _, s := range []struct {
		selected bool
		name     string
	}{{e.OAuth.Selected, "OAuth grant"}, {e.Mail.Selected, "mail forwarding"}} {
		// In Recon these are still Check's to read.
		if s.selected && !e.usersPending {
			checks = append(checks, s.name)
		}
	}
	return strings.Join(checks[:len(checks)-1], ", ") + " and " + checks[len(checks)-1]
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
	limited := slices.ContainsFunc(reads, limitedRead)
	if e.InventoryComplete && e.Access.Complete && !limited {
		return Outcome{Status: OutcomeComplete, Detail: "Workspace " + e.checksCollected() + " checks collected; notes and coverage show any unresolved evidence."}
	}
	o := Outcome{Status: OutcomeIncomplete, Detail: "Workspace evidence is incomplete; notes show what was read and what remains unknown."}
	for _, read := range reads {
		if limitedRead(read) {
			o.Reason = "limit_reached"
			if read.Decision == "unavailable:bootstrap_required" {
				o.Detail = "The Workspace session's token expired before every Workspace read was made; resume to read the rest."
			}
		}
		if read.Reason == "no_credentials" {
			o.Reason, o.Detail = read.Reason, read.Detail
		}
	}
	return o
}
