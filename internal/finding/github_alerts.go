package finding

// Provider reports are evidence of an open alert, never a credential-usability or
// exploitability test. docs/spec/github-collector.md, "Secret metadata and provider alerts: step 5 definition".
const (
	IDGitHubOrgSecretAll       = "github.org_secret_all_repositories" //nolint:gosec // compiled identifier, not a credential
	IDGitHubDependabotHigh     = "github.dependabot_high"
	IDGitHubDependabotMedium   = "github.dependabot_medium"
	IDGitHubDependabotLow      = "github.dependabot_low"
	IDGitHubSecretScanningOpen = "github.secret_scanning_open" //nolint:gosec // compiled identifier, not a credential
)

func GitHubAlertIDs() []string {
	return []string{IDGitHubOrgSecretAll, IDGitHubDependabotHigh, IDGitHubDependabotMedium, IDGitHubDependabotLow, IDGitHubSecretScanningOpen}
}
func init() {
	sharing := githubDef(IDGitHubOrgSecretAll, "Organization secret is available to all repositories", SevMedium, "secret_location", "A compromised repository workflow may reach this organization secret; its name does not establish production use or leakage.", "Limit this organization secret to the repositories that need it. Review workflows in those repositories before changing access.")
	sharing.Area = AreaSecrets
	sharing.Category = "secrets"
	defs[sharing.ID] = sharing
	for _, s := range []struct {
		id  string
		sev Severity
	}{{IDGitHubDependabotHigh, SevHigh}, {IDGitHubDependabotMedium, SevMedium}, {IDGitHubDependabotLow, SevLow}} {
		label := string(s.sev)
		if s.sev == SevHigh {
			label = "high or critical"
		}
		d := githubDef(s.id, "GitHub reports an open "+label+" severity dependency alert", s.sev, "dependency_alert", "GitHub reports an affected dependency in this manifest; installed deployed versions and exploitability were not established.", "Review the affected manifest and upgrade to a patched version where available. Confirm the deployed dependency and test the change; scheck did not establish exploitability.")
		d.Area = AreaCICD
		d.Category = "ci"
		defs[d.ID] = d
	}
	d := githubDef(IDGitHubSecretScanningOpen, "GitHub reports an open secret-scanning alert", SevHigh, "secret_location", "The provider reports a credential in this location. Its authenticity, current usability and use were not independently tested.", "Revoke or rotate this credential at its provider first. Review its use, then remove it from the reported locations. Closing an alert or deleting a commit does not revoke a credential.")
	d.Area = AreaSecrets
	d.Category = "secrets"
	defs[d.ID] = d
}
