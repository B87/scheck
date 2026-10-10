package finding

// GitHub identity and repository-access findings (docs/spec/github-collector.md, "Rules: evidence outcomes").
const (
	IDGitHubMFANotRequired               = "github.mfa_not_required"
	IDGitHubOwnerWithoutMFA              = "github.owner_without_mfa"
	IDGitHubMemberWithoutMFA             = "github.member_without_mfa"
	IDIdentityUnexpectedAdmin            = "identity.unexpected_admin"
	IDIdentityUnattributedAdmin          = "identity.unattributed_admin"
	IDIdentityExternalAdmin              = "identity.external_admin"
	IDIdentitySharedAdmin                = "identity.shared_admin"
	IDIdentityFormerPersonHasAccess      = "identity.former_person_has_access"
	IDIdentityFormerPersonInvited        = "identity.former_person_invited"
	IDGitHubTooManyOwners                = "github.too_many_owners"
	IDGitHubUndeclaredPublicRepository   = "github.undeclared_public_repository"
	IDGitHubBroadDefaultMemberPermission = "github.broad_default_member_permission"
	IDGitHubOutsideAdminOnProduction     = "github.outside_admin_on_production"
	IDGitHubWritableDeployKey            = "github.writable_deploy_key"
)

var githubDefs = []Def{
	githubDef(IDGitHubMFANotRequired, "The organization does not require two-factor authentication", SevHigh, "", "An account can join or remain without the organization's second-factor requirement.", "Enable GitHub's organization two-factor requirement after checking users and automation; SAML or identity-provider MFA does not replace this GitHub control."),
	githubDef(IDGitHubOwnerWithoutMFA, "An organization owner has no two-factor authentication", SevHigh, "account", "Compromise of this owner's password can grant organization administration.", "Enable strong GitHub two-factor authentication for this account, preferably security keys; check it even when SAML sign-in uses MFA."),
	githubDef(IDGitHubMemberWithoutMFA, "A member has no two-factor authentication", SevMedium, "account", "Compromise of this member's password can grant the account's repository access.", "Enable two-factor authentication and require it for the organization."),
	githubDef(IDIdentityUnexpectedAdmin, "An owner is not among the declared expected owners", SevMedium, "account", "The observed administrative access exceeds the operator's stated expectations.", "Confirm whether the person needs owner access; remove it or correct the expected owner declaration."),
	githubDef(IDIdentityUnattributedAdmin, "An administrator is not tied to a declared person", SevHigh, "account", "The operator cannot identify who controls this administrative access.", "Identify the account owner and declare their login, or remove the unnecessary administrative access."),
	githubDef(IDIdentityExternalAdmin, "A contractor is an organization owner", SevMedium, "account", "An external person's account can administer the organization.", "Confirm the administrative need and use a narrower role when possible."),
	githubDef(IDIdentitySharedAdmin, "A shared account is an organization owner", SevMedium, "account", "Administrative actions cannot reliably be attributed to one person.", "Use individually assigned owner accounts and retain a separate recovery account."),
	githubDef(IDIdentityFormerPersonHasAccess, "A departed person or retired account retains access", SevHigh, "account", "An account whose declared leaving date has passed retains observed access.", "Remove its memberships and repository access, and review credentials and sessions."),
	githubDef(IDIdentityFormerPersonInvited, "A departed person retains a pending invitation", SevHigh, "invitation", "The invitation may restore access after the person's declared departure.", "Cancel the pending invitation and confirm the offboarding declaration."),
	githubDef(IDGitHubTooManyOwners, "The organization has more owners than its size needs", SevMedium, "", "A larger owner population increases the number of accounts that can fully administer the organization.", "Reduce owner privileges to the people who need them while retaining at least two recovery-capable owners."),
	githubDef(IDGitHubUndeclaredPublicRepository, "A repository is public without a public declaration", SevHigh, "repository", "The repository's contents are publicly available although the operator has not declared that intention.", "Confirm public visibility is intentional and declare public: true, or change the repository visibility."),
	githubDef(IDGitHubBroadDefaultMemberPermission, "Organization members receive broad default repository access", SevMedium, "", "Every member receives write or administrative access by default.", "Set a narrow base permission and grant repository access through specific teams."),
	githubDef(IDGitHubOutsideAdminOnProduction, "An outside collaborator administers a production repository", SevHigh, "account", "This external account can administer the repository declared to deploy to production.", "Confirm the administrative need and reduce repository permissions where possible."),
	githubDef(IDGitHubWritableDeployKey, "A deploy key can write to the repository", SevMedium, "deploy_key", "Possession of this deploy key permits repository changes.", "Replace the key with a read-only deploy key or a narrowly scoped application credential."),
}

func githubDef(id, title string, severity Severity, subject SubjectKind, impact, fix string) Def {
	return Def{ID: id, Title: title, Category: "accounts", Area: AreaIdentity, Exposure: NotExposure, Subject: subject, Judges: title, BaseSeverity: severity, Impact: impact, Remediation: Remediation{Summary: fix}}
}
func GitHubIDs() []string {
	ids := make([]string, 0, len(githubDefs))
	for _, d := range githubDefs {
		ids = append(ids, d.ID)
	}
	return ids
}
func init() {
	for _, d := range githubDefs {
		if d.ID == IDGitHubUndeclaredPublicRepository || d.ID == IDGitHubWritableDeployKey {
			d.Area = AreaCICD
		}
		defs[d.ID] = d
	}
}
