package finding

// Credential detection never tests usability. docs/spec/github-collector.md,
// "Rules and subjects".
const (
	IDGitHubHistoryCredential = "github.history_credential" //nolint:gosec // Compiled finding ID.
	IDGitHubRemoteCredential  = "github.remote_credential"  //nolint:gosec // Compiled finding ID.
)

func GitHubHistoryIDs() []string {
	return []string{IDGitHubHistoryCredential, IDGitHubRemoteCredential}
}
func init() {
	for _, d := range []Def{
		githubDef(IDGitHubHistoryCredential, "Credential pattern found in repository history", SevHigh, "secret_location", "A recognized credential pattern exists in this commit. Authenticity and current usability were not tested.", "Treat this credential as exposed. Revoke or rotate it with its provider, review its use, then remove it from repository history and other copies."),
		githubDef(IDGitHubRemoteCredential, "Credential found in mirror origin configuration", SevMedium, "secret_location", "The operator's local mirror configuration holds credential-bearing userinfo or a recognized credential pattern. This does not establish hosted repository exposure.", "Remove the credential from origin configuration and revoke or rotate it; use the provider's credential helper."),
	} {
		d.Area = AreaSecrets
		d.Category = "secrets"
		defs[d.ID] = d
	}
}
