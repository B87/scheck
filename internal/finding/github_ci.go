package finding

// CI findings describe configured controls, never successful workflow execution.
// docs/spec/github-collector.md, "CI controls: step 4 definition".
const (
	IDGitHubOrganizationWorkflowWrite = "github.organization_workflow_default_write"
	IDGitHubRepositoryWorkflowWrite   = "github.repository_workflow_default_write"
	IDGitHubDefaultBranchUnprotected  = "github.default_branch_unprotected"
	IDGitHubMutableAction             = "github.mutable_action_reference"
	IDGitHubMutableActionWrite        = "github.mutable_action_with_write_token"
	IDGitHubPRTargetUnsafe            = "github.pr_target_unsafe_checkout"
)

func GitHubCIIDs() []string {
	return []string{IDGitHubOrganizationWorkflowWrite, IDGitHubRepositoryWorkflowWrite, IDGitHubDefaultBranchUnprotected, IDGitHubMutableAction, IDGitHubMutableActionWrite, IDGitHubPRTargetUnsafe}
}
func init() {
	entries := []Def{
		githubDef(IDGitHubOrganizationWorkflowWrite, "Organization workflow tokens default to write permission", SevMedium, "", "Inherited write defaults widen what a compromised workflow can request.", "Use read defaults; grant each job only the permissions it needs."),
		githubDef(IDGitHubRepositoryWorkflowWrite, "Repository workflow tokens default to write permission", SevMedium, "repository", "Inherited write defaults widen what a compromised workflow can request.", "Use read defaults; grant each job only the permissions it needs."),
		githubDef(IDGitHubDefaultBranchUnprotected, "Default branch has no observed active protection", SevMedium, "branch", "Changes to this branch lack observed active protection; review strength and bypass access were not assessed.", "Add active default-branch protection, then review required PR reviews, checks and bypass access."),
		githubDef(IDGitHubMutableAction, "Workflow action references are mutable", SevLow, "workflow", "A tag or branch may change the dependency a later workflow run requests.", "Pin remote dependencies to reviewed full commits or image digests; automate updates."),
		githubDef(IDGitHubMutableActionWrite, "Workflow requests mutable dependencies with write permission", SevHigh, "workflow", "A changed dependency could act with the mutation permission requested by this job; actual execution was not verified.", "Pin remote dependencies and reduce the job's token permissions."),
		githubDef(IDGitHubPRTargetUnsafe, "Workflow requests PR-controlled code execution with write permission", SevMedium, "workflow", "This configuration requests execution of PR-controlled code in a privileged context; runtime policies, checkout protection, approvals and actual execution were not verified.", "Run PR code under pull_request; separate privileged reporting and never execute PR-controlled code in that privileged job."),
	}
	for _, d := range entries {
		d.Area = AreaCICD
		d.Category = "ci"
		defs[d.ID] = d
	}
}
