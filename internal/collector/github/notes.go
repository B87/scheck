package github

import "strings"

// ReadNote explains an observed read without assigning report placement or severity.
type ReadNote struct{ Detail string }

// ReadNotes describes reuse, incomplete populations and unavailable reads.
// Permission guidance belongs to the operation that needs the permission
// (docs/spec/github-collector.md, "Reporting and coverage").
func ReadNotes(read Read) []ReadNote {
	var out []ReadNote
	if read.Reused {
		out = append(out, ReadNote{Detail: read.Op + ": reused evidence observed at " + read.ObservedAt.UTC().Format("2006-01-02T15:04:05Z") + "; current access was not validated"})
	}
	if read.Population != nil && len(read.Population.Incomplete) > 0 {
		out = append(out, ReadNote{Detail: read.Op + ": population incomplete (" + InventoryGapText(read.Population.Incomplete) + ")"})
	}
	if read.Reason != "" || read.Gap != "" {
		detail := strings.TrimSpace(read.Detail)
		if detail == "" {
			detail = strings.TrimSpace(read.Reason + " " + read.Gap)
			if read.Reason == "insufficient_permission" {
				detail = "Read unavailable; access or feature availability was not established"
			}
		}
		if read.Reason == "insufficient_permission" {
			switch read.Op {
			case OpOrganizationSecrets, OpSelectedSecretRepositories, OpRepositorySecrets:
				detail += ". Ask the owner to authorize Secrets read at the relevant organization or repository level, then resume"
			case OpDependabotAlerts:
				detail += ". Ask the repository owner to check Dependabot alerts read permission, repository selection and feature availability, then resume"
			case OpSecretAlerts, OpSecretLocations:
				detail += ". Ask the repository owner to authorize Secret scanning alerts read and confirm the account has the required repository role, then resume"
			case OpRepositoryWorkflow, OpOrganizationWorkflow:
				detail += ". Ask the owner to authorize Administration read at the relevant repository or organization level, then resume"
			case OpBranch, OpWorkflowDirectory, OpWorkflowFile:
				detail += ". Ask the repository owner to authorize Contents read for this repository, then resume"
			case OpBranchRules:
				detail += ". Ask the repository owner to authorize Metadata read, then resume"
			case OpDeployKeys:
				detail += ". Ask the repository owner to authorize Administration read permission for this credential, then resume"
			case OpCollaborators:
				detail += ". Ask the repository owner to authorize Metadata read and confirm this account has sufficient repository privilege to list collaborators, then resume"
			case OpRepository, OpRepositories:
				detail += ". Ask the owner to authorize Metadata read for the intended repositories, then resume"
			case OpPrincipal, OpOrganization:
			default:
				detail += ". Ask the GitHub organization owner to authorize Members read and confirm the required organization role, then resume"
			}
		}
		if detail == "" {
			detail = read.Reason + " " + read.Gap
		}
		out = append(out, ReadNote{Detail: read.Op + ": " + strings.TrimSpace(detail)})
	}
	return out
}

// InventoryGapText explains provider inventory gaps without claiming completeness.
func InventoryGapText(gaps []string) string {
	explanations := map[string]string{
		"member_visibility_unknown":                  "complete membership visibility was not established",
		"owner_visibility_unknown":                   "organization-owner visibility was not established",
		"repository_visibility_unknown":              "the credential may hide repositories",
		"repository_collaborator_visibility_unknown": "the credential may hide repository collaborators",
		"owner_authority_unknown":                    "organization-owner authority was not established",
		"duplicate_item":                             "duplicate entries were returned and counted once",
		"unrecognized_item":                          "some returned entries could not be recognized",
		"unrecognized_population":                    "the returned list could not be recognized",
		"read_unavailable":                           "a required read did not succeed",
		"population_unknown":                         "list completeness could not be established",
		"pagination_unrecognized":                    "the next page could not be identified",
		"page_limit":                                 "the page limit was reached",
	}
	out := make([]string, 0, len(gaps))
	for _, gap := range gaps {
		if phrase := explanations[gap]; phrase != "" {
			out = append(out, phrase)
		} else {
			out = append(out, strings.ReplaceAll(gap, "_", " "))
		}
	}
	return strings.Join(out, "; ")
}
