package workspace

import "strings"

// CredentialNote uses returned grants only; requested scopes are not assurance.
func CredentialNote(b Binding) Note {
	detail := "Returned credential permissions are unknown; effective permissions were not tested."
	kind := "workspace_credential"
	if b.ScopesKnown {
		narrow := map[string]bool{}
		for _, name := range []string{"admin.directory.customer.readonly", "admin.directory.domain.readonly", "admin.directory.orgunit.readonly", "admin.directory.user.readonly", "admin.directory.rolemanagement.readonly", "admin.directory.group.readonly", "gmail.readonly", "userinfo.email", "userinfo.profile"} {
			narrow["https://www.googleapis.com/auth/"+name] = true
		}
		broad := map[string]bool{}
		for _, name := range []string{"admin.directory.customer", "admin.directory.domain", "admin.directory.orgunit", "admin.directory.user", "admin.directory.rolemanagement", "admin.directory.group", "admin.directory.user.security", "gmail.settings.basic", "gmail.modify", "gmail.send"} {
			broad["https://www.googleapis.com/auth/"+name] = true
		}
		broad["https://mail.google.com/"] = true
		hasBroad, unknown := false, len(b.Scopes) == 0
		for _, scope := range b.Scopes {
			hasBroad = hasBroad || broad[scope]
			unknown = unknown || !narrow[scope] && !broad[scope]
		}
		if hasBroad {
			kind = "workspace_credential_warning"
			detail = "Google returned permissions beyond the supported read scopes. Use a dedicated assessment credential with the narrow approved permissions; effective permissions were not tested."
		} else if !unknown {
			detail = "No recognized beyond-read scope observed; effective permissions untested."
		}
	}

	return Note{Kind: kind, Source: b.Domain, Detail: detail}
}

func ReadNotes(read Read, asset string) []Note {
	out := []Note{}
	if read.Population != nil && len(read.Population.Incomplete) > 0 {
		out = append(out, Note{Kind: "workspace_inventory", Source: asset, Detail: read.Op + ": inventory incomplete (" + strings.Join(read.Population.Incomplete, ", ") + "). Counts are lower bounds."})
	}
	if read.Reason != "" {
		detail := read.Detail
		if detail == "" {
			detail = "The read did not return usable evidence."
		}
		if read.Reason == "insufficient_permission" {
			detail += " Ask the Workspace administrator to check the approved Directory read permissions and administrator role, then resume."
		}
		out = append(out, Note{Kind: "workspace_inventory", Source: asset, Detail: read.Op + ": " + detail})
	}
	return out
}
