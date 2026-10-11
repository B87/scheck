package workspace

import (
	"slices"
	"strings"
)

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

// Readout is the collector's interpretation of collected evidence for the
// readout: administrative and 2-step verification notes beside the rules.
func Readout(e Evidence, asset string, c Context) []Note {
	views := accountViews(e, c, attribute(asset, e.Users.Items, c.People, e.Users.Complete))
	return slices.Concat(accessNotes(e, asset, c), twoStepNotes(e, asset, c), oauthNotes(e, asset, views), mailNotes(e, asset, views, c.MailApproval))
}

// accessNotes owns interpretation and readout wording beside the rules.
func accessNotes(e Evidence, asset string, c Context) []Note {
	out := []Note{{Kind: "workspace_inventory", Source: asset, Detail: "Administrative checks cover current super-administrator flags and supported direct or indirect role assignments. Group membership paths and effective permissions were not tested."}, {Kind: "workspace_inventory", Source: asset, Detail: "Domain-wide delegation inventory is not assessed. Review Security → Access and data control → API controls → Manage Domain Wide Delegation in the Admin console."}}
	note := func(text string) { out = append(out, Note{Kind: "workspace_inventory", Source: asset, Detail: text}) }
	attrs := attribute(asset, e.Users.Items, c.People, e.Users.Complete)
	for _, expected := range c.ExpectedAdmins {
		observed := false
		for _, u := range e.Users.Items {
			if p := personForUser(u, attrs, c); p != nil && p.Handle == expected && yes(u.IsAdmin) {
				observed = true
			}
		}
		if !observed {
			note("Declared expected administrator " + expected + " was not observed as a super administrator. Incomplete evidence or a removed old address can prevent a match; this is not a finding.")
		}
	}
	for _, u := range e.Users.Items {
		p := personForUser(u, attrs, c)
		if p == nil {
			continue
		}
		if leftPassed(p.Left, c) && !strings.EqualFold(u.Primary, firstPrimary(p, u)) {
			note("A departed person's declared address matches an alias of " + u.Primary + ". Verify ownership or a rename; active access was not concluded from an alias-only match.")
		}
		if p.Kind == "shared" {
			for _, handle := range p.UsedBy {
				if used := person(c, handle); used != nil && leftPassed(used.Left, c) {
					note("A departed person was declared to use shared account " + u.Primary + ". Rotate its password and second factors; rotation was not observed.")
				}
			}
		}
		if p.Kind == "break_glass" {
			note("Review recovery-role assignment and exercise sign-in for declared break-glass account " + u.Primary + ". Recovery readiness and second-factor strength were not tested.")
		}
	}
	for _, gap := range e.Access.InterpretationGaps {
		note(gap)
	}
	for _, a := range e.Access.Accounts {
		if a.Conflict {
			note("Current list and detail security flags conflicted for account id " + a.ID + "; affected conclusions remain unknown.")
		}
		for _, assignment := range a.Assignments.Items {
			if _, known := currentAssignment(assignment, c.AssessedAt); !known {
				note("Role assignment " + assignment.ID + " has an unsupported condition or unreadable expiry; its current privilege remains unknown.")
			}
		}
	}
	if !e.Users.Complete {
		note("Partial account populations cannot prove address absence or an administrator ratio. Counts are lower bounds.")
	}
	return out
}
func firstPrimary(p *Person, u User) string {
	for _, address := range p.Addresses {
		if strings.EqualFold(address, u.Primary) {
			return address
		}
	}
	return ""
}
