package main

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/report"
)

// writeGitHubPeople prints suggestions only; an empty kind requires an explicit
// operator answer (docs/spec/engagement.md, "People", "The recon stanza").
func writeGitHubPeople(w io.Writer, doc *engagement.ReconDoc) {
	if len(doc.PeopleCandidates) == 0 && len(doc.PeopleInvitationComments) == 0 {
		return
	}
	header := "Accounts no handle under people names"
	if doc.PeopleCandidatesPartial {
		header = "At least these accounts have no handle under people names"
	}
	fmt.Fprintf(w, "\n# %s, read %s.\n", header, doc.Started.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "# Set kind for each and paste under people: in %s.\n", githubPeopleComment(doc.PeopleSource))
	fmt.Fprintln(w, "# One entry per account; merge accounts belonging to the same person by hand.")
	fmt.Fprintln(w, "# kind: employee | contractor | shared | service | break_glass (add left: YYYY-MM-DD if they left)")
	fmt.Fprintln(w, "people:")
	tenants := slices.Clone(doc.PeopleTenantOrder)
	for _, c := range doc.PeopleCandidates {
		if !slices.Contains(tenants, c.Tenant) {
			tenants = append(tenants, c.Tenant)
		}
	}
	for _, c := range doc.PeopleInvitationComments {
		if !slices.Contains(tenants, c.Tenant) {
			tenants = append(tenants, c.Tenant)
		}
	}
	for _, tenant := range tenants {
		for _, c := range doc.PeopleCandidates {
			if c.Tenant != tenant {
				continue
			}
			fmt.Fprintf(w, "  # %s  %s  GitHub reports no sign-ins\n", githubPeopleComment(c.Tenant), githubPeopleComment(c.Role))
			// Quoted YAML scalars cannot inject another key even if a caller hands
			// this renderer malformed evidence; control characters are escaped first.
			fmt.Fprintf(w, "  %s:\n    kind: \"\"\n    github: [%s]\n", strconv.Quote(report.Sanitize(c.Handle)), strconv.Quote(report.Sanitize(c.Login)))
		}
		for _, c := range doc.PeopleInvitationComments {
			if c.Tenant == tenant {
				fmt.Fprintf(w, "  # %s  pending invitation %s, role %s (no account to declare yet)\n", githubPeopleComment(c.Tenant), githubPeopleComment(c.InvitationID), githubPeopleComment(c.Role))
			}
		}
	}
}

func githubPeopleComment(s string) string {
	return strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(report.Sanitize(s))
}
