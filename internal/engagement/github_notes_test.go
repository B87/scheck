package engagement

import (
	"strings"
	"testing"
	"time"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/policy"
)

func TestGitHubMFANotesRequireRecognizedReads(t *testing.T) {
	res := &Resolved{Access: Access{MFA: []MFA{{Where: "github:acme", Enforced: "unknown"}}}, refs: map[string]Ref{"github:acme": {ID: "saas:github:acme"}}}
	r := &run{res: res, session: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), zone: time.UTC}
	for _, tc := range []struct {
		name     string
		read     githubc.Read
		complete bool
		want     string
		absent   string
	}{
		{"denied", githubc.Read{Decision: "sent", Status: 403}, true, "enrollment evidence was unavailable", "0 accounts were returned"},
		{"redacted", githubc.Read{Decision: "sent", Status: 200, Redactions: []policy.Hit{{}}}, true, "enrollment evidence was unavailable", "0 accounts were returned"},
		{"partial", githubc.Read{Decision: "sent", Status: 200}, false, "at least 0 accounts were returned", "observed 0"},
		{"complete", githubc.Read{Decision: "sent", Status: 200}, true, "observed 0 accounts were returned", "at least 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := githubc.Evidence{OwnerAuthority: true, MembersWithoutMFA: githubc.Population[githubc.Account]{Reads: []githubc.Read{tc.read}, Complete: tc.complete, VisibilityComplete: tc.complete}}
			var text string
			for _, n := range r.githubPeopleNotes("saas:github:acme", e) {
				if n.Source == "access.mfa[0]" {
					text += n.Detail + "\n"
				}
			}
			if !strings.Contains(text, tc.want) || strings.Contains(text, tc.absent) {
				t.Fatalf("notes %q", text)
			}
		})
	}
	res.Access.MFA[0].Enforced = "none"
	e := githubc.Evidence{OwnerAuthority: true, Organization: &githubc.OrganizationObject{TwoFactorRequirementEnabled: new(true)}, OrganizationRead: githubc.Read{Decision: "sent", Status: 200, Redactions: []policy.Hit{{}}}}
	for _, n := range r.githubPeopleNotes("saas:github:acme", e) {
		if strings.Contains(n.Detail, "observed organization requires") {
			t.Fatal(n.Detail)
		}
	}
}
