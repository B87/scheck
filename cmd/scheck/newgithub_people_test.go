package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement"
)

func TestGitHubPeopleStanza(t *testing.T) {
	doc := &engagement.ReconDoc{
		PeopleSource: "engagement.yaml", PeopleCandidatesPartial: true,
		PeopleCandidates:         []engagement.PeopleCandidate{{Tenant: "github:acme", Login: "dave", Handle: "dave-2", Role: "owner"}},
		PeopleInvitationComments: []engagement.PeopleInvitationComment{{Tenant: "github:acme", InvitationID: "7", Role: "direct_member"}},
	}
	var out bytes.Buffer
	writeGitHubPeople(&out, doc)
	for _, want := range []string{"At least these accounts", "engagement.yaml", "\"dave-2\":", "kind: \"\"", "github: [\"dave\"]", "pending invitation 7", "no account to declare yet"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func TestGitHubPeopleStanzaEscapesTargetText(t *testing.T) {
	doc := &engagement.ReconDoc{PeopleCandidates: []engagement.PeopleCandidate{{Tenant: "github:evil\x1b[31m", Role: "owner\nINJECTED", Handle: "user:\nkind:employee", Login: "login\nnext"}}}
	var out bytes.Buffer
	writeGitHubPeople(&out, doc)
	for _, raw := range []string{"\x1b", "owner\nINJECTED", "login\nnext", "user:\nkind"} {
		if strings.Contains(out.String(), raw) {
			t.Errorf("raw control characters printed: %q", out.String())
		}
	}
	out.Reset()
	writeGitHubPeople(&out, &engagement.ReconDoc{})
	if out.Len() != 0 {
		t.Fatal("empty stanza printed")
	}
}

func TestGitHubPeopleStanzaRootOrderIncludesInvitations(t *testing.T) {
	doc := &engagement.ReconDoc{
		PeopleTenantOrder:        []string{"github:z-org", "github:a-org"},
		PeopleCandidates:         []engagement.PeopleCandidate{{Tenant: "github:a-org", Login: "alice", Handle: "alice", Role: "owner"}},
		PeopleInvitationComments: []engagement.PeopleInvitationComment{{Tenant: "github:z-org", InvitationID: "9", Role: "admin"}},
	}
	var out bytes.Buffer
	writeGitHubPeople(&out, doc)
	if strings.Index(out.String(), "github:z-org") > strings.Index(out.String(), "github:a-org") {
		t.Fatalf("root order reversed: %s", out.String())
	}
}
