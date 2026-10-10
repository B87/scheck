package github

import (
	"strings"
	"testing"

	"github.com/b87/scheck/internal/policy"
)

func credentialPrincipal(scopes ...string) PrincipalRead {
	return PrincipalRead{Read: Read{Decision: "sent", Status: 200}, Account: &Account{ID: 1, Login: "alice", Type: "User"}, Identity: "github:user:1", Scopes: scopes}
}

func TestAssessmentCredentialScopeOutcomes(t *testing.T) {
	// Independent fixtures from the supported scope meanings frozen by DEFINE.
	broad := []string{"repo", "repo:status", "public_repo", "repo:invite", "security_events", "admin:repo_hook", "write:repo_hook", "read:repo_hook", "admin:org", "write:org", "admin:public_key", "write:public_key", "admin:org_hook", "gist", "notifications", "user", "user:follow", "project", "delete_repo", "write:packages", "delete:packages", "admin:gpg_key", "write:gpg_key", "codespace", "workflow"}
	reads := []string{"read:org", "read:public_key", "read:user", "user:email", "read:project", "read:packages", "read:gpg_key", "read:audit_log"}
	for _, scope := range broad {
		t.Run(scope, func(t *testing.T) {
			for _, scopes := range [][]string{{scope}, {scope, "read:org"}, {scope, "future:permission"}} {
				note := AssessmentCredential(credentialPrincipal(scopes...))
				if note.Capability != CapabilityBeyondReads || !strings.Contains(note.Detail, "beyond reads ("+scope+")") || strings.Contains(note.Detail, "future:permission") {
					t.Fatalf("%v: %+v", scopes, note)
				}
			}
		})
	}
	for _, scope := range reads {
		if note := AssessmentCredential(credentialPrincipal(scope)); note.Capability != CapabilityReadScopes || !strings.Contains(note.Detail, "effective permissions were not tested") {
			t.Fatalf("%s: %+v", scope, note)
		}
	}
	if note := AssessmentCredential(credentialPrincipal(reads...)); note.Capability != CapabilityReadScopes {
		t.Fatal(note)
	}
	for _, scopes := range [][]string{nil, {}, {"future:permission"}, {"read:future"}, {"read:org", "future:permission"}, {"repo", "malformed scope"}} {
		if note := AssessmentCredential(credentialPrincipal(scopes...)); note.Capability != CapabilityUnknown || !strings.Contains(note.Detail, "was not determined") {
			t.Fatalf("%v: %+v", scopes, note)
		}
	}
	note := AssessmentCredential(credentialPrincipal("workflow", "repo", "repo"))
	if !strings.Contains(note.Detail, "beyond reads (repo, workflow)") {
		t.Fatal(note)
	}
}

func TestAssessmentCredentialUnknownPrincipal(t *testing.T) {
	for name, modify := range map[string]func(*PrincipalRead){
		"failed":      func(p *PrincipalRead) { p.Read.Status = 401; p.Read.Reason = "refused" },
		"redacted":    func(p *PrincipalRead) { p.Read.Redactions = []policy.Hit{{}} },
		"truncated":   func(p *PrincipalRead) { p.Read.Truncated = true },
		"malformed":   func(p *PrincipalRead) { p.Read.Gap = "unrecognized_principal" },
		"unsupported": func(p *PrincipalRead) { p.Read.Decision = "unavailable:unsupported_principal" },
		"no identity": func(p *PrincipalRead) { p.Identity = "" },
		"no account":  func(p *PrincipalRead) { p.Account = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := credentialPrincipal("repo")
			modify(&p)
			if note := AssessmentCredential(p); note.Capability != CapabilityUnknown {
				t.Fatal(note)
			}
		})
	}
}
