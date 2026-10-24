package github

import (
	"slices"
	"strings"
)

const (
	CapabilityBeyondReads = "beyond_reads"
	CapabilityReadScopes  = "read_scopes_only"
	CapabilityUnknown     = "unknown"
)

// CredentialNote describes the assessment credential, never a finding or rule
// verdict (docs/spec/github-collector.md, "Principal and resume").
type CredentialNote struct{ Capability, Detail string }

// AssessmentCredential uses only the recognized principal's observed OAuth
// scopes. Missing scopes cannot distinguish a scopeless classic token from
// fine-grained/App permissions. Effective resource permissions remain untested.
func AssessmentCredential(p PrincipalRead) CredentialNote {
	unknown := CredentialNote{Capability: CapabilityUnknown, Detail: "GitHub assessment credential: write capability was not determined. scheck sent only read requests. Check the credential's permissions with the organization owner; use an approved token with only the read permissions needed."}
	if !usableRead(p.Read) || p.Identity == "" || p.Account == nil || len(p.Scopes) == 0 {
		return unknown
	}
	var broad []string
	allRead := true
	for _, scope := range p.Scopes {
		if !scopeRE.MatchString(scope) {
			return unknown
		}
		switch scopeCapability[scope] {
		case CapabilityBeyondReads:
			broad = append(broad, scope)
		case CapabilityReadScopes:
		default:
			allRead = false
		}
	}
	if len(broad) > 0 {
		slices.Sort(broad)
		broad = slices.Compact(broad)
		return CredentialNote{Capability: CapabilityBeyondReads, Detail: "GitHub assessment credential: observed OAuth scopes permit operations beyond reads (" + strings.Join(broad, ", ") + "). scheck sent only read requests. Prefer an organization-approved fine-grained token with the read permissions this assessment needs; revoke a dedicated assessment token when finished. Effective write access to this organization was not tested."}
	}
	if allRead {
		return CredentialNote{Capability: CapabilityReadScopes, Detail: "GitHub assessment credential: the observed OAuth scopes contain no recognized write grant. scheck sent only read requests; effective permissions were not tested."}
	}
	return unknown
}

// Exact meanings verified against GitHub's documented OAuth scopes, 2026-10-10:
// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
// read:repo_hook permits webhook pings, so prefix matching would be unsafe.
// Unlisted scopes remain unknown (docs/spec/scope.md, "Methods and credentials").
var scopeCapability = map[string]string{
	"repo": CapabilityBeyondReads, "repo:status": CapabilityBeyondReads,
	"public_repo": CapabilityBeyondReads, "repo:invite": CapabilityBeyondReads,
	"security_events": CapabilityBeyondReads, "admin:repo_hook": CapabilityBeyondReads,
	"write:repo_hook": CapabilityBeyondReads, "read:repo_hook": CapabilityBeyondReads,
	"admin:org": CapabilityBeyondReads, "write:org": CapabilityBeyondReads,
	"admin:public_key": CapabilityBeyondReads, "write:public_key": CapabilityBeyondReads,
	"admin:org_hook": CapabilityBeyondReads, "gist": CapabilityBeyondReads,
	"notifications": CapabilityBeyondReads, "user": CapabilityBeyondReads,
	"user:follow": CapabilityBeyondReads, "project": CapabilityBeyondReads,
	"delete_repo": CapabilityBeyondReads, "write:packages": CapabilityBeyondReads,
	"delete:packages": CapabilityBeyondReads, "admin:gpg_key": CapabilityBeyondReads,
	"write:gpg_key": CapabilityBeyondReads, "codespace": CapabilityBeyondReads,
	"workflow": CapabilityBeyondReads,
	"read:org": CapabilityReadScopes, "read:public_key": CapabilityReadScopes,
	"read:user": CapabilityReadScopes, "user:email": CapabilityReadScopes,
	"read:project": CapabilityReadScopes, "read:packages": CapabilityReadScopes,
	"read:gpg_key": CapabilityReadScopes, "read:audit_log": CapabilityReadScopes,
}
