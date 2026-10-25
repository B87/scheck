package finding

// alsoReadsDeclarations lists, beside the definitions that set
// Def.ReadsDeclarations, the ids whose presence depends on the engagement
// file although their findings carry no `declared:` read when they fire: the
// file decides a service is expected, a repository public, who counts as an
// owner. Every identity finding is covered by its area instead (below).
var alsoReadsDeclarations = map[string]bool{
	IDExpectedMissing:                  true,
	IDGitHubTooManyOwners:              true,
	IDGitHubUndeclaredPublicRepository: true,
	// Which of these a DNS record is filed as depends on the domain roots
	// the file declares (a target inside a root is internal) and on its
	// excludes.
	// The pages a rule reads include every intent URL the file lists, and
	// a leaked secret or a version is a finding about one page.
	IDWebSecretInResponse:    true,
	IDWebVersionDisclosed:    true,
	IDDNSDanglingExternal:    true,
	IDDNSDanglingInternal:    true,
	IDDNSTakeoverCandidate:   true,
	IDDNSUnclaimedAtProvider: true,
}

// ReadsDeclarations says whether a change to the engagement file alone could
// make a finding of this id vanish or appear, so that a comparison of two
// runs cannot call it fixed or new across such a change
// (docs/spec/runs.md, "Comparing two runs"). It fails closed: an id this
// build does not know, and every finding in the identity area (who is a
// person, a service account or an administrator is declared), counts.
func ReadsDeclarations(id string) bool {
	d, ok := Lookup(id)
	return !ok || d.ReadsDeclarations || d.Area == AreaIdentity || alsoReadsDeclarations[id]
}
