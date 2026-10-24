package github

import (
	"cmp"
	"slices"
	"strings"
)

// The facts the engagement's context notes read of what this collector
// holds (docs/spec/engagement.md, "Context notes"). Each is a reading of
// evidence already collected, worded nowhere: the engagement owns which of
// them contradict a declaration.

// ActionUse is one action a workflow uses: the repository asset, the
// workflow's path and the action as owner/repo, lowercased, its ref and any
// subpath dropped.
type ActionUse struct {
	Asset, Workflow, Action string
}

// ActionUses are the remote actions the workflows read name, at job and
// step level, in repository and workflow order. A marked, templated or
// unrecognized reference is left out.
func ActionUses(e Evidence) []ActionUse {
	var out []ActionUse
	for _, ci := range e.RepositoriesCI {
		for _, w := range ci.Workflows {
			jobs, ok := mapping(w.Document["jobs"])
			if w.Gap != "" || !ok {
				continue
			}
			ids := make([]string, 0, len(jobs))
			for id := range jobs {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			add := func(v any) {
				r := actionReference(v)
				if !r.Known || !r.External || strings.HasPrefix(r.Value, "docker://") {
					return
				}
				name, _, _ := strings.Cut(r.Value, "@")
				parts := strings.Split(strings.ToLower(name), "/")
				if len(parts) < 2 {
					return
				}
				u := ActionUse{Asset: ci.Asset, Workflow: w.Path, Action: parts[0] + "/" + parts[1]}
				if !slices.Contains(out, u) {
					out = append(out, u)
				}
			}
			for _, id := range ids {
				job, ok := mapping(jobs[id])
				if !ok {
					continue
				}
				if v, ok := job["uses"]; ok {
					add(v)
				}
				steps, _ := job["steps"].([]any)
				for _, entry := range steps {
					if step, ok := mapping(entry); ok {
						if v, ok := step["uses"]; ok {
							add(v)
						}
					}
				}
			}
		}
	}
	return out
}

// SecretName is one Actions secret's name and the asset holding it: the
// organization, or a repository.
type SecretName struct{ Asset, Name string }

// SecretNames are the Actions secret names the organization and repository
// reads returned; a marked name is left out. Names only: no value is ever
// read.
func SecretNames(e Evidence, org string) []SecretName {
	var out []SecretName
	add := func(asset string, p Population[ActionsSecret]) {
		for _, s := range p.Items {
			if s.Name != "" && !marked(s.Name) {
				out = append(out, SecretName{Asset: asset, Name: s.Name})
			}
		}
	}
	add(org, e.OrganizationSecrets)
	for _, r := range e.RepositoriesAlerts {
		add(r.Asset, r.Secrets)
	}
	return out
}

// The states of a declared repository as its direct read left it.
const (
	RepositoryFound    = "found"
	RepositoryArchived = "archived"
	RepositoryMissing  = "missing"
	RepositoryUnread   = "unread"
)

// RepositoryState is what the direct read of a declared repository says:
// found, archived, missing (GitHub answered 404: no such repository, or
// none this credential may see), or unread with the read's reason.
func RepositoryState(e Evidence, asset string) (state, reason string) {
	for _, r := range e.RepositoriesAccess {
		if r.Asset != asset {
			continue
		}
		read := r.RepositoryRead
		switch {
		case read.Status == 404:
			return RepositoryMissing, ""
		case !usableRead(read) || r.Repository == nil:
			return RepositoryUnread, cmp.Or(read.Reason, read.Gap, "failed")
		case archived(r):
			return RepositoryArchived, ""
		}
		return RepositoryFound, ""
	}
	// No direct read was attempted for it.
	return RepositoryUnread, ""
}
