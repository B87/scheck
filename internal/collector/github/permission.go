package github

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// The permission follow-up, F1 (docs/spec/engagement.md, "Plan selection
// and follow-ups"; docs/spec/github-collector.md, "Selection under a budget
// and the permission follow-up (E9)"): a left person's declared login on a
// production repository whose object this run recognized. GitHub's answer
// is the highest role from every source of grant, so it settles a login
// the collaborators list did not show. The engagement picks the
// repositories and keeps the cap; what an answer means is decided here.

// Not-sent reasons a permission entry records for a pair the engagement
// opened but did not ask.
const (
	ReasonFollowUpCap  = "follow_up_cap"
	ReasonLimitReached = "limit_reached"
)

// PermissionTarget is one pair to ask: a login on a repository.
type PermissionTarget struct {
	Repo  RepositoryTarget
	Login string
}

// PermissionUser is the user object of a permission answer, as retained.
type PermissionUser struct {
	Account
	RoleName    *string      `json:"role_name,omitempty"`
	Permissions *Permissions `json:"permissions,omitempty"`
}

// PermissionAnswer is the retained answer: the legacy level, the role and
// the user.
type PermissionAnswer struct {
	Permission *string         `json:"permission,omitempty"`
	RoleName   *string         `json:"role_name,omitempty"`
	User       *PermissionUser `json:"user,omitempty"`
}

// PermissionRead is one pair the follow-up opened: what was asked and
// what came back, or why it was not asked.
type PermissionRead struct {
	Asset  string            `json:"asset"`
	Login  string            `json:"login"`
	Read   Read              `json:"read"`
	Answer *PermissionAnswer `json:"answer,omitempty"`
}

// CollectPermission asks GitHub one login's permission on one repository.
// The login may name no account, so a 404 is an answer, not a hidden
// repository.
func CollectPermission(ctx context.Context, g Sender, t PermissionTarget, stage string) PermissionRead {
	r := g.Send(ctx, gate.Request{Op: OpCollaboratorPermission, Asset: t.Repo.Asset, Stage: stage,
		Params: map[string]string{"owner": t.Repo.Owner, "repo": t.Repo.Name, "username": t.Login}})
	pr := PermissionRead{Asset: t.Repo.Asset, Login: strings.ToLower(t.Login), Read: readOf(OpCollaboratorPermission, r)}
	if usable(r) {
		var a PermissionAnswer
		if json.Unmarshal(r.Response.Body, &a) == nil && a.Permission != nil {
			pr.Answer = &a
		} else {
			pr.Read.Gap = "unrecognized_permission"
		}
	}
	return pr
}

// PermissionNotAsked is the entry of a pair the engagement opened and did
// not ask: the cap, or a limit that stopped the run first.
func PermissionNotAsked(t PermissionTarget, reason, detail string) PermissionRead {
	return PermissionRead{Asset: t.Repo.Asset, Login: strings.ToLower(t.Login),
		Read: Read{Op: OpCollaboratorPermission, Decision: "not_sent", Reason: reason, Detail: detail}}
}

// PermissionNotSent says a pair was never asked: the loop cut it, or the
// gate stopped it for a limit before any send line, which reaches GitHub.
// A request sent and then cut (the deadline in flight) was asked.
func PermissionNotSent(r Read) bool {
	return r.Decision == "not_sent" || r.Reason == ReasonLimitReached && !r.Sent && !r.Reused && r.Status == 0
}

// permissionFor is the entry for login on asset, if one was opened.
func (e Evidence) permissionFor(asset, login string) (PermissionRead, bool) {
	i := slices.IndexFunc(e.Permissions, func(p PermissionRead) bool { return p.Asset == asset && strings.EqualFold(p.Login, login) })
	if i < 0 {
		return PermissionRead{}, false
	}
	return e.Permissions[i], true
}

// PermissionReads are the follow-up's reads that went to the gate.
func (e Evidence) PermissionReads() []Read {
	var out []Read
	for _, p := range e.Permissions {
		if p.Read.RequestID != "" {
			out = append(out, p.Read)
		}
	}
	return out
}

// access is what an answer establishes on one repository.
type access int

const (
	accessUnknown access = iota
	accessNone
	accessWrite
)

// grant is one answer interpreted: write, known not write, or
// unknown with the cause R4 words.
type grant struct {
	access access
	admin  bool
	// read is read access on a private or internal repository: enough to
	// fire the leaver finding, never write.
	read bool
	// none is GitHub's own "none".
	none    bool
	cause   string
	excerpt string
	account Account
}

// interpretPermission reads one entry (docs/spec/github-collector.md,
// "Selection under a budget and the permission follow-up (E9)"). A 404 says
// the login names no account now, never that it holds no access.
func interpretPermission(pr PermissionRead, repo RepositoryAccess, e Evidence) grant {
	name, login := repositoryName(repo), pr.Login
	r := pr.Read
	unknown := grant{cause: "the permissions returned for " + login + " on " + name + " were missing or contradictory"}
	switch {
	case r.Decision == "not_sent" && r.Reason == ReasonFollowUpCap:
		return grant{cause: login + "'s permission on " + name + " was not asked: scheck sends GitHub at most 20 permission requests per run"}
	case PermissionNotSent(r) && r.Reason == ReasonLimitReached:
		return grant{cause: login + "'s permission on " + name + " was not asked: the run stopped first (" + stopPhrase(r) + ")"}
	case r.Reason == ReasonLimitReached:
		return grant{cause: login + "'s permission on " + name + " could not be read: " + stopPhrase(r)}
	case strings.HasPrefix(r.Reason, "insufficient_permission") || r.Status == 401 || r.Status == 403:
		return grant{cause: "the credential was not allowed to read " + login + "'s permission on " + name}
	case r.Status == 404 && r.Reason == "":
		return grant{cause: "GitHub has no account named " + login + " now (it may have been renamed or deleted), so its access to " + name + " could not be read"}
	case !usableRead(r) && r.Gap != "unrecognized_permission":
		return grant{cause: login + "'s permission on " + name + " could not be read: " + readPhrase(r)}
	case pr.Answer == nil || pr.Answer.Permission == nil:
		return unknown
	}
	a := pr.Answer
	marked := func(s *string) bool {
		return s != nil && (strings.Contains(*s, "[REDACTED:") || strings.Contains(*s, "[TRUNCATED:"))
	}
	if marked(a.Permission) || marked(a.RoleName) || a.User != nil && marked(a.User.RoleName) {
		return unknown
	}
	account := Account{Login: login}
	if u := a.User; u != nil {
		if !strings.EqualFold(u.Login, login) || u.Type != "User" || !accountOK(u.Account) {
			return unknown
		}
		if u.RoleName != nil && a.RoleName != nil && *u.RoleName != *a.RoleName {
			return unknown
		}
		// A login re-registered by someone else is not the account this
		// run saw.
		for _, pop := range []Population[Account]{e.Members, e.Owners, e.OutsideCollaborators} {
			for _, seen := range pop.Items {
				if strings.EqualFold(seen.Login, login) && seen.ID != u.ID {
					return grant{cause: "the account now named " + login + " is not the one this run saw in " + strings.TrimPrefix(e.orgName(), "saas:github:")}
				}
			}
		}
		account = u.Account
		account.Login = strings.ToLower(u.Login)
	}
	role := a.RoleName
	if role != nil && (*role == "" || *role == "none") {
		role = nil
	}
	c := Collaborator{Account: account, RoleName: role}
	if a.User != nil {
		c.Permissions = a.User.Permissions
	}
	level := *a.Permission
	levelWrite := level == "admin" || level == "write"
	levelNot := level == "read" || level == "none"
	if !levelWrite && !levelNot {
		return unknown
	}
	in := func(v *string, set ...string) bool { return v != nil && slices.Contains(set, *v) }
	out := grant{account: account, excerpt: "permission: " + level + "; " + permissionExcerpt(c)}
	if c.Permissions != nil {
		write, known := EffectiveWrite(c)
		switch {
		case known && write && levelWrite:
			out.access = accessWrite
		case known && !write && levelNot:
			out.access = accessNone
		default:
			return unknown
		}
	} else {
		switch {
		case levelWrite && !in(role, "read", "pull", "triage"):
			out.access = accessWrite
		case levelNot && !in(role, "write", "push", "maintain", "admin"):
			out.access = accessNone
		default:
			return unknown
		}
	}
	if admin, known := EffectiveAdmin(c); known && admin && level == "admin" {
		out.admin = true
	}
	if out.access == accessWrite && archived(repo) && !out.admin {
		return grant{cause: name + " is archived", account: account}
	}
	out.none = level == "none"
	if level == "read" && (c.Permissions == nil || c.Permissions.Pull == nil || *c.Permissions.Pull) && privateRepository(repo) {
		out.read = true
	}
	return out
}

// privateRepository is a recognized private or internal repository: on a
// public one GitHub answers read for anyone.
func privateRepository(r RepositoryAccess) bool {
	return r.Repository != nil && r.Repository.Visibility != nil && (*r.Repository.Visibility == "private" || *r.Repository.Visibility == "internal")
}

func (e Evidence) orgName() string {
	if e.Organization != nil && e.Organization.Login != "" {
		return e.Organization.Login
	}
	return "the organization"
}

// readPhrase says why one read did not answer.
func readPhrase(r Read) string {
	switch {
	case r.Truncated:
		return "the answer was cut short"
	case len(r.Redactions) > 0:
		return "part of the answer was redacted"
	case r.Reason != "":
		return strings.ReplaceAll(strings.TrimPrefix(r.Reason, "unavailable:"), "_", " ")
	case strings.HasPrefix(r.Decision, "unavailable:"):
		return strings.ReplaceAll(strings.TrimPrefix(r.Decision, "unavailable:"), "_", " ")
	case r.Gap != "":
		return InventoryGapText([]string{r.Gap})
	case r.Status != 0 && r.Status != 200:
		return fmt.Sprintf("GitHub answered %d", r.Status)
	}
	return "the read did not succeed"
}

func stopPhrase(r Read) string {
	if r.Detail != "" {
		return r.Detail
	}
	return "a limit was reached"
}

// collaboratorState is what the collaborators list says of login on repo.
type collaboratorState int

const (
	listWrite collaboratorState = iota + 1
	listNotWrite
	listArchived
	listNotListed
	listUnknown
	listUnread
	listDenied
)

func listState(repo RepositoryAccess, login string) collaboratorState {
	idx := slices.IndexFunc(repo.Collaborators.Items, func(c Collaborator) bool { return strings.EqualFold(c.Login, login) })
	if idx < 0 {
		switch {
		case slices.ContainsFunc(repo.Collaborators.Reads, func(r Read) bool { return strings.HasPrefix(r.Reason, "insufficient_permission") }):
			return listDenied
		case len(repo.Collaborators.Reads) == 0 || slices.ContainsFunc(repo.Collaborators.Reads, func(r Read) bool { return !usableRead(r) }):
			return listUnread
		}
		return listNotListed
	}
	c := repo.Collaborators.Items[idx]
	write, known := EffectiveWrite(c)
	admin, adminKnown := EffectiveAdmin(c)
	switch {
	case !known:
		return listUnknown
	case write && archived(repo) && (!adminKnown || !admin):
		return listArchived
	case write:
		return listWrite
	}
	return listNotWrite
}

// PermissionTrigger is the leaver judgment that opened a pair, as
// check.json records why a read was sent.
type PermissionTrigger struct {
	ID      string `json:"id"`
	Asset   string `json:"asset"`
	Subject string `json:"subject"`
	Person  string `json:"person"`
	Verdict string `json:"verdict"`
}

// PermissionLogin is one left login's open pairs, in Plan's repository
// order, with what orders it against the others.
type PermissionLogin struct {
	Login, Handle, Left string
	Fired               bool
	Trigger             PermissionTrigger
	Open                []PermissionTarget
}

// PermissionOpen lists the pairs F1 would ask now, per left login, from
// the leaver judgments over e and the engagement's production
// repositories (docs/spec/engagement.md, "Plan selection and follow-ups").
// A pair already in e.Permissions is never open again: the follow-up does
// not reopen what it asked. A fired login opens a production repository
// the list did not settle, until one is write_held; a login seen nowhere,
// abstained for lack of repository visibility, opens every production
// repository whose collaborators read was not denied.
func PermissionOpen(judged []Judgment, e Evidence, c Context, production []string) []PermissionLogin {
	var out []PermissionLogin
	for _, p := range c.People {
		if p.Left == "" {
			continue
		}
		for _, login := range p.GitHub {
			// An app's login is no collaborator: the read takes a user's.
			if !loginRE.MatchString(login) {
				continue
			}
			key := strings.ToLower(login)
			var fired, none *Judgment
			held := false
			for i := range judged {
				j := &judged[i]
				if j.ID != finding.IDIdentityFormerPersonHasAccess || j.Subject.Key != key {
					continue
				}
				if j.Verdict == Fired && fired == nil {
					fired = j
				}
				if j.Verdict == Fired && slices.ContainsFunc(j.Attributes, func(a finding.Attribute) bool {
					return a.Name == "write_held" && slices.Contains(production, a.Asset)
				}) {
					held = true
				}
				if j.Verdict == Abstained && j.Reason == "insufficient_evidence" && j.Details["membership"] == "none" {
					none = j
				}
			}
			pl := PermissionLogin{Login: key, Handle: p.Handle, Left: p.Left}
			switch {
			case fired != nil:
				if held || containsAccount(e.Owners.Items, login) {
					continue
				}
				pl.Fired, pl.Trigger = true, trigger(*fired, p.Handle)
			case none != nil:
				// An unread population also leaves the reason standing:
				// only a leaving date passed at every read opens a pair.
				population := [][]Read{e.Members.Reads, e.Owners.Reads, e.OutsideCollaborators.Reads, e.Invitations.Reads}
				for _, repo := range e.RepositoriesAccess {
					population = append(population, repo.Collaborators.Reads)
				}
				if leftAt(p.Left, c, population...) != finding.LeftPassed {
					continue
				}
				pl.Trigger = trigger(*none, p.Handle)
			default:
				continue
			}
			for _, repo := range e.RepositoriesAccess {
				if !slices.Contains(production, repo.Asset) || repo.Repository == nil {
					continue
				}
				if _, asked := e.permissionFor(repo.Asset, key); asked {
					continue
				}
				st := listState(repo, login)
				if st == listDenied || pl.Fired && st != listNotListed && st != listUnknown && st != listUnread {
					continue
				}
				pl.Open = append(pl.Open, PermissionTarget{Repo: RepositoryTarget{Asset: repo.Asset, Owner: repo.Repository.Owner.Login, Name: repo.Repository.Name}, Login: key})
			}
			if len(pl.Open) > 0 {
				out = append(out, pl)
			}
		}
	}
	return out
}

func trigger(j Judgment, handle string) PermissionTrigger {
	return PermissionTrigger{ID: j.ID, Asset: j.Asset, Subject: j.Subject.Key, Person: handle, Verdict: j.Verdict}
}
