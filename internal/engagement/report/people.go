package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b87/scheck/internal/finding"
)

// PersonLeft is one person with a declared leaving date and what each
// tenant shows of them (docs/spec/report.md, "People who left"). It
// restates verdicts already made and decides nothing.
type PersonLeft struct {
	Handle  string         `json:"handle"`
	Left    string         `json:"left"`
	Tenants []PersonTenant `json:"tenants"`
}

// PersonTenant is one tenant's line for a person: its asset (null when no
// tenant of that provider is in scope), its state, and the line printed.
type PersonTenant struct {
	Asset    *string         `json:"asset"`
	Provider string          `json:"provider"`
	State    string          `json:"state"`
	Reason   string          `json:"reason,omitempty"`
	Line     string          `json:"line"`
	Accounts []PersonAccount `json:"accounts"`
}

// PersonAccount is one declared or attributed account of the person in a
// tenant.
type PersonAccount struct {
	Key             string           `json:"key"`
	State           string           `json:"state"`
	FindingKeys     []Key            `json:"finding_keys"`
	ProductionWrite *ProductionWrite `json:"production_write,omitempty"`
}

// ProductionWrite is R4 on a login: applied, with the repositories, or
// said and not established.
type ProductionWrite struct {
	Applied      bool     `json:"applied"`
	Repositories []string `json:"repositories"`
}

// The states of a person's line, worst first: a tenant takes the worst of
// its accounts'.
var personStates = []string{"finding", "accepted", "not_proven", "not_checked", "not_judged", "no_login_declared", "not_in_scope", "no_access_observed"}

// leaverIDs are the findings a person line reads.
var leaverIDs = []string{finding.IDIdentityFormerPersonHasAccess, finding.IDIdentityFormerPersonInvited}

// tenant is a Workspace or GitHub tenant in scope.
type tenant struct {
	asset    AssetInput
	provider string
	name     string
}

func providerOf(id string) string {
	switch {
	case strings.HasPrefix(id, "saas:github:"):
		return "github"
	case strings.HasPrefix(id, "saas:google-workspace:"):
		return "workspace"
	}
	return ""
}

var providerWord = map[string]string{"workspace": "Workspace", "github": "GitHub"}

// tenants are the Workspace and GitHub tenants in coverage-table asset
// order, each named "Workspace" or "GitHub" when it is the only one of its
// provider, else with its name.
func (b *builder) tenants() []tenant {
	var out []tenant
	count := map[string]int{}
	for _, a := range b.in.Assets {
		if p := providerOf(a.ID); p != "" && a.Kind == "saas" {
			out = append(out, tenant{asset: a, provider: p})
			count[p]++
		}
	}
	for i := range out {
		out[i].name = providerWord[out[i].provider]
		if count[out[i].provider] > 1 {
			out[i].name += " " + out[i].asset.Name
		}
	}
	return out
}

// tenantOf is the tenant a judgment on asset a belongs to: a repository's
// organization, else the asset itself.
func tenantOf(a AssetInput) string {
	if a.Kind == "repo" && a.ReadWith != "" {
		return a.ReadWith
	}
	return a.ID
}

// personJudgment is a leaver judgment with the asset it was found under.
type personJudgment struct {
	j      Judgment
	tenant string
	owner  string
}

func (b *builder) personJudgments(handle string) []personJudgment {
	var out []personJudgment
	for _, a := range b.in.Assets {
		for _, j := range a.Judged {
			if slices.Contains(leaverIDs, j.ID) && j.Subject.Person == handle {
				out = append(out, personJudgment{j: j, tenant: tenantOf(a), owner: b.ownerOf(a, j).ID})
			}
		}
	}
	return out
}

// findingOf is the finding a fired judgment became.
func (b *builder) findingOf(pj personJudgment) *Finding {
	for i := range b.r.Findings {
		f := &b.r.Findings[i]
		if f.Key.ID == pj.j.ID && f.Key.Asset == pj.owner && deref(f.Key.Subject) == pj.j.Subject.Key {
			return f
		}
	}
	return nil
}

// asOf is the date of the earliest read a judgment cites.
func (b *builder) asOf(j Judgment) string {
	var at time.Time
	for _, r := range j.Reads {
		if meta, ok := b.in.Observations[r]; ok && !meta.CollectedAt.IsZero() && (at.IsZero() || meta.CollectedAt.Before(at)) {
			at = meta.CollectedAt
		}
	}
	if at.IsZero() {
		at = b.in.Started
	}
	return b.day(at)
}

// peopleLeft is every person with a declared leaving date and one line per
// tenant: every tenant in scope, and a provider the person declares an
// account at with no tenant in scope.
func (b *builder) peopleLeft() []PersonLeft {
	out := []PersonLeft{}
	tenants := b.tenants()
	for _, d := range b.in.Departed {
		p := PersonLeft{Handle: d.Handle, Left: d.Left, Tenants: []PersonTenant{}}
		js := b.personJudgments(d.Handle)
		for _, t := range tenants {
			var mine []personJudgment
			for _, pj := range js {
				if pj.tenant == t.asset.ID {
					mine = append(mine, pj)
				}
			}
			p.Tenants = append(p.Tenants, b.tenantLine(t, d, mine))
		}
		for _, provider := range d.Providers {
			if !slices.ContainsFunc(tenants, func(t tenant) bool { return t.provider == provider }) {
				p.Tenants = append(p.Tenants, PersonTenant{Provider: provider, State: "not_in_scope", Accounts: []PersonAccount{},
					Line: providerWord[provider] + ": not in this engagement's scope, not checked."})
			}
		}
		out = append(out, p)
	}
	return out
}

// worst is the first of the states in personStates order.
func worst(states ...string) string {
	best := len(personStates)
	for _, s := range states {
		if i := slices.Index(personStates, s); i >= 0 && i < best {
			best = i
		}
	}
	if best == len(personStates) {
		return "not_checked"
	}
	return personStates[best]
}

// state words a fired finding's status: open, or accepted until its date.
func stateOf(fs []*Finding) (string, string) {
	open := slices.ContainsFunc(fs, func(f *Finding) bool { return f == nil || f.Status != finding.StatusAccepted })
	if open || len(fs) == 0 {
		return "finding", "(finding)"
	}
	if e := fs[0].Acceptance; e != nil && e.Expires != nil {
		return "accepted", "(accepted until " + *e.Expires + ")"
	}
	return "accepted", "(accepted)"
}

// timeReason words an abstention for a leaving date the reads could not
// place, "" for any other reason.
func timeReason(j Judgment, left, date string) string {
	switch j.Reason {
	case "leaving_date_not_passed":
		return "leaving date had not passed at the read of " + date + ", not judged"
	case finding.ReasonLeftDuringCollection:
		return "leaving date falls within collection, not judged; re-run after " + left
	case finding.ReasonNoCollectionTime:
		return "collection time not recorded, not judged"
	}
	return ""
}

func (b *builder) reasonPhrase(reason string) string {
	if reason == "" {
		return "no reason was recorded"
	}
	return (&text{r: b.r}).reasonText(ReasonDetail{Reason: reason})
}

func (b *builder) tenantLine(t tenant, d Departure, js []personJudgment) PersonTenant {
	id := t.asset.ID
	out := PersonTenant{Asset: &id, Provider: t.provider, Accounts: []PersonAccount{}}
	if len(js) == 0 {
		out.State, out.Reason = "not_checked", t.asset.Reason
		what := "users"
		if t.provider == "github" {
			what = "the organization"
		}
		if t.asset.Status == statusCollected || t.asset.Status == statusIncomplete {
			out.Line = t.name + ": nothing was judged for this person, not checked."
		} else {
			out.Line = t.name + ": " + what + " could not be read (" + b.reasonPhrase(t.asset.Reason) + "), not checked."
		}
		return out
	}
	// Accounts in the order the collector judged them.
	var keys []string
	byKey := map[string][]personJudgment{}
	for _, pj := range js {
		k := pj.j.Subject.Key
		if pj.j.ID == finding.IDIdentityFormerPersonInvited {
			// An invitation is named "login (invitation:N)".
			k, _, _ = strings.Cut(pj.j.Subject.Label, " (")
			k = strings.ToLower(k)
		}
		if _, ok := byKey[k]; !ok {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], pj)
	}
	var parts, states []string
	for _, k := range keys {
		var acct PersonAccount
		var part string
		if t.provider == "github" {
			acct, part = b.githubAccount(k, d, byKey[k])
		} else {
			acct, part = b.workspaceAccount(t, k, d, byKey[k])
		}
		if acct.State == "not_checked" && out.Reason == "" {
			out.Reason = byKey[k][0].j.Reason
		}
		out.Accounts = append(out.Accounts, acct)
		states = append(states, acct.State)
		if !slices.Contains(parts, part) {
			parts = append(parts, part)
		}
	}
	out.State = worst(states...)
	out.Line = t.name + ": " + strings.Join(parts, "; ") + "."
	return out
}

func (b *builder) workspaceAccount(t tenant, key string, d Departure, js []personJudgment) (PersonAccount, string) {
	acct := PersonAccount{Key: key, FindingKeys: []Key{}}
	var fired []*Finding
	admin := false
	for _, pj := range js {
		if reported(pj.j) {
			f := b.findingOf(pj)
			fired = append(fired, f)
			admin = admin || pj.j.Has("admin")
			if f != nil {
				acct.FindingKeys = append(acct.FindingKeys, f.Key)
			}
		}
	}
	addr := key
	if len(fired) > 0 {
		state, mark := stateOf(fired)
		acct.State = state
		if admin && state == "finding" {
			return acct, addr + " still active, with administrator rights " + mark
		}
		return acct, addr + " still active " + mark
	}
	j := js[0].j
	for _, pj := range js {
		if pj.j.Verdict == verdictDisproved {
			acct.State = "no_access_observed"
			return acct, addr + " no access observed as of " + b.asOf(pj.j)
		}
	}
	if strings.HasPrefix(key, "declared:") {
		acct.State = "not_checked"
		return acct, "no address declared, not checked"
	}
	if why := timeReason(j, d.Left, b.asOf(j)); why != "" {
		acct.State = "not_judged"
		return acct, addr + " " + why
	}
	acct.State = "not_checked"
	switch {
	case slices.Contains(j.NotChecked, finding.NotCheckedLeaverIdentity):
		return acct, addr + " account identity missing or ambiguous, not checked"
	case slices.Contains(j.NotChecked, finding.NotCheckedUsersUnread):
		// The read's own reason, when the asset records one.
		return acct, "users could not be read (" + b.reasonPhrase(cmp.Or(t.asset.Reason, j.Reason)) + "), not checked"
	case slices.Contains(j.NotChecked, finding.NotCheckedUsersIncomplete):
		acct.State = "not_proven"
		return acct, addr + " not seen as of " + b.asOf(j) + "; the users list was incomplete, so no access is not proven"
	case j.Subject.ProviderID == "":
		// No account was read for it: never say one was observed.
		return acct, addr + " could not be checked (" + b.reasonPhrase(j.Reason) + ")"
	}
	return acct, addr + " account observed, but its status or access evidence was not recognized, not checked"
}

var membershipWord = map[string]string{"owner": "owner", "member": "member", "outside_collaborator": "outside collaborator"}

func (b *builder) githubAccount(login string, d Departure, js []personJudgment) (PersonAccount, string) {
	acct := PersonAccount{Key: login, FindingKeys: []Key{}}
	if len(js) == 1 && js[0].j.Reason == "no_declared_github_login" {
		acct.State = "no_login_declared"
		return acct, "no login declared, not checked"
	}
	var parts, states []string
	var org, repos, pushed, invites []*Finding
	var pushRepos []string
	membership, established := "", true
	for _, pj := range js {
		if !reported(pj.j) {
			continue
		}
		f := b.findingOf(pj)
		if f != nil {
			acct.FindingKeys = append(acct.FindingKeys, f.Key)
		}
		for _, m := range chainMoves(pj.j) {
			if m.Rule == "attribute:production_write" && m.Stopped == finding.StoppedNotEstablished {
				established = false
			}
		}
		switch {
		case pj.j.ID == finding.IDIdentityFormerPersonInvited:
			invites = append(invites, f)
		case productionWriteApplied(pj.j):
			pushed = append(pushed, f)
			pushRepos = append(pushRepos, strings.TrimPrefix(pj.owner, "repo:github:"))
		case pj.j.Details["membership"] == "collaborator":
			repos = append(repos, f)
		default:
			org = append(org, f)
			if m, ok := pj.j.Details["membership"].(string); ok {
				membership = m
			}
		}
	}
	add := func(fs []*Finding, text string) {
		if len(fs) > 0 {
			state, mark := stateOf(fs)
			states = append(states, state)
			parts = append(parts, text+" "+mark)
		}
	}
	add(org, login+" still has access as "+cmp.Or(membershipWord[membership], "member"))
	if len(pushed) > 0 {
		slices.Sort(pushRepos)
		more := ""
		if len(pushRepos) > 1 {
			more = fmt.Sprintf(" and %d more", len(pushRepos)-1)
		}
		add(pushed, login+" can still push to "+pushRepos[0]+", declared production"+more)
		acct.ProductionWrite = &ProductionWrite{Applied: true, Repositories: pushRepos}
	}
	add(repos, fmt.Sprintf("%s is a collaborator on %d %s", login, len(repos), plural(len(repos), "repository")))
	if !established {
		parts = append(parts, "write access to production repositories was not established")
		acct.ProductionWrite = &ProductionWrite{Applied: false, Repositories: []string{}}
	}
	add(invites, "pending invitation for "+login)
	if len(parts) > 0 {
		acct.State = worst(states...)
		return acct, strings.Join(parts, "; ")
	}
	var j Judgment
	for _, pj := range js {
		if pj.j.ID == finding.IDIdentityFormerPersonHasAccess {
			j = pj.j
			if j.Verdict == verdictDisproved {
				acct.State = "no_access_observed"
				return acct, login + " no access observed as of " + b.asOf(j)
			}
		}
	}
	if why := timeReason(j, d.Left, b.asOf(j)); why != "" {
		acct.State = "not_judged"
		return acct, login + " " + why
	}
	if j.Details["membership"] == "none" {
		acct.State = "not_proven"
		return acct, login + " not seen as of " + b.asOf(j) + "; access to repositories cannot be fully listed, so no access is not proven"
	}
	acct.State = "not_checked"
	return acct, login + " could not be checked (" + b.reasonPhrase(j.Reason) + ")"
}

// productionWriteApplied says R4 moved, or would have moved but for the
// scale's end, this judgment.
func productionWriteApplied(j Judgment) bool {
	if j.Chain == nil {
		return false
	}
	return slices.ContainsFunc(j.Chain.Moves, func(m finding.Move) bool {
		return m.Rule == "attribute:production_write" && (m.Stopped == "" || m.Stopped == finding.StoppedScaleEnd)
	})
}

func chainMoves(j Judgment) []finding.Move {
	if j.Chain == nil {
		return nil
	}
	return j.Chain.Moves
}

// rankGroup is one item of "Fix these first" while it is being ranked.
type rankGroup struct {
	item  Item
	rank  int
	area  int
	dmm   string // the first asset data.matters_most names
	count int
	// people are the distinct people (or accounts) its instances are
	// about; top is the instance that set its severity.
	people map[string]bool
	top    Finding
}

func (g *rankGroup) add(f Finding, dmm []string) {
	if r := finding.Severity(f.Severity).Rank(); r > g.rank {
		g.rank, g.item.Severity, g.top = r, f.Severity, f
	}
	g.item.Keys = append(g.item.Keys, f.Key)
	g.item.Assets = appendUnique(g.item.Assets, f.Key.Asset)
	g.count++
	if g.people == nil {
		g.people = map[string]bool{}
	}
	if f.Subject != nil {
		g.people[cmp.Or(f.Subject.Person, f.Subject.Key)] = true
	}
	if g.dmm == "" && slices.Contains(dmm, f.Key.Asset) {
		g.dmm = f.Key.Asset
	}
}

// findingTenant is the tenant a finding's asset belongs to: a repository's
// organization, whether the engagement declares the repository or not.
func (b *builder) findingTenant(asset string) string {
	for _, a := range b.in.Assets {
		if a.ID == asset {
			return tenantOf(a)
		}
	}
	if key, ok := strings.CutPrefix(asset, "repo:github:"); ok {
		owner, _, _ := strings.Cut(key, "/")
		return "saas:github:" + owner
	}
	return asset
}

// The ranking's person items at most.
const maxPersonItems = 2

// personGroups are the person items of "Fix these first": a person who
// left whose open findings span two or more tenants or two or more ids,
// the highest-ranked two, and which of open they take. Tied are the leaver
// findings and any other open identity finding on an account where the
// person's access finding fired in the same tenant: removing the account
// fixes it (docs/spec/report.md, "A person item").
func (b *builder) personGroups(open []Finding) ([]*rankGroup, map[int]bool) {
	left := map[string]string{}
	for _, d := range b.in.Departed {
		left[d.Handle] = d.Left
	}
	// The accounts a person's access finding fired on, by tenant.
	fired := map[string]bool{}
	for _, f := range b.r.Findings {
		if f.ID == finding.IDIdentityFormerPersonHasAccess && f.Subject != nil && f.Subject.Person != "" {
			fired[f.Subject.Person+"\x00"+b.findingTenant(f.Key.Asset)+"\x00"+f.Subject.Key] = true
		}
	}
	tied := map[string][]int{}
	var handles []string
	for i, f := range open {
		if f.Subject == nil {
			continue
		}
		h := f.Subject.Person
		if _, ok := left[h]; !ok {
			continue
		}
		if slices.Contains(leaverIDs, f.ID) || f.Area == string(finding.AreaIdentity) && fired[h+"\x00"+b.findingTenant(f.Key.Asset)+"\x00"+f.Subject.Key] {
			if _, ok := tied[h]; !ok {
				handles = append(handles, h)
			}
			tied[h] = append(tied[h], i)
		}
	}
	tenants := b.tenants()
	var groups []*rankGroup
	for _, h := range handles {
		tenantSet, ids := map[string]bool{}, map[string]bool{}
		for _, i := range tied[h] {
			tenantSet[b.findingTenant(open[i].Key.Asset)] = true
			ids[open[i].ID] = true
		}
		if len(tenantSet) < 2 && len(ids) < 2 {
			continue
		}
		handle := h
		g := &rankGroup{item: Item{Kind: "person", IDs: []string{}, Person: &handle, Keys: []Key{}, Assets: []string{}}, rank: -1,
			area: slices.Index(finding.Areas, finding.AreaIdentity)}
		for _, i := range tied[h] {
			g.add(open[i], b.in.DataMattersMost)
			g.item.IDs = appendUnique(g.item.IDs, open[i].ID)
		}
		g.count = len(tied[h])
		// The instance that set the severity leads, so its raise is the one
		// the item prints.
		top := slices.IndexFunc(g.item.Keys, func(k Key) bool {
			return k.ID == g.top.Key.ID && k.Asset == g.top.Key.Asset && deref(k.Subject) == deref(g.top.Key.Subject)
		})
		g.item.Keys[0], g.item.Keys[top] = g.item.Keys[top], g.item.Keys[0]
		g.item.Title = personTitle(h, left[h], tenants, b, open, tied[h])
		groups = append(groups, g)
	}
	slices.SortStableFunc(groups, func(x, y *rankGroup) int {
		return cmp.Or(cmp.Compare(y.rank, x.rank), boolFirst(x.dmm != "", y.dmm != ""), cmp.Compare(y.count, x.count), cmp.Compare(*x.item.Person, *y.item.Person))
	})
	if len(groups) > maxPersonItems {
		groups = groups[:maxPersonItems]
	}
	taken := map[int]bool{}
	for _, g := range groups {
		for _, i := range tied[*g.item.Person] {
			taken[i] = true
		}
	}
	return groups, taken
}

// personTitle is "handle, who left on date, " and the phrases of the
// person's open leaver findings in tenant order, a verb's tenants merged.
func personTitle(handle, left string, tenants []tenant, b *builder, open []Finding, idx []int) string {
	type phrase struct{ verb, tenant string }
	var phrases []phrase
	for _, t := range tenants {
		for _, i := range idx {
			f := open[i]
			if b.findingTenant(f.Key.Asset) != t.asset.ID {
				continue
			}
			var verb string
			switch {
			case f.ID == finding.IDIdentityFormerPersonInvited:
				verb = "has a pending invitation to"
			case f.ID == finding.IDIdentityFormerPersonHasAccess && t.provider == "workspace":
				verb = "is still active in"
			case f.ID == finding.IDIdentityFormerPersonHasAccess:
				verb = "still has access to"
			default:
				continue
			}
			if p := (phrase{verb, t.name}); !slices.Contains(phrases, p) {
				phrases = append(phrases, p)
			}
		}
	}
	var verbs []string
	byVerb := map[string][]string{}
	for _, p := range phrases {
		if _, ok := byVerb[p.verb]; !ok {
			verbs = append(verbs, p.verb)
		}
		byVerb[p.verb] = append(byVerb[p.verb], p.tenant)
	}
	var groups []string
	for _, v := range verbs {
		ts := byVerb[v]
		names := ts[0]
		if len(ts) > 1 {
			names = strings.Join(ts[:len(ts)-1], ", ") + " and " + ts[len(ts)-1]
		}
		groups = append(groups, v+" "+names)
	}
	what := "has open findings on accounts held before leaving"
	switch n := len(groups); {
	case n == 1:
		what = groups[0]
	case n > 1:
		what = strings.Join(groups[:n-1], ", ") + ", and " + groups[n-1]
	}
	return handle + ", who left on " + left + ", " + what
}
