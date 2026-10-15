package github

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// Selection under a budget: Plan orders an organization's repositories in
// the tier table below, Check reads them breadth first by kind under a
// compiled request budget (docs/spec/engagement.md, "Plan selection and
// follow-ups"; docs/spec/github-collector.md, "Selection under a budget and
// the permission follow-up (E9)").

// TiersVersion versions the tier table and the kind order; changing either
// changes which repositories a cut leaves read.
const TiersVersion = "github-tiers:2026-10-15"

// RepositoryBudget is the compiled request budget per organization per run
// for the per-repository reads Check sends. It is not a setting.
const RepositoryBudget = 4000

type tierDef struct{ basis, source string }

// tiers is the repository tier table, 1 to 8; the lowest tier wins.
var tiers = [...]tierDef{
	1: {"deploys_to production", "assets.*.deploys_to"},
	2: {"declared secret store", "secrets.production"},
	3: {"public", "observed"},
	4: {"data that matters most", "data.matters_most"},
	5: {"deploys_to staging", "assets.*.deploys_to"},
	6: {"declared repository asset", "assets"},
	7: {"most recently pushed", ""},
	8: {"archived", ""},
}

// Declared is a declaration naming an asset by canonical id, with the key
// it came from (`secrets.production[0]`, `data.matters_most[1]`).
type Declared struct{ Asset, Key string }

// Selected is one repository in Plan's order.
type Selected struct {
	Target   RepositoryTarget `json:"-"`
	Asset    string           `json:"asset"`
	FullName string           `json:"full_name"`
	Tier     int              `json:"tier"`
	Basis    string           `json:"basis"`
	// Source is the declaration or observation that put it in its tier.
	Source   string `json:"source,omitempty"`
	PushedAt string `json:"pushed_at,omitempty"`
	Declared bool   `json:"declared,omitempty"`
	Public   bool   `json:"public,omitempty"`
	Archived bool   `json:"archived,omitempty"`
	Mirror   bool   `json:"mirror,omitempty"`
}

// Selection is Plan's order of one GitHub root's repositories.
type Selection struct {
	Asset   string `json:"asset"`
	Version string `json:"tiers_version"`
	// Budget is the request budget, zero for a repository root, which is
	// read in full.
	Budget  int `json:"budget"`
	InScope int `json:"in_scope"`
	// InScopeAtLeast is true when the inventory's repository list was not
	// complete: more repositories may be in scope than were listed.
	InScopeAtLeast bool       `json:"in_scope_at_least,omitempty"`
	Order          []Selected `json:"order"`
	// Notes are Plan's sentences about a declaration that ordered nothing.
	Notes []string `json:"notes,omitempty"`
}

// Select orders the repositories the inventory listed and the repositories
// declared under the root by the tier table. It reads only what Recon read
// and what c declares; it sends nothing.
func Select(e Evidence, c Context, declared []RepositoryTarget, checkouts map[string]string) Selection {
	s := Selection{Asset: c.OrganizationAsset, Version: TiersVersion}
	if strings.HasPrefix(c.OrganizationAsset, "saas:github:") {
		s.Budget = RepositoryBudget
	}
	contexts := map[string]RepositoryContext{}
	for id, rc := range c.RepositoryContexts {
		contexts[strings.ToLower(id)] = rc
	}
	selectedBySecret, orderedBySecret := secretSelected(e, c)
	byKey := map[string]int{}
	add := func(target RepositoryTarget, repo *Repository, isDeclared bool) {
		key := strings.ToLower(target.Owner + "/" + target.Name)
		if i, ok := byKey[key]; ok {
			s.Order[i].Declared = s.Order[i].Declared || isDeclared
			return
		}
		item := Selected{Target: target, Asset: "repo:github:" + key, FullName: key, Declared: isDeclared}
		if repo != nil {
			item.Public = repo.Visibility != nil && *repo.Visibility == "public"
			item.Archived = repo.Archived != nil && *repo.Archived
			if repo.PushedAt != nil {
				if t, err := time.Parse(time.RFC3339, *repo.PushedAt); err == nil {
					item.PushedAt = t.UTC().Format(time.RFC3339)
				}
			}
		}
		item.Mirror = checkouts[item.Asset] != "" || checkouts[target.Asset] != ""
		rc, hasContext := contexts[item.Asset]
		matters := declaredKey(c.MattersMost, item.Asset)
		store := declaredKey(c.SecretStores, item.Asset)
		if store == "" {
			store = selectedBySecret[key]
		}
		switch {
		case hasContext && rc.DeploysTo == "production":
			item.Tier, item.Source = 1, rc.Source+".deploys_to"
		case store != "":
			item.Tier, item.Source = 2, store
		case item.Public:
			item.Tier, item.Source = 3, "observed"
		case matters != "":
			item.Tier, item.Source = 4, matters
		case hasContext && rc.DeploysTo == "staging":
			item.Tier, item.Source = 5, rc.Source+".deploys_to"
		case item.Declared:
			item.Tier, item.Source = 6, rc.Source
			if item.Source == "" {
				item.Source = "assets"
			}
		case item.Archived:
			item.Tier = 8
		default:
			item.Tier = 7
		}
		item.Basis = tiers[item.Tier].basis
		byKey[key] = len(s.Order)
		s.Order = append(s.Order, item)
	}
	for i := range e.Repositories.Items {
		repo := &e.Repositories.Items[i]
		owner, name, _ := strings.Cut(strings.ToLower(repo.FullName), "/")
		add(RepositoryTarget{Asset: "repo:github:" + strings.ToLower(repo.FullName), Owner: owner, Name: name}, repo, false)
	}
	for _, t := range declared {
		add(t, nil, true)
	}
	// A declared repository listed by the inventory was added from the
	// list first; its declaration still decides its tier.
	for i := range s.Order {
		if s.Order[i].Declared && s.Order[i].Tier > 6 {
			s.Order[i].Tier, s.Order[i].Source = 6, cmp.Or(contexts[s.Order[i].Asset].Source, "assets")
			s.Order[i].Basis = tiers[6].basis
		}
	}
	slices.SortStableFunc(s.Order, func(a, b Selected) int {
		if a.Tier != b.Tier {
			return a.Tier - b.Tier
		}
		switch {
		case a.PushedAt == "" && b.PushedAt != "":
			return 1
		case a.PushedAt != "" && b.PushedAt == "":
			return -1
		case a.PushedAt != b.PushedAt:
			return strings.Compare(b.PushedAt, a.PushedAt)
		}
		return strings.Compare(a.FullName, b.FullName)
	})
	s.InScope = len(s.Order)
	s.InScopeAtLeast = s.Budget > 0 && !e.Repositories.Complete
	for _, d := range c.SecretStores {
		if strings.EqualFold(d.Asset, c.OrganizationAsset) && !orderedBySecret {
			s.Notes = append(s.Notes, fmt.Sprintf("`%s` names the organization; every repository can read its secrets, so it orders none.", d.Key))
		}
	}
	return s
}

func declaredKey(ds []Declared, asset string) string {
	for _, d := range ds {
		if strings.EqualFold(d.Asset, asset) {
			return d.Key
		}
	}
	return ""
}

// secretSelected is, for a `secrets.production` entry naming the
// organization, the repositories inventory shows selected for an
// organization secret, keyed by full name, and whether any was. Ordering
// only: selected visibility is not production use for any finding.
func secretSelected(e Evidence, c Context) (map[string]string, bool) {
	key := declaredKey(c.SecretStores, c.OrganizationAsset)
	out := map[string]string{}
	if key == "" {
		return out, false
	}
	for _, sel := range e.SelectedSecrets {
		if !metadataComplete(sel.Repositories) {
			continue
		}
		for _, r := range sel.Repositories.Items {
			out[strings.ToLower(r.FullName)] = key + " (organization secrets, selected repositories)"
		}
	}
	return out, len(out) > 0
}

// The kinds Check reads, in order, each over every selected repository in
// Plan's order before the next starts (docs/spec/engagement.md, "Breadth
// first by kind").
const (
	KindAccess          = "access"
	KindCI              = "ci"
	KindSecretAlerts    = "secret_alerts"
	KindDependabot      = "dependabot_alerts"
	KindSecretLocations = "secret_locations"
)

// kindRules are the finding ids whose evidence each kind reads, so the
// report can say which coverage a cut kind leaves sampled.
var kindRules = map[string][]string{
	KindAccess: {finding.IDGitHubUndeclaredPublicRepository, finding.IDIdentityFormerPersonHasAccess, finding.IDGitHubOutsideAdminOnProduction, finding.IDGitHubWritableDeployKey,
		finding.IDGitHubRepositoryWorkflowWrite, finding.IDGitHubDefaultBranchUnprotected},
	KindCI:              {finding.IDGitHubMutableAction, finding.IDGitHubMutableActionWrite, finding.IDGitHubPRTargetUnsafe},
	KindSecretAlerts:    {finding.IDGitHubSecretScanningOpen},
	KindDependabot:      {finding.IDGitHubDependabotHigh, finding.IDGitHubDependabotMedium, finding.IDGitHubDependabotLow},
	KindSecretLocations: {finding.IDGitHubSecretScanningOpen},
}

var kinds = []string{KindAccess, KindCI, KindSecretAlerts, KindDependabot, KindSecretLocations}

// CheckInput is what Check passes beside the selection: the stage its
// requests are attributed to and the declared local mirrors by asset.
type CheckInput struct {
	Stage     string
	Checkouts map[string]string
}

// Repositories is what Check read of a selection: per-repository evidence
// in Plan's order, how far each kind reached, which kinds the budget cut,
// and the repositories whose object was not found or not recognized,
// which ends their reads whatever the budget.
type Repositories struct {
	Selection Selection           `json:"selection"`
	Spent     int                 `json:"spent"`
	Reached   map[string][]string `json:"reached"`
	Cut       []string            `json:"cut,omitempty"`
	NoObject  []string            `json:"no_object,omitempty"`
	Access    []RepositoryAccess  `json:"access,omitempty"`
	CI        []RepositoryCI      `json:"ci,omitempty"`
	Alerts    []RepositoryAlerts  `json:"alerts,omitempty"`
	History   []RepositoryHistory `json:"history,omitempty"`
}

// meter counts the requests Check sends under the budget: a request the
// gate sent, whatever came back, or answered from its ledger, once per page
// however often it was retried, so a resumed run reaches the same
// selection. A request the gate refused or stopped without sending (a
// limit, a cancelled run) is not spent. It forwards to the gate and is
// never a second way to send.
type meter struct {
	g            Sender
	spent, calls int
	// stopped is set once the gate says every later request would be
	// answered the same way (a provider's rate limit, the deadline): Check
	// starts nothing more, and that is the limit's, never the budget's.
	// stop is that answer's detail.
	stopped bool
	stop    string
}

func (m *meter) Send(ctx context.Context, r gate.Request) gate.Result {
	m.calls++
	res := m.g.Send(ctx, r)
	if res.Sent || res.Decision == gate.DecisionSent || res.Decision == gate.DecisionReused {
		m.spent++
	}
	if res.Repeats && !m.stopped {
		m.stopped, m.stop = true, res.Detail
	}
	return res
}

// CollectRepositories reads the selection breadth first by kind: a kind
// starts on a repository only while the requests spent are below the
// budget, finishes on it once started, and never skips a declared
// repository. A run the deadline ends starts nothing more, and that is the
// limit's, never the budget's. The local mirror runs last and is not
// counted.
func CollectRepositories(ctx context.Context, g Sender, sel Selection, in CheckInput) Repositories {
	out := Repositories{Selection: sel, Reached: map[string][]string{}}
	m := &meter{g: g}
	type state struct {
		item   Selected
		access RepositoryAccess
		ci     RepositoryCI
		alerts RepositoryAlerts
		done   map[string]bool
		// budget names the kinds the budget did not let start here.
		budget map[string]bool
	}
	states := make([]*state, len(sel.Order))
	for i, item := range sel.Order {
		states[i] = &state{item: item, done: map[string]bool{}, budget: map[string]bool{}}
	}
	for _, kind := range kinds {
		cut := false
		for _, s := range states {
			if ctx.Err() != nil || m.stopped {
				break
			}
			if kind != KindAccess && s.budget[KindAccess] {
				// Its access kind was cut, so every later kind is too.
				s.budget[kind], cut = true, true
				continue
			}
			if kind != KindAccess && s.access.Repository == nil {
				// The object was not found or not recognized, or the run
				// ended first: that ends the repository's reads.
				continue
			}
			if sel.Budget > 0 && m.spent >= sel.Budget && !s.item.Declared {
				s.budget[kind], cut = true, true
				continue
			}
			before, calls := m.spent, m.calls
			switch kind {
			case KindAccess:
				s.access = repositoryObject(ctx, m, s.item.Target, in.Stage)
				if s.access.Repository != nil {
					s.ci = ciProtection(ctx, m, s.access, in.Stage)
					s.alerts = alertsFor(s.access)
				} else if s.access.RepositoryRead.Status == 404 || s.access.RepositoryRead.Gap == "unrecognized_repository" {
					// Not found, or answered with an object that is not
					// this repository: there is nothing more to read. A
					// failed read stays in scope with its own reason.
					out.NoObject = append(out.NoObject, s.item.Asset)
				}
				repositoryChildren(ctx, m, s.item.Target, &s.access, in.Stage)
			case KindCI:
				entries := ciDirectory(ctx, m, s.access, &s.ci, in.Stage)
				repositorySecrets(ctx, m, s.access, &s.alerts, in.Stage)
				ciWorkflows(ctx, m, s.access, &s.ci, entries, in.Stage)
			case KindSecretAlerts:
				secretAlerts(ctx, m, s.access, &s.alerts, in.Stage)
			case KindDependabot:
				dependabotAlerts(ctx, m, s.access, &s.alerts, in.Stage)
			case KindSecretLocations:
				secretLocations(ctx, m, s.access, &s.alerts, in.Stage)
			}
			s.done[kind] = true
			// Reached counts a repository the kind read: its object for the
			// access kind, a request sent or answered for the others. One
			// the gate refused outright was attempted, not read.
			// A kind with nothing to ask (no alert to locate: none open, or
			// none readable, which the alerts kind already says) read all
			// there was.
			if kind == KindAccess && s.access.Repository != nil || kind != KindAccess && (m.spent > before || m.calls == calls) {
				out.Reached[kind] = append(out.Reached[kind], s.item.Asset)
			}
		}
		if cut {
			out.Cut = append(out.Cut, kind)
		}
	}
	out.Spent = m.spent
	stopped := cmp.Or(m.stop, "the run ended before this repository was read")
	for _, s := range states {
		if !s.done[KindAccess] {
			if !s.budget[KindAccess] && s.item.Declared {
				// The deadline or a provider's stop came first: a declared
				// repository is unread for the limit's reason, never
				// dropped. An undeclared one is counted unread by Kinds and
				// RepositoriesUnread, and adds no note of its own.
				out.Access = append(out.Access, RepositoryAccess{Asset: s.item.Asset,
					RepositoryRead: Read{Op: OpRepository, Decision: "unavailable:not_started", Reason: "limit_reached", Detail: stopped}})
			}
			continue
		}
		out.Access = append(out.Access, s.access)
		if s.access.Repository == nil {
			continue
		}
		s.ci.Sampled = s.budget[KindCI]
		out.CI = append(out.CI, s.ci)
		for _, kind := range []string{KindCI, KindSecretAlerts, KindDependabot, KindSecretLocations} {
			if s.budget[kind] {
				s.alerts.Sampled = append(s.alerts.Sampled, kind)
			}
		}
		out.Alerts = append(out.Alerts, s.alerts)
	}
	// The mirror is read through the gate itself: it is not counted, and
	// its redaction hooks are the gate's. A repository with no declared
	// mirror sends nothing and records that none was declared.
	for _, s := range states {
		if s.done[KindAccess] {
			checkout := ""
			if s.item.Mirror {
				checkout = cmp.Or(in.Checkouts[s.item.Asset], in.Checkouts[s.item.Target.Asset])
			}
			out.History = append(out.History, repositoryHistory(ctx, g, s.access, checkout, in.Stage))
		}
	}
	return out
}

// With is the evidence Analyze judges: Recon's inventory and what Check
// read of the selection.
func (e Evidence) With(r Repositories) Evidence {
	e.RepositoriesAccess, e.RepositoriesCI, e.RepositoriesAlerts, e.RepositoriesHistory = r.Access, r.CI, r.Alerts, r.History
	read := 0
	for _, a := range r.Access {
		if a.Repository != nil {
			read++
		}
	}
	e.RepositoriesUnread = read < len(r.Selection.Order)
	return e
}

// Kinds is how far each kind reached among the selection, with the finding
// ids each rests on, for the report's coverage. A repository root, which
// has no budget, has none.
func (r Repositories) Kinds() []finding.KindSelection {
	if r.Selection.Budget == 0 {
		return nil
	}
	org := strings.TrimPrefix(r.Selection.Asset, "saas:github:")
	var out []finding.KindSelection
	for _, kind := range kinds {
		reached := r.Reached[kind]
		inScope := r.Selection.InScope
		if kind != KindAccess {
			// A repository whose object was not found has no later kind to
			// read: its access coverage says so, not a budget choice.
			inScope -= len(r.NoObject)
		}
		ks := finding.KindSelection{Kind: kind, Rules: slices.Clone(kindRules[kind]), Selection: finding.Selection{
			Kind: kind, Unit: "repositories", Fallback: "pushed_at desc", Read: len(reached), InScope: inScope,
			InScopeAtLeast: r.Selection.InScopeAtLeast, Spent: r.Spent, Budget: r.Selection.Budget, Tiers: []finding.SelectionTier{},
		}}
		counts := map[int]int{}
		for _, item := range r.Selection.Order {
			if slices.Contains(reached, item.Asset) {
				counts[item.Tier]++
			}
		}
		for t := 1; t < len(tiers); t++ {
			if counts[t] > 0 {
				ks.Selection.Tiers = append(ks.Selection.Tiers, finding.SelectionTier{Basis: tiers[t].basis, Source: tiers[t].source, Count: counts[t]})
			}
		}
		if slices.Contains(r.Cut, kind) {
			ks.Cut = "the " + thousands(r.Selection.Budget) + "-request budget for " + org
		}
		out = append(out, ks)
	}
	return out
}

// CollectInventory is everything Recon reads of an organization: its
// metadata, membership and populations, the MFA filter lists, the
// organization's workflow default and its Actions secrets with each
// selected secret's repositories. No per-repository read is sent here.
func CollectInventory(ctx context.Context, g Sender, org Organization, p PrincipalRead) Evidence {
	e := Collect(ctx, g, org, p)
	e = collectMFA(ctx, g, org, e)
	e = collectOrganizationWorkflow(ctx, g, e, org)
	return collectOrganizationSecrets(ctx, g, e, org)
}

// thousands writes n with a comma between groups of three digits.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
