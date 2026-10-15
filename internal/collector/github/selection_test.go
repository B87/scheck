package github

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/engagement/gate"
	"github.com/b87/scheck/internal/finding"
)

// repoWorld answers every per-repository read of an organization of n
// repositories by operation and parameters, and records what was asked.
type repoWorld struct {
	sent []gate.Request
}

func (w *repoWorld) Send(_ context.Context, r gate.Request) gate.Result {
	w.sent = append(w.sent, r)
	repo := r.Params["repo"]
	sha := strings.Repeat("a", 40)
	blob := strings.Repeat("b", 40)
	switch r.Op {
	case OpRepository:
		return result("repo-"+repo, fmt.Sprintf(`{"id":%d,"name":%q,"full_name":"acme/%s","owner":{"id":2,"login":"acme","type":"Organization"},"visibility":"private","default_branch":"main"}`, 100+len(w.sent), repo, repo), false)
	case OpBranch:
		return result("branch-"+repo, fmt.Sprintf(`{"name":"main","protected":true,"commit":{"sha":%q}}`, sha), false)
	case OpBranchRules, OpCollaborators, OpDeployKeys, OpDependabotAlerts:
		return result(r.Op+"-"+repo, `[]`, true)
	case OpRepositoryWorkflow:
		return result("default-"+repo, `{"default_workflow_permissions":"read"}`, false)
	case OpWorkflowDirectory:
		return result("dir-"+repo, fmt.Sprintf(`[{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":10}]`, blob), true)
	case OpWorkflowFile:
		return result("file-"+repo, fmt.Sprintf(`{"name":"ci.yml","path":".github/workflows/ci.yml","type":"file","sha":%q,"size":10,"decoded_bytes":10,"workflow":{"on":"push","jobs":{"b":{"runs-on":"ubuntu-latest","steps":[{"run":"make"}]}}}}`, blob), false)
	case OpRepositorySecrets:
		return result("secrets-"+repo, `[]`, true)
	case OpSecretAlerts:
		return result("alerts-"+repo, `[{"number":1,"state":"open","secret_type":"github_pat"}]`, true)
	case OpSecretLocations:
		return result("loc-"+repo, `[]`, true)
	}
	return gate.Result{RequestID: "missing", Decision: "unavailable:missing", Reason: "missing_permission"}
}

func (w *repoWorld) repos(op string) []string {
	var out []string
	for _, r := range w.sent {
		if r.Op == op && !slices.Contains(out, r.Params["repo"]) {
			out = append(out, r.Params["repo"])
		}
	}
	return out
}

// orgOf is an inventory of n repositories, repository i pushed i hours
// after a fixed time, so the highest index is the most recently pushed.
func orgOf(n int) Evidence {
	e := Evidence{Organization: &OrganizationObject{ID: 2, Login: "acme", Type: "Organization"}}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range n {
		name := fmt.Sprintf("r%03d", i)
		pushed := base.Add(time.Duration(i) * time.Hour).Format(time.RFC3339)
		e.Repositories.Items = append(e.Repositories.Items, Repository{ID: int64(10 + i), Name: name, FullName: "acme/" + name,
			Owner: Account{ID: 2, Login: "acme", Type: "Organization"}, Visibility: new("private"), Archived: new(false), PushedAt: &pushed})
	}
	return e
}

func orgContext() Context {
	return Context{OrganizationAsset: "saas:github:acme", RepositoryContexts: map[string]RepositoryContext{}}
}

func TestSelectOrdersByTierThenPushedThenName(t *testing.T) {
	e := orgOf(6)
	e.Repositories.Items[0].Visibility = new("public")
	e.Repositories.Items[0].Archived = new(true)       // public and archived: tier 3
	e.Repositories.Items[1].Archived = new(true)       // archived: tier 8
	e.Repositories.Items[2].Archived = new(true)       // archived production: tier 1
	e.Repositories.Items[3].PushedAt = nil             // no pushed_at: last of tier 7
	e.Repositories.Items[4].Visibility = new("public") // public and staging: tier 3 wins
	c := orgContext()
	c.RepositoryContexts["repo:github:acme/r002"] = RepositoryContext{DeploysTo: "production", Source: "assets.shop"}
	c.RepositoryContexts["repo:github:acme/r004"] = RepositoryContext{DeploysTo: "staging", Source: "assets.web"}
	c.RepositoryContexts["repo:github:acme/hidden"] = RepositoryContext{Source: "assets.hidden"}
	c.MattersMost = []Declared{{Asset: "repo:github:acme/r005", Key: "data.matters_most[0]"}}
	declared := []RepositoryTarget{{Asset: "repo:github:acme/hidden", Owner: "acme", Name: "hidden"}}
	s := Select(e, c, declared, map[string]string{"repo:github:acme/r005": "/m"})
	var got []string
	for _, item := range s.Order {
		got = append(got, fmt.Sprintf("%s:%d:%s", item.FullName, item.Tier, item.Source))
	}
	want := []string{"acme/r002:1:assets.shop.deploys_to", "acme/r004:3:observed", "acme/r000:3:observed",
		"acme/r005:4:data.matters_most[0]", "acme/hidden:6:assets.hidden", "acme/r003:7:", "acme/r001:8:"}
	if !slices.Equal(got, want) {
		t.Fatalf("order:\n got %v\nwant %v", got, want)
	}
	if s.Budget != RepositoryBudget || s.InScope != 7 || !s.Order[3].Mirror || !s.Order[4].Declared || s.Order[4].PushedAt != "" {
		t.Fatalf("selection: %+v", s)
	}
}

func TestSelectOrganizationSecretOrdersOnlySelectedRepositories(t *testing.T) {
	e := orgOf(3)
	c := orgContext()
	c.SecretStores = []Declared{{Asset: "saas:github:acme", Key: "secrets.production[0]"}}
	s := Select(e, c, nil, nil)
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "`secrets.production[0]` names the organization; every repository can read its secrets, so it orders none.") {
		t.Fatalf("notes: %v", s.Notes)
	}
	e.SelectedSecrets = []SelectedSecret{{Name: "DEPLOY", Repositories: Population[Repository]{Complete: true, VisibilityComplete: true,
		Reads: []Read{{Op: OpSelectedSecretRepositories, Decision: gate.DecisionSent, Status: 200}}, Items: []Repository{e.Repositories.Items[0]}}}}
	s = Select(e, c, nil, nil)
	if len(s.Notes) != 0 || s.Order[0].FullName != "acme/r000" || s.Order[0].Tier != 2 || s.Order[0].Source != "secrets.production[0] (organization secrets, selected repositories)" {
		t.Fatalf("selected secret: %+v %v", s.Order[0], s.Notes)
	}
}

// With 150 repositories under a small budget, the repositories read are
// those the tiers name, breadth first by kind, and the selection says so.
func TestCollectRepositoriesReadsTheTiersUnderASmallBudget(t *testing.T) {
	e := orgOf(150)
	c := orgContext()
	c.RepositoryContexts["repo:github:acme/r010"] = RepositoryContext{DeploysTo: "production", Source: "assets.shop"}
	c.RepositoryContexts["repo:github:acme/r020"] = RepositoryContext{Source: "assets.tools"}
	declared := []RepositoryTarget{{Asset: "repo:github:acme/r010", Owner: "acme", Name: "r010"}, {Asset: "repo:github:acme/r020", Owner: "acme", Name: "r020"}}
	sel := Select(e, c, declared, nil)
	// Each repository's access kind costs six requests: the object, the
	// branch, its rules, the workflow default, collaborators, deploy keys.
	sel.Budget = 60
	w := &repoWorld{}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	accessed := w.repos(OpRepository)
	want := []string{"r010", "r020", "r149", "r148", "r147", "r146", "r145", "r144", "r143", "r142"}
	if !slices.Equal(accessed, want) {
		t.Fatalf("access kind read %v, want %v", accessed, want)
	}
	// The budget is spent: later kinds reach only the declared
	// repositories, which the budget never cuts.
	for _, op := range []string{OpWorkflowDirectory, OpRepositorySecrets, OpSecretAlerts, OpDependabotAlerts, OpSecretLocations} {
		if got := w.repos(op); !slices.Equal(got, []string{"r010", "r020"}) {
			t.Fatalf("%s read %v", op, got)
		}
	}
	for _, r := range w.sent {
		if r.Stage != "check" {
			t.Fatalf("stage %q", r.Stage)
		}
	}
	if rep.Spent != len(w.sent) || !slices.Equal(rep.Cut, kinds) || rep.Spent != 72 {
		t.Fatalf("spent %d of %d sent; cut %v", rep.Spent, len(w.sent), rep.Cut)
	}
	reached := rep.Kinds()
	if reached[0].Kind != KindAccess || reached[0].Cut != "the 60-request budget for acme" || reached[0].Selection.Read != 10 || reached[0].Selection.InScope != 150 {
		t.Fatalf("access: %+v", reached[0])
	}
	ci := reached[1]
	if ci.Cut != "the 60-request budget for acme" || ci.Selection.Read != 2 ||
		!slices.Equal(ci.Selection.Tiers, []finding.SelectionTier{{Basis: "deploys_to production", Source: "assets.*.deploys_to", Count: 1}, {Basis: "declared repository asset", Source: "assets", Count: 1}}) {
		t.Fatalf("ci: %+v", ci)
	}
	if got := reached[0].Selection.Tiers; got[len(got)-1] != (finding.SelectionTier{Basis: "most recently pushed", Count: 8}) {
		t.Fatalf("access tiers: %+v", got)
	}
	// A repository the CI kind did not reach is not judged on workflows:
	// absence of a read is never a negative.
	ev := Evidence{Organization: e.Organization}.With(rep)
	for _, j := range JudgeCI(ev, c) {
		if j.Asset == "repo:github:acme/r149" && slices.Contains(kindRules[KindCI], j.ID) {
			t.Fatalf("judged an unread workflow: %+v", j)
		}
	}
	for _, j := range JudgeAlerts(ev, c) {
		if j.Asset == "repo:github:acme/r149" {
			t.Fatalf("judged unread alerts: %+v", j)
		}
	}
}

// A kind, once started on a repository, finishes there; below the budget
// every kind reaches every repository and nothing is cut.
func TestCollectRepositoriesFinishesAStartedKindAndCutsNothingBelowBudget(t *testing.T) {
	sel := Select(orgOf(3), orgContext(), nil, nil)
	sel.Budget = 1
	w := &repoWorld{}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	if got := w.repos(OpRepository); len(got) != 1 || len(w.repos(OpDeployKeys)) != 1 {
		t.Fatalf("a started kind did not finish: %v", w.sent)
	}
	if rep.Kinds()[0].Cut == "" {
		t.Fatal("no cut")
	}
	sel.Budget = RepositoryBudget
	w = &repoWorld{}
	rep = CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	for _, k := range rep.Kinds() {
		if k.Cut != "" || k.Selection.Read != 3 {
			t.Fatalf("%+v", k)
		}
	}
	if len(w.repos(OpSecretLocations)) != 3 {
		t.Fatal("locations not read")
	}
}

// A repository root has no budget and no selection line.
func TestRepositoryRootIsReadInFull(t *testing.T) {
	c := Context{OrganizationAsset: "repo:github:acme/r000", RepositoryContexts: map[string]RepositoryContext{}}
	sel := Select(Evidence{}, c, []RepositoryTarget{{Asset: "repo:github:acme/r000", Owner: "acme", Name: "r000"}}, nil)
	if sel.Budget != 0 || sel.InScope != 1 {
		t.Fatalf("%+v", sel)
	}
	rep := CollectRepositories(context.Background(), &repoWorld{}, sel, CheckInput{Stage: "check"})
	if len(rep.Kinds()) != 0 || len(rep.Cut) != 0 || len(rep.Alerts) != 1 || len(rep.Alerts[0].Located) != 1 {
		t.Fatalf("%+v", rep)
	}
}

// When the budget cuts the access kind, every later kind is cut on those
// repositories too, even when every repository the access kind reached was
// declared.
func TestAnAccessCutCutsEveryLaterKind(t *testing.T) {
	e := orgOf(5)
	var declared []RepositoryTarget
	for _, n := range []string{"r000", "r001", "r002"} {
		declared = append(declared, RepositoryTarget{Asset: "repo:github:acme/" + n, Owner: "acme", Name: n})
	}
	sel := Select(e, orgContext(), declared, nil)
	sel.Budget = 10
	rep := CollectRepositories(context.Background(), &repoWorld{}, sel, CheckInput{Stage: "check"})
	for _, k := range rep.Kinds() {
		if k.Selection.Read != 3 || k.Selection.InScope != 5 || k.Cut != "the 10-request budget for acme" {
			t.Fatalf("%s: %+v", k.Kind, k)
		}
	}
}

// refusingWorld answers like repoWorld but stops sending after n requests,
// as a provider whose rate limit ran out does.
type refusingWorld struct {
	repoWorld
	n int
}

func (w *refusingWorld) Send(ctx context.Context, r gate.Request) gate.Result {
	if len(w.sent) >= w.n {
		return gate.Result{RequestID: "stopped", Decision: "unavailable:provider_stopped", Reason: "limit_reached"}
	}
	return w.repoWorld.Send(ctx, r)
}

// Only requests the gate sent or answered from its ledger are spent: a
// limit that stops the provider is the limit's, never the budget's.
func TestTheMeterCountsOnlyWhatWasSent(t *testing.T) {
	sel := Select(orgOf(20), orgContext(), nil, nil)
	sel.Budget = 100
	w := &refusingWorld{n: 12}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	if rep.Spent != 12 || len(rep.Cut) != 0 {
		t.Fatalf("spent %d, cut %v", rep.Spent, rep.Cut)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep = CollectRepositories(ctx, &repoWorld{}, sel, CheckInput{Stage: "check"})
	// None is declared, so none gets an entry; all are unread.
	if rep.Spent != 0 || len(rep.Cut) != 0 || len(rep.Reached) != 0 || len(rep.Access) != 0 || !(Evidence{}).With(rep).RepositoriesUnread {
		t.Fatalf("a cancelled run read or cut: spent %d cut %v reached %v access %d", rep.Spent, rep.Cut, rep.Reached, len(rep.Access))
	}
}

// A repository Check read with no declared mirror records that none was
// declared, sending nothing, so its history coverage does not disappear.
func TestHistoryIsRecordedWithoutAMirror(t *testing.T) {
	sel := Select(orgOf(2), orgContext(), nil, nil)
	w := &repoWorld{}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	if len(rep.History) != 2 || !slices.Equal(rep.History[0].Gaps, []string{"mirror_not_declared"}) || len(w.repos(OpHistoryHeads)) != 0 {
		t.Fatalf("%+v", rep.History)
	}
}

// A repository whose object was not found ends its reads; later kinds do
// not count it as a budget choice.
func TestAMissingObjectIsNotABudgetChoice(t *testing.T) {
	sel := Select(orgOf(3), orgContext(), nil, nil)
	w := &missingWorld{missing: "r001"}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	k := rep.Kinds()
	// The access kind asked for all three but read two objects.
	if k[0].Selection.Read != 2 || k[0].Selection.InScope != 3 || k[1].Selection.Read != 2 || k[1].Selection.InScope != 2 || k[1].Cut != "" {
		t.Fatalf("%+v", k)
	}
}

type missingWorld struct {
	repoWorld
	missing string
}

func (w *missingWorld) Send(ctx context.Context, r gate.Request) gate.Result {
	if r.Op == OpRepository && r.Params["repo"] == w.missing {
		w.sent = append(w.sent, r)
		return gate.Result{RequestID: "404", Decision: gate.DecisionSent, Response: &gate.Response{Status: 404}}
	}
	return w.repoWorld.Send(ctx, r)
}

// An incomplete repository list makes the in-scope count a lower bound.
func TestAnIncompleteListIsALowerBound(t *testing.T) {
	e := orgOf(2)
	e.Repositories.Complete = false
	sel := Select(e, orgContext(), nil, nil)
	rep := CollectRepositories(context.Background(), &repoWorld{}, sel, CheckInput{Stage: "check"})
	if !rep.Kinds()[0].Selection.InScopeAtLeast {
		t.Fatal("not a lower bound")
	}
}

// A public repository the budget cut keeps its inventory judgment.
func TestAPublicRepositoryPastTheBudgetIsJudgedFromInventory(t *testing.T) {
	e := orgOf(4)
	for i := range e.Repositories.Items {
		e.Repositories.Items[i].Visibility = new("public")
	}
	c := orgContext()
	sel := Select(e, c, nil, nil)
	sel.Budget = 1
	rep := CollectRepositories(context.Background(), &repoWorld{}, sel, CheckInput{Stage: "check"})
	fired := 0
	for _, j := range JudgeAccess(e.With(rep), c) {
		if j.ID == finding.IDGitHubUndeclaredPublicRepository && j.Verdict == Fired {
			fired++
		}
	}
	// The one repository read directly is judged by its own object, which
	// repoWorld answers private; the three past the budget from the list.
	if fired != 3 {
		t.Fatalf("fired %d of 3", fired)
	}
}

// A failed object read is not "not found": the repository stays in scope
// for the later kinds, unread, with no budget cut claimed.
func TestAFailedObjectStaysInScope(t *testing.T) {
	sel := Select(orgOf(3), orgContext(), nil, nil)
	w := &failingWorld{failing: "r001"}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	k := rep.Kinds()
	if len(rep.NoObject) != 0 || k[1].Selection.Read != 2 || k[1].Selection.InScope != 3 || k[1].Cut != "" {
		t.Fatalf("%+v %+v", rep.NoObject, k[1])
	}
}

type failingWorld struct {
	repoWorld
	failing string
}

func (w *failingWorld) Send(ctx context.Context, r gate.Request) gate.Result {
	if r.Op == OpRepository && r.Params["repo"] == w.failing {
		w.sent = append(w.sent, r)
		return gate.Result{RequestID: "500", Decision: "unavailable:server_error", Reason: "failed", Sent: true, Response: &gate.Response{Status: 502}}
	}
	return w.repoWorld.Send(ctx, r)
}

// limitedWorld stops sending after n requests, as GitHub's rate limit
// does: every later request is refused, and says so for all that follow.
type limitedWorld struct {
	repoWorld
	n, calls int
}

func (w *limitedWorld) Send(ctx context.Context, r gate.Request) gate.Result {
	w.calls++
	if len(w.sent) >= w.n {
		return gate.Result{RequestID: "limited", Decision: "refused:rate_limit", Reason: "limit_reached", Repeats: true, Detail: "GitHub's rate limit for this token is used up"}
	}
	return w.repoWorld.Send(ctx, r)
}

// A rate-limit stop is the limit's: the repositories it left are not
// counted as read, nothing is cut by the budget, and Check stops asking.
func TestARateLimitStopIsNotAReadNorABudgetCut(t *testing.T) {
	sel := Select(orgOf(10), orgContext(), nil, nil)
	w := &limitedWorld{n: 20}
	rep := CollectRepositories(context.Background(), w, sel, CheckInput{Stage: "check"})
	k := rep.Kinds()
	if k[0].Selection.Read != 4 || k[0].Cut != "" || len(rep.Cut) != 0 {
		t.Fatalf("access %+v cut %v", k[0], rep.Cut)
	}
	// The repository the stop came in finishes its kind (at most six
	// calls); no later repository is asked.
	if w.calls > 20+6 {
		t.Fatalf("kept asking after the stop: %d calls", w.calls)
	}
}

// A public repository whose object read failed keeps its inventory
// judgment.
func TestAPublicRepositoryWithAFailedObjectIsJudgedFromInventory(t *testing.T) {
	e := orgOf(3)
	e.Repositories.Items[1].Visibility = new("public")
	c := orgContext()
	rep := CollectRepositories(context.Background(), &failingWorld{failing: "r001"}, Select(e, c, nil, nil), CheckInput{Stage: "check"})
	if !slices.ContainsFunc(JudgeAccess(e.With(rep), c), func(j Judgment) bool {
		return j.ID == finding.IDGitHubUndeclaredPublicRepository && j.Asset == "repo:github:acme/r001" && j.Verdict == Fired
	}) {
		t.Fatal("not fired from the list")
	}
}

// A declared repository a provider's stop left unstarted is unread for the
// limit's reason, with the stop's own words, never dropped.
func TestAStopLeavesDeclaredRepositoriesLimitReached(t *testing.T) {
	e := orgOf(3)
	var declared []RepositoryTarget
	for _, n := range []string{"r000", "r001", "r002"} {
		declared = append(declared, RepositoryTarget{Asset: "repo:github:acme/" + n, Owner: "acme", Name: n})
	}
	rep := CollectRepositories(context.Background(), &limitedWorld{n: 6}, Select(e, orgContext(), declared, nil), CheckInput{Stage: "check"})
	i := slices.IndexFunc(rep.Access, func(a RepositoryAccess) bool { return a.Asset == "repo:github:acme/r000" })
	if i < 0 || rep.Access[i].RepositoryRead.Reason != "limit_reached" || rep.Access[i].Repository != nil ||
		rep.Access[i].RepositoryRead.Decision != "unavailable:not_started" || rep.Access[i].RepositoryRead.Detail != "GitHub's rate limit for this token is used up" {
		t.Fatalf("%+v", rep.Access)
	}
	// An undeclared repository the stop left gets no entry of its own.
	rep = CollectRepositories(context.Background(), &limitedWorld{n: 6}, Select(orgOf(3), orgContext(), nil, nil), CheckInput{Stage: "check"})
	if !orgOf(3).With(rep).RepositoriesUnread || slices.ContainsFunc(rep.Access, func(a RepositoryAccess) bool { return a.RepositoryRead.Decision == "unavailable:not_started" }) {
		t.Fatalf("undeclared not_started entry: %+v", rep.Access)
	}
}

// A repository with no open secret alert has no location to read: the
// locations kind read all there was.
func TestNoAlertMeansNoLocationToRead(t *testing.T) {
	rep := CollectRepositories(context.Background(), &noAlertWorld{}, Select(orgOf(3), orgContext(), nil, nil), CheckInput{Stage: "check"})
	for _, k := range rep.Kinds() {
		if k.Selection.Read != 3 {
			t.Fatalf("%s read %d of 3", k.Kind, k.Selection.Read)
		}
	}
}

type noAlertWorld struct{ repoWorld }

func (w *noAlertWorld) Send(ctx context.Context, r gate.Request) gate.Result {
	if r.Op == OpSecretAlerts {
		w.sent = append(w.sent, r)
		return result("alerts-"+r.Params["repo"], `[]`, true)
	}
	return w.repoWorld.Send(ctx, r)
}
