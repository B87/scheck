package engagement

import (
	"slices"
	"testing"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/workspace"
)

// Plan's not-judged list names each rule a missing declaration leaves
// undecided, in the spec's words, and nothing a declaration answers.
func TestPlanNamesWhatWillNotBeJudged(t *testing.T) {
	file := `schema: 1
engagement: {name: plan, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}, {saas: "google-workspace:example.com"}]
assets:
  shop: {repo: "github:acme/shop", deploys_to: staging}
people:
  alice: {kind: employee, github: [alice], workspace: [alice@example.com]}
  bob: {kind: employee, workspace: [bob@example.com], left: "2026-01-01"}
access:
  admins: {"github:acme": [alice]}
  mfa: [{where: "github:acme", enforced: everyone}]
`
	res, err := Parse("engagement.yaml", []byte(file), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := &run{res: res, recon: &ReconDoc{}}
	got := r.notJudged()
	want := []string{
		"`identity.unexpected_admin` on `saas:google-workspace:example.com` will not be judged: `access.admins` lists nobody for this Workspace tenant, so scheck cannot tell an expected admin from an unexpected one.",
		"`identity.former_person_has_access` on `saas:github:acme` will not be judged for `bob`: their `people` entry gives no GitHub login.",
		"`github.outside_admin_on_production` on `saas:github:acme` will not be judged: no repository in this organization declares `deploys_to: production`.",
		"`workspace.external_forwarding` on `saas:google-workspace:example.com` will not be judged: `authorization.mailboxes` authorizes no mailbox, so no forwarding settings are read.",
		"No repository declares `deploys_to: production`: no finding is raised for reaching production, a departed person's push to production cannot be raised, and no repository is read first for it.",
		"`data.matters_most` is empty: you named nothing as holding the data that would hurt most, so no finding is raised for it and nothing is read or ranked first for it.",
		"`access.mfa` does not say who must use 2-step verification in `saas:google-workspace:example.com`: scheck reports what it reads, but cannot raise a gap as a contradiction of what you believe.",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}

// Check's Workspace reads can only leave a collected tenant incomplete,
// recorded once; a tenant Recon left short keeps its single shortfall.
func TestCheckedWorkspaceStatus(t *testing.T) {
	limited := workspace.Outcome{Status: workspace.OutcomeIncomplete, Reason: "limit_reached", Detail: "d"}
	got, short := checkedWorkspace(ReconAsset{Status: StatusCollected}, limited)
	if !short || got.Status != StatusIncomplete || got.Reason != "limit_reached" {
		t.Fatalf("%+v %v", got, short)
	}
	got, short = checkedWorkspace(ReconAsset{Status: StatusIncomplete, Reason: ReasonFailed}, limited)
	if short || got.Reason != ReasonFailed {
		t.Fatalf("%+v %v", got, short)
	}
	got, short = checkedWorkspace(ReconAsset{Status: StatusCollected}, workspace.Outcome{Status: workspace.OutcomeComplete, Detail: "ok"})
	if short || got.Status != StatusCollected || got.Detail != "ok" {
		t.Fatalf("%+v %v", got, short)
	}
}

// Plan says Check may ask about a departed person's permission only when a
// left person declares a login and the organization deploys to production.
func TestPlanNamesThePermissionFollowUp(t *testing.T) {
	const note = "After these reads, Check may ask GitHub for a departed person's permission on each production repository (at most 20 requests, not counted in the budget)."
	for _, c := range []struct {
		deploys, left string
		want          bool
	}{{"production", `, left: "2026-01-01"`, true}, {"staging", `, left: "2026-01-01"`, false}, {"production", "", false}} {
		file := `schema: 1
engagement: {name: plan, operator: alice, timezone: UTC, trigger: routine}
roots: [{saas: "github:acme"}]
assets:
  shop: {repo: "github:acme/shop", deploys_to: ` + c.deploys + `}
people:
  bob: {kind: employee, github: [bob]` + c.left + `}
`
		res, err := Parse("engagement.yaml", []byte(file), testOpts)
		if err != nil {
			t.Fatal(err)
		}
		r := &run{res: res, recon: &ReconDoc{Assets: []ReconAsset{{Name: "saas:github:acme", ID: "saas:github:acme", Root: "saas:github:acme", GitHub: &githubc.Evidence{}}}}}
		sels := r.planGitHub()
		if len(sels) != 1 || slices.Contains(sels[0].Notes, note) != c.want {
			t.Fatalf("%+v: %+v", c, sels)
		}
	}
}
