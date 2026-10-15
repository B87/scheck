package engagement

import (
	"slices"
	"testing"
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
		"`data.matters_most` is empty: no finding is raised for the data that matters most, and nothing is read or ranked first for it.",
		"`access.mfa` does not say who must use 2-step verification in `saas:google-workspace:example.com`: scheck reports what it reads, but cannot raise a gap as a contradiction of what you believe.",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}
