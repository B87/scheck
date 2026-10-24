package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func TestSelectionTextWordsWhatChoseTheRead(t *testing.T) {
	for _, c := range []struct {
		s    finding.Selection
		want string
	}{
		{finding.Selection{Unit: "repositories", Read: 40, InScope: 120, Spent: 4012, Budget: 4000, Tiers: []finding.SelectionTier{
			{Basis: "deploys_to production", Source: "assets.*.deploys_to", Count: 3}, {Basis: "declared secret store", Source: "secrets.production", Count: 1},
			{Basis: "public", Source: "observed", Count: 2}, {Basis: "most recently pushed", Count: 34}}},
			"40 of 120 repositories: deploys_to production (3, assets.*.deploys_to), declared secret store (1, secrets.production), public (2, observed), then most recently pushed (34); sent 4,012 of a 4,000 budget."},
		{finding.Selection{Unit: "repositories", Read: 30, InScope: 90, Spent: 4003, Budget: 4000, Tiers: []finding.SelectionTier{
			{Basis: "public", Source: "observed", Count: 2}, {Basis: "most recently pushed", Count: 28}}},
			"30 of 90 repositories: public (2, observed), no declaration named any repository; most recently pushed (28); sent 4,003 of a 4,000 budget."},
		{finding.Selection{Unit: "users", Read: 3, InScope: 40, Tiers: []finding.SelectionTier{
			{Basis: "left and still active", Source: "people.*.left", Count: 1}, {Basis: "admin holders no one named", Source: "observed", Count: 2}}},
			"3 of 40 users: left and still active (1, people.*.left), admin holders no one named (2, observed)."},
		{finding.Selection{Unit: "users", Read: 5, InScope: 9, Tiers: []finding.SelectionTier{
			{Basis: "the rest, active and most recently signed in first", Count: 5}}},
			"5 of 9 users: no declaration named any user; the rest, active and most recently signed in first (5)."},
		{finding.Selection{Kind: "oauth_grants", Unit: "users", Read: 3, InScope: 40, Tiers: []finding.SelectionTier{
			{Basis: "admin holders no one named", Source: "observed", Count: 3}}},
			"3 of 40 users: admin holders no one named (3, observed), no declaration named any user."},
		{finding.Selection{Kind: "oauth_grants", Unit: "users", Read: 0, InScope: 9, Tiers: []finding.SelectionTier{}},
			"0 of 9 users: no declaration named any user."},
		{finding.Selection{Unit: "repositories", Read: 12, InScope: 12, Spent: 80, Budget: 4000},
			"all 12 repositories read; the request budget cut nothing; sent 80 of a 4,000 budget."},
	} {
		if got := selectionText(c.s); got != c.want {
			t.Errorf("\n got %s\nwant %s", got, c.want)
		}
	}
}

// githubSelectionCutReport is the CI report of an organization whose
// request budget cut the workflow kind: coverage says sampled, names the
// budget, and the exit code does not change.
func githubSelectionCutReport(t *testing.T) Input {
	in := githubCIReport(t, verdictFired)
	in.Name = "GitHub selection under a budget"
	sel := func(kind string, read int, tiers []finding.SelectionTier) finding.Selection {
		return finding.Selection{Kind: kind, Unit: "repositories", Fallback: "pushed_at desc", Read: read, InScope: 150, Spent: 4006, Budget: 4000, Tiers: tiers}
	}
	all := []finding.SelectionTier{{Basis: "deploys_to production", Source: "assets.*.deploys_to", Count: 1}, {Basis: "most recently pushed", Count: 149}}
	few := []finding.SelectionTier{{Basis: "deploys_to production", Source: "assets.*.deploys_to", Count: 1}, {Basis: "most recently pushed", Count: 39}}
	in.Assets[0].Selections = []finding.KindSelection{
		{Kind: "access", Rules: []string{finding.IDIdentityFormerPersonHasAccess, finding.IDGitHubOutsideAdminOnProduction, finding.IDGitHubWritableDeployKey, finding.IDGitHubRepositoryWorkflowWrite, finding.IDGitHubDefaultBranchUnprotected}, Selection: sel("access", 150, all)},
		{Kind: "ci", Rules: []string{finding.IDGitHubMutableAction, finding.IDGitHubMutableActionWrite, finding.IDGitHubPRTargetUnsafe}, Cut: "the 4,000-request budget for example-org", Selection: sel("ci", 40, few)},
	}
	return in
}

func TestGitHubSelectionCutIsSampledAndKeepsTheExitCode(t *testing.T) {
	base := build(githubCIReport(t, verdictFired))
	r := build(githubSelectionCutReport(t))
	validate(t, schema(t), r)
	if r.Exit.Code != base.Exit.Code {
		t.Fatalf("exit %d, was %d", r.Exit.Code, base.Exit.Code)
	}
	found := false
	for _, row := range r.Coverage {
		for _, si := range row.SubItems {
			if !slices.ContainsFunc(si.Reasons, func(rd ReasonDetail) bool { return rd.Reason == "sampled" }) {
				continue
			}
			found = true
			if si.Mark == "assessed" || si.Population == nil || si.Population.Read != 40 || si.Population.Selection == nil ||
				!strings.Contains(si.Reasons[len(si.Reasons)-1].Detail, "the 4,000-request budget for example-org") {
				t.Fatalf("%+v", si)
			}
		}
		if slices.ContainsFunc(row.Reasons, func(rd ReasonDetail) bool { return rd.Reason == "limit_reached" }) {
			t.Fatalf("a budget cut read as limit_reached: %+v", row.Reasons)
		}
	}
	if !found {
		t.Fatal("no sampled sub-item")
	}
}

// A host finding the grader capped at high says why under "Why here"
// (docs/spec/engagement.md, "Severity in context", "Ceilings").
func TestHostFindingCappedAtHighSaysWhy(t *testing.T) {
	in := manyFindings(t)
	i := slices.IndexFunc(in.Assets, func(a AssetInput) bool { return a.Host != nil && len(a.Host.Envelope.Findings) > 0 })
	if i < 0 {
		t.Fatal("no host finding in the input")
	}
	fs := in.Assets[i].Host.Envelope.Findings
	fs[0].CappedBy = "exposure:internet"
	r := build(in)
	for _, f := range r.Findings {
		if f.ID == fs[0].ID {
			if !slices.Contains(f.WhyHere, finding.WhyPastHigh("exposure:internet")) {
				t.Fatalf("why here %q", f.WhyHere)
			}
			return
		}
	}
	t.Fatalf("finding %s not reported", fs[0].ID)
}
