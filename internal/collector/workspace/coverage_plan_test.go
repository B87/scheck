package workspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/finding"
)

func oauthGroup(t *testing.T, e Evidence) finding.CoverageGroup {
	t.Helper()
	for _, g := range e.Coverage()[0].Groups {
		if slices.Contains(g.Rules, IDOAuthBroadScope) {
			return g
		}
	}
	t.Fatal("no OAuth coverage group")
	return finding.CoverageGroup{}
}

// Every rule id the collector judges belongs to exactly one coverage group
// of exactly one plan (docs/spec/workspace-collector.md, "Reporting and
// coverage").
func TestEveryWorkspaceRuleHasOneCoverageGroup(t *testing.T) {
	plans := Evidence{}.Coverage()
	for _, id := range RuleIDs() {
		n := 0
		for _, p := range plans {
			for _, g := range p.Groups {
				if slices.Contains(g.Rules, id) {
					n++
				}
			}
		}
		if n != 1 {
			t.Fatalf("%s is in %d coverage groups", id, n)
		}
	}
}

func TestCoverageGapsCollapseAndLimits(t *testing.T) {
	e, _ := oauthFixture(oauthUser("amy"))
	if g := oauthGroup(t, e); g.NotOnPlan != nil || g.Collapse != nil || g.Limit != oauthLimit || !g.Always {
		t.Fatal(g)
	}
	e.Judgments = []finding.Judgment{{ID: IDOAuthBroadScope, Verdict: Abstained, Reason: reasonUnclassified}, {ID: IDOAuthBroadScope, Verdict: Abstained, Reason: reasonUnclassified}}
	if g := oauthGroup(t, e); g.Collapse == nil || !strings.HasPrefix(g.Collapse.Detail, "2 apps hold scopes scheck does not classify") {
		t.Fatal(g)
	}
	e.Access.AdministrationComplete = false
	for _, g := range e.Coverage()[0].Groups {
		if (g.Gap != nil) != slices.Contains(g.Rules, IDSuspendedAdminAssignment) {
			t.Fatal("assignment gap on the wrong group", g)
		}
	}
	// The readout's limits note and the coverage limit are one sentence.
	if !slices.ContainsFunc(Readout(e, "asset", Context{}), func(n Note) bool { return n.Detail == oauthLimit+"." }) {
		t.Fatal("limits note differs from the coverage limit")
	}
}

func TestOutcomeNamesWhatCutCollection(t *testing.T) {
	e, _ := oauthFixture(oauthUser("amy"))
	e.InventoryComplete, e.Access.Complete = true, true
	if o := e.Outcome(); o.Status != OutcomeComplete || !strings.Contains(o.Detail, "2-step verification, OAuth grant and mail forwarding checks collected") {
		t.Fatal(o)
	}
	e.Mail.Selected = false
	if o := e.Outcome(); o.Status != OutcomeComplete || !strings.Contains(o.Detail, "2-step verification and OAuth grant checks collected") {
		t.Fatal(o)
	}
	e.OAuth.Selected = false
	if o := e.Outcome(); o.Status != OutcomeComplete || strings.Contains(o.Detail, "OAuth") {
		t.Fatal(o)
	}
	// A refused optional permission is a coverage gap; a limit cuts collection.
	e.OAuth.Accounts[0].Read.Reason = "insufficient_permission:admin.directory.user.security"
	if o := e.Outcome(); o.Status != OutcomeComplete {
		t.Fatal("a refused optional permission made the run incomplete", o)
	}
	e.OAuth.Accounts[0].Read.Reason = "limit_reached"
	if o := e.Outcome(); o.Status != OutcomeIncomplete || o.Reason != "limit_reached" {
		t.Fatal(o)
	}
	e.OAuth.Accounts[0].Read.Reason = ""
	e.Access.Complete = false
	if o := e.Outcome(); o.Status != OutcomeIncomplete || o.Reason != "" || !strings.HasPrefix(o.Detail, "Workspace evidence is incomplete") {
		t.Fatal(o)
	}
	e = Evidence{Binding: Binding{Reads: []Read{{Op: OpCustomer, Reason: "no_credentials", Detail: "GOOGLE_APPLICATION_CREDENTIALS is not set"}}}}
	if o := e.Outcome(); o.Status != OutcomeIncomplete || o.Reason != "no_credentials" || o.Detail != "GOOGLE_APPLICATION_CREDENTIALS is not set" {
		t.Fatal(o)
	}
}
