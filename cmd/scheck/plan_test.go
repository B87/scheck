package main

import (
	"bytes"
	"strings"
	"testing"

	githubc "github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/engagement"
)

// The plan text lists the declared tiers in full, fills to 20 lines, and
// never predicts what the budget will cut (docs/spec/engagement.md,
// "--stop-after plan").
func TestWritePlanListsTheOrderWithoutPredictingTheCut(t *testing.T) {
	sel := githubc.Selection{Asset: "saas:github:acme", Budget: 4000, InScope: 30}
	for i := range 30 {
		item := githubc.Selected{FullName: "acme/r" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), Tier: 7, Basis: "most recently pushed", PushedAt: "2026-10-01T00:00:00Z"}
		if i < 2 {
			item.Tier, item.Basis, item.Source, item.Declared = 1, "deploys_to production", "assets.shop.deploys_to", true
		}
		sel.Order = append(sel.Order, item)
	}
	var b bytes.Buffer
	writePlan(&b, &engagement.PlanDoc{GitHub: []githubc.Selection{sel}, NotJudged: []string{"`data.matters_most` is empty: x."}})
	out := b.String()
	for _, want := range []string{
		"saas:github:acme  30 repositories in scope",
		"budget 4,000 requests; inventory, the local mirror and follow-ups not counted",
		"    1  acme/ra  tier 1: deploys_to production (assets.shop.deploys_to)  pushed 2026-10-01  [declared]",
		"   20  acme/rt  tier 7: most recently pushed  pushed 2026-10-01",
		"  and 10 more, most recently pushed first (plan.json lists all)",
		"Check sends nothing until you resume this run; the budget may not reach the later kinds on every repository.",
		"Not judged for lack of a declaration:\n  - `data.matters_most` is empty: x.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "acme/ru ") {
		t.Errorf("listed past 20:\n%s", out)
	}
}
