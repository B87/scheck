package eval

import (
	"context"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
)

const suiteDir = "../../testdata/eval"

func load(t *testing.T) *Suite {
	t.Helper()
	s, err := Load(suiteDir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The committed suite meets the minimums frozen in the criteria (§2).
func TestSuiteMeetsMinimums(t *testing.T) {
	s := load(t)
	if missing := s.Validate(); len(missing) > 0 {
		t.Fatalf("suite short: %v", missing)
	}
	if len(s.Cases) < 14 {
		t.Errorf("%d cases", len(s.Cases))
	}
}

// Every case's rules arm produces exactly the rule findings its labels
// expect: the fixtures say what they claim to say.
func TestRulesArmMatchesLabels(t *testing.T) {
	s := load(t)
	o := Options{Suite: s, Profile: check.ProfileBaseline}
	for _, c := range s.Cases {
		run, err := o.run(context.Background(), c, ArmRules, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range c.Labels.ExpectRules {
			found := false
			for _, got := range run.RuleIDs {
				if got == id {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: rules arm lacks %s (got %v)", c.Name, id, run.RuleIDs)
			}
		}
		if run.Status != "complete" || len(run.Findings) < len(c.Labels.ExpectRules) {
			t.Errorf("%s: %+v", c.Name, run)
		}
	}
}

// A mock run exercises every metric the criteria define and renders the
// comparison; the record says it is not a quality claim.
func TestMockRunScoresAndRenders(t *testing.T) {
	s := load(t)
	res, err := Execute(context.Background(), Options{Suite: s, Provider: MockProvider, Repeat: 2, Model: "mock-model",
		Profile: check.ProfileBaseline, Corpus: "../../testdata/context", AdversarialCase: "linux-password-auth-public",
		Log: func(f string, a ...any) { t.Logf(f, a...) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Live || len(res.Notes) == 0 || res.Provider != "mock" || !strings.HasPrefix(res.PromptVersion, "sp-") {
		t.Errorf("record: %+v", res)
	}
	byKey := map[string]Run{}
	for _, r := range res.Runs {
		byKey[r.Case+"/"+string(r.Arm)+"/"+itoa(r.Repeat)] = r
	}
	// The scripted follow-up: the agent reads the unit file and reports;
	// single-pass abstains and misses.
	if r := byKey["linux-unit-in-tmp/agent/1"]; !r.Metrics.Resolved || r.Metrics.Correct != 1 || r.Checks != 1 || r.Status != "complete" {
		t.Errorf("follow-up agent: %+v", r.Metrics)
	}
	if r := byKey["linux-unit-in-tmp/single-pass/1"]; r.Metrics.Missed != 1 || r.Metrics.Resolved || r.Metrics.Correct != 0 {
		t.Errorf("follow-up single-pass: %+v", r.Metrics)
	}
	// The scripted false positive on the clean host.
	if r := byKey["linux-clean/agent/1"]; r.Metrics.FalsePositives != 1 || r.Metrics.Abstained {
		t.Errorf("clean agent: %+v", r.Metrics)
	}
	if r := byKey["linux-clean/single-pass/1"]; !r.Metrics.Abstained || r.Metrics.FalsePositives != 0 {
		t.Errorf("clean single-pass: %+v", r.Metrics)
	}
	// The correlated case reported in both model arms.
	for _, arm := range []string{"agent", "single-pass"} {
		if r := byKey["linux-password-auth-public/"+arm+"/2"]; r.Metrics.Correct != 1 || r.Metrics.Missed != 0 {
			t.Errorf("correlated %s: %+v", arm, r.Metrics)
		}
	}
	// A case with context grades through it: the declared postgres listener
	// is info, so the misleading case has no forbidden model finding.
	if r := byKey["linux-context-explains/rules/1"]; len(r.RuleIDs) != 0 {
		t.Errorf("context-explains rules: %v", r.RuleIDs)
	}
	// Rules arm runs once; model arms twice.
	rules, agents := 0, 0
	for _, r := range res.Runs {
		switch r.Arm {
		case ArmRules:
			rules++
		case ArmAgent:
			agents++
		}
	}
	if rules != len(s.Cases) || agents != 2*len(s.Cases) {
		t.Errorf("%d rules runs, %d agent runs", rules, agents)
	}
	// Adversarial pairs over the scripted transcript: identical by
	// construction, which is what the harness must be able to see.
	if len(res.Pairs) != 8*2 {
		t.Fatalf("%d pair runs", len(res.Pairs))
	}
	for _, p := range res.Pairs {
		if !p.RulesIdentical || p.ExtraDenied != 0 || len(p.Suppressed)+len(p.Fabricated) != 0 {
			t.Errorf("pair %s #%d: %+v", p.Name, p.Repeat, p)
		}
	}
	sums := res.Summarize()
	if len(sums) != 3 || sums[2].Arm != ArmAgent || sums[2].Correct < 2 || sums[2].FalsePositives != 1 || sums[2].Resolved != 1 {
		t.Errorf("summary: %+v", sums)
	}
	md := res.Markdown()
	for _, want := range []string{"# Phase 2 evaluation", "mock", "not** a pass or fail", "| agent |", "linux-unit-in-tmp", "§3.1", "§4.1", "## Adversarial pairs"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	verdicts := res.Verdicts()
	if len(verdicts) < 8 {
		t.Errorf("%d verdicts", len(verdicts))
	}
	// The scripted run cannot pass §3.1 (one resolved follow-up, not two):
	// the harness must say so rather than flatter the mock.
	if verdicts[0].Pass {
		t.Errorf("§3.1 passed on the mock: %+v", verdicts[0])
	}
}

func itoa(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+n))) }

func TestLoadRejectsBadLabels(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("empty dir loaded")
	}
}
