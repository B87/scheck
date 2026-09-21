package eval

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/bounded"
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
	// The drift baseline: one benign-twice comparison per repeat.
	if len(res.Baseline) != 2 || res.Baseline[0].Repeat != 1 || res.Baseline[1].Repeat != 2 || !res.Baseline[0].RulesIdentical {
		t.Errorf("baseline: %+v", res.Baseline)
	}
	sums := res.Summarize()
	if len(sums) != 3 || sums[2].Arm != ArmAgent || sums[2].Correct < 2 || sums[2].FalsePositives != 1 || sums[2].Resolved != 1 {
		t.Errorf("summary: %+v", sums)
	}
	md := res.Markdown()
	for _, want := range []string{"# Phase 2 evaluation", "mock", "not** a pass or fail", "| agent |", "linux-unit-in-tmp", "§3.1", "§4.1", "## Adversarial pairs", "## Natural drift", "NOTE — natural drift"} {
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

// Select narrows to named cases, keeps them sorted and calls the record
// incomplete against the minimums; an unknown name is an error.
func TestSelectAndCheckpoint(t *testing.T) {
	s := load(t)
	sub, err := s.Select([]string{"macos-clean", "linux-clean"})
	if err != nil || len(sub.Cases) != 2 || sub.Cases[0].Name != "linux-clean" || len(sub.Validate()) == 0 {
		t.Fatalf("select: %v %+v", err, sub)
	}
	if _, err := s.Select([]string{"no-such-case"}); err == nil {
		t.Error("unknown case selected")
	}
	checkpoints := 0
	res, err := Execute(context.Background(), Options{Suite: sub, Provider: MockProvider, Profile: check.ProfileBaseline, Version: "test",
		Checkpoint: func(r *Results) { checkpoints++; _ = r.Markdown() }})
	if err != nil {
		t.Fatal(err)
	}
	if checkpoints != len(res.Runs) || res.Version != "test" || len(res.Runs) != 6 {
		t.Errorf("%d checkpoints for %d runs, version %q", checkpoints, len(res.Runs), res.Version)
	}
}

func TestLoadRejectsBadLabels(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("empty dir loaded")
	}
}

// The fixture target answers with the first matching argv, so a case that
// records the same argv twice tests something other than what its labels say
// (two firewall cases did, and the "ufw active" preamble shadowed their own
// entry until a live run showed it). This is the guard.
func TestCaseManifestsRecordEachArgvOnce(t *testing.T) {
	s := load(t)
	for _, c := range s.Cases {
		raw, err := os.ReadFile(filepath.Join(c.Dir, "manifest.yaml"))
		if err != nil {
			continue // a case without a manifest uses its base as recorded
		}
		var m struct {
			Execs []struct {
				Argv []string `yaml:"argv"`
			} `yaml:"execs"`
		}
		if err := yaml.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		seen := map[string]bool{}
		for _, e := range m.Execs {
			key := strings.Join(e.Argv, "\x00")
			if seen[key] {
				t.Errorf("%s: argv %q is recorded twice; only the first answers", c.Name, strings.Join(e.Argv, " "))
			}
			seen[key] = true
		}
	}
}

// The bounded research arm (docs/ROADMAP-RESEARCH.md R1) runs beside the
// three frozen arms on the same cases, facts, rule findings and context.
// Scripted answers exercise it; they make no quality claim, and the record
// says so.
func TestBoundedArmRunsOnScriptedAnswers(t *testing.T) {
	s := load(t)
	res, err := Execute(context.Background(), Options{Suite: s, Provider: MockProvider, Answers: ScriptedAnswers,
		Arms: Arms, Profile: check.ProfileBaseline, Repeat: 1, Log: func(f string, a ...any) { t.Logf(f, a...) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.BoundedSource != "scripted" || !strings.HasPrefix(res.BoundedQuestions, "bq-") {
		t.Errorf("record: source %q questions %q", res.BoundedSource, res.BoundedQuestions)
	}
	byCase := map[string]Run{}
	for _, r := range res.Runs {
		if r.Arm == ArmBounded {
			byCase[r.Case] = r
		}
	}
	if len(byCase) != len(s.Cases) {
		t.Fatalf("%d bounded runs for %d cases", len(byCase), len(s.Cases))
	}
	// The two follow-up cases the arm's judgement ids cover are resolved by
	// a read code ran, and the SUID correlation is filed.
	for _, tc := range []struct {
		name     string
		filed    []string
		resolved bool
	}{
		{"linux-unit-in-tmp", []string{"persist.unexpected_entry"}, true},
		{"linux-cron-fetch", []string{"persist.unexpected_entry"}, true},
		{"linux-suid-in-world-writable", []string{"fs.suid_unexpected"}, false},
	} {
		r := byCase[tc.name]
		if strings.Join(r.ModelIDs, ",") != strings.Join(tc.filed, ",") || r.Metrics.Resolved != tc.resolved {
			t.Errorf("%s: filed %v resolved %v, want %v %v", tc.name, r.ModelIDs, r.Metrics.Resolved, tc.filed, tc.resolved)
		}
		if r.Bounded == nil || r.Bounded.Source != "scripted" || r.Bounded.Requests == 0 {
			t.Errorf("%s: bounded record %+v", tc.name, r.Bounded)
		}
	}
	// No case reports a forbidden id, and every case that should abstain
	// does: a candidate nothing explains is not a finding.
	for name, r := range byCase {
		if r.Metrics.FalsePositives != 0 {
			t.Errorf("%s: %d false positives (%v)", name, r.Metrics.FalsePositives, r.ModelIDs)
		}
		if r.Status != "complete" {
			t.Errorf("%s: status %q", name, r.Status)
		}
	}
	if r := byCase["linux-truncated-listeners"]; r.Bounded == nil || r.Bounded.Counts()[bounded.StatusInsufficient] == 0 {
		t.Errorf("truncated listeners: %+v", r.Bounded)
	}
	if r := byCase["linux-context-explains"]; r.Bounded == nil || r.Bounded.Counts()[bounded.StatusFiltered] == 0 {
		t.Errorf("context-explains: %+v", r.Bounded)
	}
	// Rule findings are the same in every arm: the arms differ in what they
	// add, never in what the rules concluded (criteria §1).
	for _, c := range s.Cases {
		var sig string
		for _, r := range res.Runs {
			if r.Case != c.Name {
				continue
			}
			got := ruleSignature(r.Findings)
			if sig == "" {
				sig = got
			} else if got != sig {
				t.Errorf("%s: %s arm rule findings %q differ from %q", c.Name, r.Arm, got, sig)
			}
		}
	}
	md := res.Markdown()
	for _, want := range []string{"## Bounded arm", "answer source `scripted`", "not** a quality claim", "| bounded |", "Outside this arm's design", "linux-no-firewall (fw.no_firewall_active)"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
}

// A record without the agent and single-pass arms states no phase 2
// verdict: the frozen criteria compare those two.
func TestVerdictsNeedTheFrozenArms(t *testing.T) {
	s, err := load(t).Select([]string{"linux-clean"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Execute(context.Background(), Options{Suite: s, Arms: []Arm{ArmRules, ArmBounded}, Answers: ScriptedAnswers,
		Profile: check.ProfileBaseline})
	if err != nil {
		t.Fatal(err)
	}
	v := res.Verdicts()
	if len(v) != 1 || v[0].Pass || !strings.Contains(v[0].Criterion, "not evaluated") {
		t.Errorf("verdicts: %+v", v)
	}
	if len(res.ArmsRun) != 2 {
		t.Errorf("arms: %v", res.ArmsRun)
	}
}

// ParseArms keeps comparison order and rejects a name that is not an arm.
func TestParseArms(t *testing.T) {
	got, err := ParseArms([]string{"bounded", "rules"})
	if err != nil || len(got) != 2 || got[0] != ArmRules || got[1] != ArmBounded {
		t.Errorf("%v %v", got, err)
	}
	// An unqualified run compares the frozen three; the research arm is
	// asked for by name.
	if def, err := ParseArms(nil); err != nil || len(def) != 3 || slices.Contains(def, ArmBounded) {
		t.Errorf("default arms: %v %v", def, err)
	}
	if all, err := ParseArms([]string{"rules", "single-pass", "agent", "bounded"}); err != nil || len(all) != 4 {
		t.Errorf("all arms: %v %v", all, err)
	}
	if _, err := ParseArms([]string{"llm"}); err == nil {
		t.Error("unknown arm accepted")
	}
}
