package bounded

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/baseline"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// harness replays a recorded fixture through the real runner and returns
// everything a bounded run needs. Nothing here touches a network or a host.
type harness struct {
	sheet *baseline.FactSheet
	run   *runner.Runner
	store *finding.Store
	audit *strings.Builder
}

// newHarness replays dir. elevate mirrors how the fixture was recorded:
// ubuntu and fedora were recorded with --sudo, macos unprivileged.
func newHarness(t *testing.T, dir string, elevate runner.Elevation) *harness {
	t.Helper()
	fx, err := fixture.Load(dir)
	if err != nil {
		t.Fatalf("fixture %s: %v", dir, err)
	}
	var audit strings.Builder
	red, err := policy.NewRedactor(nil)
	if err != nil {
		t.Fatalf("redactor: %v", err)
	}
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red,
		Budgets: policy.DefaultBudgets(), Audit: policy.NewAudit(&audit), Elevate: elevate}
	sheet := baseline.Run(context.Background(), r, baseline.Plan(fx.Platform(), nil), nil)
	return &harness{sheet: sheet, run: r, store: finding.NewStore(finding.Input{Sheet: sheet}), audit: &audit}
}

func ubuntu(t *testing.T) *harness {
	return newHarness(t, filepath.Join("..", "..", "testdata", "fixtures", "ubuntu"), runner.ElevateSudo)
}

// recorder answers with a fixed map and keeps every request, so a test can
// assert what would have been sent to a model.
type recorder struct {
	answers map[string]float64
	byKey   map[string]map[string]float64
	seen    []Request
	err     error
}

func (r *recorder) Source() string { return "test" }

func (r *recorder) Answer(_ context.Context, req Request) (map[string]float64, error) {
	r.seen = append(r.seen, req)
	if r.err != nil {
		return nil, r.err
	}
	if a, ok := r.byKey[req.ItemKey]; ok {
		return a, nil
	}
	return r.answers, nil
}

// benign is an answer set that files nothing under any rule: the item is
// recognized, no hallmarks, and a person's account.
var benign = map[string]float64{QExplained: 0, QVendor: 1, QHallmarks: 0, QSensitive: 1, QPerson: 1}

func run(t *testing.T, h *harness, a Answerer, ctx *operator.Merged) *Result {
	t.Helper()
	res, err := Run(context.Background(), Options{Sheet: h.sheet, Runner: h.run, Store: h.store,
		Context: ctx, Answers: a, Budgets: policy.DefaultBudgets()})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func find(items []Item, key string) (Item, bool) {
	for _, it := range items {
		if it.Key == key {
			return it, true
		}
	}
	return Item{}, false
}

// The deterministic filters are the point of the design: what code can
// settle is settled by code and never becomes a question.
func TestFiltersSettleWhatCodeKnows(t *testing.T) {
	h := ubuntu(t)
	items := Enumerate(h.sheet, nil)
	for _, tc := range []struct{ key, status, reason string }{
		{"listener:22/tcp", StatusInsufficient, "the capture does not name the owning process"},
		{"admin:root", StatusFiltered, "root is the account uid 0 names"},
		{"admin:%sudo", StatusFiltered, "a distribution's own administrative principal"},
		{"admin:ops", StatusFiltered, "the sudo grant lists specific commands, not ALL"},
		{"suid:/usr/bin/sudo", StatusJudged, ""},
		{"unit:ssh.socket", StatusJudged, ""},
	} {
		it, ok := find(items, tc.key)
		if !ok {
			t.Fatalf("%s was not enumerated", tc.key)
		}
		if it.Status != tc.status || (tc.reason != "" && it.Reason != tc.reason) {
			t.Errorf("%s: status %q reason %q, want %q %q", tc.key, it.Status, it.Reason, tc.status, tc.reason)
		}
	}
}

// A declared service is §6.3's answer, in code. Asking about it produced a
// phase 2 false positive (docs/eval/phase2-results.md).
func TestDeclaredServiceIsNeverAsked(t *testing.T) {
	h := ubuntu(t)
	ctx := &operator.Merged{Structured: operator.Structured{
		Role:             "bastion",
		ExpectedServices: []operator.Service{{Port: 22, Proto: "tcp", Purpose: "ssh"}},
	}}
	rec := &recorder{answers: benign}
	res := run(t, h, rec, ctx)
	it, ok := find(res.Items, "listener:22/tcp")
	if !ok || it.Status != StatusFiltered {
		t.Fatalf("listener:22/tcp = %+v, want filtered", it)
	}
	for _, req := range rec.seen {
		if req.ItemKey == "listener:22/tcp" {
			t.Fatal("a declared listener was sent to the answer source")
		}
	}
}

// Truncated or redacted evidence is insufficient: it is never sent and
// never filed, however the questions would have been answered.
func TestInsufficientEvidenceIsNeverSentOrFiled(t *testing.T) {
	h := newHarness(t, filepath.Join("testdata", "truncated"), runner.ElevateNone)
	// An answer set that would file every kind if it were ever asked.
	damning := map[string]float64{QExplained: 0, QVendor: 0, QHallmarks: 1, QSensitive: 1, QPerson: 0}
	rec := &recorder{answers: damning}
	res := run(t, h, rec, nil)
	if len(res.Items) == 0 {
		t.Fatal("no listeners enumerated from the truncated capture")
	}
	for _, it := range res.Items {
		if it.Status != StatusInsufficient {
			t.Errorf("%s: status %q, want insufficient", it.Key, it.Status)
		}
	}
	if len(rec.seen) != 0 {
		t.Errorf("%d requests sent for insufficient evidence", len(rec.seen))
	}
	if len(res.Filed) != 0 {
		t.Errorf("filed %v from insufficient evidence", res.Filed)
	}
}

// A listener whose capture does not name the owning process cannot be
// judged: `ss` names it only for a privileged session, and asking anyway
// answers "not a known component" for every listener on an unprivileged run,
// which is the phase 2 false positive (sshd on 0.0.0.0:22) refiled by a
// different route. Found by the R3 probe's dry run, 2026-09-21.
func TestListenerWithoutAProcessIsNotJudged(t *testing.T) {
	h := ubuntu(t)
	damning := map[string]float64{QExplained: 0, QVendor: 0, QHallmarks: 1, QSensitive: 1, QPerson: 0}
	rec := &recorder{answers: damning}
	res := run(t, h, rec, nil)
	it, ok := find(res.Items, "listener:22/tcp")
	if !ok || it.Status != StatusInsufficient {
		t.Fatalf("listener:22/tcp = %+v, want insufficient", it)
	}
	for _, req := range rec.seen {
		if req.Kind == KindListener {
			t.Errorf("a listener with no process name was sent: %s", req.ItemKey)
		}
	}
	if slices.Contains(res.Filed, finding.IDUnexpectedListener) {
		t.Errorf("filed %v", res.Filed)
	}
}

// One state holds one item. Accuracy falls as unrelated detail grows
// (jev-1.13 limitation 5), and an item's judgement must not depend on
// another item's evidence.
func TestStateCarriesOnlyItsOwnItem(t *testing.T) {
	h := ubuntu(t)
	rec := &recorder{answers: benign}
	res := run(t, h, rec, &operator.Merged{Structured: operator.Structured{Role: "bastion", Exposure: "internet"}})
	if len(rec.seen) < 10 {
		t.Fatalf("only %d requests", len(rec.seen))
	}
	other := map[string]bool{"/opt/tool/bin/helper": true, "agent.service": true}
	for _, req := range rec.seen {
		raw, err := json.Marshal(req.State)
		if err != nil {
			t.Fatal(err)
		}
		state := string(raw)
		for o := range other {
			if strings.Contains(state, o) {
				t.Errorf("%s: state mentions %q", req.ItemKey, o)
			}
		}
		if !strings.Contains(state, `"role":"bastion"`) {
			t.Errorf("%s: state does not carry the declared role: %s", req.ItemKey, state)
		}
		// Every item of another kind is absent: a listener's state never
		// carries a unit, an account or a binary.
		for _, it := range res.Items {
			if it.Key == req.ItemKey || it.Kind == req.Kind {
				continue
			}
			if v := it.Fields["path"]; v != "" && strings.Contains(state, v) {
				t.Errorf("%s: state carries %s's evidence", req.ItemKey, it.Key)
			}
		}
	}
}

// Context that does not bear on an item is left out: expected_services is a
// listener's business and nothing else's.
func TestUnrelatedContextIsLeftOut(t *testing.T) {
	ctx := &operator.Merged{Structured: operator.Structured{
		ExpectedServices: []operator.Service{{Port: 5432, Proto: "tcp", Purpose: "postgres"}},
	}}
	unit := Item{Kind: KindPersistence, Key: "unit:agent.service", Fields: map[string]string{"unit": "agent.service"}}
	if s := StateFor(unit, ctx); len(s.DeclaredServices) != 0 {
		t.Errorf("a unit's state carries declared services: %+v", s.DeclaredServices)
	}
	listener := Item{Kind: KindListener, Key: "listener:5432/tcp", Fields: map[string]string{"port": "5432", "protocol": "tcp"}}
	if s := StateFor(listener, ctx); len(s.DeclaredServices) != 1 {
		t.Errorf("the listener's own declared service is missing: %+v", s)
	}
}

// Absent context is stated, not omitted: jev-1.13 reads instructions
// literally, and a missing field is not an answer.
func TestUndeclaredContextIsSpelledOut(t *testing.T) {
	s := StateFor(Item{Kind: KindAdmin, Platform: "linux", Fields: map[string]string{"account": "deploy"}}, nil)
	if s.Host.Role != "not declared" || s.Host.Exposure != "not declared" || s.Host.Platform != "linux" {
		t.Errorf("host state = %+v", s.Host)
	}
}

// Every follow-up read goes through the runner and lands in the audit log
// under this arm's origin (AGENTS.md rule 3).
func TestFollowUpReadsGoThroughTheRunner(t *testing.T) {
	h := newHarness(t, filepath.Join("..", "..", "testdata", "eval", "cases", "linux-unit-in-tmp"), runner.ElevateSudo)
	rec := &recorder{answers: benign}
	res := run(t, h, rec, nil)
	it, ok := find(res.Items, "unit:agent.service")
	if !ok || it.FollowUp == nil || it.FollowUp.Status != string(runner.StatusOK) {
		t.Fatalf("unit:agent.service follow-up = %+v", it.FollowUp)
	}
	if it.FollowUp.Check != "text.cat" || it.FollowUp.Path != "/etc/systemd/system/agent.service" {
		t.Errorf("follow-up = %+v", it.FollowUp)
	}
	var reads int
	for line := range strings.SplitSeq(strings.TrimSpace(h.audit.String()), "\n") {
		var e policy.AuditEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.Tool == "" {
			continue
		}
		if e.Tool != OriginTool {
			t.Errorf("audit tool = %q", e.Tool)
		}
		reads++
	}
	if reads != res.FollowUps+1 { // the reads are the unit file and the one directory listing
		t.Errorf("%d audited reads, %d follow-ups", reads, res.FollowUps)
	}
	// The state the model would see carries what code read.
	for _, req := range rec.seen {
		if req.ItemKey == "unit:agent.service" && !strings.Contains(req.State.Definition, "/tmp/.x/agent") {
			t.Errorf("the unit's definition did not reach its state: %q", req.State.Definition)
		}
	}
}

// A read the policy denies is a note in the state, not a failure and not a
// finding: the affirmative-evidence rule has nothing to stand on.
func TestUnreadableDefinitionIsRecordedNotConcluded(t *testing.T) {
	it := Item{Kind: KindPersistence, Key: "unit:x.service",
		FollowUp: &FollowUp{Check: "text.cat", Path: "/etc/systemd/system/x.service", Status: "denied", Reason: "path.not_allowed"}}
	s := StateFor(it, nil)
	if s.Definition != "" || !strings.Contains(s.DefinitionNote, "denied") {
		t.Errorf("state = %+v", s)
	}
}

// A missing, malformed or out-of-range answer files nothing and marks the
// item. Typed output guarantees the shape, never the value.
func TestUnusableAnswersFileNothing(t *testing.T) {
	for name, answers := range map[string]map[string]float64{
		"missing":   {QVendor: 0.1},
		"too large": {QExplained: 1.4, QVendor: 0.1, QHallmarks: 0.9, QSensitive: 0.2, QPerson: 0},
		"negative":  {QExplained: -0.1, QVendor: 0.1, QHallmarks: 0.9, QSensitive: 0.2, QPerson: 0},
		"nan":       {QExplained: math.NaN(), QVendor: 0, QHallmarks: 1, QSensitive: 1, QPerson: 0},
	} {
		t.Run(name, func(t *testing.T) {
			h := ubuntu(t)
			res := run(t, h, &recorder{answers: answers}, nil)
			if len(res.Filed) != 0 {
				t.Errorf("filed %v", res.Filed)
			}
			marked := 0
			for _, it := range res.Items {
				if it.Status == StatusNoAnswer {
					marked++
				}
			}
			if marked == 0 {
				t.Error("no item was marked as unanswered")
			}
		})
	}
}

// Nothing is filed because the context failed to mention something. Every
// rule needs an affirmative signal; this is the deterministic answer to the
// phase 2 false positives.
func TestSilenceAloneFilesNothing(t *testing.T) {
	unexplainedButOrdinary := map[string]float64{QExplained: 0, QVendor: 1, QHallmarks: 0, QSensitive: 1, QPerson: 1}
	for _, k := range Kinds {
		it := Item{Kind: k, Answers: unexplainedButOrdinary, Fields: map[string]string{"directory_is_world_writable": "false"}}
		if d := Decide(it, DefaultThresholds()); d.File {
			t.Errorf("%s: filed on an unexplained but ordinary item: %s", k, d.Reason)
		}
	}
}

// A filed finding carries evidence the store validated against the exact
// observation, and the severity the catalog assigns — never one a model
// proposed (docs/SPEC.md §7.1).
func TestFiledFindingIsValidatedAndGradedByCode(t *testing.T) {
	// macOS names the owning process, so a listener there can be judged.
	h := newHarness(t, filepath.Join("..", "..", "testdata", "eval", "cases", "macos-filevault-off"), runner.ElevateNone)
	rec := &recorder{answers: benign, byKey: map[string]map[string]float64{
		"listener:7000/tcp": {QExplained: 0, QVendor: 0.05, QHallmarks: 0, QSensitive: 0.95, QPerson: 1},
	}}
	res := run(t, h, rec, nil)
	if len(res.Filed) != 1 || res.Filed[0] != finding.IDUnexpectedListener {
		t.Fatalf("filed %v", res.Filed)
	}
	var f finding.Finding
	for _, x := range h.store.Findings() {
		if x.ID == finding.IDUnexpectedListener {
			f = x
		}
	}
	if f.Severity != finding.SevMedium || f.SeverityBase != finding.SevMedium {
		t.Errorf("severity = %s/%s, want the catalog's", f.Severity, f.SeverityBase)
	}
	if len(f.Evidence) == 0 || !strings.Contains(f.Evidence[0].Excerpt, ":7000") {
		t.Errorf("evidence = %+v", f.Evidence)
	}
	if f.Service == nil || f.Service.Port != 7000 {
		t.Errorf("service = %+v", f.Service)
	}
	obs, ok := h.run.Observations().Get(f.Evidence[0].Observation)
	if !ok || !strings.Contains(obs.Raw, f.Evidence[0].Excerpt) {
		t.Errorf("the excerpt is not in the cited observation")
	}
}

// Every kind asks at least two questions, every question defines both
// answers, and every question the rule reads is actually asked.
func TestQuestionSetIsWellFormed(t *testing.T) {
	for _, k := range Kinds {
		qs := Questions(k)
		if len(qs) < 2 {
			t.Errorf("%s: %d questions", k, len(qs))
		}
		asked := map[string]bool{}
		for _, q := range qs {
			if q.Type != "noul" {
				t.Errorf("%s/%s: type %q", k, q.ID, q.Type)
			}
			if q.Criteria == nil || q.Criteria.True == "" || q.Criteria.False == "" {
				t.Errorf("%s/%s: criteria are what pin the boundary down", k, q.ID)
			}
			asked[q.ID] = true
		}
		// Decide reads only what was asked: an answer map holding exactly
		// this kind's ids must be enough to reach a decision.
		full := map[string]float64{}
		for id := range asked {
			full[id] = 0
		}
		if d := Decide(Item{Kind: k, Answers: full, Fields: map[string]string{}}, DefaultThresholds()); d.Reason == "no rule for this kind" {
			t.Errorf("%s: no decision rule", k)
		}
		if _, err := validAnswers(qs, full); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if v := QuestionsVersion(); !strings.HasPrefix(v, "bq-") || len(v) != 15 {
		t.Errorf("questions version = %q", v)
	}
}

// The item budget ends the arm by name, like every other budget.
func TestItemBudgetEndsTheArmByName(t *testing.T) {
	h := ubuntu(t)
	rec := &recorder{answers: benign}
	res, err := Run(context.Background(), Options{Sheet: h.sheet, Runner: h.run, Store: h.store,
		Answers: rec, MaxItems: 3, Budgets: policy.DefaultBudgets()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ended != "budget: items" {
		t.Errorf("ended = %q", res.Ended)
	}
	if len(rec.seen) != 3 {
		t.Errorf("%d requests under a budget of 3", len(rec.seen))
	}
}

// Enumeration reads the fact sheet and nothing else: no check runs.
func TestEnumerateRunsNothing(t *testing.T) {
	h := ubuntu(t)
	before := len(h.run.Observations().All())
	Enumerate(h.sheet, nil)
	if after := len(h.run.Observations().All()); after != before {
		t.Errorf("enumeration ran %d checks", after-before)
	}
}

// macOS enumerates from its own checks: the admin group and the
// third-party launchd plists, which is where the phase 2 false positives
// were.
func TestMacOSEnumeration(t *testing.T) {
	h := newHarness(t, filepath.Join("..", "..", "testdata", "fixtures", "macos"), runner.ElevateNone)
	items := Enumerate(h.sheet, nil)
	want := map[string]Kind{
		"admin:alice": KindAdmin,
		"launchd:/Library/LaunchDaemons/com.docker.vmnetd.plist": KindPersistence,
	}
	for key, kind := range want {
		it, ok := find(items, key)
		if !ok {
			t.Fatalf("%s was not enumerated", key)
		}
		if it.Kind != kind || it.Status != StatusJudged {
			t.Errorf("%s = %s/%s", key, it.Kind, it.Status)
		}
	}
	if it, ok := find(items, "admin:root"); !ok || it.Status != StatusFiltered {
		t.Errorf("admin:root = %+v", it)
	}
}
