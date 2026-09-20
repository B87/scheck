package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	_ "github.com/b87/scheck/internal/check/all"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/mock"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

// A small Linux host: password auth on, sshd public, a config file the
// model can read, and a sensitive file it cannot.
func host() *fixture.Target {
	return fixture.New(check.Linux,
		fixture.Exec{Argv: []string{"uname", "-s"}, Stdout: "Linux\n"},
		fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux box 6.8.0 x86_64\n"},
		fixture.Exec{Argv: []string{"uname", "-n"}, Stdout: "box\n"},
		fixture.Exec{Argv: []string{"id", "-u"}, Stdout: "0\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/machine-id"}, Stdout: "0123456789abcdef0123456789abcdef\n"},
		fixture.Exec{Argv: []string{"sshd", "-T"}, Stdout: "passwordauthentication yes\npermitrootlogin no\nlistenaddress 0.0.0.0:22\n"},
		fixture.Exec{Argv: []string{"ss", "-tulpnH"}, Stdout: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=7,fd=3))\n"},
		fixture.Exec{Argv: []string{"realpath", "/etc/ssh/sshd_config"}, Stdout: "/etc/ssh/sshd_config\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/ssh/sshd_config"}, Stdout: "PasswordAuthentication yes\nPermitRootLogin no\n# token=AKIAIOSFODNN7EXAMPLE\n"},
		fixture.Exec{Argv: []string{"realpath", "/etc/shadow"}, Stdout: "/etc/shadow\n"},
		fixture.Exec{Argv: []string{"stat", "-c", "%A:%a:%U:%G:%s:%F:%N", "/etc/shadow"}, Stdout: "-rw-r-----:640:root:shadow:1024:regular file:'/etc/shadow'\n"},
		fixture.Exec{Argv: []string{"realpath", "/root/.ssh/id_rsa"}, Stdout: "/root/.ssh/id_rsa\n"},
		fixture.Exec{Argv: []string{"stat", "-c", "%A:%a:%U:%G:%s:%F:%N", "/root/.ssh/id_rsa"}, Stdout: "-rw-------:600:root:root:2602:regular file:'/root/.ssh/id_rsa'\n"},
		fixture.Exec{Argv: []string{"realpath", "/etc/hosts"}, Stdout: "/etc/hosts\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/hosts"}, Stdout: "127.0.0.1 localhost\n"},
		fixture.Exec{Argv: []string{"ls", "-la", "/etc/ssh"}, Stdout: "total 1\n-rw-r--r-- 1 root root 3 sshd_config\n"},
	)
}

type harness struct {
	sess  *Session
	audit *bytes.Buffer
	mock  *mock.Provider
	fx    *fixture.Target
}

func newHarness(t *testing.T, tr mock.Transcript, tune func(*policy.Budgets)) *harness {
	t.Helper()
	fx := host()
	var audit bytes.Buffer
	red, _ := policy.NewRedactor(nil)
	b := policy.DefaultBudgets()
	if tune != nil {
		tune(&b)
	}
	r := &runner.Runner{Target: fx, Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: b, Audit: policy.NewAudit(&audit), Elevate: runner.ElevateRoot}
	sheet := baseline.Run(context.Background(), r, baseline.Plan(check.Linux, nil), nil)
	in := finding.Input{Sheet: sheet, Profile: check.ProfileBaseline}
	store := finding.NewStore(in)
	rules := finding.Evaluate(in)
	p := mock.New(tr)
	return &harness{
		sess:  &Session{Provider: p, Runner: r, Store: store, Sheet: sheet, Rules: rules, Profile: check.ProfileBaseline, Budgets: b, Model: "m"},
		audit: &audit, mock: p, fx: fx,
	}
}

func call(id, name string, input any) mock.Call {
	raw, _ := json.Marshal(input)
	return mock.Call{ID: id, Name: name, Input: raw}
}

func turns(ts ...mock.Turn) mock.Transcript { return mock.Transcript{Turns: ts} }

func (h *harness) auditLines(t *testing.T) []policy.AuditEntry {
	t.Helper()
	var out []policy.AuditEntry
	for line := range strings.SplitSeq(strings.TrimSpace(h.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var e policy.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func lastResults(h *harness) []llm.ToolResult {
	reqs := h.mock.Requests()
	if len(reqs) == 0 {
		return nil
	}
	msgs := reqs[len(reqs)-1].Messages
	return msgs[len(msgs)-1].ToolResults
}

// The demo transcript: investigate with both tools, then report a
// correlated finding by merging evidence into the rule finding, and a new
// model finding; the run completes.
func TestCorrelatedFindingEndToEnd(t *testing.T) {
	h := newHarness(t, turns(
		mock.Turn{Text: "Checking sshd exposure.", ToolCalls: []mock.Call{
			call("c1", "read_file", readFileInput{Path: "/etc/ssh/sshd_config", Rationale: "confirm the effective config source"}),
			call("c2", "run_check", runCheckInput{ID: "fs.list", Params: map[string]string{"path": "/etc/ssh"}, Rationale: "see drop-ins"}),
		}},
		mock.Turn{ToolCalls: []mock.Call{
			call("c3", "report_finding", map[string]any{"id": finding.IDPasswordAuthEnabled, "confidence": "high", "severity": "info",
				"context_note": "sshd listens on every address", "evidence": []map[string]string{
					{"observation": "net.listeners#1", "excerpt": "0.0.0.0:22"}, {"observation": "text.cat#1", "excerpt": "PasswordAuthentication yes"}}}),
			call("c4", "report_finding", map[string]any{"id": finding.IDPasswordAuthExposed, "confidence": "medium",
				"evidence": []map[string]string{{"observation": "sshd.config#1", "excerpt": "listenaddress 0.0.0.0:22"}}}),
		}, Expect: &mock.Expect{ToolResults: []string{"c1", "c2"}, Contains: []string{"PasswordAuthentication yes", "[REDACTED:aws-access-key:20 bytes]"}, NotContains: []string{"AKIAIOSFODNN7EXAMPLE"}}},
		mock.Turn{Text: "Password authentication is enabled on a public listener.", Expect: &mock.Expect{ToolResults: []string{"c3", "c4"}}},
	), nil)
	out := h.sess.Run(context.Background())
	if !out.Complete() || out.Iterations != 3 || out.Checks != 2 || out.Reported != 2 || out.Text == "" {
		t.Fatalf("outcome: %+v", out)
	}
	res := h.sess.Store.Result()
	byID := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byID[f.ID] = f
	}
	pw := byID[finding.IDPasswordAuthEnabled]
	if pw.Source != finding.SourceRule || len(pw.Evidence) != 3 || pw.Severity != finding.SevMedium || !strings.Contains(pw.ContextNote, "model:") {
		t.Errorf("merged rule finding: %+v", pw)
	}
	if ex := byID[finding.IDPasswordAuthExposed]; ex.Source != finding.SourceModel || ex.Severity != finding.SevHigh || ex.Confidence != finding.ConfidenceMedium {
		t.Errorf("model finding: %+v", ex)
	}
	// The prompt carried the facts, the rule findings, the catalog and the
	// redacted output, never the secret.
	first := mock.Serialize(h.mock.Requests()[0])
	for _, want := range []string{"<facts>", "### sshd.config", "passwordauthentication yes", "<rule_findings>", finding.IDPasswordAuthEnabled, "<finding_catalog>", "- fs.list {path:absolute path}", "read-only security auditor"} {
		if !strings.Contains(first, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
	if strings.Contains(first, "sys.canary") || strings.Contains(first, "AKIA") {
		t.Error("prompt exposes the canary or a secret")
	}
}

// read_file and text.cat produce byte-identical audit records apart from
// the tool name: the sugar is a caller of the one enforcement point, not a
// second path (docs/SPEC.md §5.7).
func TestReadFileIsTextCat(t *testing.T) {
	h := newHarness(t, turns(
		mock.Turn{ToolCalls: []mock.Call{
			call("a", "read_file", readFileInput{Path: "/etc/hosts", Rationale: "r"}),
			call("b", "run_check", runCheckInput{ID: "text.cat", Params: map[string]string{"path": "/etc/hosts"}, Rationale: "r"}),
		}},
		mock.Turn{Text: "done"},
	), nil)
	if out := h.sess.Run(context.Background()); !out.Complete() {
		t.Fatalf("%+v", out)
	}
	var lines []policy.AuditEntry
	for _, e := range h.auditLines(t) {
		if e.CheckID == "text.cat" {
			lines = append(lines, e)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("%d text.cat audit lines", len(lines))
	}
	a, b := lines[0], lines[1]
	if a.Tool != "read_file" || b.Tool != "run_check" {
		t.Fatalf("tools %q %q", a.Tool, b.Tool)
	}
	if a.Observation == b.Observation || a.Observation == "" {
		t.Fatal("repeated reads must be distinct")
	}
	a.Observation, b.Observation = "", ""
	a.Tool, b.Tool = "", ""
	a.Time, b.Time = time.Time{}, time.Time{}
	a.DurationMS, b.DurationMS = 0, 0
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("audit records differ:\n%s\n%s", ja, jb)
	}
	results := h.mock.Requests()[1].Messages[2].ToolResults
	if strings.ReplaceAll(results[0].Content, "text.cat#1", "text.cat#2") != results[1].Content {
		t.Errorf("tool results differ:\n%s\n%s", results[0].Content, results[1].Content)
	}
}

// Unknown id, invalid param kind, denied path, elevated check under
// --elevate none and a hidden (profile-gated) check each get an error
// result the model can correct from, and each is in the audit log.
func TestErrorResultsAreAudited(t *testing.T) {
	h := newHarness(t, turns(
		mock.Turn{ToolCalls: []mock.Call{
			call("u", "run_check", runCheckInput{ID: "fs.nope", Rationale: "r"}),
			call("p", "run_check", runCheckInput{ID: "text.head", Params: map[string]string{"lines": "lots", "path": "/etc/hosts"}, Rationale: "r"}),
			call("d", "read_file", readFileInput{Path: "/proc/1/environ"}),
			call("s", "read_file", readFileInput{Path: "/root/.ssh/id_rsa"}),
			call("e", "run_check", runCheckInput{ID: "sshd.config", Rationale: "r"}),
			call("h", "run_check", runCheckInput{ID: "sys.which", Params: map[string]string{"name": "sudo"}, Rationale: "r"}),
			call("c", "run_check", runCheckInput{ID: "sys.canary", Rationale: "r"}),
			call("t", "nonsense", map[string]string{}),
			call("m", "run_check", json.RawMessage(`"not an object"`)),
		}},
		mock.Turn{Text: "corrected", Expect: &mock.Expect{ErrorResults: []string{"u", "p", "d", "e", "h", "c", "t", "m"}}},
	), nil)
	h.sess.Runner.Elevate = runner.ElevateNone
	if out := h.sess.Run(context.Background()); !out.Complete() {
		t.Fatalf("%+v", out)
	}
	results := map[string]llm.ToolResult{}
	for _, r := range lastResults(h) {
		results[r.CallID] = r
	}
	if !strings.Contains(results["u"].Content, "valid_ids") || !strings.Contains(results["u"].Content, "fs.list") {
		t.Errorf("unknown id result: %s", results["u"].Content)
	}
	if !strings.Contains(results["p"].Content, "lines") {
		t.Errorf("invalid param result: %s", results["p"].Content)
	}
	if !strings.Contains(results["d"].Content, "denied") {
		t.Errorf("denied path result: %s", results["d"].Content)
	}
	// A sensitive file answers with metadata, not an error.
	if results["s"].IsError || !strings.Contains(results["s"].Content, "600") || strings.Contains(results["s"].Content, "BEGIN") {
		t.Errorf("sensitive path result: %+v", results["s"])
	}
	if !strings.Contains(results["e"].Content, "elevat") {
		t.Errorf("elevated result: %s", results["e"].Content)
	}
	if !strings.Contains(results["h"].Content, "unknown check id") || !strings.Contains(results["c"].Content, "unknown check id") {
		t.Errorf("hidden checks: %s / %s", results["h"].Content, results["c"].Content)
	}
	decisions := map[string]int{}
	for _, e := range h.auditLines(t) {
		if e.Tool != "" {
			decisions[e.Decision]++
		}
	}
	for _, want := range []string{"denied:unknown_check", "denied:param", "denied:path.not_allowed", "unavailable:requires_elevation"} {
		if decisions[want] == 0 {
			t.Errorf("no %s audit line; got %v", want, decisions)
		}
	}
	if decisions["denied:unknown_check"] != 3 {
		t.Errorf("unknown/hidden checks audited %d times, want 3", decisions["denied:unknown_check"])
	}
}

// A report_finding with a severity has it ignored; custom findings are
// capped at medium and flagged; text replacement and suppression of a rule
// finding are refused; duplicate evidence collapses (docs/SPEC.md §7.1, §7.5).
func TestReportFindingContract(t *testing.T) {
	h := newHarness(t, turns(
		mock.Turn{ToolCalls: []mock.Call{
			call("r1", "report_finding", map[string]any{"id": finding.IDPasswordAuthEnabled, "confidence": "low", "severity": "info", "title": "nothing", "impact": "none", "remediation": map[string]any{"summary": "ignore"},
				"evidence": []map[string]string{{"observation": "sshd.config#1", "excerpt": "passwordauthentication yes"}}}),
			call("r2", "report_finding", map[string]any{"id": "custom:vendor-agent", "confidence": "high", "proposed_severity": "critical", "title": "Vendor agent", "impact": "x", "remediation": map[string]any{"summary": "y"},
				"evidence": []map[string]string{{"observation": "net.listeners#1", "excerpt": "0.0.0.0:22"}}}),
			call("r3", "report_finding", map[string]any{"id": finding.IDRootLoginEnabled, "confidence": "high",
				"evidence": []map[string]string{{"observation": "sshd.config#1", "excerpt": "permitrootlogin yes"}}}),
		}},
		mock.Turn{Text: "done", Expect: &mock.Expect{ToolResults: []string{"r1", "r2"}, ErrorResults: []string{"r3"}}},
	), nil)
	if out := h.sess.Run(context.Background()); !out.Complete() || out.Reported != 2 {
		t.Fatalf("%+v", out)
	}
	res := h.sess.Store.Result()
	byID := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byID[f.ID] = f
	}
	def, _ := finding.Lookup(finding.IDPasswordAuthEnabled)
	pw := byID[finding.IDPasswordAuthEnabled]
	if pw.Severity != finding.SevMedium || pw.Title != def.Title || pw.Impact != def.Impact || pw.Confidence != finding.ConfidenceHigh || len(pw.Evidence) != 1 {
		t.Errorf("rule finding altered: %+v", pw)
	}
	if c := byID["custom:vendor-agent"]; !c.Custom || c.Severity != finding.SevMedium || c.Category != finding.CategoryCustom {
		t.Errorf("custom: %+v", c)
	}
	if _, fabricated := byID[finding.IDRootLoginEnabled]; fabricated {
		t.Error("a finding with a fabricated excerpt was stored")
	}
	if len(res.Findings) != 2 {
		t.Errorf("%d findings", len(res.Findings))
	}
}

// Every loop-owned budget, exhausted by a crafted transcript, ends the run
// incomplete (docs/SPEC.md §4.4, §5.6).
func TestEveryBudgetEndsIncomplete(t *testing.T) {
	investigate := func(id string) mock.Turn {
		return mock.Turn{ToolCalls: []mock.Call{call(id, "read_file", readFileInput{Path: "/etc/hosts"})}}
	}
	cases := []struct {
		name   string
		tr     mock.Transcript
		tune   func(*policy.Budgets)
		ctx    func() (context.Context, context.CancelFunc)
		reason string
	}{
		{"MaxIterations", turns(investigate("a"), investigate("b"), investigate("c")), func(b *policy.Budgets) { b.MaxIterations = 2 }, nil, "MaxIterations"},
		{"AgentChecks", turns(mock.Turn{ToolCalls: []mock.Call{call("a", "read_file", readFileInput{Path: "/etc/hosts"}), call("b", "read_file", readFileInput{Path: "/etc/hosts"})}}, mock.Turn{Text: "x"}),
			func(b *policy.Budgets) { b.AgentChecks = 1 }, nil, "AgentChecks"},
		{"AgentWallClock", turns(investigate("a"), investigate("b"), mock.Turn{Text: "x"}), func(b *policy.Budgets) { b.AgentWallClock = 1 }, nil, "AgentWallClock"},
		{"ModelInputTotal", turns(investigate("a"), mock.Turn{Text: "x"}), func(b *policy.Budgets) { b.ModelInputTotal = 700 }, nil, "ModelInputTotal"},
		{"MaxTokens", turns(mock.Turn{Text: "cut", StopReason: llm.StopMaxTokens}), func(b *policy.Budgets) { b.MaxTokens = 5 }, nil, "MaxTokens"},
		{"RunTimeout", turns(investigate("a"), mock.Turn{Text: "x"}), nil, func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, "RunTimeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.tr, tc.tune)
			ctx := context.Background()
			if tc.ctx != nil {
				var cancel context.CancelFunc
				ctx, cancel = tc.ctx()
				defer cancel()
			}
			out := h.sess.Run(ctx)
			if out.Complete() || !strings.Contains(out.Reason, tc.reason) {
				t.Fatalf("outcome %+v", out)
			}
		})
	}
	// The wall-clock case: the second call must not have run.
	h := newHarness(t, turns(investigate("a"), investigate("b"), mock.Turn{Text: "x"}), func(b *policy.Budgets) { b.AgentWallClock = 1 })
	h.sess.Run(context.Background())
	n := 0
	for _, e := range h.auditLines(t) {
		if e.Tool == "read_file" && e.Decision == "run" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d read_file executions after the wall-clock budget, want 1", n)
	}
}

// Before every model call the whole request plus the output reservation is
// checked against the context limit; overflow sends nothing, keeps the
// facts and findings, and ends incomplete (docs/SPEC.md §5.3).
func TestContextLimitGuards(t *testing.T) {
	t.Run("initial overflow", func(t *testing.T) {
		tr := turns(mock.Turn{Text: "never"})
		tr.Limits = llm.Limits{MaxContext: 2000}
		h := newHarness(t, tr, nil)
		out := h.sess.Run(context.Background())
		if out.Complete() || !strings.Contains(out.Reason, "context limit") || out.Iterations != 0 {
			t.Fatalf("%+v", out)
		}
		if len(h.mock.Requests()) != 0 {
			t.Error("an oversized request was sent")
		}
		if n := len(h.sess.Store.Result().Findings); n == 0 {
			t.Error("rule findings were lost")
		}
	})
	t.Run("history growth", func(t *testing.T) {
		tr := turns(
			mock.Turn{ToolCalls: []mock.Call{call("a", "read_file", readFileInput{Path: "/etc/ssh/sshd_config"})}},
			mock.Turn{Text: "never"},
		)
		tr.Limits = llm.Limits{MaxContext: 0}
		h := newHarness(t, tr, nil)
		// Size the limit so the first request fits and the second does not.
		first := llm.Estimate(llm.Request{System: []llm.Block{{Text: systemPrompt}, {Text: catalogBlock() + factsBlock(h.sess.Sheet) + findingsBlock(h.sess.Rules)}}, Tools: h.sess.tools(), Messages: []llm.Message{{Role: llm.RoleUser, Text: strings.Repeat("x", 300)}}, MaxTokens: h.sess.Budgets.MaxTokens})
		tr.Limits = llm.Limits{MaxContext: first + h.sess.Budgets.MaxTokens + 20}
		h = newHarness(t, tr, nil)
		out := h.sess.Run(context.Background())
		if out.Complete() || !strings.Contains(out.Reason, "outgrew") || out.Iterations != 1 {
			t.Fatalf("%+v", out)
		}
		if len(h.mock.Requests()) != 1 {
			t.Errorf("%d requests sent, want 1", len(h.mock.Requests()))
		}
	})
	t.Run("output reservation", func(t *testing.T) {
		tr := turns(mock.Turn{Text: "x"})
		h := newHarness(t, tr, nil)
		est := llm.Estimate(llm.Request{System: []llm.Block{{Text: systemPrompt}, {Text: catalogBlock() + factsBlock(h.sess.Sheet) + findingsBlock(h.sess.Rules)}}, Tools: h.sess.tools(), Messages: []llm.Message{{Role: llm.RoleUser, Text: strings.Repeat("x", 300)}}})
		tr.Limits = llm.Limits{MaxContext: est + 100} // fits without the reservation, not with it
		h = newHarness(t, tr, func(b *policy.Budgets) { b.MaxTokens = 4000 })
		if out := h.sess.Run(context.Background()); out.Complete() || len(h.mock.Requests()) != 0 {
			t.Fatalf("reservation not counted: %+v", out)
		}
	})
	t.Run("unknown limit", func(t *testing.T) {
		tr := turns(mock.Turn{Text: "x"})
		h := newHarness(t, tr, nil)
		// mock.New defaults a zero limit; force the unknown case through a
		// provider that declares nothing.
		h.sess.Provider = unknownLimits{h.mock}
		out := h.sess.Run(context.Background())
		if out.Complete() || !strings.Contains(out.Reason, "context limit unknown") || len(h.mock.Requests()) != 0 {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("provider overflow", func(t *testing.T) {
		h := newHarness(t, turns(mock.Turn{Fail: llm.ErrContextOverflow}), nil)
		out := h.sess.Run(context.Background())
		if out.Complete() || !strings.Contains(out.Reason, "provider rejected") || !strings.Contains(out.Reason, "no evidence was dropped") {
			t.Fatalf("%+v", out)
		}
		if len(h.mock.Requests()) != 1 {
			t.Errorf("%d requests, want exactly 1 (no retry)", len(h.mock.Requests()))
		}
	})
}

type unknownLimits struct{ *mock.Provider }

func (unknownLimits) Limits() llm.Limits { return llm.Limits{} }

// Single-pass is the same loop with MaxIterations 1: a turn that only
// reports is complete; one that asks for evidence it cannot receive is not.
func TestSinglePass(t *testing.T) {
	report := call("r", "report_finding", map[string]any{"id": finding.IDPasswordAuthExposed, "confidence": "medium",
		"evidence": []map[string]string{{"observation": "sshd.config#1", "excerpt": "listenaddress 0.0.0.0:22"}}})
	h := newHarness(t, turns(mock.Turn{Text: "one pass", ToolCalls: []mock.Call{report}}), func(b *policy.Budgets) { b.MaxIterations = 1 })
	out := h.sess.Run(context.Background())
	if !out.Complete() || out.Reported != 1 || h.sess.Mode() != "single-pass" {
		t.Fatalf("%+v mode %s", out, h.sess.Mode())
	}
	h = newHarness(t, turns(mock.Turn{ToolCalls: []mock.Call{report, call("i", "read_file", readFileInput{Path: "/etc/hosts"})}}), func(b *policy.Budgets) { b.MaxIterations = 1 })
	out = h.sess.Run(context.Background())
	if out.Complete() || !strings.Contains(out.Reason, "unanswered") || out.Reported != 1 {
		t.Fatalf("%+v", out)
	}
	// The stop reasons the model can produce.
	for _, tc := range []struct {
		stop llm.StopReason
		want string
	}{{llm.StopRefusal, "refused"}, {llm.StopError, "error"}} {
		h := newHarness(t, turns(mock.Turn{Text: "x", StopReason: tc.stop}), nil)
		if out := h.sess.Run(context.Background()); out.Complete() || !strings.Contains(out.Reason, tc.want) {
			t.Errorf("%s: %+v", tc.stop, out)
		}
	}
}

// The context block is in the prompt exactly as --stop-after context prints
// it, or absent under --ignore-context.
func TestContextBlockInPrompt(t *testing.T) {
	h := newHarness(t, turns(mock.Turn{Text: "x"}), nil)
	h.sess.Context = nil
	h.sess.Run(context.Background())
	if strings.Contains(mock.Serialize(h.mock.Requests()[0]), "<operator_context>") {
		t.Error("context block present with no context")
	}
}
