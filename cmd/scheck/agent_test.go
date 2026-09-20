package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/config"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/mock"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
	"github.com/b87/scheck/internal/target/fixture"
)

func agentFixture() *fixture.Target {
	return fixture.New(check.Linux,
		fixture.Exec{Argv: []string{"uname", "-s"}, Stdout: "Linux\n"},
		fixture.Exec{Argv: []string{"uname", "-a"}, Stdout: "Linux box 6.8.0 x86_64\n"},
		fixture.Exec{Argv: []string{"uname", "-n"}, Stdout: "box\n"},
		fixture.Exec{Argv: []string{"id", "-u"}, Stdout: "1000\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/machine-id"}, Stdout: "0123456789abcdef0123456789abcdef\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/os-release"}, Stdout: "PRETTY_NAME=\"Ubuntu 24.04\"\n"},
		fixture.Exec{Argv: []string{"ss", "-tulpnH"}, Stdout: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"},
		fixture.Exec{Argv: []string{"realpath", "/etc/hosts"}, Stdout: "/etc/hosts\n"},
		fixture.Exec{Argv: []string{"cat", "/etc/hosts"}, Stdout: "127.0.0.1 localhost\n"},
	)
}

// agentSession is the CLI's own phase 1 + phase 2 path over a fixture
// target and a mock transcript.
func agentSession(t *testing.T, tr mock.Transcript, format string, tune func(*policy.Budgets)) (*session, *baseline.FactSheet) {
	t.Helper()
	red, _ := policy.NewRedactor(nil)
	b := policy.DefaultBudgets()
	if tune != nil {
		tune(&b)
	}
	r := &runner.Runner{Target: agentFixture(), Paths: policy.NewPathPolicy(nil), Redactor: red, Budgets: b, Elevate: runner.ElevateNone}
	sess := &session{opts: &globalOpts{Format: format, NoPersist: true}, cfg: &config.Config{Model: "mock-model"},
		budgets: b, runner: r, started: time.Now(), elevate: runner.ElevateNone, canary: "n/a", provider: mock.New(tr)}
	sheet := baseline.Run(context.Background(), r, baseline.Plan(check.Linux, nil), nil)
	return sess, sheet
}

func schemaFor(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "report-schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("report-schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("report-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The M2.4 demo end to end through the CLI's path: a full report with a
// model finding in it, in both renderers, validating against the schema.
func TestAgentRunProducesFullReport(t *testing.T) {
	tr := mock.Transcript{Turns: []mock.Turn{
		{ToolCalls: []mock.Call{{ID: "c1", Name: "read_file", Input: json.RawMessage(`{"path":"/etc/hosts","rationale":"r"}`)}}},
		{ToolCalls: []mock.Call{{ID: "c2", Name: "report_finding", Input: json.RawMessage(`{"id":"net.unexpected_listener","confidence":"medium","service":{"port":22,"proto":"tcp"},"evidence":[{"check":"net.listeners","excerpt":"0.0.0.0:22"}]}`)}}},
		{Text: "sshd is the only listener; nothing else to report.", Usage: &llm.Usage{Input: 1200, Output: 80}},
	}}
	sess, sheet := agentSession(t, tr, "json", nil)
	sess.runAgent(context.Background(), sheet)
	var out bytes.Buffer
	err := reportAndExit(sess, &out, sheet)
	if got := exitCodeOf(err); got != exitFindings {
		t.Fatalf("exit %d (%v)", got, err)
	}
	var doc any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemaFor(t).Validate(doc); err != nil {
		t.Fatalf("schema violation:\n%v", err)
	}
	var env struct {
		Run struct {
			Mode          string      `json:"mode"`
			Assessment    string      `json:"assessment"`
			Status        string      `json:"status"`
			Provider      *string     `json:"provider"`
			Model         *string     `json:"model"`
			Native        *llm.Native `json:"native"`
			Limits        *llm.Limits `json:"limits"`
			Usage         llm.Usage   `json:"usage"`
			PromptVersion string      `json:"prompt_version"`
			Agent         *struct {
				Iterations, Checks, Reported int
				Ended, Text                  string
			} `json:"agent"`
		} `json:"run"`
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	r := env.Run
	if r.Mode != "agent" || r.Assessment != "agent" || r.Status != "complete" || r.Provider == nil || *r.Provider != "mock" || *r.Model != "mock-model" {
		t.Errorf("run block: %+v", r)
	}
	if r.Native == nil || !r.Native.ToolCalling || r.Limits == nil || r.Limits.MaxContext == 0 || r.Usage.Input != 1200 || r.Usage.CostUSD != nil || !strings.HasPrefix(r.PromptVersion, "sp-") {
		t.Errorf("provider block: %+v", r)
	}
	if r.Agent == nil || r.Agent.Iterations != 3 || r.Agent.Checks != 1 || r.Agent.Reported != 1 || r.Agent.Ended != "model stopped" || r.Agent.Text == "" {
		t.Errorf("agent block: %+v", r.Agent)
	}
	var model *finding.Finding
	for i := range env.Findings {
		if env.Findings[i].Source == finding.SourceModel {
			model = &env.Findings[i]
		}
	}
	if model == nil || model.ID != finding.IDUnexpectedListener || model.Severity != finding.SevMedium || model.Service == nil {
		t.Fatalf("model finding: %+v", model)
	}
	// Text renders the same run.
	sess.opts.Format = "text"
	var text bytes.Buffer
	_ = reportAndExit(sess, &text, sheet)
	for _, want := range []string{"net.unexpected_listener", "Model summary", "sshd is the only listener", "agent pass (mock, mock-model; 3 turns, 1 model-initiated check", "Model findings carry code-assigned severity"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
}

// An agentic pass that hits a budget or a context limit ends the run
// incomplete with exit 2, keeping the facts and findings (docs/SPEC.md §5.3).
func TestIncompleteAgentRunExitsTwo(t *testing.T) {
	tr := mock.Transcript{Limits: llm.Limits{MaxContext: 500}, Turns: []mock.Turn{{Text: "never"}}}
	sess, sheet := agentSession(t, tr, "json", nil)
	sess.runAgent(context.Background(), sheet)
	var out bytes.Buffer
	err := reportAndExit(sess, &out, sheet)
	if got := exitCodeOf(err); got != exitIncomplete {
		t.Fatalf("exit %d (%v)", got, err)
	}
	var env struct {
		Run struct {
			Status   string                 `json:"status"`
			Warnings []string               `json:"warnings"`
			Agent    struct{ Ended string } `json:"agent"`
		} `json:"run"`
		Facts       map[string]any `json:"facts"`
		Assessments []any          `json:"assessments"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Run.Status != "incomplete" || len(env.Facts) == 0 || len(env.Assessments) == 0 || !strings.Contains(env.Run.Agent.Ended, "context limit") {
		t.Errorf("incomplete report: %+v", env.Run)
	}
	joined := strings.Join(env.Run.Warnings, " ")
	if !strings.Contains(joined, "AI assessment did not finish") || !strings.Contains(joined, "no evidence was dropped") {
		t.Errorf("warnings: %v", env.Run.Warnings)
	}
	if err := schemaFor(t).Validate(mustAny(t, out.Bytes())); err != nil {
		t.Fatalf("schema violation:\n%v", err)
	}
}

func mustAny(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Provider selection fails before any target is contacted: a missing
// transcript, a deferred adapter, the reference adapter that is not built
// yet, --local-only and allow_egress: false each exit 3 with no report.
func TestAgentModeConfigurationErrorsExitThree(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{"local", "--provider", "mock"},
		{"local", "--provider", "anthropic", "--model", "x"},
		{"local", "--provider", "ollama", "--model", "x"},
		{"local", "--provider", "nope", "--model", "x"},
		{"local", "--model", "gpt-5", "--local-only"},
		{"local", "--provider", "mock", "--transcript", filepath.Join(dir, "missing.json")},
		{"local", "--only", "network", "--stop-after", "facts"},
	}
	for _, args := range cases {
		out, code := runIn(t, dir, args...)
		if code != exitUsage || out != "" {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "allow_egress: false\nmodel: gpt-5\n")
	if out, code := runIn(t, dir, "local"); code != exitUsage || out != "" {
		t.Errorf("allow_egress false: exit %d %q", code, out)
	}
	// --stop-after facts ignores provider settings entirely.
	writeFile(t, filepath.Join(dir, "scheck.yaml"), "provider: anthropic\n")
	if _, code := runIn(t, dir, "local", "--stop-after", "plan"); code != exitOK {
		t.Errorf("plan with a deferred provider configured: exit %d", code)
	}
}

// The reference adapter's configuration errors are usage errors before any
// target contact: no key on OpenAI's endpoint, an unknown context window;
// `scheck providers` reports the same states without a request.
func TestOpenAICompatibleConfiguration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENAI_API_KEY", "")
	_ = os.Unsetenv("OPENAI_API_KEY")
	if out, code := runIn(t, dir, "local"); code != exitUsage || out != "" {
		t.Errorf("default luna, no key: exit %d %q", code, out)
	}
	if out, code := runIn(t, dir, "local", "--model", "gpt-5"); code != exitUsage || out != "" {
		t.Errorf("no key: exit %d %q", code, out)
	}
	t.Setenv("OPENAI_API_KEY", "sk-test")
	if out, code := runIn(t, dir, "local", "--model", "mystery-7b"); code != exitUsage || out != "" {
		t.Errorf("unknown window: exit %d %q", code, out)
	}
	out, code := runIn(t, dir, "providers", "--model", "gpt-5", "--format", "json")
	if code != exitOK {
		t.Fatalf("providers: exit %d", code)
	}
	var doc struct {
		Providers []providerStatus `json:"providers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Providers {
		if p.Name != "openai-compatible" {
			continue
		}
		if p.Status != "ready" || p.Limits == nil || p.Limits.MaxContext != 400000 || p.Native == nil || !p.Native.ToolCalling || p.Native.PromptCaching {
			t.Errorf("openai-compatible: %+v", p)
		}
	}
	if strings.Contains(out, "sk-test") {
		t.Error("credential printed")
	}
	out, code = runIn(t, dir, "providers", "--format", "json")
	if code != exitOK {
		t.Fatalf("providers default model: exit %d", code)
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Providers {
		if p.Name != "openai-compatible" {
			continue
		}
		if p.Status != "ready" || p.Limits == nil || p.Limits.MaxContext != 1050000 {
			t.Errorf("default luna window: %+v", p)
		}
	}
	out, _ = runIn(t, dir, "providers", "--model", "mystery-7b", "--base-url", "http://localhost:8000/v1", "--max-context", "8192")
	if !strings.Contains(out, "openai-compatible") || !strings.Contains(out, "ready") || !strings.Contains(out, "8192") {
		t.Errorf("declared window not honoured:\n%s", out)
	}
}

// The hidden eval command runs the suite with the mock provider and emits
// the record; it never contacts a live target.
func TestEvalCommandWithMock(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"eval", "--provider", "mock", "--suite", filepath.Join("..", "..", "testdata", "eval"),
		"--corpus", filepath.Join("..", "..", "testdata", "context"), "--repeat", "1", "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Live     bool     `json:"live"`
		Provider string   `json:"provider"`
		Notes    []string `json:"notes"`
		Runs     []struct {
			Arm string `json:"arm"`
		} `json:"runs"`
		Pairs []any `json:"pairs"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Live || res.Provider != "mock" || len(res.Notes) == 0 || len(res.Runs) < 45 || len(res.Pairs) != 8 {
		t.Errorf("record: live=%v provider=%s runs=%d pairs=%d", res.Live, res.Provider, len(res.Runs), len(res.Pairs))
	}
	root = newRootCmd()
	out.Reset()
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"eval", "--provider", "mock", "--suite", filepath.Join("..", "..", "testdata", "eval"), "--no-pairs"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "# Phase 2 evaluation") || !strings.Contains(out.String(), "not** a pass or fail") {
		t.Errorf("markdown:\n%s", out.String())
	}
	// --cases narrows the suite and --out receives the record (rewritten
	// after every run); progress lines go to stderr without -v.
	root = newRootCmd()
	out.Reset()
	var errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	record := filepath.Join(t.TempDir(), "record.md")
	root.SetArgs([]string{"eval", "--provider", "mock", "--suite", filepath.Join("..", "..", "testdata", "eval"), "--no-pairs",
		"--cases", "linux-clean", "--out", record})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(record)
	if err != nil || !strings.Contains(string(raw), "| linux-clean |") || strings.Contains(string(raw), "| macos-clean |") || out.Len() != 0 {
		t.Errorf("record: %v stdout=%q\n%s", err, out.String(), raw)
	}
	if !strings.Contains(errOut.String(), "below the frozen minimums") || !strings.Contains(errOut.String(), "unexpected=") {
		t.Errorf("stderr:\n%s", errOut.String())
	}
}
