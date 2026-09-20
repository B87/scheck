package agent

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

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/mock"
	"github.com/b87/scheck/internal/report"
)

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

// envelope builds the report a phase 2 pass produces, the way the harness
// does. No CLI path reaches this in 0.0.1 (docs/SPEC.md §2.1); the envelope
// contract still has to hold for the evaluation harness and for whatever
// revives the loop, so it is pinned here rather than in cmd/scheck.
func envelope(t *testing.T, h *harness, out Outcome) report.Envelope {
	t.Helper()
	res := h.sess.Store.Result()
	ended := "model stopped"
	if !out.Complete() {
		ended = out.Reason
	}
	p := h.sess.Provider
	return report.Build(h.sess.Sheet, report.Meta{
		Started: time.Now(), Profile: "baseline", Transport: "fixture", Elevation: "root", Canary: "n/a",
		Result: &res,
		Phase2: &report.Phase2{
			Provider: p.Name(), Model: "mock-model", Native: p.Native(), Limits: p.Limits(), Usage: out.Usage,
			Mode: h.sess.Mode(), PromptVersion: PromptVersion, Complete: out.Complete(), Reason: out.Reason,
			Agent: report.AgentRun{Iterations: out.Iterations, Checks: out.Checks, Reported: out.Reported,
				Ended: ended, Text: out.Text, RuledOut: res.RuledOut},
		},
	})
}

// A complete pass: the provider block, the agent block and a graded model
// finding, in an envelope that validates against docs/report-schema.json
// and renders in the text report.
func TestAgentEnvelopeValidatesAgainstSchema(t *testing.T) {
	h := newHarness(t, turns(
		mock.Turn{ToolCalls: []mock.Call{call("c1", toolReadFile, map[string]string{"path": "/etc/hosts", "rationale": "r"})}},
		mock.Turn{ToolCalls: []mock.Call{call("c2", toolReportFinding, map[string]any{
			"id": finding.IDUnexpectedListener, "confidence": "medium", "service": map[string]any{"port": 22, "proto": "tcp"},
			"evidence": []map[string]string{{"observation": "net.listeners#1", "excerpt": "0.0.0.0:22"}}})}},
		mock.Turn{Text: "sshd is the only listener; nothing else to report.", Usage: &llm.Usage{Input: 1200, Output: 80}},
	), nil)
	out := h.sess.Run(context.Background())
	if !out.Complete() {
		t.Fatalf("outcome: %+v", out)
	}
	env := envelope(t, h, out)
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, env); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemaFor(t).Validate(doc); err != nil {
		t.Fatalf("schema violation:\n%v", err)
	}
	r := env.Run
	if r.Mode != "agent" || r.Assessment != "agent" || r.Status != "complete" || r.Provider == nil || *r.Provider != "mock" {
		t.Errorf("run block: %+v", r)
	}
	if r.Native == nil || !r.Native.ToolCalling || r.Limits == nil || r.Limits.MaxContext == 0 || r.Usage.Input != 1200 || !strings.HasPrefix(r.PromptVersion, "sp-") {
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
	var text bytes.Buffer
	if err := report.WriteText(&text, env, report.Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"net.unexpected_listener", "Model summary", "sshd is the only listener",
		"agent pass (mock, mock-model; 3 turns, 1 model-initiated check", "Model findings carry code-assigned severity"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
}

// A pass that hits a context limit leaves an incomplete report that keeps
// the facts and the rule findings and says what happened, without dropping
// evidence to make the request fit (docs/SPEC.md §5.3).
func TestIncompleteAgentEnvelopeKeepsFacts(t *testing.T) {
	h := newHarness(t, mock.Transcript{Limits: llm.Limits{MaxContext: 500}, Turns: []mock.Turn{{Text: "never"}}}, nil)
	out := h.sess.Run(context.Background())
	if out.Complete() {
		t.Fatalf("outcome: %+v", out)
	}
	env := envelope(t, h, out)
	if env.Run.Status != "incomplete" || len(env.Facts) == 0 || len(env.Assessments) == 0 ||
		env.Run.Agent == nil || !strings.Contains(env.Run.Agent.Ended, "context limit") {
		t.Errorf("incomplete report: %+v", env.Run)
	}
	joined := strings.Join(env.Run.Warnings, " ")
	if !strings.Contains(joined, "AI assessment did not finish") || !strings.Contains(joined, "no evidence was dropped") {
		t.Errorf("warnings: %v", env.Run.Warnings)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, env); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemaFor(t).Validate(doc); err != nil {
		t.Fatalf("schema violation:\n%v", err)
	}
}
