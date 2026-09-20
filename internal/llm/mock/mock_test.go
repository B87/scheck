package mock

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/conformance"
)

func harness(t *testing.T, s conformance.Script) llm.Provider {
	t.Helper()
	tr := Transcript{Limits: s.Limits, Native: s.Native}
	for _, turn := range s.Turns {
		mt := Turn{Text: turn.Text, StopReason: turn.StopReason, Fail: turn.Fail}
		u := turn.Usage
		mt.Usage = &u
		for _, c := range turn.ToolCalls {
			mt.ToolCalls = append(mt.ToolCalls, Call{ID: c.ID, Name: c.Name, Input: c.Input})
		}
		tr.Turns = append(tr.Turns, mt)
	}
	return New(tr)
}

// The mock passes the same table every real adapter must pass (docs/SPEC.md §11).
func TestConformance(t *testing.T) { conformance.Run(t, Name, harness) }

// A transcript file drives a three-turn tool-calling exchange, asserted
// turn by turn, and the provider records what it was sent.
func TestTranscriptReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	raw := `{
	  "limits": {"max_context": 32000},
	  "turns": [
	    {"tool_calls": [{"id": "c1", "name": "run_check", "input": {"id": "sshd.config", "params": {}}}]},
	    {"tool_calls": [{"id": "c2", "name": "read_file", "input": {"path": "/etc/ssh/sshd_config"}}],
	     "expect": {"tool_results": ["c1"], "contains": ["passwordauthentication yes"]}},
	    {"text": "done", "expect": {"error_results": ["c2"]}}
	  ]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := llm.Build(Name, llm.Config{Transcript: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.Limits().MaxContext != 32000 || !p.Native().ToolCalling {
		t.Fatalf("declared %+v %+v", p.Limits(), p.Native())
	}
	ctx := context.Background()
	req := llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Text: "go"}}}
	r1, err := llm.Complete(ctx, p, req)
	if err != nil || len(r1.ToolCalls) != 1 || r1.ToolCalls[0].Name != "run_check" || r1.StopReason != llm.StopToolUse {
		t.Fatalf("turn 1: %+v %v", r1, err)
	}
	// Turn 2 expects c1's result and a substring; send them.
	req.Messages = append(req.Messages,
		llm.Message{Role: llm.RoleAssistant, ToolCalls: r1.ToolCalls},
		llm.Message{Role: llm.RoleUser, ToolResults: []llm.ToolResult{{CallID: "c1", Content: "passwordauthentication yes"}}})
	r2, err := llm.Complete(ctx, p, req)
	if err != nil || len(r2.ToolCalls) != 1 || r2.ToolCalls[0].Name != "read_file" {
		t.Fatalf("turn 2: %+v %v", r2, err)
	}
	// Turn 3 expects c2 to have been answered with an error; first send a
	// non-error and watch the expectation fail, then the right thing.
	bad := req
	bad.Messages = append(bad.Messages,
		llm.Message{Role: llm.RoleAssistant, ToolCalls: r2.ToolCalls},
		llm.Message{Role: llm.RoleUser, ToolResults: []llm.ToolResult{{CallID: "c2", Content: "contents"}}})
	if _, err := llm.Complete(ctx, p, bad); err == nil {
		t.Fatal("expectation violation went unreported")
	}
	// The failed turn was consumed; the transcript is now exhausted.
	if _, err := llm.Complete(ctx, p, bad); err == nil || llm.KindOf(err) != llm.ErrResponse {
		t.Fatalf("exhausted transcript: %v", err)
	}
	mp := p.(*Provider)
	if n := len(mp.Requests()); n != 4 {
		t.Errorf("recorded %d requests, want 4", n)
	}
	var in map[string]any
	if err := json.Unmarshal(r1.ToolCalls[0].Input, &in); err != nil || in["id"] != "sshd.config" {
		t.Errorf("tool call input not round-tripped: %s", r1.ToolCalls[0].Input)
	}
}

func TestMissingTranscriptIsAnError(t *testing.T) {
	if _, err := llm.Build(Name, llm.Config{}); err == nil {
		t.Fatal("mock without --transcript built")
	}
	if _, err := llm.Build(Name, llm.Config{Transcript: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Fatal("missing transcript file built")
	}
}
