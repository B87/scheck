package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm/mock"
	"github.com/b87/scheck/internal/report"
	"github.com/b87/scheck/internal/state"
)

// Offline M2.6a demo: two file reads remain independently citable after both
// return. The same finding keeps both references, including through persistence.
func TestObservationCitationsEndToEnd(t *testing.T) {
	candidate := func(ref, excerpt string) finding.Candidate {
		return finding.Candidate{ID: "custom:file-review", Title: "File review", Confidence: "high", ProposedSeverity: "medium",
			Impact: "Fixture demonstration", Remediation: &finding.Remediation{Summary: "Review configuration"},
			Evidence: []finding.Evidence{{Observation: ref, Excerpt: excerpt}}}
	}
	h := newHarness(t, turns(
		mock.Turn{ToolCalls: []mock.Call{
			call("first", toolReadFile, map[string]string{"path": "/etc/ssh/sshd_config"}),
			call("second", toolReadFile, map[string]string{"path": "/etc/hosts"}),
			call("denied", toolReadFile, map[string]string{"path": "/tmp/forbidden"}),
			call("unavailable", toolReadFile, map[string]string{"path": "/etc/missing"}),
		}},
		mock.Turn{ToolCalls: []mock.Call{
			call("cite-first", toolReportFinding, candidate("text.cat#1", "PasswordAuthentication yes")),
			call("cite-second", toolReportFinding, candidate("text.cat#2", "127.0.0.1 localhost")),
			call("cross", toolReportFinding, candidate("text.cat#1", "127.0.0.1 localhost")),
			call("unknown", toolReportFinding, candidate("text.cat#999", "PasswordAuthentication yes")),
			call("no-output", toolReportFinding, candidate("text.cat#3", "forbidden")),
		}},
		mock.Turn{Text: "Done", Expect: &mock.Expect{ErrorResults: []string{"cross", "unknown", "no-output"}}},
	), nil)
	outcome := h.sess.Run(context.Background())
	if !outcome.Complete() || outcome.Reported != 2 {
		t.Fatalf("outcome: %+v", outcome)
	}
	result := h.sess.Store.Result()
	env := report.Build(h.sess.Sheet, report.Meta{Started: time.Now(), Profile: "baseline", Transport: "fixture", Elevation: "root", Canary: "n/a", Result: &result})
	var demo *finding.Finding
	for i := range env.Findings {
		if env.Findings[i].ID == "custom:file-review" {
			demo = &env.Findings[i]
		}
	}
	if demo == nil || len(demo.Evidence) != 2 {
		t.Fatalf("lost merged citations: %+v", demo)
	}
	for _, e := range demo.Evidence {
		obs, ok := env.Observations[e.Observation]
		if !ok || obs.Check != e.Check || !strings.Contains(obs.Output, e.Excerpt) {
			t.Fatalf("unresolved evidence %+v", e)
		}
	}
	for _, a := range env.Assessments {
		if a.Observation == "" && a.Reason == "" {
			t.Fatalf("unexplained missing observation %+v", a)
		}
	}
	var compact, full bytes.Buffer
	if err := report.WriteJSON(&compact, env); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteJSONEvidence(&full, env, true); err != nil {
		t.Fatal(err)
	}
	path, err := state.Write(t.TempDir(), &env)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved report.Envelope
	if err := json.Unmarshal(persisted, &saved); err != nil {
		t.Fatal(err)
	}
	for _, e := range demo.Evidence {
		if _, ok := saved.Observations[e.Observation]; !ok {
			t.Fatalf("persisted citation missing: %s", e.Observation)
		}
	}
	requests, _ := json.Marshal(h.mock.Requests())
	// The marker must survive wherever the capture is carried (the model's
	// tool result, the opt-in evidence report); default JSON and persistence
	// carry no capture at all, so they must simply not leak.
	for name, artifact := range map[string]string{"model": string(requests), "audit": h.audit.String(), "compact": compact.String(), "full": full.String(), "persisted": string(persisted)} {
		if strings.Contains(artifact, "AKIAIOSFODNN7EXAMPLE") || ((name == "model" || name == "full") && !strings.Contains(artifact, "[REDACTED:")) {
			t.Errorf("%s leaked secret or lost marker", name)
		}
	}
	for _, artifact := range []string{compact.String(), string(persisted)} {
		if strings.Contains(artifact, `"stdout"`) || strings.Contains(artifact, `"stderr"`) {
			t.Fatal("default artifact includes raw captures")
		}
	}
	if !strings.Contains(full.String(), `"stdout"`) {
		t.Fatal("opt-in evidence missing")
	}
}
