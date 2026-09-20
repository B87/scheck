package agent

import (
	"encoding/json"
	"fmt"

	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/runner"
)

// The closed tool surface of docs/SPEC.md §5.7.
const (
	toolRunCheck      = "run_check"
	toolReadFile      = "read_file"
	toolReportFinding = "report_finding"
)

// runCheckInput is what the model sends to run_check.
type runCheckInput struct {
	ID        string            `json:"id"`
	Params    map[string]string `json:"params"`
	Rationale string            `json:"rationale"`
}

type readFileInput struct {
	Path      string `json:"path"`
	Rationale string `json:"rationale"`
}

// checkResult is what run_check and read_file return: the same redacted,
// bounded capture the report shows, never anything else.
type checkResult struct {
	Check      string `json:"check"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Output     string `json:"output,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Redactions int    `json:"redactions,omitempty"`
}

type toolError struct {
	Error    string   `json:"error"`
	ValidIDs []string `json:"valid_ids,omitempty"`
}

// Static tool descriptions. They are part of what the model is told, so
// PromptVersion hashes them with the system prompt (§5.8); the run_check
// menu is per platform and profile and is not.
const (
	readFileDesc = "Read one file by absolute path. Only files under the allowed prefixes (/etc, /usr/local/etc, /opt/*/etc, systemd unit directories, /Library/Launch*) can be read; a sensitive file (shadow, keys, ~/.ssh) answers with its metadata instead of its contents; anything else is denied. Identical to run_check with text.cat."
	// The first live runs showed the model calling report_finding to record
	// a hypothesis it had ruled out ("UFW is active", filed under
	// fw.no_firewall_active). The description says what the tool is not for.
	reportFindingDesc = "Record one open finding: a problem that is present on the host. Never call it for something you checked and found in order, or to note that a hypothesis was ruled out; that belongs in your closing summary, and a call here would file it as an open issue. Choose a catalog finding id (see <finding_catalog>) or custom:<slug> only when no catalog id fits. Cite evidence as verbatim excerpts of check output you have seen. Do not send a severity: scheck grades. Reporting an id that a posture rule already produced adds your evidence and context note to it."
)

func (s *Session) tools() []llm.Tool {
	desc, ids := menu(s.Sheet.Platform, s.Profile)
	s.menuIDs = ids
	return []llm.Tool{
		{Name: toolRunCheck, Description: desc, Schema: llm.MustJSON(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":        map[string]any{"type": "string", "description": "catalog check id"},
				"params":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "parameter values by name; every value is a string"},
				"rationale": map[string]any{"type": "string", "description": "why this check, one sentence; logged, not returned"},
			},
			"required": []string{"id", "rationale"},
		})},
		{Name: toolReadFile, Description: readFileDesc, Schema: llm.MustJSON(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":      map[string]any{"type": "string"},
				"rationale": map[string]any{"type": "string"},
			},
			"required": []string{"path"},
		})},
		{Name: toolReportFinding, Description: reportFindingDesc, Schema: llm.MustJSON(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":         map[string]any{"type": "string"},
				"title":      map[string]any{"type": "string", "description": "custom findings only"},
				"confidence": map[string]any{"type": "string", "enum": []string{"high", "medium", "low"}},
				"evidence": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"check":   map[string]any{"type": "string", "description": "the check id whose output holds the excerpt"},
						"excerpt": map[string]any{"type": "string", "description": "a verbatim excerpt of that output"},
					},
					"required": []string{"check", "excerpt"},
				}},
				"impact":            map[string]any{"type": "string"},
				"remediation":       map[string]any{"type": "object", "properties": map[string]any{"summary": map[string]any{"type": "string"}, "commands": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "caveat": map[string]any{"type": "string"}}},
				"context_note":      map[string]any{"type": "string", "description": "how operator context bears on this finding"},
				"proposed_severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}, "description": "custom findings only; capped at medium"},
				"service":           map[string]any{"type": "object", "properties": map[string]any{"port": map[string]any{"type": "integer"}, "proto": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}}}, "required": []string{"port"}, "description": "for a network finding: the listener it is about"},
			},
			"required": []string{"id", "confidence", "evidence"},
		})},
	}
}

// call executes one tool call and returns the result the model sees. Every
// execution goes through runner.RunAs; the tool is a caller of the one
// enforcement point, never a second path (docs/SPEC.md §4, §5.7).
func (s *Session) call(c llm.ToolCall) llm.ToolResult {
	switch c.Name {
	case toolRunCheck:
		var in runCheckInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return s.errorResult(c.ID, "run_check input must be an object {id, params, rationale}: "+err.Error(), nil)
		}
		if in.ID == "" {
			return s.errorResult(c.ID, "run_check needs an id", s.menuIDs)
		}
		return s.execute(c.ID, in.ID, in.Params, runner.Origin{Tool: toolRunCheck, Rationale: in.Rationale, Profile: s.Profile})
	case toolReadFile:
		var in readFileInput
		if err := json.Unmarshal(c.Input, &in); err != nil {
			return s.errorResult(c.ID, "read_file input must be an object {path, rationale}: "+err.Error(), nil)
		}
		if in.Path == "" {
			return s.errorResult(c.ID, "read_file needs an absolute path", nil)
		}
		// Sugar for text.cat {path}: the same binding, the same policy, the
		// same audit line apart from the tool name.
		return s.execute(c.ID, "text.cat", map[string]string{"path": in.Path}, runner.Origin{Tool: toolReadFile, Rationale: in.Rationale, Profile: s.Profile})
	case toolReportFinding:
		return s.report(c)
	default:
		return s.errorResult(c.ID, fmt.Sprintf("unknown tool %q; the tools are run_check, read_file and report_finding", c.Name), nil)
	}
}

// execute runs a model-initiated check under the agent budgets.
func (s *Session) execute(callID, id string, params map[string]string, o runner.Origin) llm.ToolResult {
	if s.checks >= s.Budgets.AgentChecks {
		s.exhaust("AgentChecks", fmt.Sprintf("%d model-initiated checks", s.Budgets.AgentChecks))
		return s.errorResult(callID, "the check budget for this run is exhausted; report what you have", nil)
	}
	if s.wall >= s.Budgets.AgentWallClock {
		s.exhaust("AgentWallClock", fmt.Sprintf("%s of model-initiated execution", s.Budgets.AgentWallClock))
		return s.errorResult(callID, "the execution time budget for this run is exhausted; report what you have", nil)
	}
	s.checks++
	res := s.Runner.RunAs(s.ctx, id, params, o)
	s.wall += res.Duration
	s.results[id] = res
	if s.Log != nil {
		s.Log("%s %s %v: %s %s", o.Tool, id, params, res.Status, res.Reason)
	}
	switch res.Status {
	case runner.StatusDenied:
		if res.ReasonCode == "unknown_check" {
			return s.errorResult(callID, fmt.Sprintf("unknown check id %q", id), s.menuIDs)
		}
		return s.errorResult(callID, fmt.Sprintf("%s: denied by policy (%s)", id, res.Reason), nil)
	case runner.StatusUnavailable:
		out := checkResult{Check: id, Status: string(res.Status), Reason: res.Reason}
		// An unavailable check is an answer, not an error the model can
		// correct: it must not reason from its absence.
		if res.ReasonCode == "requires_elevation" || res.ReasonCode == "sudo_refused" {
			return s.errorResult(callID, fmt.Sprintf("%s: %s; this cannot be obtained in this run, do not infer anything from its absence", id, res.Reason), nil)
		}
		return s.jsonResult(callID, out, false)
	}
	c, _ := check.Lookup(res.RanAs, s.Sheet.Platform)
	out := checkResult{Check: id, Status: string(res.Status), Reason: res.Reason,
		Summary: check.Summary(c, res.Parsed), Output: res.Raw, Truncated: res.Truncated, Redactions: res.Redactions}
	if !s.account(len(res.Raw)) {
		return s.errorResult(callID, "the model-input budget for this run is exhausted; report what you have", nil)
	}
	return s.jsonResult(callID, out, false)
}

// report validates and stores a candidate through finding.Store, which owns
// the merge contract (docs/SPEC.md §7.5). The loop never edits a finding.
func (s *Session) report(c llm.ToolCall) llm.ToolResult {
	var cand finding.Candidate
	// Unknown fields — a `severity` the model sends anyway — are ignored,
	// not rejected (§7.2).
	if err := json.Unmarshal(c.Input, &cand); err != nil {
		return s.errorResult(c.ID, "report_finding input must be an object: "+err.Error(), nil)
	}
	f, err := s.Store.Report(cand)
	if err != nil {
		return s.errorResult(c.ID, err.Error(), nil)
	}
	s.reported++
	if s.Log != nil {
		s.Log("report_finding %s: %s (%s)", f.ID, f.Severity, f.Status)
	}
	return s.jsonResult(c.ID, struct {
		Recorded string           `json:"recorded"`
		Severity finding.Severity `json:"severity"`
		Status   string           `json:"status"`
		Source   string           `json:"source"`
		Note     string           `json:"note"`
	}{f.ID, f.Severity, f.Status, f.Source, "severity is assigned by scheck; evidence and notes were merged"}, false)
}

func (s *Session) jsonResult(callID string, v any, isErr bool) llm.ToolResult {
	raw, err := json.Marshal(v)
	if err != nil {
		raw = []byte(`{"error":"could not encode result"}`)
		isErr = true
	}
	return llm.ToolResult{CallID: callID, Content: string(raw), IsError: isErr}
}

func (s *Session) errorResult(callID, msg string, validIDs []string) llm.ToolResult {
	if s.Log != nil {
		s.Log("tool error: %s", msg)
	}
	return s.jsonResult(callID, toolError{Error: msg, ValidIDs: validIDs}, true)
}

// output answers finding.Store.Output: the redacted capture of a check that
// ran in phase 1 or on the model's request, so a candidate's excerpt is
// validated against what the host actually said.
func (s *Session) output(id string) (string, bool) {
	if r, ok := s.results[id]; ok && r.Status == runner.StatusOK {
		return r.Raw, true
	}
	if r, ok := s.Sheet.Results[id]; ok && r.Status == runner.StatusOK {
		return r.Raw, true
	}
	return "", false
}
