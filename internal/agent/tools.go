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
	Observation string   `json:"observation"`
	Error       string   `json:"error,omitempty"`
	ValidIDs    []string `json:"valid_ids,omitempty"`
	Check       string   `json:"check"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Output      string   `json:"output,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`
	Redactions  int      `json:"redactions,omitempty"`
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
	// Three live contracts showed the model calling report_finding to record
	// a hypothesis it had ruled out ("UFW is active", filed under
	// fw.no_firewall_active) whatever the prose said. The tool now has a
	// verdict for that: ruled_out files nothing and is shown with the
	// model's summary (docs/SPEC.md §5.7).
	reportFindingDesc = "Record the verdict on one finding id. verdict: open (the default) files a problem that is present on the host. verdict: ruled_out records that you checked the id and it does not apply (an active firewall under fw.no_firewall_active, a narrow sudo grant under privesc.sudo_nopasswd_broad): nothing is filed, the note is shown with your summary, and the same id can still be reported open later on new evidence. Never file something you found in order as open. Choose a catalog finding id (see <finding_catalog>) or custom:<slug> only when no catalog id fits. Cite evidence with the exact observation reference and a verbatim excerpt of its output; a ruled-out verdict needs a note and may cite evidence the same way. Different invocations of a check have different references. Do not send a severity: scheck grades. Reporting an id open that a posture rule already produced adds your evidence and context note to it; a rule finding cannot be ruled out."
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
				"verdict":    map[string]any{"type": "string", "enum": []string{finding.VerdictOpen, finding.VerdictRuledOut}, "description": "open files a finding (the default); ruled_out files nothing and records the note"},
				"note":       map[string]any{"type": "string", "description": "ruled_out only: what you checked and why the id does not apply"},
				"title":      map[string]any{"type": "string", "description": "custom findings only"},
				"confidence": map[string]any{"type": "string", "enum": []string{"high", "medium", "low"}},
				"evidence": map[string]any{"type": "array", "items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"observation": map[string]any{"type": "string", "description": "the exact observation reference whose output holds the excerpt"},
						"excerpt":     map[string]any{"type": "string", "description": "a verbatim excerpt of that output"},
					},
					"required": []string{"observation", "excerpt"},
				}},
				"impact":            map[string]any{"type": "string"},
				"remediation":       map[string]any{"type": "object", "properties": map[string]any{"summary": map[string]any{"type": "string"}, "commands": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "caveat": map[string]any{"type": "string"}}},
				"context_note":      map[string]any{"type": "string", "description": "how operator context bears on this finding"},
				"proposed_severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}, "description": "custom findings only; capped at medium"},
				"service":           map[string]any{"type": "object", "properties": map[string]any{"port": map[string]any{"type": "integer"}, "proto": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}}}, "required": []string{"port"}, "description": "for a network finding: the listener it is about"},
			},
			"required": []string{"id"},
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
	out := checkResult{Observation: res.Observation, Check: res.CheckID, Status: string(res.Status), Reason: res.Reason}

	if s.Log != nil {
		s.Log("%s %s %v: %s %s", o.Tool, res.CheckID, res.Params, res.Status, res.Reason)
	}
	switch res.Status {
	case runner.StatusDenied:
		out.Error = fmt.Sprintf("%s: denied by policy (%s)", res.CheckID, res.Reason)
		if res.ReasonCode == "unknown_check" {
			out.Error = fmt.Sprintf("unknown check id %q", res.CheckID)
			out.ValidIDs = s.menuIDs
		}
	case runner.StatusUnavailable:
		if res.ReasonCode == "requires_elevation" || res.ReasonCode == "sudo_refused" {
			out.Error = fmt.Sprintf("%s: %s; this cannot be obtained in this run, do not infer anything from its absence", res.CheckID, res.Reason)
		}
	case runner.StatusOK:
		c, _ := check.Lookup(res.RanAs, s.Sheet.Platform)
		out.Summary = check.Summary(c, res.Parsed)
		if s.account(len(res.Raw)) {
			out.Output, out.Truncated, out.Redactions = res.Raw, res.Truncated, res.Redactions
		} else {
			out.Error = "the model-input budget for this run is exhausted; report what you have"
		}
	}
	return s.jsonResult(callID, out, out.Error != "")
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
	switch cand.Verdict {
	case "", finding.VerdictOpen:
	case finding.VerdictRuledOut:
		r, err := s.Store.RuleOut(cand)
		if err != nil {
			return s.errorResult(c.ID, err.Error(), nil)
		}
		if s.Log != nil {
			s.Log("report_finding %s: ruled out", r.ID)
		}
		return s.jsonResult(c.ID, struct {
			RuledOut string `json:"ruled_out"`
			Note     string `json:"note"`
		}{r.ID, "nothing was filed; this is shown with your closing summary"}, false)
	default:
		return s.errorResult(c.ID, fmt.Sprintf("verdict must be %s or %s, got %q", finding.VerdictOpen, finding.VerdictRuledOut, cand.Verdict), nil)
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
