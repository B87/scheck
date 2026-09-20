// Package agent is phase 2: the tool-calling loop scheck owns (docs/SPEC.md
// §2.1, §5.6). It has one code path. Every execution goes through
// runner.RunAs, every finding through finding.Store, every model call
// through llm.CheckFit and llm.Provider; the loop branches on nothing but
// Limits.MaxContext and its own budgets. Single-pass mode is this loop with
// MaxIterations: 1, not a second implementation.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/finding"
	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/operator"
	"github.com/b87/scheck/internal/policy"
	"github.com/b87/scheck/internal/runner"
)

// Session is one agentic pass over a fact sheet.
type Session struct {
	Provider llm.Provider
	Runner   *runner.Runner
	Store    *finding.Store
	Sheet    *baseline.FactSheet
	Rules    finding.Result // the phase 1 findings and assessments, for the prompt
	Profile  check.Profile
	Budgets  policy.Budgets
	Context  *operator.Merged // nil: omitted from the prompt (--ignore-context)
	Model    string
	Effort   llm.Effort
	// Log receives diagnostics (-v); Progress receives stream events so the
	// CLI can show the model working. Both may be nil.
	Log      func(format string, args ...any)
	Progress func(llm.Event)

	ctx      context.Context
	menuIDs  []string
	checks   int
	reported int
	wall     time.Duration
	input    int // bytes of check output handed to the model (ModelInputTotal)
	stop     *stopReason
}

// Mode names the loop's configuration for the report (docs/SPEC.md §5.6).
func (s *Session) Mode() string {
	if s.Budgets.MaxIterations == 1 {
		return "single-pass"
	}
	return "agent"
}

// Outcome is what the loop reports back: how it ended and what it cost.
// A run that hit any budget is incomplete, never a clean bill of health.
type Outcome struct {
	Status     string `json:"status"` // complete | incomplete
	Reason     string `json:"reason,omitempty"`
	Iterations int    `json:"iterations"`
	Checks     int    `json:"checks"`         // model-initiated
	Reported   int    `json:"reported"`       // accepted report_finding calls
	Text       string `json:"text,omitempty"` // the model's closing summary
	Usage      llm.Usage
	Warnings   []string
}

// Complete reports whether the loop ended because the model stopped.
func (o Outcome) Complete() bool { return o.Status == "complete" }

type stopReason struct {
	budget string
	detail string
}

func (s *Session) exhaust(budget, detail string) {
	if s.stop == nil {
		s.stop = &stopReason{budget, detail}
	}
}

// account adds bytes of check output to the ModelInputTotal budget.
func (s *Session) account(n int) bool {
	s.input += n
	if s.input > s.Budgets.ModelInputTotal {
		s.exhaust("ModelInputTotal", fmt.Sprintf("%d bytes of check output", s.Budgets.ModelInputTotal))
		return false
	}
	return true
}

// Run drives the loop until the model stops calling tools or a budget ends
// the run (docs/SPEC.md §5.6).
func (s *Session) Run(ctx context.Context) Outcome {
	s.ctx = ctx
	out := Outcome{Status: "incomplete", Warnings: []string{}}
	if s.Provider == nil || s.Runner == nil || s.Store == nil || s.Sheet == nil {
		out.Reason = "agent session is not fully configured"
		return out
	}
	s.Store.Output = s.Runner.Observations().Get
	limits := s.Provider.Limits()
	tools := s.tools()
	facts := factsBlock(s.Sheet)
	if !s.account(len(facts)) {
		out.Reason = "the fact sheet alone exceeds the model-input budget (ModelInputTotal)"
		return out
	}
	system := []llm.Block{
		{Text: systemPrompt, Cacheable: true},
		{Text: catalogBlock() + "\n" + facts + "\n" + findingsBlock(s.Rules), Cacheable: true},
	}
	if cb := contextBlock(s.Context); cb != "" {
		system = append(system, llm.Block{Text: cb})
	}
	messages := []llm.Message{{Role: llm.RoleUser, Text: fmt.Sprintf(
		"Assess this host. Budgets for this run: at most %d model-initiated checks, %s of check execution, %d turns. Investigate what needs confirming, report findings with report_finding, then stop and summarise.",
		s.Budgets.AgentChecks, s.Budgets.AgentWallClock, s.Budgets.MaxIterations)}}

	for iter := 0; iter < s.Budgets.MaxIterations; iter++ {
		if err := ctx.Err(); err != nil {
			out.Reason = "run timeout (RunTimeout) before turn " + fmt.Sprint(iter+1)
			return out
		}
		req := llm.Request{Model: s.Model, System: system, Messages: messages, Tools: tools,
			MaxTokens: s.Budgets.MaxTokens, Effort: s.Effort}
		// The whole serialized request plus the output reservation is checked
		// against the context limit before any byte leaves the machine
		// (docs/SPEC.md §5.3). Overflow sends nothing and ends the run.
		if fit, err := llm.CheckFit(req, limits); err != nil {
			if llm.KindOf(err) == llm.ErrUnsupported {
				out.Reason = "context limit unknown: " + err.Error()
				return out
			}
			out.Reason = fmt.Sprintf("the AI assessment could not %s: %s; no evidence was dropped to make it fit",
				startOrContinue(iter), fit)
			return out
		}
		stream, err := s.Provider.Stream(ctx, req)
		if err != nil {
			out.Reason = providerFailure(err)
			return out
		}
		resp, err := llm.Drain(stream, s.Progress)
		_ = stream.Close()
		if err != nil {
			out.Reason = providerFailure(err)
			return out
		}
		out.Iterations = iter + 1
		out.Usage.Add(resp.Usage)
		messages = append(messages, llm.Message{Role: llm.RoleAssistant, Text: resp.Text, ToolCalls: resp.ToolCalls})
		switch resp.StopReason {
		case llm.StopMaxTokens:
			out.Reason = fmt.Sprintf("the model's reply was cut at the per-completion token budget (MaxTokens %d)", s.Budgets.MaxTokens)
			out.Text = resp.Text
			return out
		case llm.StopRefusal:
			out.Reason = "the model refused to continue"
			out.Text = resp.Text
			return out
		case llm.StopError:
			out.Reason = "the provider reported an error mid-reply"
			return out
		}
		if len(resp.ToolCalls) == 0 {
			out.Status, out.Text = "complete", resp.Text
			out.Checks, out.Reported = s.checks, s.reported
			return out
		}
		results := make([]llm.ToolResult, 0, len(resp.ToolCalls))
		investigating := 0
		for _, call := range resp.ToolCalls {
			if call.Name != toolReportFinding {
				investigating++
			}
			results = append(results, s.call(call))
			if s.stop != nil {
				break
			}
		}
		for i := len(results); i < len(resp.ToolCalls); i++ {
			results = append(results, llm.ToolResult{CallID: resp.ToolCalls[i].ID, Content: `{"error":"not executed: a run budget was exhausted"}`, IsError: true})
		}
		messages = append(messages, llm.Message{Role: llm.RoleUser, ToolResults: results})
		out.Checks, out.Reported = s.checks, s.reported
		if s.stop != nil {
			out.Reason = fmt.Sprintf("budget exhausted: %s (%s)", s.stop.budget, s.stop.detail)
			return out
		}
		if iter == s.Budgets.MaxIterations-1 {
			// The last permitted turn. A turn that only reported findings is
			// a finished pass (single-pass mode); one that asked for evidence
			// it will never receive is not.
			if investigating == 0 {
				out.Status, out.Text = "complete", resp.Text
				return out
			}
			out.Reason = fmt.Sprintf("iteration budget exhausted (MaxIterations %d) with %d investigation %s unanswered",
				s.Budgets.MaxIterations, investigating, plural(investigating, "call"))
			return out
		}
	}
	out.Reason = fmt.Sprintf("iteration budget exhausted (MaxIterations %d)", s.Budgets.MaxIterations)
	return out
}

func startOrContinue(iter int) string {
	if iter == 0 {
		return "start: the initial request exceeds the model's context limit"
	}
	return "continue: the conversation outgrew the model's context limit"
}

// providerFailure words a classified provider error for the report. A
// context overflow the provider caught is the same incomplete answer as
// one caught locally, never a retry with less evidence (docs/SPEC.md §5.3).
func providerFailure(err error) string {
	switch llm.KindOf(err) {
	case llm.ErrContextOverflow:
		return "the provider rejected the request as exceeding its context limit; no evidence was dropped to retry"
	case llm.ErrUnsupported:
		return "the provider lacks a required feature: " + err.Error()
	case llm.ErrAuth:
		return "the provider refused the credential: " + err.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "run timeout (RunTimeout) during a model call"
	}
	return "provider error: " + strings.TrimSpace(err.Error())
}

func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}
