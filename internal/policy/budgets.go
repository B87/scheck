package policy

import (
	"errors"
	"time"
)

// Budgets bounds every run. This struct is the only place these numbers
// exist (SPEC.md §4.4); the runner and the agent loop receive it and enforce
// their own fields. Exhausting any budget ends the run as incomplete, never
// as a clean bill of health.
type Budgets struct {
	PerCheckSoft    time.Duration // logged as slow
	PerCheckHard    time.Duration // killed, recorded as unavailable
	PerCheckOutput  int           // bytes, then [TRUNCATED]
	AgentChecks     int           // model-initiated checks per run
	AgentWallClock  time.Duration // aggregate for model-initiated checks
	ModelInputTotal int           // bytes of check output across the run
	MaxIterations   int           // model turns
	MaxTokens       int           // per completion
	ContextBytes    int           // merged operator context
	RunTimeout      time.Duration // bounds everything else; --timeout
}

// DefaultBudgets returns the v1 defaults.
func DefaultBudgets() Budgets {
	return Budgets{
		PerCheckSoft:    5 * time.Second,
		PerCheckHard:    30 * time.Second,
		PerCheckOutput:  64 << 10,
		AgentChecks:     60,
		AgentWallClock:  120 * time.Second,
		ModelInputTotal: 256 << 10,
		MaxIterations:   24,
		MaxTokens:       32000,
		ContextBytes:    32 << 10,
		RunTimeout:      5 * time.Minute,
	}
}

// redactSlack is how far past PerCheckOutput the capture reads so that a
// secret straddling the cap is inside the redacted window before the cut.
const redactSlack = 4 << 10

// CaptureLimit is the per-stream byte cap handed to a target: the output
// budget plus slack for redaction (SPEC.md §4.2, decision 4 in the plan).
func (b Budgets) CaptureLimit() int { return b.PerCheckOutput + redactSlack }

// Validate rejects a zero or negative budget, which would end every run
// immediately.
func (b Budgets) Validate() error {
	if b.PerCheckHard <= 0 || b.PerCheckOutput <= 0 || b.RunTimeout <= 0 {
		return errors.New("budgets: per-check hard timeout, output cap and run timeout must be positive")
	}
	if b.PerCheckSoft > b.PerCheckHard {
		return errors.New("budgets: soft timeout exceeds hard timeout")
	}
	return nil
}
