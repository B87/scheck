// Package policy is the single owner of every decision about what data may
// leave the target and reach the model, the report, or the audit log
// (SPEC.md §4): path sensitivity, redaction and budgets. check, runner and
// the agent tools call into it; none of them re-implements any part of it.
package policy
