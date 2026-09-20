package main

import "fmt"

// Exit codes per SPEC.md §8.
const (
	exitOK         = 0 // no open finding at or above the profile threshold
	exitFindings   = 1 // findings present
	exitIncomplete = 2 // check/agent/transport failure, budget exhausted
	exitUsage      = 3 // usage or policy error (failed canary, bad config, ...)
)

// exitError carries a process exit code alongside the error message.
type exitError struct {
	Code int
	Err  error
}

func (e *exitError) Error() string { return e.Err.Error() }
func (e *exitError) Unwrap() error { return e.Err }

func usageErr(format string, args ...any) error {
	return &exitError{Code: exitUsage, Err: fmt.Errorf(format, args...)}
}

func incompleteErr(format string, args ...any) error {
	return &exitError{Code: exitIncomplete, Err: fmt.Errorf(format, args...)}
}
