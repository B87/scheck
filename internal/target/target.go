// Package target abstracts "a host on which scheck can execute one argv".
//
// A Target never receives a shell command line: it receives argv tokens that
// come from the compiled check catalog. On the local target that contract is
// honoured by os/exec; on SSH it is honoured by a quoter plus a canary check
// (docs/SPEC.md §4.3). Nothing in this package decides what may run — that is the
// catalog's and the policy's job; this package only runs it and captures the
// result within a byte cap.
package target

import (
	"context"
	"errors"
	"time"
)

// Platform is the operating system family of a target.
type Platform string

// Platforms scheck knows how to audit.
const (
	Linux   Platform = "linux"
	MacOS   Platform = "macos"
	Unknown Platform = "unknown"
)

// Transport names how a target is reached; recorded in the report header.
type Transport string

// Transports.
const (
	TransportLocal   Transport = "local"
	TransportSSH     Transport = "ssh"
	TransportFixture Transport = "fixture"
)

// Result is the captured outcome of one Exec.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	Code     int
	Duration time.Duration
	// StdoutTruncated / StderrTruncated report that the stream exceeded the
	// capture cap and the tail was dropped. Callers mark this explicitly for
	// the model; nothing downstream may treat a truncated stream as complete.
	StdoutTruncated bool
	StderrTruncated bool
}

// Sentinel errors. A Target returns these wrapped, alongside a Result whose
// Code is set to the conventional value (127 for not found).
var (
	ErrNotFound = errors.New("binary not found")
	ErrTimeout  = errors.New("timed out")
	ErrCanary   = errors.New("ssh canary mismatch")
)

// CodeNotFound is the exit code reported when argv[0] cannot be found.
const CodeNotFound = 127

// Target runs one argv on a host.
type Target interface {
	// Exec runs argv[0] with argv[1:] as literal arguments and waits for it to
	// finish or for ctx to end. A non-zero exit is not an error: it is reported
	// in Result.Code. err is non-nil only when the command could not run
	// (ErrNotFound), ran out of time (ErrTimeout), or the transport failed.
	Exec(ctx context.Context, argv []string) (Result, error)
	// Platform reports the target's OS family, or Unknown before it is known.
	Platform() Platform
	// Transport reports how the target is reached.
	Transport() Transport
}

// PlatformFromUname maps `uname -s` output to a Platform.
func PlatformFromUname(s string) Platform {
	switch s {
	case "Linux":
		return Linux
	case "Darwin":
		return MacOS
	default:
		return Unknown
	}
}
