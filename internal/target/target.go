// Package target abstracts "a host on which scheck can execute one argv".
//
// A Target never receives a shell command line: it receives argv tokens that
// come from the compiled check catalog. On the local target that contract is
// honoured by os/exec; on SSH it is honoured by a quoter plus a canary check
// (docs/spec/host-collector.md §4.3). Nothing in this package decides what may run — that is the
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
	// ErrAccess marks a connection refused by the operator's own
	// configuration or by the host's answer to it: an unknown or changed
	// host key, an unreadable identity or known_hosts file, failed
	// authentication. It is a usage error; every other failure to connect
	// is ErrUnreachable, a transport failure (docs/spec/engagement.md,
	// "Exit codes").
	ErrAccess = errors.New("access refused")
	// ErrHostKeyUnknown and ErrHostKeyChanged say which host-key refusal an
	// ErrAccess is, so a report can tell an unverified host from a changed
	// key, which can mean an interception (docs/spec/engagement.md,
	// "Incompleteness and refusals").
	ErrHostKeyUnknown = errors.New("host key unknown")
	ErrHostKeyChanged = errors.New("host key changed")
	// ErrJumpHost marks a failure on the jump host itself, before the
	// target was contacted, so a refusal names the hop and not the target.
	ErrJumpHost = errors.New("jump host")
	// ErrExcluded marks a host or jump host whose address an exclude in the
	// engagement file covers: refused before the connection opens
	// (docs/spec/scope.md, "The scope gate"). It is an ErrAccess.
	ErrExcluded = errors.New("address excluded")
	// ErrUnreachable marks a connection that never reached a working
	// session for any reason other than ErrAccess: a name that does not
	// resolve, TCP refused or timed out, a handshake reset or cut off.
	ErrUnreachable = errors.New("host unreachable")
	// ErrTransport marks a session lost after it worked: an Exec whose
	// command could not be sent or whose answer never came back. The run
	// stops there, incomplete (docs/spec/host-collector.md §7).
	ErrTransport = errors.New("transport lost")
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
