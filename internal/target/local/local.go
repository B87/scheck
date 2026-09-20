// Package local runs argv on this machine through os/exec with no shell.
package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/b87/scheck/internal/target"
)

// Target executes on the local machine.
type Target struct {
	// MaxOutput caps each of stdout and stderr, in bytes. Required (> 0).
	MaxOutput int
}

// New returns a local target that captures at most maxOutput bytes per stream.
func New(maxOutput int) *Target {
	return &Target{MaxOutput: maxOutput}
}

// Platform is derived from the Go runtime.
func (t *Target) Platform() target.Platform {
	switch runtime.GOOS {
	case "linux":
		return target.Linux
	case "darwin":
		return target.MacOS
	default:
		return target.Unknown
	}
}

// Transport implements target.Target.
func (t *Target) Transport() target.Transport { return target.TransportLocal }

// Exec implements target.Target. argv is passed to the kernel verbatim: no
// expansion, no quoting, no shell.
func (t *Target) Exec(ctx context.Context, argv []string) (target.Result, error) {
	if len(argv) == 0 {
		return target.Result{}, errors.New("empty argv")
	}
	if t.MaxOutput <= 0 {
		return target.Result{}, errors.New("local target: MaxOutput must be > 0")
	}
	start := time.Now()
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return target.Result{
			Code:     target.CodeNotFound,
			Stderr:   []byte(argv[0] + ": not found"),
			Duration: time.Since(start),
		}, fmt.Errorf("%w: %s", target.ErrNotFound, argv[0])
	}

	stdout := &target.CapWriter{Max: t.MaxOutput}
	stderr := &target.CapWriter{Max: t.MaxOutput}
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = nil
	cmd.Dir = "/"
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	// Give pipes a moment to drain after a kill so Wait cannot hang on a
	// grandchild that inherited them.
	cmd.WaitDelay = 2 * time.Second

	runErr := cmd.Run()
	res := target.Result{
		Stdout:          stdout.Buf,
		Stderr:          stderr.Buf,
		StdoutTruncated: stdout.Truncated,
		StderrTruncated: stderr.Truncated,
		Duration:        time.Since(start),
	}
	if ctx.Err() != nil {
		res.Code = -1
		return res, fmt.Errorf("%w after %s", target.ErrTimeout, res.Duration.Round(time.Millisecond))
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.Code = 0
	case errors.As(runErr, &exitErr):
		res.Code = exitErr.ExitCode()
	default:
		res.Code = -1
		return res, fmt.Errorf("exec %s: %w", argv[0], runErr)
	}
	return res, nil
}
