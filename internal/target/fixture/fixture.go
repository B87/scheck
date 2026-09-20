// Package fixture is a target.Target that replays recorded exec results, so
// every check-parsing, runner and report test runs with zero network and zero
// real commands.
package fixture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/target"
)

// Exec is one recorded command.
type Exec struct {
	Argv       []string `yaml:"argv"`
	Stdout     string   `yaml:"stdout,omitempty"`      // inline
	Stderr     string   `yaml:"stderr,omitempty"`      // inline
	StdoutFile string   `yaml:"stdout_file,omitempty"` // relative to the manifest dir
	StderrFile string   `yaml:"stderr_file,omitempty"`
	Code       int      `yaml:"code"`
	// Sleep makes the replay block for that long (bounded by ctx) so timeout
	// handling can be tested deterministically.
	Sleep time.Duration `yaml:"sleep,omitempty"`
}

// Manifest is the on-disk shape of a fixture directory.
type Manifest struct {
	Platform target.Platform `yaml:"platform"`
	Execs    []Exec          `yaml:"execs"`
}

// Target replays a Manifest.
type Target struct {
	platform target.Platform
	execs    []Exec
	dir      string
	// Calls records every argv that was executed, in order, for assertions.
	Calls [][]string
}

// New builds an in-memory fixture target.
func New(platform target.Platform, execs ...Exec) *Target {
	return &Target{platform: platform, execs: execs}
}

// Load reads <dir>/manifest.yaml.
func Load(dir string) (*Target, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", dir, err)
	}
	if m.Platform == "" {
		return nil, fmt.Errorf("fixture %s: platform is required", dir)
	}
	return &Target{platform: m.Platform, execs: m.Execs, dir: dir}, nil
}

// Add appends a recorded exec.
func (t *Target) Add(e Exec) { t.execs = append(t.execs, e) }

// Platform implements target.Target.
func (t *Target) Platform() target.Platform { return t.platform }

// Transport implements target.Target.
func (t *Target) Transport() target.Transport { return target.TransportFixture }

// Exec implements target.Target. An argv with no recording behaves like a
// missing binary: code 127 and target.ErrNotFound.
func (t *Target) Exec(ctx context.Context, argv []string) (target.Result, error) {
	t.Calls = append(t.Calls, slices.Clone(argv))
	if len(argv) == 0 {
		return target.Result{}, errors.New("empty argv")
	}
	start := time.Now()
	for _, e := range t.execs {
		if !slices.Equal(e.Argv, argv) {
			continue
		}
		if e.Sleep > 0 {
			select {
			case <-time.After(e.Sleep):
			case <-ctx.Done():
				return target.Result{Code: -1, Duration: time.Since(start)}, fmt.Errorf("%w after %s", target.ErrTimeout, e.Sleep)
			}
		}
		stdout, err := t.stream(e.Stdout, e.StdoutFile)
		if err != nil {
			return target.Result{}, err
		}
		stderr, err := t.stream(e.Stderr, e.StderrFile)
		if err != nil {
			return target.Result{}, err
		}
		return target.Result{Stdout: stdout, Stderr: stderr, Code: e.Code, Duration: time.Since(start)}, nil
	}
	return target.Result{
		Code:     target.CodeNotFound,
		Stderr:   []byte(argv[0] + ": not found"),
		Duration: time.Since(start),
	}, fmt.Errorf("%w: %s", target.ErrNotFound, argv[0])
}

func (t *Target) stream(inline, file string) ([]byte, error) {
	if file == "" {
		return []byte(inline), nil
	}
	b, err := os.ReadFile(filepath.Join(t.dir, file))
	if err != nil {
		return nil, fmt.Errorf("fixture stream: %w", err)
	}
	return b, nil
}
