// Package state persists run envelopes under the state directory
// (docs/SPEC.md §7.4): <state-dir>/runs/<host.id>/<started>.json. Persistence
// never blocks a run; a failure is returned for the caller to report as a
// warning.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/b87/scheck/internal/report"
)

// Dir resolves the state directory: the explicit value (flag or config),
// else $XDG_STATE_HOME/scheck, else ~/.local/state/scheck.
func Dir(explicit string) (string, error) {
	if explicit != "" {
		return expand(explicit)
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "scheck"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("state dir: %w", err)
	}
	return filepath.Join(home, ".local", "state", "scheck"), nil
}

func expand(p string) (string, error) {
	if len(p) >= 2 && p[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, p[2:])
	}
	return filepath.Abs(p)
}

// Path is where an envelope for this host and start time lands.
func Path(dir string, env *report.Envelope) string {
	return filepath.Join(dir, "runs", env.Host.ID, env.Run.Started.UTC().Format(time.RFC3339)+".json")
}

// Write stores env at Path, recording that path inside the envelope first
// so the file and the rendered report agree. The write is atomic (temp file
// plus rename) and the file is 0600.
func Write(dir string, env *report.Envelope) (string, error) {
	if env.Host.ID == "" {
		return "", errors.New("state: envelope has no host.id")
	}
	path := Path(dir, env)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	env.Run.Persisted = &path
	tmp, err := os.CreateTemp(filepath.Dir(path), ".run-*.json")
	if err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(env); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	return path, nil
}

// List returns the persisted run files for a host, oldest first.
func List(dir, hostID string) ([]string, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "runs", hostID, "*.json"))
	if err != nil {
		return nil, err
	}
	return entries, nil
}
