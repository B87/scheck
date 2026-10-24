// Package state resolves the state directory, under which each engagement
// run keeps its run directory (docs/spec/runs.md, "Runs, state and
// configuration"). From 0.0.2 nothing is persisted under runs/<host.id>/: a
// host's envelope is its asset's evidence file in the run directory.
package state

import (
	"fmt"
	"os"
	"path/filepath"
)

// Dir resolves the state directory: the explicit value (--state-dir), else
// $XDG_STATE_HOME/scheck, else ~/.local/state/scheck.
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
