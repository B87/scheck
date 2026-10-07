package engagement

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrLocked is a run directory another run holds.
var ErrLocked = errors.New("is locked by another run")

// RunDir is one run's directory, <state-dir>/engagements/<name>/<started>/,
// created 0700 and locked while the run holds it (docs/spec/engagement.md,
// "Runs, state and configuration"). Every file in it is written 0600.
type RunDir struct {
	Path string
	lock *os.File
}

// CreateRunDir creates and locks the directory for a run of name started at
// started. A directory that already exists is refused: locked, it belongs
// to a run in progress; unlocked, to a finished one, and resuming one
// arrives in 0.0.2 E4.
func CreateRunDir(stateDir, name string, started time.Time) (*RunDir, error) {
	dir := filepath.Join(stateDir, "engagements", name, started.UTC().Format(time.RFC3339))
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, fmt.Errorf("run directory: %w", err)
	}
	switch err := os.Mkdir(dir, 0o700); {
	case errors.Is(err, os.ErrExist):
		// The probe holds the lock only for an instant; the run that
		// created the directory waits for it rather than failing (below).
		d, err := LockRunDir(dir)
		if err != nil {
			return nil, err
		}
		d.Close()
		return nil, fmt.Errorf("run directory %s already holds a run: resuming one is not available in this build (0.0.2 E4)", dir)
	case err != nil:
		return nil, fmt.Errorf("run directory: %w", err)
	}
	// The directory is new, so only a probe can hold its lock, and only
	// for an instant: wait for it rather than fail.
	return lock(dir, syscall.LOCK_EX)
}

// LockRunDir takes the run directory's lock without waiting, or returns
// ErrLocked. The lock is an flock on .lock, held until Close or the
// process ends, so a crashed run never leaves a directory locked.
func LockRunDir(dir string) (*RunDir, error) {
	return lock(dir, syscall.LOCK_EX|syscall.LOCK_NB)
}

func lock(dir string, how int) (*RunDir, error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("run directory: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("run directory %s %w", dir, ErrLocked)
		}
		return nil, fmt.Errorf("run directory: lock: %w", err)
	}
	return &RunDir{Path: dir, lock: f}, nil
}

// Close releases the lock.
func (d *RunDir) Close() {
	if d == nil || d.lock == nil {
		return
	}
	_ = syscall.Flock(int(d.lock.Fd()), syscall.LOCK_UN)
	_ = d.lock.Close()
	d.lock = nil
}

// File is the path of name inside the directory.
func (d *RunDir) File(name string) string { return filepath.Join(d.Path, name) }

// Write stores data as name, atomically (temp file and rename), 0600.
func (d *RunDir) Write(name string, data []byte) error {
	path := d.File(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteJSON stores v as indented JSON.
func (d *RunDir) WriteJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return d.Write(name, append(b, '\n'))
}
