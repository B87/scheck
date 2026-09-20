package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditEntry is one attempted check (docs/SPEC.md §4.5). A denied call is a logged
// line, never a silent drop.
type AuditEntry struct {
	Observation string            `json:"observation,omitempty"`
	Time        time.Time         `json:"time"`
	CheckID     string            `json:"check"`
	Params      map[string]string `json:"params,omitempty"`
	Argv        []string          `json:"argv,omitempty"`
	Decision    string            `json:"decision"` // run | denied:<rule> | unavailable:<reason>
	ExitCode    *int              `json:"exit_code,omitempty"`
	DurationMS  int64             `json:"duration_ms"`
	OutputHash  string            `json:"output_sha256,omitempty"` // of the redacted output
	Elevated    bool              `json:"elevated,omitempty"`
	Tool        string            `json:"tool,omitempty"`      // run_check | read_file for a model-initiated call, phase 2
	Rationale   string            `json:"rationale,omitempty"` // model-supplied, phase 2
}

// Audit writes JSONL entries. A nil *Audit is valid and discards everything,
// so callers never branch on whether a log was requested.
type Audit struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

// NewAudit logs to w.
func NewAudit(w io.Writer) *Audit { return &Audit{w: w} }

// OpenAudit appends to path, creating it 0600.
func OpenAudit(path string) (*Audit, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return &Audit{w: f, c: f}, nil
}

// Log writes one entry. Errors are returned, not swallowed, because an audit
// log that silently stops is worse than none.
func (a *Audit) Log(e AuditEntry) error {
	if a == nil {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.w.Write(append(line, '\n'))
	return err
}

// Close releases the underlying file, if any.
func (a *Audit) Close() error {
	if a == nil || a.c == nil {
		return nil
	}
	return a.c.Close()
}

// OutputHash hashes redacted output for the audit line.
func OutputHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
