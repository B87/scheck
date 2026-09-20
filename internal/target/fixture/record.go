package fixture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/b87/scheck/internal/target"
)

// Recorder wraps a live target and writes every exec into a fixture
// directory (manifest.yaml plus one file per non-empty stream), so real
// hosts can be turned into offline fixtures with `--record-fixtures DIR`.
// Redact is applied to every stream before it touches disk.
type Recorder struct {
	Inner  target.Target
	Dir    string
	Redact func([]byte) []byte

	mu sync.Mutex
	m  Manifest
	n  int
}

// Platform delegates to the wrapped target.
func (r *Recorder) Platform() target.Platform { return r.Inner.Platform() }

// Transport delegates to the wrapped target.
func (r *Recorder) Transport() target.Transport { return r.Inner.Transport() }

// Exec runs the command on the wrapped target and records the outcome.
func (r *Recorder) Exec(ctx context.Context, argv []string) (target.Result, error) {
	res, err := r.Inner.Exec(ctx, argv)
	if rerr := r.record(argv, res); rerr != nil {
		return res, fmt.Errorf("record fixture: %w", rerr)
	}
	return res, err
}

func (r *Recorder) record(argv []string, res target.Result) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.Dir, 0o750); err != nil {
		return err
	}
	r.n++
	e := Exec{Argv: argv, Code: res.Code}
	stem := fmt.Sprintf("%03d-%s", r.n, sanitize(filepath.Base(argv[0])))
	for _, s := range []struct {
		data []byte
		name *string
		ext  string
	}{{res.Stdout, &e.StdoutFile, ".stdout"}, {res.Stderr, &e.StderrFile, ".stderr"}} {
		if len(s.data) == 0 {
			continue
		}
		data := s.data
		if r.Redact != nil {
			data = r.Redact(data)
		}
		*s.name = stem + s.ext
		if err := os.WriteFile(filepath.Join(r.Dir, *s.name), data, 0o600); err != nil {
			return err
		}
	}
	r.m.Platform = r.Inner.Platform()
	r.m.Execs = append(r.m.Execs, e)
	out, err := yaml.Marshal(r.m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.Dir, "manifest.yaml"), out, 0o600)
}

func sanitize(s string) string {
	return strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			return c
		}
		return '_'
	}, s)
}
